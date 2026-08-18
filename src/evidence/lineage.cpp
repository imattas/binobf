#include <binobf/evidence/lineage.hpp>

#include <binobf/evidence/manifest.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace binobf::evidence {
namespace {

template <typename Value>
auto failure(std::string code, std::string message) -> Result<Value, Diagnostic> {
    return Result<Value, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

auto address_kind(AddressKind kind) noexcept -> std::string_view {
    switch (kind) {
    case AddressKind::FileOffset: return "file-offset";
    case AddressKind::RelativeVirtual: return "relative-virtual";
    case AddressKind::Virtual: return "virtual";
    }
    return "unknown";
}

auto nesting_within_limit(std::span<const std::byte> bytes, std::size_t limit) noexcept
    -> bool {
    std::size_t depth = 0;
    bool inString = false;
    bool escaped = false;
    for (const auto raw : bytes) {
        const auto character = static_cast<char>(std::to_integer<unsigned char>(raw));
        if (inString) {
            if (escaped) {
                escaped = false;
            } else if (character == '\\') {
                escaped = true;
            } else if (character == '"') {
                inString = false;
            }
            continue;
        }
        if (character == '"') {
            inString = true;
        } else if (character == '{' || character == '[') {
            ++depth;
            if (depth > limit) return false;
        } else if ((character == '}' || character == ']') && depth > 0) {
            --depth;
        }
    }
    return true;
}

auto exact_keys(const nlohmann::json& object,
                std::span<const std::string_view> allowed) -> bool {
    if (!object.is_object()) return false;
    for (auto item = object.begin(); item != object.end(); ++item) {
        if (std::find(allowed.begin(), allowed.end(), item.key()) == allowed.end()) {
            return false;
        }
    }
    return true;
}

auto checked_string(const nlohmann::json& object,
                    std::string_view key,
                    const LineageParseLimits& limits)
    -> Result<std::string, Diagnostic> {
    const auto item = object.find(key);
    if (item == object.end() || !item->is_string()) {
        return failure<std::string>(
            "lineage.schema", "lineage field '" + std::string{key} + "' must be a string");
    }
    auto value = item->get<std::string>();
    if (value.empty() || value.size() > limits.maxStringBytes) {
        return failure<std::string>(
            "lineage.limit", "lineage field '" + std::string{key} + "' has invalid length");
    }
    return Result<std::string, Diagnostic>::success(std::move(value));
}

auto checked_u64(const nlohmann::json& object, std::string_view key)
    -> Result<std::uint64_t, Diagnostic> {
    const auto item = object.find(key);
    if (item == object.end() || !item->is_number_unsigned()) {
        return failure<std::uint64_t>(
            "lineage.schema",
            "lineage field '" + std::string{key} + "' must be an unsigned integer");
    }
    return Result<std::uint64_t, Diagnostic>::success(item->get<std::uint64_t>());
}

auto find_section(const BinaryImage& image, EntityId id) -> const Section* {
    const auto found = std::find_if(
        image.sections.begin(), image.sections.end(),
        [id](const auto& section) { return section.id == id; });
    return found == image.sections.end() ? nullptr : &*found;
}

auto find_symbol(const BinaryImage& image, EntityId id) -> const Symbol* {
    const auto found = std::find_if(
        image.symbols.begin(), image.symbols.end(),
        [id](const auto& symbol) { return symbol.id == id; });
    return found == image.symbols.end() ? nullptr : &*found;
}

auto symbol_section_name(const BinaryImage& image, const Symbol& symbol)
    -> std::optional<std::string_view> {
    if (!symbol.section.has_value()) return std::nullopt;
    const auto* section = find_section(image, *symbol.section);
    if (section == nullptr) return std::nullopt;
    return section->name;
}

auto find_provenance_symbol(const BinaryImage& verified,
                            const Symbol& verifiedSymbol,
                            const BinaryImage& provenance) -> const Symbol* {
    const auto verifiedSection = symbol_section_name(verified, verifiedSymbol);
    const Symbol* match = nullptr;
    for (const auto& candidate : provenance.symbols) {
        if (candidate.name != verifiedSymbol.name
            || candidate.kind != verifiedSymbol.kind
            || candidate.address != verifiedSymbol.address
            || candidate.size != verifiedSymbol.size
            || candidate.defined != verifiedSymbol.defined
            || symbol_section_name(provenance, candidate) != verifiedSection) {
            continue;
        }
        if (match != nullptr) return nullptr;
        match = &candidate;
    }
    return match;
}

auto find_section_by_name(const BinaryImage& image, std::string_view name)
    -> const Section* {
    const Section* match = nullptr;
    for (const auto& section : image.sections) {
        if (section.name != name) continue;
        if (match != nullptr) return nullptr;
        match = &section;
    }
    return match;
}

auto function_entity(const Function& function,
                     const BinaryImage& image,
                     std::string domain) -> LineageEntity {
    const auto* section = find_section(image, function.section);
    return LineageEntity{
        .id = domain + ":function:" + std::to_string(function.id.value()),
        .domain = std::move(domain),
        .kind = "function",
        .name = function.name,
        .section = section == nullptr ? std::string{} : section->name,
        .address = function.address.value,
        .size = function.size,
        .addressKind = std::string{address_kind(function.address.kind)},
        .origin = std::nullopt,
        .transforms = {},
    };
}

void append_transforms(
    std::vector<LineageTransform>& destination,
    const TransformationLineage& lineage) {
    for (const auto& record : lineage.parents) {
        const auto duplicate = std::find_if(
            destination.begin(), destination.end(), [&](const auto& existing) {
                return existing.id == record.transform.value()
                    && existing.sourceEntity == record.source.value()
                    && existing.pass == record.passName;
            });
        if (duplicate == destination.end()) {
            destination.push_back(LineageTransform{
                record.transform.value(), record.source.value(), record.passName});
        }
    }
}

} // namespace

auto serialize_lineage(const LineageDocument& document) -> std::string {
    nlohmann::json entities = nlohmann::json::array();
    for (const auto& entity : document.entities) {
        nlohmann::json transforms = nlohmann::json::array();
        for (const auto& transform : entity.transforms) {
            transforms.push_back(nlohmann::json{
                {"id", transform.id},
                {"pass", transform.pass},
                {"source_entity", transform.sourceEntity},
            });
        }
        entities.push_back(nlohmann::json{
            {"address", entity.address},
            {"address_kind", entity.addressKind},
            {"domain", entity.domain},
            {"id", entity.id},
            {"kind", entity.kind},
            {"name", entity.name},
            {"origin", entity.origin.has_value() ? nlohmann::json(*entity.origin)
                                                  : nlohmann::json(nullptr)},
            {"section", entity.section},
            {"size", entity.size},
            {"transforms", std::move(transforms)},
        });
    }
    const nlohmann::json json{
        {"architecture", document.architecture},
        {"entities", std::move(entities)},
        {"format", document.format},
        {"input_sha256", document.inputSha256},
        {"output_sha256", document.outputSha256},
        {"schema_version", document.schemaVersion},
        {"tool", nlohmann::json{{"name", "binobf"},
                                 {"version", document.toolVersion}}},
    };
    return json.dump() + '\n';
}

auto parse_lineage(std::span<const std::byte> bytes, const LineageParseLimits& limits)
    -> Result<LineageDocument, Diagnostic> {
    if (bytes.size() > limits.maxInputBytes ||
        !nesting_within_limit(bytes, limits.maxDepth)) {
        return failure<LineageDocument>(
            "lineage.limit", "lineage sidecar exceeds parser resource limits");
    }

    auto root = nlohmann::json::parse(bytes.begin(), bytes.end(), nullptr, false);
    if (root.is_discarded()) {
        return failure<LineageDocument>(
            "lineage.syntax", "invalid lineage JSON syntax");
    }

    constexpr std::array<std::string_view, 7> rootKeys{
        "architecture", "entities", "format", "input_sha256", "output_sha256",
        "schema_version", "tool"};
    if (!exact_keys(root, rootKeys)) {
        return failure<LineageDocument>(
            "lineage.schema", "lineage root contains missing, unknown, or invalid fields");
    }
    const auto version = checked_u64(root, "schema_version");
    if (!version.has_value() || version.value() != 1) {
        return failure<LineageDocument>("lineage.version", "unsupported lineage schema version");
    }
    const auto tool = root.find("tool");
    constexpr std::array<std::string_view, 2> toolKeys{"name", "version"};
    if (tool == root.end() || !exact_keys(*tool, toolKeys)) {
        return failure<LineageDocument>("lineage.schema", "invalid lineage tool identity");
    }
    const auto toolName = tool->find("name");
    if (toolName == tool->end() || !toolName->is_string() ||
        toolName->get<std::string>() != "binobf") {
        return failure<LineageDocument>("lineage.schema", "invalid lineage tool identity");
    }
    auto toolVersion = checked_string(*tool, "version", limits);
    auto inputHash = checked_string(root, "input_sha256", limits);
    auto outputHash = checked_string(root, "output_sha256", limits);
    auto format = checked_string(root, "format", limits);
    auto architecture = checked_string(root, "architecture", limits);
    if (!toolVersion.has_value() || !inputHash.has_value() || !outputHash.has_value() ||
        !format.has_value() || !architecture.has_value()) {
        return failure<LineageDocument>("lineage.schema", "invalid lineage metadata fields");
    }
    const auto entitiesJson = root.find("entities");
    if (entitiesJson == root.end() || !entitiesJson->is_array()) {
        return failure<LineageDocument>("lineage.schema", "lineage entities must be an array");
    }
    if (entitiesJson->size() > limits.maxEntities) {
        return failure<LineageDocument>("lineage.limit", "lineage entity limit exceeded");
    }

    LineageDocument document{
        .schemaVersion = 1,
        .toolVersion = std::move(toolVersion).value(),
        .inputSha256 = std::move(inputHash).value(),
        .outputSha256 = std::move(outputHash).value(),
        .format = std::move(format).value(),
        .architecture = std::move(architecture).value(),
        .entities = {},
    };
    document.entities.reserve(entitiesJson->size());
    std::set<std::string, std::less<>> ids;
    std::size_t transformCount = 0;
    constexpr std::array<std::string_view, 10> entityKeys{
        "address", "address_kind", "domain", "id", "kind", "name", "origin",
        "section", "size", "transforms"};
    constexpr std::array<std::string_view, 3> transformKeys{
        "id", "pass", "source_entity"};
    for (const auto& item : *entitiesJson) {
        if (!exact_keys(item, entityKeys)) {
            return failure<LineageDocument>("lineage.schema", "invalid lineage entity fields");
        }
        auto id = checked_string(item, "id", limits);
        auto domain = checked_string(item, "domain", limits);
        auto kind = checked_string(item, "kind", limits);
        auto name = checked_string(item, "name", limits);
        auto section = checked_string(item, "section", limits);
        auto addressKind = checked_string(item, "address_kind", limits);
        auto address = checked_u64(item, "address");
        auto size = checked_u64(item, "size");
        if (!id.has_value() || !domain.has_value() || !kind.has_value() ||
            !name.has_value() || !section.has_value() || !addressKind.has_value() ||
            !address.has_value() || !size.has_value()) {
            return failure<LineageDocument>("lineage.schema", "invalid lineage entity value");
        }
        if (!ids.insert(id.value()).second) {
            return failure<LineageDocument>("lineage.duplicate", "duplicate lineage entity id");
        }
        std::optional<std::string> origin;
        const auto originJson = item.find("origin");
        if (originJson == item.end()) {
            return failure<LineageDocument>("lineage.schema", "lineage origin is required");
        }
        if (!originJson->is_null()) {
            if (!originJson->is_string()) {
                return failure<LineageDocument>("lineage.schema", "lineage origin must be string or null");
            }
            origin = originJson->get<std::string>();
            if (origin->empty() || origin->size() > limits.maxStringBytes) {
                return failure<LineageDocument>("lineage.limit", "lineage origin has invalid length");
            }
        }
        const auto transformsJson = item.find("transforms");
        if (transformsJson == item.end() || !transformsJson->is_array() ||
            transformsJson->size() > limits.maxTransforms -
                std::min(transformCount, limits.maxTransforms)) {
            return failure<LineageDocument>("lineage.limit", "lineage transform limit exceeded");
        }
        std::vector<LineageTransform> transforms;
        transforms.reserve(transformsJson->size());
        for (const auto& transform : *transformsJson) {
            if (!exact_keys(transform, transformKeys)) {
                return failure<LineageDocument>("lineage.schema", "invalid lineage transform fields");
            }
            auto transformId = checked_u64(transform, "id");
            auto sourceEntity = checked_u64(transform, "source_entity");
            auto pass = checked_string(transform, "pass", limits);
            if (!transformId.has_value() || !sourceEntity.has_value() || !pass.has_value()) {
                return failure<LineageDocument>("lineage.schema", "invalid lineage transform value");
            }
            transforms.push_back(LineageTransform{
                transformId.value(), sourceEntity.value(), std::move(pass).value()});
            ++transformCount;
        }
        document.entities.push_back(LineageEntity{
            .id = std::move(id).value(),
            .domain = std::move(domain).value(),
            .kind = std::move(kind).value(),
            .name = std::move(name).value(),
            .section = std::move(section).value(),
            .address = address.value(),
            .size = size.value(),
            .addressKind = std::move(addressKind).value(),
            .origin = std::move(origin),
            .transforms = std::move(transforms),
        });
    }
    for (const auto& entity : document.entities) {
        if (entity.origin.has_value() && !ids.contains(*entity.origin)) {
            return failure<LineageDocument>("lineage.reference", "lineage origin references a missing entity");
        }
    }
    return Result<LineageDocument, Diagnostic>::success(std::move(document));
}

auto query_lineage(const LineageDocument& document, std::uint64_t address)
    -> Result<LineageQueryResult, Diagnostic> {
    std::vector<const LineageEntity*> matches;
    for (const auto& entity : document.entities) {
        if (entity.domain != "protected" || entity.size == 0 || address < entity.address ||
            address - entity.address >= entity.size) {
            continue;
        }
        matches.push_back(&entity);
    }
    if (matches.empty()) {
        return failure<LineageQueryResult>(
            "lineage.not_found", "no protected entity contains the requested address");
    }
    const auto minimum = std::min_element(
        matches.begin(), matches.end(),
        [](const auto* left, const auto* right) { return left->size < right->size; });
    const auto narrowestSize = (*minimum)->size;
    const auto equallyNarrow = static_cast<std::size_t>(std::count_if(
        matches.begin(), matches.end(),
        [narrowestSize](const auto* entity) { return entity->size == narrowestSize; }));
    if (equallyNarrow != 1) {
        return failure<LineageQueryResult>(
            "lineage.ambiguous", "multiple protected entities contain the requested address");
    }

    std::unordered_map<std::string, const LineageEntity*> byId;
    for (const auto& entity : document.entities) byId.emplace(entity.id, &entity);
    const auto* current = *minimum;
    const auto protectedEntity = *current;
    std::vector<LineageTransform> transforms;
    std::set<std::string, std::less<>> visited;
    while (current->domain != "original") {
        if (!visited.insert(current->id).second) {
            return failure<LineageQueryResult>("lineage.cycle", "lineage origin chain contains a cycle");
        }
        transforms.insert(
            transforms.end(), current->transforms.begin(), current->transforms.end());
        if (!current->origin.has_value()) {
            return failure<LineageQueryResult>(
                "lineage.incomplete", "protected entity has no verified original mapping");
        }
        const auto next = byId.find(*current->origin);
        if (next == byId.end()) {
            return failure<LineageQueryResult>(
                "lineage.reference", "lineage origin references a missing entity");
        }
        current = next->second;
    }
    return Result<LineageQueryResult, Diagnostic>::success(LineageQueryResult{
        .protectedEntity = protectedEntity,
        .originalEntity = *current,
        .transforms = std::move(transforms),
    });
}

auto make_object_lineage(const BinaryImage& original,
                         const BinaryImage& protectedImage,
                         const BinaryImage& protectedProvenance,
                         std::string inputSha256,
                         std::string outputSha256)
    -> Result<LineageDocument, Diagnostic> {
    LineageDocument document{
        .schemaVersion = 1,
        .toolVersion = std::string{tool_version()},
        .inputSha256 = std::move(inputSha256),
        .outputSha256 = std::move(outputSha256),
        .format = std::string{to_string(protectedImage.format)},
        .architecture = std::string{to_string(protectedImage.architecture)},
        .entities = {},
    };
    document.entities.reserve(original.functions.size() + protectedImage.functions.size());
    for (const auto& function : original.functions) {
        document.entities.push_back(function_entity(function, original, "original"));
    }
    for (const auto& function : protectedImage.functions) {
        auto entity = function_entity(function, protectedImage, "protected");
        std::optional<EntityId> sourceSymbol;
        if (function.symbol.has_value()) {
            const auto* verifiedSymbol = find_symbol(protectedImage, *function.symbol);
            if (verifiedSymbol != nullptr) {
                const auto* provenanceSymbol = find_provenance_symbol(
                    protectedImage, *verifiedSymbol, protectedProvenance);
                if (provenanceSymbol != nullptr) {
                    append_transforms(entity.transforms, provenanceSymbol->lineage);
                    sourceSymbol = provenanceSymbol->id;
                    if (!provenanceSymbol->lineage.parents.empty()) {
                        sourceSymbol = provenanceSymbol->lineage.parents.back().source;
                    }
                }
            }
        }
        const auto* section = find_section(protectedImage, function.section);
        if (section != nullptr) {
            const auto* provenanceSection = find_section_by_name(
                protectedProvenance, section->name);
            if (provenanceSection != nullptr) {
                append_transforms(entity.transforms, provenanceSection->lineage);
            }
        }
        if (sourceSymbol.has_value()) {
            const auto originalFunction = std::find_if(
                original.functions.begin(), original.functions.end(),
                [&](const auto& candidate) { return candidate.symbol == sourceSymbol; });
            if (originalFunction != original.functions.end()) {
                entity.origin = "original:function:" +
                    std::to_string(originalFunction->id.value());
            }
        }
        document.entities.push_back(std::move(entity));
    }
    return Result<LineageDocument, Diagnostic>::success(std::move(document));
}

} // namespace binobf::evidence

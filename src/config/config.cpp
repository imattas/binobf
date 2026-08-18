#include <binobf/config/config.hpp>
#include <binobf/transforms/selection.hpp>

#include <nlohmann/json.hpp>
#include <toml++/toml.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <optional>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace binobf::config {
namespace {

using ParseResult = Result<ParsedConfig, Diagnostic>;

constexpr std::array<std::string_view, 11> kSupportedPasses{
    "strip-debug",
    "cleanup-metadata",
    "strip-local-symbols",
    "rename-private-symbols",
    "instruction-substitution",
    "constant-rewriting",
    "branch-inversion",
    "dead-code-insertion",
    "block-splitting",
    "block-reordering",
    "function-reordering",
};

auto failure(std::string code, std::string message) -> ParseResult {
    return ParseResult::failure(Diagnostic{
        DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

auto contains(std::span<const std::string_view> allowed, std::string_view key) noexcept
    -> bool {
    return std::find(allowed.begin(), allowed.end(), key) != allowed.end();
}

auto unknown_key(const toml::table& table,
                 std::span<const std::string_view> allowed,
                 std::string_view prefix) -> std::optional<std::string> {
    for (const auto& [key, unused] : table) {
        static_cast<void>(unused);
        if (!contains(allowed, key.str())) {
            auto qualified = std::string{prefix};
            if (!qualified.empty()) {
                qualified.push_back('.');
            }
            qualified.append(key.str());
            return qualified;
        }
    }
    return std::nullopt;
}

auto resolved_path(std::string_view value, const std::filesystem::path& source)
    -> std::filesystem::path {
    auto result = std::filesystem::path{value};
    if (result.is_relative()) {
        result = source.parent_path() / result;
    }
    return result.lexically_normal();
}

auto json_path(const std::optional<std::filesystem::path>& path) -> nlohmann::json {
    if (!path.has_value()) {
        return nullptr;
    }
    return path->generic_string();
}

auto visibility_name(SelectionVisibility visibility) noexcept -> std::string_view {
    switch (visibility) {
    case SelectionVisibility::Local: return "local";
    case SelectionVisibility::Hidden: return "hidden";
    case SelectionVisibility::External: return "external";
    }
    return "unknown";
}

auto joined_passes(const std::vector<std::string>& passes) -> std::string {
    if (passes.empty()) {
        return "none";
    }
    std::ostringstream result;
    for (std::size_t index = 0; index < passes.size(); ++index) {
        if (index != 0) {
            result << ',';
        }
        result << passes[index];
    }
    return result.str();
}

auto is_valid_toml_text(std::span<const std::byte> bytes) noexcept -> bool {
    std::size_t index = 0;
    while (index < bytes.size()) {
        const auto first = std::to_integer<std::uint8_t>(bytes[index]);
        if (first <= 0x7fU) {
            if ((first < 0x20U && first != 0x09U && first != 0x0aU && first != 0x0dU) ||
                first == 0x7fU) {
                return false;
            }
            ++index;
            continue;
        }

        std::size_t continuationCount = 0;
        std::uint32_t codePoint = 0;
        if (first >= 0xc2U && first <= 0xdfU) {
            continuationCount = 1;
            codePoint = first & 0x1fU;
        } else if (first >= 0xe0U && first <= 0xefU) {
            continuationCount = 2;
            codePoint = first & 0x0fU;
        } else if (first >= 0xf0U && first <= 0xf4U) {
            continuationCount = 3;
            codePoint = first & 0x07U;
        } else {
            return false;
        }
        if (continuationCount > bytes.size() - index - 1U) return false;
        for (std::size_t offset = 1; offset <= continuationCount; ++offset) {
            const auto continuation =
                std::to_integer<std::uint8_t>(bytes[index + offset]);
            if ((continuation & 0xc0U) != 0x80U) return false;
            codePoint = (codePoint << 6U) | (continuation & 0x3fU);
        }
        if ((continuationCount == 2 && codePoint < 0x800U) ||
            (continuationCount == 3 && codePoint < 0x10000U) ||
            (codePoint >= 0xd800U && codePoint <= 0xdfffU) || codePoint > 0x10ffffU) {
            return false;
        }
        index += continuationCount + 1U;
    }
    return true;
}

auto has_safe_non_ascii_syntax(std::span<const std::byte> bytes) noexcept -> bool {
    enum class State : std::uint8_t {
        Normal,
        Comment,
        BasicString,
        LiteralString,
        MultilineBasicString,
        MultilineLiteralString,
    };
    State state = State::Normal;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        const auto value = std::to_integer<std::uint8_t>(bytes[index]);
        const auto character = static_cast<char>(value);
        if (state == State::Normal) {
            if (value >= 0x80U) return false;
            if (character == '#') {
                state = State::Comment;
            } else if (character == '"') {
                const bool multiline = index + 2U < bytes.size()
                    && bytes[index + 1U] == std::byte{'"'}
                    && bytes[index + 2U] == std::byte{'"'};
                state = multiline ? State::MultilineBasicString : State::BasicString;
                if (multiline) index += 2U;
            } else if (character == '\'') {
                const bool multiline = index + 2U < bytes.size()
                    && bytes[index + 1U] == std::byte{'\''}
                    && bytes[index + 2U] == std::byte{'\''};
                state = multiline ? State::MultilineLiteralString : State::LiteralString;
                if (multiline) index += 2U;
            }
            continue;
        }
        if (state == State::Comment) {
            if (value >= 0x80U) return false;
            if (character == '\n' || character == '\r') state = State::Normal;
            continue;
        }
        if (state == State::BasicString) {
            if (character == '\\' && index + 1U < bytes.size()) {
                ++index;
            } else if (character == '"') {
                state = State::Normal;
            }
            continue;
        }
        if (state == State::LiteralString) {
            if (character == '\'') state = State::Normal;
            continue;
        }
        if (state == State::MultilineBasicString) {
            if (character == '\\' && index + 1U < bytes.size()) {
                ++index;
            } else if (character == '"' && index + 2U < bytes.size()
                       && bytes[index + 1U] == std::byte{'"'}
                       && bytes[index + 2U] == std::byte{'"'}) {
                state = State::Normal;
                index += 2U;
            }
            continue;
        }
        if (character == '\'' && index + 2U < bytes.size()
            && bytes[index + 1U] == std::byte{'\''}
            && bytes[index + 2U] == std::byte{'\''}) {
            state = State::Normal;
            index += 2U;
        }
    }
    return true;
}

auto trim_ascii(std::string_view value) noexcept -> std::string_view {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t'
                              || value.front() == '\r')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t'
                              || value.back() == '\r')) {
        value.remove_suffix(1);
    }
    return value;
}

auto without_comment(std::string_view line) noexcept -> std::string_view {
    char quote = 0;
    bool escaped = false;
    for (std::size_t index = 0; index < line.size(); ++index) {
        const auto character = line[index];
        if (quote == '"' && escaped) {
            escaped = false;
            continue;
        }
        if (quote == '"' && character == '\\') {
            escaped = true;
            continue;
        }
        if (quote != 0) {
            if (character == quote) quote = 0;
            continue;
        }
        if (character == '"' || character == '\'') {
            quote = character;
        } else if (character == '#') {
            return line.substr(0, index);
        }
    }
    return line;
}

auto consume_string(std::string_view value, std::size_t& position) noexcept -> bool {
    if (position >= value.size()
        || (value[position] != '"' && value[position] != '\'')) {
        return false;
    }
    const auto quote = value[position++];
    while (position < value.size()) {
        const auto character = value[position++];
        if (quote == '"' && character == '\\') {
            if (position >= value.size()) return false;
            ++position;
        } else if (character == quote) {
            return true;
        }
    }
    return false;
}

void skip_spaces(std::string_view value, std::size_t& position) noexcept {
    while (position < value.size()
           && (value[position] == ' ' || value[position] == '\t')) {
        ++position;
    }
}

auto valid_schema_value(std::string_view value) noexcept -> bool {
    value = trim_ascii(value);
    if (value.empty()) return false;
    if (value == "true" || value == "false") return true;
    if (value.front() == '"' || value.front() == '\'') {
        std::size_t position = 0;
        return consume_string(value, position) && position == value.size();
    }
    if (value.front() == '[') {
        std::size_t position = 1;
        skip_spaces(value, position);
        if (position < value.size() && value[position] == ']') {
            return position + 1U == value.size();
        }
        while (position < value.size()) {
            if (!consume_string(value, position)) return false;
            skip_spaces(value, position);
            if (position >= value.size()) return false;
            if (value[position] == ']') return position + 1U == value.size();
            if (value[position] != ',') return false;
            ++position;
            skip_spaces(value, position);
            if (position < value.size() && value[position] == ']') {
                return position + 1U == value.size();
            }
        }
        return false;
    }
    std::size_t position = 0;
    if (value[position] == '+' || value[position] == '-') ++position;
    if (position == value.size()) return false;
    for (; position < value.size(); ++position) {
        if (value[position] < '0' || value[position] > '9') return false;
    }
    return true;
}

auto valid_schema_key(std::string_view key) noexcept -> bool {
    if (key.empty()) return false;
    return std::all_of(key.begin(), key.end(), [](unsigned char value) {
        return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')
            || (value >= '0' && value <= '9') || value == '_';
    });
}

auto has_safe_schema_grammar(std::string_view text) noexcept -> bool {
    while (!text.empty()) {
        const auto newline = text.find('\n');
        auto line = text.substr(0, newline);
        line = trim_ascii(without_comment(line));
        if (!line.empty()) {
            if (line.front() == '[') {
                if (line != "[manifest]" && line != "[lineage]"
                    && line != "[selection]") {
                    return false;
                }
            } else {
                const auto equals = line.find('=');
                if (equals == std::string_view::npos
                    || !valid_schema_key(trim_ascii(line.substr(0, equals)))
                    || !valid_schema_value(line.substr(equals + 1U))) {
                    return false;
                }
            }
        }
        if (newline == std::string_view::npos) break;
        text.remove_prefix(newline + 1U);
    }
    return true;
}

auto checked_string(const toml::node* node,
                    std::string_view qualifiedName,
                    const ConfigParseLimits& limits)
    -> Result<std::string, Diagnostic> {
    if (node == nullptr || !node->is_string()) {
        return Result<std::string, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "config.type",
            std::string{qualifiedName} + " must be a string"});
    }
    const auto value = node->value<std::string>();
    if (!value.has_value()) {
        return Result<std::string, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "config.type",
            std::string{qualifiedName} + " must be a string"});
    }
    if (value->size() > limits.maxStringBytes) {
        return Result<std::string, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "config.limit",
            std::string{qualifiedName} + " exceeds the configured string-size limit"});
    }
    if (value->empty()) {
        return Result<std::string, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "config.value",
            std::string{qualifiedName} + " must not be empty"});
    }
    return Result<std::string, Diagnostic>::success(*value);
}

auto checked_string_array(const toml::node* node,
                          std::string_view qualifiedName,
                          const ConfigParseLimits& limits)
    -> Result<std::vector<std::string>, Diagnostic> {
    if (node == nullptr || !node->is_array()) {
        return Result<std::vector<std::string>, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "config.type",
            std::string{qualifiedName} + " must be an array of strings"});
    }
    const auto* array = node->as_array();
    if (array == nullptr) {
        return Result<std::vector<std::string>, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "config.type",
            std::string{qualifiedName} + " must be an array of strings"});
    }
    if (array->size() > limits.maxArrayEntries) {
        return Result<std::vector<std::string>, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "config.limit",
            std::string{qualifiedName} + " exceeds the configured array-size limit"});
    }

    std::vector<std::string> result;
    result.reserve(array->size());
    std::set<std::string, std::less<>> seen;
    for (const auto& item : *array) {
        auto value = checked_string(&item, qualifiedName, limits);
        if (!value.has_value()) {
            return Result<std::vector<std::string>, Diagnostic>::failure(
                std::move(value).error());
        }
        if (!seen.insert(value.value()).second) {
            return Result<std::vector<std::string>, Diagnostic>::failure(Diagnostic{
                DiagnosticSeverity::Error,
                "config.duplicate",
                std::string{qualifiedName} + " contains duplicate entry '" +
                    value.value() + "'"});
        }
        result.push_back(std::move(value).value());
    }
    return Result<std::vector<std::string>, Diagnostic>::success(std::move(result));
}

} // namespace

auto is_supported_pass(std::string_view pass) noexcept -> bool {
    return std::find(kSupportedPasses.begin(), kSupportedPasses.end(), pass) !=
           kSupportedPasses.end();
}

auto expand_profile(std::string_view profile) -> std::optional<std::vector<std::string>> {
    if (profile == "none") {
        return std::vector<std::string>{};
    }
    if (profile == "minimal") {
        return std::vector<std::string>{
            "strip-debug", "cleanup-metadata", "strip-local-symbols",
            "rename-private-symbols"};
    }
    if (profile == "balanced") {
        std::vector<std::string> result;
        result.reserve(kSupportedPasses.size());
        for (const auto pass : kSupportedPasses) {
            result.emplace_back(pass);
        }
        return result;
    }
    return std::nullopt;
}

auto canonicalize_transform_config(const TransformConfig& config) -> std::string {
    nlohmann::json json;
    json["allow_signature_invalidation"] = config.allowSignatureInvalidation.has_value()
                                                  ? nlohmann::json(*config.allowSignatureInvalidation)
                                                  : nlohmann::json(nullptr);
    json["dry_run"] = config.dryRun.has_value() ? nlohmann::json(*config.dryRun)
                                                 : nlohmann::json(nullptr);
    json["input"] = json_path(config.input);
    json["lineage_path"] = json_path(config.lineagePath);
    json["manifest"] = nlohmann::json{
        {"enabled",
         config.manifest.enabled.has_value() ? nlohmann::json(*config.manifest.enabled)
                                             : nlohmann::json(nullptr)},
        {"path", json_path(config.manifest.path)}};
    json["output"] = json_path(config.output);
    json["pass_description"] = config.passDescription.has_value()
                                   ? nlohmann::json(*config.passDescription)
                                   : nlohmann::json(nullptr);
    json["passes"] = config.passes.has_value() ? nlohmann::json(*config.passes)
                                                : nlohmann::json(nullptr);
    json["preserve_symbols"] = config.preservedSymbols;
    if (config.selection.has_value()) {
        const auto& selection = *config.selection;
        nlohmann::json visibilities = nlohmann::json::array();
        for (const auto visibility : selection.visibilities) {
            visibilities.push_back(visibility_name(visibility));
        }
        json["selection"] = nlohmann::json{
            {"exclude", selection.excludeNames},
            {"exclude_regex", selection.excludeRegex},
            {"include", selection.includeNames},
            {"include_regex", selection.includeRegex},
            {"percentage", selection.percentage.has_value()
                ? nlohmann::json(*selection.percentage) : nlohmann::json(nullptr)},
            {"sections", selection.sections},
            {"seed", selection.seed.has_value()
                ? nlohmann::json(*selection.seed) : nlohmann::json(nullptr)},
            {"visibility", std::move(visibilities)},
        };
    } else {
        json["selection"] = nullptr;
    }
    json["seed"] = config.seed.has_value() ? nlohmann::json(*config.seed)
                                            : nlohmann::json(nullptr);
    json["version"] = config.version;
    return json.dump();
}

auto parse_transform_config(std::span<const std::byte> bytes,
                            const std::filesystem::path& source,
                            const ConfigParseLimits& limits) -> ParseResult {
    if (bytes.size() > limits.maxInputBytes) {
        return failure("config.limit", "configuration exceeds the configured input-size limit");
    }
    const auto text = std::string_view{
        reinterpret_cast<const char*>(bytes.data()), bytes.size()};
    if (!is_valid_toml_text(bytes) || !has_safe_non_ascii_syntax(bytes)
        || !has_safe_schema_grammar(text)) {
        return failure("config.syntax", "configuration must be valid UTF-8 TOML text");
    }
    auto parsedToml = toml::parse(text, source.generic_string());
    if (!parsedToml.succeeded()) {
        return failure("config.syntax", "invalid TOML syntax");
    }
    auto root = std::move(parsedToml).table();

    constexpr std::array<std::string_view, 12> rootKeys{
        "version", "input", "output", "seed", "profile", "passes", "dry_run",
        "allow_signature_invalidation", "preserve_symbols", "selection", "manifest", "lineage"};
    if (root.size() > limits.maxArrayEntries) {
        return failure("config.limit", "configuration contains too many root keys");
    }
    if (const auto key = unknown_key(root, rootKeys, "config"); key.has_value()) {
        return failure("config.unknown_key", "unknown configuration key '" + *key + "'");
    }

    TransformConfig config;
    const auto version = root["version"].value<std::int64_t>();
    if (!version.has_value()) {
        return failure("config.version", "config.version is required and must be integer 1");
    }
    if (*version != 1) {
        return failure("config.version", "unsupported config.version; expected 1");
    }

    const auto parsePath = [&](std::string_view key)
        -> Result<std::filesystem::path, Diagnostic> {
        auto value = checked_string(root.get(key), "config." + std::string{key}, limits);
        if (!value.has_value()) {
            return Result<std::filesystem::path, Diagnostic>::failure(
                std::move(value).error());
        }
        return Result<std::filesystem::path, Diagnostic>::success(
            resolved_path(value.value(), source));
    };

    if (root.contains("input")) {
        auto path = parsePath("input");
        if (!path.has_value()) {
            return ParseResult::failure(std::move(path).error());
        }
        config.input = std::move(path).value();
    }
    if (root.contains("output")) {
        auto path = parsePath("output");
        if (!path.has_value()) {
            return ParseResult::failure(std::move(path).error());
        }
        config.output = std::move(path).value();
    }

    if (root.contains("seed")) {
        const auto seed = root["seed"].value<std::int64_t>();
        if (!seed.has_value()) {
            return failure("config.type", "config.seed must be a non-negative integer");
        }
        if (*seed < 0) {
            return failure("config.value", "config.seed must be non-negative");
        }
        config.seed = static_cast<std::uint64_t>(*seed);
    }

    const auto hasProfile = root.contains("profile");
    const auto hasPasses = root.contains("passes");
    if (hasProfile && hasPasses) {
        return failure("config.pass_conflict", "config.profile and config.passes are mutually exclusive");
    }
    if (hasProfile) {
        auto profile = checked_string(root.get("profile"), "config.profile", limits);
        if (!profile.has_value()) {
            return ParseResult::failure(std::move(profile).error());
        }
        auto expanded = expand_profile(profile.value());
        if (!expanded.has_value()) {
            return failure("config.profile", "unsupported config.profile '" + profile.value() + "'");
        }
        config.passDescription = profile.value();
        config.passes = std::move(*expanded);
    } else if (hasPasses) {
        auto passes = checked_string_array(root.get("passes"), "config.passes", limits);
        if (!passes.has_value()) {
            return ParseResult::failure(std::move(passes).error());
        }
        for (const auto& pass : passes.value()) {
            if (!is_supported_pass(pass)) {
                return failure("config.pass", "unsupported transform pass '" + pass + "'");
            }
        }
        config.passDescription = joined_passes(passes.value());
        config.passes = std::move(passes).value();
    }

    const auto parseBool = [&](std::string_view key) -> Result<bool, Diagnostic> {
        const auto value = root[key].value<bool>();
        if (!value.has_value()) {
            return Result<bool, Diagnostic>::failure(Diagnostic{
                DiagnosticSeverity::Error,
                "config.type",
                "config." + std::string{key} + " must be a boolean"});
        }
        return Result<bool, Diagnostic>::success(*value);
    };
    if (root.contains("dry_run")) {
        auto value = parseBool("dry_run");
        if (!value.has_value()) {
            return ParseResult::failure(std::move(value).error());
        }
        config.dryRun = value.value();
    }
    if (root.contains("allow_signature_invalidation")) {
        auto value = parseBool("allow_signature_invalidation");
        if (!value.has_value()) {
            return ParseResult::failure(std::move(value).error());
        }
        config.allowSignatureInvalidation = value.value();
    }

    if (root.contains("preserve_symbols")) {
        auto symbols = checked_string_array(
            root.get("preserve_symbols"), "config.preserve_symbols", limits);
        if (!symbols.has_value()) {
            return ParseResult::failure(std::move(symbols).error());
        }
        config.preservedSymbols = std::move(symbols).value();
    }

    if (root.contains("selection")) {
        const auto* table = root["selection"].as_table();
        if (table == nullptr) {
            return failure("config.type", "config.selection must be a table");
        }
        constexpr std::array<std::string_view, 8> selectionKeys{
            "include", "exclude", "include_regex", "exclude_regex",
            "sections", "visibility", "percentage", "seed"};
        if (const auto key = unknown_key(*table, selectionKeys, "config.selection");
            key.has_value()) {
            return failure("config.unknown_key", "unknown configuration key '" + *key + "'");
        }
        SelectionConfig selection;
        const auto parseArray = [&](std::string_view key, std::vector<std::string>& output)
            -> std::optional<Diagnostic> {
            if (!table->contains(key)) return std::nullopt;
            auto values = checked_string_array(
                table->get(key), "config.selection." + std::string{key}, limits);
            if (!values.has_value()) return std::move(values).error();
            output = std::move(values).value();
            return std::nullopt;
        };
        if (const auto issue = parseArray("include", selection.includeNames)) {
            return ParseResult::failure(*issue);
        }
        if (const auto issue = parseArray("exclude", selection.excludeNames)) {
            return ParseResult::failure(*issue);
        }
        if (const auto issue = parseArray("include_regex", selection.includeRegex)) {
            return ParseResult::failure(*issue);
        }
        if (const auto issue = parseArray("exclude_regex", selection.excludeRegex)) {
            return ParseResult::failure(*issue);
        }
        if (const auto issue = parseArray("sections", selection.sections)) {
            return ParseResult::failure(*issue);
        }
        if (table->contains("visibility")) {
            auto values = checked_string_array(
                table->get("visibility"), "config.selection.visibility", limits);
            if (!values.has_value()) {
                return ParseResult::failure(std::move(values).error());
            }
            for (const auto& value : values.value()) {
                if (value == "local") {
                    selection.visibilities.push_back(SelectionVisibility::Local);
                } else if (value == "hidden") {
                    selection.visibilities.push_back(SelectionVisibility::Hidden);
                } else if (value == "external") {
                    selection.visibilities.push_back(SelectionVisibility::External);
                } else {
                    return failure(
                        "config.value",
                        "config.selection.visibility contains unsupported value '" + value + "'");
                }
            }
        }
        if (table->contains("percentage")) {
            const auto value = (*table)["percentage"].value<std::int64_t>();
            if (!value.has_value()) {
                return failure(
                    "config.type", "config.selection.percentage must be an integer");
            }
            if (*value < 0 || *value > 100) {
                return failure(
                    "config.value", "config.selection.percentage must be between 0 and 100");
            }
            selection.percentage = static_cast<std::uint8_t>(*value);
        }
        if (table->contains("seed")) {
            const auto value = (*table)["seed"].value<std::int64_t>();
            if (!value.has_value()) {
                return failure(
                    "config.type", "config.selection.seed must be a non-negative integer");
            }
            if (*value < 0) {
                return failure(
                    "config.value", "config.selection.seed must be non-negative");
            }
            selection.seed = static_cast<std::uint64_t>(*value);
        }
        FunctionSelectionPolicy policy;
        policy.includeNames = selection.includeNames;
        policy.excludeNames = selection.excludeNames;
        policy.includeRegex = selection.includeRegex;
        policy.excludeRegex = selection.excludeRegex;
        policy.sections = selection.sections;
        policy.percentage = selection.percentage;
        for (const auto visibility : selection.visibilities) {
            switch (visibility) {
            case SelectionVisibility::Local:
                policy.visibilities.push_back(SymbolVisibility::Local);
                break;
            case SelectionVisibility::Hidden:
                policy.visibilities.push_back(SymbolVisibility::Hidden);
                break;
            case SelectionVisibility::External:
                policy.visibilities.push_back(SymbolVisibility::External);
                break;
            }
        }
        if (selection.seed.has_value()) policy.seed = *selection.seed;
        const auto compiled = FunctionSelector::compile(std::move(policy));
        if (!compiled.has_value()) {
            return ParseResult::failure(compiled.error());
        }
        config.selection = std::move(selection);
    }

    if (root.contains("manifest")) {
        const auto* manifest = root["manifest"].as_table();
        if (manifest == nullptr) {
            return failure("config.type", "config.manifest must be a table");
        }
        constexpr std::array<std::string_view, 2> manifestKeys{"enabled", "path"};
        if (const auto key = unknown_key(*manifest, manifestKeys, "config.manifest");
            key.has_value()) {
            return failure("config.unknown_key", "unknown configuration key '" + *key + "'");
        }
        if (manifest->contains("enabled")) {
            const auto enabled = (*manifest)["enabled"].value<bool>();
            if (!enabled.has_value()) {
                return failure("config.type", "config.manifest.enabled must be a boolean");
            }
            config.manifest.enabled = *enabled;
        }
        if (manifest->contains("path")) {
            auto value = checked_string(
                manifest->get("path"), "config.manifest.path", limits);
            if (!value.has_value()) {
                return ParseResult::failure(std::move(value).error());
            }
            config.manifest.path = resolved_path(value.value(), source);
        }
        if (config.manifest.enabled == std::optional<bool>{false} &&
            config.manifest.path.has_value()) {
            return failure("config.manifest_conflict",
                           "config.manifest.path cannot be set when manifest output is disabled");
        }
    }

    if (root.contains("lineage")) {
        const auto* lineage = root["lineage"].as_table();
        if (lineage == nullptr) {
            return failure("config.type", "config.lineage must be a table");
        }
        constexpr std::array<std::string_view, 1> lineageKeys{"path"};
        if (const auto key = unknown_key(*lineage, lineageKeys, "config.lineage");
            key.has_value()) {
            return failure("config.unknown_key", "unknown configuration key '" + *key + "'");
        }
        if (!lineage->contains("path")) {
            return failure("config.lineage", "config.lineage.path is required when lineage is configured");
        }
        auto value = checked_string(lineage->get("path"), "config.lineage.path", limits);
        if (!value.has_value()) {
            return ParseResult::failure(std::move(value).error());
        }
        config.lineagePath = resolved_path(value.value(), source);
    }

    ParsedConfig parsed{
        .config = std::move(config),
        .source = source.lexically_normal(),
        .canonicalJson = {},
    };
    parsed.canonicalJson = canonicalize_transform_config(parsed.config);
    return ParseResult::success(std::move(parsed));
}

} // namespace binobf::config

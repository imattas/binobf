#include <binobf/transforms/object_rewrite.hpp>

#include <binobf/architecture/backend.hpp>

#include "../formats/object_writer_internal.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace binobf {
namespace {

template <typename T>
auto failure(std::string code, std::string message) -> Result<T, Diagnostic> {
    return Result<T, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

struct MappingSegment {
    EntityId section;
    std::uint64_t oldBegin{0};
    std::uint64_t oldEnd{0};
    std::uint64_t newBegin{0};
    std::uint64_t newLength{0};
    std::vector<std::byte> bytes;
};

struct SectionMapping {
    EntityId section;
    std::uint64_t oldSize{0};
    std::uint64_t newSize{0};
    std::vector<MappingSegment> sourceSegments;
    std::vector<MappingSegment> outputSegments;
};

struct MappedSpan {
    std::uint64_t begin{0};
    std::uint64_t size{0};
};

auto checked_shift(std::uint64_t value, std::int64_t delta) -> std::optional<std::uint64_t> {
    if (delta >= 0) {
        const auto amount = static_cast<std::uint64_t>(delta);
        if (value > std::numeric_limits<std::uint64_t>::max() - amount) return std::nullopt;
        return value + amount;
    }
    const auto amount = static_cast<std::uint64_t>(-(delta + 1)) + 1U;
    if (value < amount) return std::nullopt;
    return value - amount;
}

auto checked_add_delta(std::int64_t current, std::uint64_t added, std::uint64_t removed)
    -> std::optional<std::int64_t> {
    if (added >= removed) {
        const auto growth = added - removed;
        if (growth > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
            || current > std::numeric_limits<std::int64_t>::max()
                - static_cast<std::int64_t>(growth)) return std::nullopt;
        return current + static_cast<std::int64_t>(growth);
    }
    const auto shrink = removed - added;
    if (shrink > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
        || current < std::numeric_limits<std::int64_t>::min()
            + static_cast<std::int64_t>(shrink)) return std::nullopt;
    return current - static_cast<std::int64_t>(shrink);
}

auto find_section(const BinaryImage& image, EntityId id) -> const Section* {
    const auto found = std::ranges::find(image.sections, id, &Section::id);
    return found == image.sections.end() ? nullptr : &*found;
}

auto find_section(BinaryImage& image, EntityId id) -> Section* {
    const auto found = std::ranges::find(image.sections, id, &Section::id);
    return found == image.sections.end() ? nullptr : &*found;
}

auto find_symbol(const BinaryImage& image, EntityId id) -> const Symbol* {
    const auto found = std::ranges::find(image.symbols, id, &Symbol::id);
    return found == image.symbols.end() ? nullptr : &*found;
}

auto find_mapping(std::span<const SectionMapping> mappings, EntityId section)
    -> const SectionMapping* {
    const auto found = std::ranges::find(mappings, section, &SectionMapping::section);
    return found == mappings.end() ? nullptr : &*found;
}

auto mapping_is_identity(
    const SectionMapping& mapping,
    const Section& sourceSection) noexcept -> bool {
    if (mapping.oldSize != mapping.newSize) return false;
    const auto unchanged = [&](const auto& segment) {
        const auto length = segment.oldEnd - segment.oldBegin;
        return segment.oldBegin == segment.newBegin && length == segment.newLength
            && segment.oldEnd <= sourceSection.contents.size()
            && std::ranges::equal(
                segment.bytes,
                std::span<const std::byte>{sourceSection.contents}.subspan(
                    static_cast<std::size_t>(segment.oldBegin),
                    static_cast<std::size_t>(length)));
    };
    return mapping.sourceSegments.size() == mapping.outputSegments.size()
        && std::ranges::all_of(mapping.sourceSegments, unchanged)
        && std::ranges::all_of(mapping.outputSegments, unchanged);
}

auto map_point(const SectionMapping& mapping, std::uint64_t point)
    -> std::optional<std::uint64_t> {
    for (const auto& segment : mapping.sourceSegments) {
        if (point >= segment.oldBegin && point < segment.oldEnd) {
            const auto relative = point - segment.oldBegin;
            if (relative >= segment.newLength) return std::nullopt;
            return segment.newBegin + relative;
        }
    }
    if (point == mapping.oldSize) return mapping.newSize;
    return std::nullopt;
}

auto map_span(const SectionMapping& mapping, std::uint64_t begin, std::uint64_t size)
    -> std::optional<MappedSpan> {
    if (begin > mapping.oldSize || size > mapping.oldSize - begin) return std::nullopt;
    if (size == 0U) {
        const auto mapped = map_point(mapping, begin);
        if (!mapped.has_value()) return std::nullopt;
        return MappedSpan{*mapped, 0U};
    }
    const auto end = begin + size;
    std::vector<const MappingSegment*> wholeSegments;
    std::uint64_t wholeCursor = begin;
    bool wholeCoverage = true;
    for (const auto& segment : mapping.sourceSegments) {
        if (segment.oldEnd <= begin || segment.oldBegin >= end) continue;
        if (segment.oldBegin != wholeCursor || segment.oldBegin < begin
            || segment.oldEnd > end) {
            wholeCoverage = false;
            break;
        }
        wholeSegments.push_back(&segment);
        wholeCursor = segment.oldEnd;
    }
    if (wholeCoverage && wholeCursor == end && !wholeSegments.empty()) {
        std::ranges::sort(wholeSegments, [](const auto* left, const auto* right) {
            return left->newBegin < right->newBegin;
        });
        auto destinationCursor = wholeSegments.front()->newBegin;
        const auto destinationBegin = destinationCursor;
        for (const auto* segment : wholeSegments) {
            if (segment->newBegin != destinationCursor) {
                wholeCoverage = false;
                break;
            }
            destinationCursor += segment->newLength;
        }
        if (wholeCoverage) {
            return MappedSpan{destinationBegin, destinationCursor - destinationBegin};
        }
    }
    std::uint64_t cursor = begin;
    std::optional<std::uint64_t> mappedBegin;
    std::uint64_t mappedCursor = 0;
    for (const auto& segment : mapping.sourceSegments) {
        if (segment.oldEnd <= cursor || segment.oldBegin >= end) continue;
        if (segment.oldBegin > cursor) return std::nullopt;
        const auto partEnd = std::min(end, segment.oldEnd);
        const auto relative = cursor - segment.oldBegin;
        const auto partLength = partEnd - cursor;
        if (relative > segment.newLength || partLength > segment.newLength - relative) {
            return std::nullopt;
        }
        const auto partBegin = segment.newBegin + relative;
        if (!mappedBegin.has_value()) {
            mappedBegin = partBegin;
            mappedCursor = partBegin;
        }
        if (partBegin != mappedCursor) {
            const auto insertion = std::ranges::find_if(
                mapping.outputSegments, [&](const auto& output) {
                    return output.oldBegin == cursor && output.oldEnd == cursor
                        && output.newBegin == mappedCursor
                        && output.newBegin + output.newLength == partBegin;
                });
            if (insertion == mapping.outputSegments.end()) return std::nullopt;
            mappedCursor += insertion->newLength;
        }
        const auto mappedLength = cursor == segment.oldBegin && partEnd == segment.oldEnd
            ? segment.newLength : partLength;
        mappedCursor += mappedLength;
        cursor = partEnd;
        if (cursor == end) break;
    }
    if (cursor != end || !mappedBegin.has_value()) return std::nullopt;
    return MappedSpan{*mappedBegin, mappedCursor - *mappedBegin};
}

auto has_duplicate_lineage(const TransformationLineage& lineage, TransformId transform) -> bool {
    return std::ranges::any_of(lineage.parents, [transform](const auto& record) {
        return record.transform == transform;
    });
}

auto image_has_duplicate_lineage(const BinaryImage& image, TransformId transform) -> bool {
    const auto any = [transform](const auto& values) {
        return std::ranges::any_of(values, [transform](const auto& value) {
            return has_duplicate_lineage(value.lineage, transform);
        });
    };
    return any(image.sections) || any(image.symbols) || any(image.relocations)
        || any(image.instructions) || any(image.basicBlocks) || any(image.functions)
        || any(image.unwindInfo);
}

template <typename T>
auto append_lineage(T& entity, TransformId transform, std::string_view pass) -> void {
    entity.lineage.parents.push_back(TransformationRecord{
        .transform = transform,
        .source = entity.id,
        .passName = std::string{pass},
    });
}

auto build_mappings(
    const BinaryImage& image,
    const ObjectRewriteRequest& request) -> Result<std::vector<SectionMapping>, Diagnostic> {
    auto ranges = request.ranges;
    std::ranges::sort(ranges, [](const auto& left, const auto& right) {
        if (left.section != right.section) return left.section < right.section;
        if (left.oldBegin != right.oldBegin) return left.oldBegin < right.oldBegin;
        if (left.oldEnd != right.oldEnd) return left.oldEnd < right.oldEnd;
        return left.newBegin < right.newBegin;
    });
    std::vector<SectionMapping> mappings;
    std::uint64_t totalGrowth = 0;
    std::size_t cursor = 0;
    while (cursor < ranges.size()) {
        const auto sectionId = ranges[cursor].section;
        const auto* section = find_section(image, sectionId);
        if (section == nullptr) {
            return failure<std::vector<SectionMapping>>(
                "rewrite.unknown_section", "rewrite range references an absent section");
        }
        const auto first = cursor;
        while (cursor < ranges.size() && ranges[cursor].section == sectionId) ++cursor;
        SectionMapping mapping{.section = sectionId,
                               .oldSize = static_cast<std::uint64_t>(section->contents.size()),
                               .newSize = 0,
                               .sourceSegments = {}, .outputSegments = {}};
        std::uint64_t oldCursor = 0;
        std::int64_t delta = 0;
        std::optional<std::uint64_t> previousZeroInsertion;
        for (std::size_t index = first; index < cursor; ++index) {
            const auto& range = ranges[index];
            if (range.oldBegin > range.oldEnd || range.oldEnd > mapping.oldSize) {
                return failure<std::vector<SectionMapping>>(
                    "rewrite.range", "rewrite source range lies outside its section");
            }
            if (range.oldBegin < oldCursor
                || (range.oldBegin == range.oldEnd
                    && previousZeroInsertion == range.oldBegin)) {
                return failure<std::vector<SectionMapping>>(
                    "rewrite.overlap", "rewrite source ranges overlap");
            }
            if (range.oldBegin == range.oldEnd) previousZeroInsertion = range.oldBegin;
            else previousZeroInsertion.reset();
            if (range.oldBegin > oldCursor) {
                const auto newGap = checked_shift(oldCursor, delta);
                if (!newGap.has_value()) {
                    return failure<std::vector<SectionMapping>>(
                        "rewrite.overflow", "unchanged rewrite gap overflows its section");
                }
                const auto length = range.oldBegin - oldCursor;
                std::vector<std::byte> bytes(
                    section->contents.begin() + static_cast<std::ptrdiff_t>(oldCursor),
                    section->contents.begin() + static_cast<std::ptrdiff_t>(range.oldBegin));
                MappingSegment gap{sectionId, oldCursor, range.oldBegin, *newGap, length,
                                   std::move(bytes)};
                mapping.sourceSegments.push_back(gap);
                mapping.outputSegments.push_back(std::move(gap));
            }
            const auto oldLength = range.oldEnd - range.oldBegin;
            const auto newLength = range.replacement.empty()
                ? oldLength : static_cast<std::uint64_t>(range.replacement.size());
            if ((oldLength == 0U && range.replacement.empty()) || newLength < oldLength) {
                return failure<std::vector<SectionMapping>>(
                    "rewrite.mapping_gap", "rewrite replacement does not provide a total old-to-new mapping");
            }
            std::vector<std::byte> bytes = range.replacement;
            if (range.replacement.empty()) {
                bytes.assign(
                    section->contents.begin() + static_cast<std::ptrdiff_t>(range.oldBegin),
                    section->contents.begin() + static_cast<std::ptrdiff_t>(range.oldEnd));
            }
            MappingSegment explicitSegment{
                sectionId, range.oldBegin, range.oldEnd, range.newBegin, newLength,
                std::move(bytes)};
            if (oldLength != 0U) mapping.sourceSegments.push_back(explicitSegment);
            mapping.outputSegments.push_back(std::move(explicitSegment));
            const auto nextDelta = checked_add_delta(delta, newLength, oldLength);
            if (!nextDelta.has_value()) {
                return failure<std::vector<SectionMapping>>(
                    "rewrite.overflow", "rewrite growth delta overflows");
            }
            delta = *nextDelta;
            oldCursor = range.oldEnd;
        }
        if (oldCursor < mapping.oldSize) {
            const auto newGap = checked_shift(oldCursor, delta);
            if (!newGap.has_value()) {
                return failure<std::vector<SectionMapping>>(
                    "rewrite.overflow", "trailing rewrite gap overflows its section");
            }
            std::vector<std::byte> bytes(
                section->contents.begin() + static_cast<std::ptrdiff_t>(oldCursor),
                section->contents.end());
            MappingSegment gap{
                sectionId, oldCursor, mapping.oldSize, *newGap,
                mapping.oldSize - oldCursor, std::move(bytes)};
            mapping.sourceSegments.push_back(gap);
            mapping.outputSegments.push_back(std::move(gap));
        }
        const auto shiftedSize = checked_shift(mapping.oldSize, delta);
        if (!shiftedSize.has_value()) {
            return failure<std::vector<SectionMapping>>(
                "rewrite.overflow", "rewritten section size overflows");
        }
        mapping.newSize = *shiftedSize;
        if (mapping.newSize >= mapping.oldSize) {
            const auto growth = mapping.newSize - mapping.oldSize;
            if (growth > request.maxOutputGrowth - std::min(request.maxOutputGrowth, totalGrowth)) {
                return failure<std::vector<SectionMapping>>(
                    "rewrite.growth_limit", "rewrite output growth exceeds the request limit");
            }
            totalGrowth += growth;
        }
        std::ranges::sort(mapping.sourceSegments, {}, &MappingSegment::oldBegin);
        std::ranges::sort(mapping.outputSegments, [](const auto& left, const auto& right) {
            if (left.newBegin != right.newBegin) return left.newBegin < right.newBegin;
            return left.newLength < right.newLength;
        });
        std::uint64_t outputCursor = 0;
        for (const auto& segment : mapping.outputSegments) {
            if (segment.newBegin != outputCursor
                || segment.newLength > mapping.newSize - std::min(mapping.newSize, segment.newBegin)) {
                return failure<std::vector<SectionMapping>>(
                    "rewrite.mapping_gap", "rewrite destination ranges overlap or leave a gap");
            }
            outputCursor += segment.newLength;
        }
        if (outputCursor != mapping.newSize) {
            return failure<std::vector<SectionMapping>>(
                "rewrite.mapping_gap", "rewrite destination mapping is not total");
        }
        mappings.push_back(std::move(mapping));
    }
    return Result<std::vector<SectionMapping>, Diagnostic>::success(std::move(mappings));
}

auto signed_fits(std::int64_t value, std::uint8_t bits) -> bool {
    if (bits == 0U || bits >= 64U) return true;
    const auto maximum = (INT64_C(1) << (bits - 1U)) - 1;
    const auto minimum = -(INT64_C(1) << (bits - 1U));
    return value >= minimum && value <= maximum;
}

auto signed_fixup_fits(
    std::int64_t value,
    const ObjectFixupSemantics& semantics) -> bool {
    const auto bias = static_cast<std::int64_t>(semantics.pcBias);
    if ((bias > 0 && value > std::numeric_limits<std::int64_t>::max() - bias)
        || (bias < 0 && value < std::numeric_limits<std::int64_t>::min() - bias)) {
        return false;
    }
    value += bias;
    if (semantics.rightShift >= 63U) return false;
    const auto scale = INT64_C(1) << semantics.rightShift;
    return value % scale == 0 && signed_fits(value / scale, semantics.bitWidth);
}

auto checked_add_i64(std::int64_t left, std::int64_t right) -> std::optional<std::int64_t> {
    if ((right > 0 && left > std::numeric_limits<std::int64_t>::max() - right)
        || (right < 0 && left < std::numeric_limits<std::int64_t>::min() - right)) {
        return std::nullopt;
    }
    return left + right;
}

} // namespace

auto ObjectRewritePlan::create(
    const BinaryImage& image,
    const ArchitectureBackend& backend,
    const ObjectRewriteRequest& request) -> Result<ObjectRewritePlan, Diagnostic> {
    if (backend.architecture() != image.architecture) {
        return failure<ObjectRewritePlan>(
            "rewrite.architecture_mismatch", "rewrite backend does not match the object architecture");
    }
    if (request.ranges.empty() || request.passName.empty() || !request.transform.valid()) {
        return failure<ObjectRewritePlan>(
            "rewrite.invalid_request", "rewrite request requires ranges, pass name, and transform ID");
    }
    if (const auto invalid = formats::detail::validate_object_model(image)) {
        return failure<ObjectRewritePlan>(invalid->code, invalid->message);
    }
    if (image_has_duplicate_lineage(image, request.transform)) {
        return failure<ObjectRewritePlan>(
            "rewrite.duplicate_lineage", "rewrite transform ID is already present in input lineage");
    }
    auto builtMappings = build_mappings(image, request);
    if (!builtMappings.has_value()) {
        return failure<ObjectRewritePlan>(
            builtMappings.error().code, builtMappings.error().message);
    }
    const auto& mappings = builtMappings.value();
    BinaryImage output = image;
    std::size_t validationCount = 0;

    for (const auto& mapping : mappings) {
        auto* section = find_section(output, mapping.section);
        section->contents.assign(static_cast<std::size_t>(mapping.newSize), std::byte{0});
        for (const auto& segment : mapping.outputSegments) {
            std::copy(
                segment.bytes.begin(), segment.bytes.end(),
                section->contents.begin() + static_cast<std::ptrdiff_t>(segment.newBegin));
        }
        section->logicalSize = mapping.newSize;
        append_lineage(*section, request.transform, request.passName);
        ++validationCount;
    }

    for (auto& symbol : output.symbols) {
        if (!symbol.section.has_value() || symbol.kind == SymbolKind::Section
            || symbol.definition != SymbolDefinitionKind::SectionRelative) continue;
        const auto* mapping = find_mapping(mappings, *symbol.section);
        if (mapping == nullptr) continue;
        const auto mapped = map_span(*mapping, symbol.address.value, symbol.size);
        if (!mapped.has_value()) {
            return failure<ObjectRewritePlan>(
                "rewrite.unmapped_symbol", "rewrite cannot map a section-relative symbol");
        }
        if (mapped->begin != symbol.address.value || mapped->size != symbol.size) {
            symbol.address.value = mapped->begin;
            symbol.size = mapped->size;
            append_lineage(symbol, request.transform, request.passName);
        }
        ++validationCount;
    }

    for (auto& function : output.functions) {
        const auto* mapping = find_mapping(mappings, function.section);
        if (mapping == nullptr) continue;
        const auto mapped = map_span(*mapping, function.address.value, function.size);
        if (!mapped.has_value()) {
            return failure<ObjectRewritePlan>(
                "rewrite.unmapped_function", "rewrite cannot map a complete function range");
        }
        if (mapped->begin != function.address.value || mapped->size != function.size) {
            function.address.value = mapped->begin;
            function.size = mapped->size;
            append_lineage(function, request.transform, request.passName);
        }
        ++validationCount;
    }

    for (auto& instruction : output.instructions) {
        const auto* mapping = find_mapping(mappings, instruction.section);
        if (mapping == nullptr) continue;
        const auto mapped = map_span(
            *mapping, instruction.sectionOffset,
            static_cast<std::uint64_t>(instruction.encoding.size()));
        if (!mapped.has_value()) {
            return failure<ObjectRewritePlan>(
                "rewrite.unmapped_instruction", "rewrite cannot map an instruction range");
        }
        bool changed = false;
        if (mapped->begin != instruction.sectionOffset) {
            instruction.sectionOffset = mapped->begin;
            instruction.address.value = mapped->begin;
            changed = true;
        }
        if (instruction.directTarget.has_value()) {
            const auto target = map_point(*mapping, instruction.directTarget->value);
            if (!target.has_value()) {
                return failure<ObjectRewritePlan>(
                    "rewrite.unmapped_target", "rewrite cannot map a direct instruction target");
            }
            if (*target != instruction.directTarget->value) {
                instruction.directTarget->value = *target;
                changed = true;
            }
        }
        if (changed) append_lineage(instruction, request.transform, request.passName);
        ++validationCount;
    }

    for (auto& block : output.basicBlocks) {
        const auto* mapping = find_mapping(mappings, block.section);
        if (mapping == nullptr) continue;
        const auto mapped = map_point(*mapping, block.sectionOffset);
        if (!mapped.has_value()) {
            return failure<ObjectRewritePlan>(
                "rewrite.unmapped_block", "rewrite cannot map a basic-block boundary");
        }
        if (*mapped != block.sectionOffset) {
            block.sectionOffset = *mapped;
            block.address.value = *mapped;
            append_lineage(block, request.transform, request.passName);
        }
        ++validationCount;
    }

    for (auto& relocation : output.relocations) {
        const auto* siteMapping = find_mapping(mappings, relocation.section);
        const auto* originalTarget = relocation.targetSymbol.has_value()
            ? find_symbol(image, *relocation.targetSymbol) : nullptr;
        const auto* targetMapping = originalTarget != nullptr && originalTarget->section.has_value()
            ? find_mapping(mappings, *originalTarget->section) : nullptr;
        if (siteMapping == nullptr && targetMapping == nullptr) continue;
        const auto semantics = backend.fixup_semantics(image.format, relocation.rawType);
        if (!semantics.has_value()) {
            bool moved = false;
            if (siteMapping != nullptr) {
                const auto* sourceSection = find_section(image, relocation.section);
                moved = sourceSection == nullptr
                    || !mapping_is_identity(*siteMapping, *sourceSection);
            }
            const auto* updatedTarget = relocation.targetSymbol.has_value()
                ? find_symbol(output, *relocation.targetSymbol) : nullptr;
            if (targetMapping != nullptr) {
                moved = moved || originalTarget == nullptr || updatedTarget == nullptr
                    || originalTarget->section != updatedTarget->section
                    || originalTarget->address != updatedTarget->address
                    || (originalTarget->kind == SymbolKind::Section
                        && [&] {
                            const auto* sourceSection = find_section(
                                image, *originalTarget->section);
                            return sourceSection == nullptr
                                || !mapping_is_identity(*targetMapping, *sourceSection);
                        }());
            }
            if (moved) {
                return failure<ObjectRewritePlan>(
                    "rewrite.unknown_relocation_moved",
                    "rewrite cannot move a relocation with unknown i386 semantics");
            }
            ++validationCount;
            continue;
        }
        if (siteMapping != nullptr) {
            const auto fieldSize = static_cast<std::uint64_t>(
                semantics.value().storageBytes != 0U
                    ? semantics.value().storageBytes
                    : semantics.value().bitWidth / 8U);
            const auto mappedSite = map_span(*siteMapping, relocation.offset, fieldSize);
            if (!mappedSite.has_value()) {
                return failure<ObjectRewritePlan>(
                    "rewrite.unmapped_relocation", "rewrite cannot map a relocation field");
            }
            relocation.offset = mappedSite->begin;
        }
        if (originalTarget == nullptr) {
            return failure<ObjectRewritePlan>(
                "rewrite.unmapped_relocation_target", "moved relocation has no owned target symbol");
        }
        if (targetMapping != nullptr && originalTarget->kind == SymbolKind::Section) {
            const auto oldTargetSigned = checked_add_i64(
                relocation.addend, static_cast<std::int64_t>(semantics.value().pcBias));
            if (!oldTargetSigned.has_value() || *oldTargetSigned < 0) {
                return failure<ObjectRewritePlan>(
                    "rewrite.unmapped_relocation_target", "section-symbol addend does not name a mapped offset");
            }
            const auto mappedTarget = map_point(
                *targetMapping, static_cast<std::uint64_t>(*oldTargetSigned));
            if (!mappedTarget.has_value()
                || *mappedTarget > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
                return failure<ObjectRewritePlan>(
                    "rewrite.unmapped_relocation_target", "section-symbol relocation target is unmapped");
            }
            relocation.addend = static_cast<std::int64_t>(*mappedTarget)
                - static_cast<std::int64_t>(semantics.value().pcBias);
        }
        const auto* updatedTarget = find_symbol(output, *relocation.targetSymbol);
        if (semantics.value().pcRelative && updatedTarget != nullptr
            && updatedTarget->defined && updatedTarget->section == relocation.section) {
            const auto targetAddress = updatedTarget->address.value
                    <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
                ? std::optional<std::int64_t>{
                    static_cast<std::int64_t>(updatedTarget->address.value)}
                : std::nullopt;
            const auto targetValue = targetAddress.has_value()
                ? checked_add_i64(*targetAddress, relocation.addend)
                : std::nullopt;
            const auto siteValue = relocation.offset
                    <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
                ? std::optional<std::int64_t>{static_cast<std::int64_t>(relocation.offset)}
                : std::nullopt;
            const auto displacement = targetValue.has_value() && siteValue.has_value()
                ? checked_add_i64(*targetValue, -*siteValue)
                : std::nullopt;
            if (!displacement.has_value()
                || !signed_fixup_fits(*displacement, semantics.value())) {
                return failure<ObjectRewritePlan>(
                    "rewrite.branch_range", "rewritten PC-relative relocation is out of range");
            }
        }
        if (semantics.value().implicitAddend && semantics.value().bitWidth != 0U) {
            const auto encoded = backend.encode_fixup(semantics.value(), relocation.addend);
            if (!encoded.has_value()) {
                const auto code = encoded.error().code == "architecture.fixup_overflow"
                    ? "rewrite.branch_range" : encoded.error().code;
                return failure<ObjectRewritePlan>(code, encoded.error().message);
            }
            auto* section = find_section(output, relocation.section);
            if (encoded.value().fieldBytes.empty()
                || encoded.value().fieldBytes.size() != encoded.value().writeMask.size()) {
                return failure<ObjectRewritePlan>(
                    "architecture.invalid_fixup",
                    "encoded relocation field and write mask have invalid lengths");
            }
            if (section == nullptr || relocation.offset > section->contents.size()
                || encoded.value().fieldBytes.size() > section->contents.size() - relocation.offset) {
                return failure<ObjectRewritePlan>(
                    "rewrite.unmapped_relocation", "encoded relocation field lies outside its section");
            }
            for (std::size_t index = 0; index < encoded.value().fieldBytes.size(); ++index) {
                const auto outputIndex = static_cast<std::size_t>(relocation.offset) + index;
                const auto original = std::to_integer<std::uint8_t>(
                    section->contents[outputIndex]);
                const auto replacement = std::to_integer<std::uint8_t>(
                    encoded.value().fieldBytes[index]);
                const auto mask = std::to_integer<std::uint8_t>(
                    encoded.value().writeMask[index]);
                section->contents[outputIndex] = static_cast<std::byte>(
                    (original & static_cast<std::uint8_t>(~mask))
                    | (replacement & mask));
            }
        }
        append_lineage(relocation, request.transform, request.passName);
        ++validationCount;
    }

    for (auto& unwind : output.unwindInfo) {
        const auto originalFunction = std::ranges::find(image.functions, unwind.function, &Function::id);
        if (originalFunction == image.functions.end()) {
            return failure<ObjectRewritePlan>(
                "rewrite.unowned_unwind", "unwind record has no owned function");
        }
        const auto* codeMapping = find_mapping(mappings, originalFunction->section);
        const auto* recordMapping = find_mapping(mappings, unwind.section);
        if (codeMapping == nullptr && recordMapping == nullptr) continue;
        auto mappedCode = MappedSpan{unwind.codeOffset, unwind.codeSize};
        auto mappedRecord = MappedSpan{
            unwind.sectionOffset, static_cast<std::uint64_t>(unwind.encoded.size())};
        if (codeMapping != nullptr) {
            const auto value = map_span(*codeMapping, unwind.codeOffset, unwind.codeSize);
            if (!value.has_value()) {
                return failure<ObjectRewritePlan>(
                    "rewrite.unowned_unwind", "unwind code range is not totally mapped");
            }
            mappedCode = *value;
        }
        if (recordMapping != nullptr) {
            const auto value = map_span(
                *recordMapping, unwind.sectionOffset,
                static_cast<std::uint64_t>(unwind.encoded.size()));
            if (!value.has_value()) {
                return failure<ObjectRewritePlan>(
                    "rewrite.unowned_unwind", "unwind record bytes are not totally mapped");
            }
            mappedRecord = *value;
        }
        const bool moved = mappedCode.begin != unwind.codeOffset
            || mappedCode.size != unwind.codeSize || mappedRecord.begin != unwind.sectionOffset;
        if (moved && unwind.rewriteState == UnwindRewriteState::Opaque) {
            return failure<ObjectRewritePlan>(
                "rewrite.unowned_unwind", "opaque unwind metadata cannot be moved");
        }
        if (moved) {
            unwind.codeOffset = mappedCode.begin;
            unwind.codeSize = mappedCode.size;
            unwind.sectionOffset = mappedRecord.begin;
            unwind.rewriteState = UnwindRewriteState::Adjusted;
            append_lineage(unwind, request.transform, request.passName);
        }
        ++validationCount;
    }

    if (const auto invalid = formats::detail::validate_object_model(output)) {
        return failure<ObjectRewritePlan>(invalid->code, invalid->message);
    }
    ObjectRewritePlan plan;
    plan.sourceSnapshot_ = image;
    plan.validationCount_ = validationCount;
    plan.output_ = std::move(output);
    return Result<ObjectRewritePlan, Diagnostic>::success(std::move(plan));
}

auto ObjectRewritePlan::validate(const BinaryImage& image) const
    -> Result<std::size_t, Diagnostic> {
    if (image != sourceSnapshot_) {
        return failure<std::size_t>(
            "rewrite.source_mismatch", "rewrite plan was created for a different object snapshot");
    }
    if (const auto invalid = formats::detail::validate_object_model(output_)) {
        return failure<std::size_t>(invalid->code, invalid->message);
    }
    return Result<std::size_t, Diagnostic>::success(validationCount_);
}

auto ObjectRewritePlan::commit(const BinaryImage& image) const
    -> Result<BinaryImage, Diagnostic> {
    const auto valid = validate(image);
    if (!valid.has_value()) {
        return failure<BinaryImage>(valid.error().code, valid.error().message);
    }
    return Result<BinaryImage, Diagnostic>::success(output_);
}

} // namespace binobf

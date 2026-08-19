#include "../linked_parser_internal.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace binobf::formats::detail {
namespace {

constexpr std::uint32_t kSegment64 = 0x19U;
constexpr std::uint32_t kSymtab = 0x2U;
constexpr std::uint32_t kLoadDylib = 0xcU;
constexpr std::uint32_t kIdDylib = 0xdU;
constexpr std::uint32_t kMain = 0x80000028U;

auto fixed_name(const ByteReader& reader, std::size_t offset, std::size_t length)
    -> std::optional<std::string> {
    const auto bytes = reader.bytes(offset, length);
    if (!bytes.has_value()) return std::nullopt;
    std::size_t end = 0;
    while (end < bytes->size() && (*bytes)[end] != std::byte{0}) ++end;
    std::string result;
    result.reserve(end);
    for (std::size_t index = 0; index < end; ++index) {
        result.push_back(static_cast<char>(std::to_integer<unsigned char>((*bytes)[index])));
    }
    return result;
}

auto section_by_index(const std::vector<EntityId>& ids, std::uint8_t index)
    -> std::optional<EntityId> {
    if (index == 0 || static_cast<std::size_t>(index) > ids.size()) return std::nullopt;
    return ids[static_cast<std::size_t>(index) - 1U];
}

auto section_is_code(const BinaryImage& image, EntityId id) -> bool {
    const auto section = std::ranges::find(image.sections, id, &Section::id);
    return section != image.sections.end() && section->kind == SectionKind::Code
        && section->executable;
}

} // namespace

auto parse_macho_linked(
    std::span<const std::byte> bytes,
    const DetectionResult& detection,
    const LinkedParseLimits& limits) -> Result<LinkedImage, Diagnostic> {
    const ByteReader reader(bytes);
    if (reader.u32(0) != 0xfeedfacfU || reader.u32(28) == std::nullopt) {
        return linked_failure("linked.macho_header", "Mach-O linked header is invalid");
    }
    const auto commandCount = reader.u32(16);
    const auto commandBytes = reader.u32(20);
    if (!commandCount || !commandBytes || *commandCount > limits.maxDirectories
        || *commandBytes > bytes.size() - 32U
        || !contains_range(32U, *commandBytes, bytes.size())) {
        return linked_failure("linked.macho_commands", "Mach-O load-command table is invalid");
    }

    LinkedImage result;
    result.image.format = BinaryFormat::MachO;
    result.image.type = detection.type;
    result.image.architecture = detection.architecture;
    result.image.objectMetadata.characteristics = reader.u32(24).value_or(0);
    result.headerSize = 32;
    result.fileAlignment = 1;
    result.memoryAlignment = 1;
    result.sourceBytes.assign(bytes.begin(), bytes.end());
    EntityIdAllocator ids;
    std::vector<EntityId> sectionIds;
    sectionIds.reserve(limits.maxSections);
    std::optional<std::uint64_t> mainOffset;
    std::uint64_t minimumAddress = std::numeric_limits<std::uint64_t>::max();
    std::size_t cursor = 32;
    std::optional<std::pair<std::uint32_t, std::uint32_t>> symtab;

    for (std::uint32_t commandIndex = 0; commandIndex < *commandCount; ++commandIndex) {
        const auto command = reader.u32(cursor);
        const auto commandSize = reader.u32(cursor + 4U);
        if (!command || !commandSize || *commandSize < 8U
            || *commandSize > *commandBytes - (cursor - 32U)
            || !contains_range(cursor, *commandSize, bytes.size())) {
            return linked_failure("linked.macho_commands", "Mach-O load command is truncated");
        }
        if (*command == kSegment64) {
            if (*commandSize < 72U) {
                return linked_failure("linked.macho_segment", "Mach-O segment command is truncated");
            }
            const auto segmentName = fixed_name(reader, cursor + 8U, 16U);
            const auto vmAddress = reader.u64(cursor + 24U);
            const auto vmSize = reader.u64(cursor + 32U);
            const auto fileOffset = reader.u64(cursor + 40U);
            const auto fileSize = reader.u64(cursor + 48U);
            const auto initProtection = reader.u32(cursor + 60U);
            const auto sectionCount = reader.u32(cursor + 64U);
            if (!segmentName || !vmAddress || !vmSize || !fileOffset || !fileSize
                || !initProtection || !sectionCount || *sectionCount > limits.maxSections
                || *commandSize < 72U + static_cast<std::uint64_t>(*sectionCount) * 80U) {
                return linked_failure("linked.macho_segment", "Mach-O segment metadata is invalid");
            }
            const auto fileStart = to_size(*fileOffset);
            const auto fileLength = to_size(*fileSize);
            if (!fileStart || !fileLength || !contains_range(*fileStart, *fileLength, bytes.size())) {
                return linked_failure("linked.macho_segment", "Mach-O segment file range is invalid");
            }
            if (*vmAddress < minimumAddress) minimumAddress = *vmAddress;
            const auto segmentId = ids.allocate();
            result.image.segments.push_back(Segment{
                .id = segmentId,
                .name = *segmentName,
                .address = BinaryAddress{*vmAddress, AddressKind::Virtual},
                .fileSize = *fileSize,
                .memorySize = *vmSize,
                .readable = (*initProtection & 1U) != 0U,
                .writable = (*initProtection & 2U) != 0U,
                .executable = (*initProtection & 4U) != 0U,
                .lineage = {},
            });
            result.segmentLayout.push_back(LinkedSegmentLayout{
                .segment = segmentId,
                .formatIndex = commandIndex,
                .headerOffset = cursor,
                .fileOffset = *fileOffset,
                .fileSize = *fileSize,
                .memorySize = *vmSize,
                .alignment = 1,
            });
            for (std::uint32_t sectionIndex = 0; sectionIndex < *sectionCount; ++sectionIndex) {
                const auto offset = cursor + 72U + static_cast<std::size_t>(sectionIndex) * 80U;
                const auto name = fixed_name(reader, offset, 16U);
                const auto address = reader.u64(offset + 32U);
                const auto size = reader.u64(offset + 40U);
                const auto rawOffset = reader.u32(offset + 48U);
                const auto alignment = reader.u32(offset + 52U);
                const auto relocationOffset = reader.u32(offset + 56U);
                const auto relocationCount = reader.u32(offset + 60U);
                const auto flags = reader.u32(offset + 64U);
                if (!name || !address || !size || !rawOffset || !alignment
                    || !relocationOffset || !relocationCount
                    || *relocationCount > limits.maxRelocations) {
                    return linked_failure("linked.macho_section", "Mach-O section metadata is invalid");
                }
                const auto sectionType = *flags & 0xffU;
                const bool zeroFill = sectionType == 1U || sectionType == 0x12U
                    || sectionType == 0x13U;
                const auto rawStart = to_size(*rawOffset);
                const auto rawLength = to_size(zeroFill ? 0U : *size);
                if (!rawStart || !rawLength || (*rawLength != 0
                    && !contains_range(*rawStart, *rawLength, bytes.size()))) {
                    return linked_failure("linked.macho_section", "Mach-O section data is outside the input");
                }
                const auto sectionId = ids.allocate();
                const auto sectionKind = (*initProtection & 4U) != 0U
                    ? SectionKind::Code : (*size == 0 ? SectionKind::UninitializedData
                                                       : SectionKind::InitializedData);
                Section section{
                    .id = sectionId,
                    .formatIndex = static_cast<std::uint32_t>(sectionIds.size() + 1U),
                    .formatType = 0,
                    .formatFlags = *flags,
                    .name = *name,
                    .kind = sectionKind,
                    .address = BinaryAddress{*address, AddressKind::Virtual},
                    .logicalSize = *size,
                    .alignment = std::uint64_t{1} << std::min(*alignment, 63U),
                    .readable = (*initProtection & 1U) != 0U,
                    .writable = (*initProtection & 2U) != 0U,
                    .executable = (*initProtection & 4U) != 0U,
                    .contents = {},
                    .lineage = {},
                };
                if (!zeroFill && *rawLength != 0) {
                    const auto content = reader.bytes(*rawStart, *rawLength);
                    section.contents.assign(content->begin(), content->end());
                }
                result.image.sections.push_back(std::move(section));
                sectionIds.push_back(sectionId);
                result.sectionLayout.push_back(LinkedSectionLayout{
                    .section = sectionId,
                    .headerOffset = offset,
                    .fileOffset = *rawOffset,
                    .fileSize = *size,
                    .memorySize = *size,
                });
                static_cast<void>(relocationOffset);
                static_cast<void>(relocationCount);
            }
        } else if (*command == kSymtab) {
            if (*commandSize < 24U) {
                return linked_failure("linked.macho_symbols", "Mach-O symbol-table command is truncated");
            }
            const auto symbolOffset = reader.u32(cursor + 8U);
            const auto symbolCount = reader.u32(cursor + 12U);
            const auto stringOffset = reader.u32(cursor + 16U);
            const auto stringSize = reader.u32(cursor + 20U);
            if (!symbolOffset || !symbolCount || !stringOffset || !stringSize
                || *symbolCount > limits.maxSymbols
                || !contains_range(*symbolOffset, static_cast<std::size_t>(*symbolCount) * 16U, bytes.size())
                || !contains_range(*stringOffset, *stringSize, bytes.size())) {
                return linked_failure("linked.macho_symbols", "Mach-O symbol table is outside the input");
            }
            symtab = std::pair{*symbolOffset, *symbolCount};
            result.directories.push_back(LinkedDirectory{
                .kind = LinkedDirectoryKind::Unknown,
                .formatIndex = commandIndex,
                .headerOffset = cursor,
                .address = *symbolOffset,
                .fileOffset = *symbolOffset,
                .size = static_cast<std::uint64_t>(*symbolCount) * 16U,
                .addressIsFileOffset = true,
            });
        } else if (*command == kMain && *commandSize >= 24U) {
            mainOffset = reader.u64(cursor + 8U);
        } else if (*command == kLoadDylib || *command == kIdDylib) {
            const auto nameOffset = reader.u32(cursor + 8U);
            if (!nameOffset || *nameOffset >= *commandSize) {
                return linked_failure("linked.macho_dylib", "Mach-O dylib name offset is invalid");
            }
            const auto name = read_string(bytes.subspan(cursor, *commandSize), *nameOffset);
            if (!name.has_value()) {
                return linked_failure("linked.macho_dylib", "Mach-O dylib name is unterminated");
            }
            if (*command == kLoadDylib) {
                result.image.imports.push_back(Import{
                    .id = ids.allocate(), .library = *name, .name = {}, .ordinal = std::nullopt,
                    .lineage = {},
                });
            }
        }
        cursor += *commandSize;
    }
    result.imageBase = minimumAddress == std::numeric_limits<std::uint64_t>::max()
        ? 0 : minimumAddress;
    result.image.entryPoint = std::nullopt;
    if (mainOffset.has_value()) {
        for (const auto& layout : result.segmentLayout) {
            if (*mainOffset < layout.fileOffset
                || *mainOffset >= layout.fileOffset + layout.fileSize) continue;
            const auto segment = std::ranges::find(
                result.image.segments, layout.segment, &Segment::id);
            if (segment != result.image.segments.end()) {
                result.image.entryPoint = BinaryAddress{
                    segment->address.value + (*mainOffset - layout.fileOffset),
                    AddressKind::Virtual};
            }
            break;
        }
    }

    // Re-scan the commands for the string-table location so symbol parsing stays
    // independent of command ordering.
    std::optional<std::pair<std::uint32_t, std::uint32_t>> strings;
    cursor = 32;
    for (std::uint32_t index = 0; index < *commandCount; ++index) {
        const auto command = reader.u32(cursor).value();
        const auto commandSize = reader.u32(cursor + 4U).value();
        if (command == kSymtab) strings = std::pair{reader.u32(cursor + 16U).value(), reader.u32(cursor + 20U).value()};
        cursor += commandSize;
    }
    if (symtab.has_value() && strings.has_value()) {
        const auto stringBytes = reader.bytes(strings->first, strings->second);
        if (!stringBytes.has_value()) return linked_failure("linked.macho_symbols", "Mach-O string table is invalid");
        for (std::uint32_t index = 0; index < symtab->second; ++index) {
            const auto offset = static_cast<std::size_t>(symtab->first) + static_cast<std::size_t>(index) * 16U;
            const auto stringIndex = reader.u32(offset);
            const auto type = reader.u8(offset + 4U);
            const auto section = reader.u8(offset + 5U);
            const auto description = reader.u16(offset + 6U);
            const auto value = reader.u64(offset + 8U);
            if (!stringIndex || !type || !section || !description || !value) continue;
            const auto name = read_string(*stringBytes, *stringIndex);
            if (!name.has_value() || name->size() > limits.maxStringBytes) continue;
            const auto sectionId = section_by_index(sectionIds, *section);
            const auto kind = sectionId.has_value() && section_is_code(result.image, *sectionId)
                ? SymbolKind::Function : SymbolKind::Object;
            const bool defined = (*type & 0x0eU) == 0x0eU;
            const auto symbolId = ids.allocate();
            result.image.symbols.push_back(Symbol{
                .id = symbolId,
                .formatIndex = index,
                .formatTableIndex = 0,
                .formatType = *type,
                .formatStorage = 0,
                .formatOther = 0,
                .formatSectionIndex = *section,
                .auxiliaryData = {},
                .name = *name,
                .section = sectionId,
                .address = BinaryAddress{*value, AddressKind::Virtual},
                .size = 0,
                .kind = kind,
                .visibility = (*type & 1U) != 0U ? SymbolVisibility::External : SymbolVisibility::Local,
                .defined = defined,
                .definition = defined ? SymbolDefinitionKind::SectionRelative
                                      : SymbolDefinitionKind::Undefined,
                .commonAlignment = 0,
                .tlsModel = TlsModel::None,
                .lineage = {},
            });
            if (defined && kind == SymbolKind::Function && !name->empty()) {
                const auto sectionRef = std::ranges::find(result.image.sections, *sectionId, &Section::id);
                if (sectionRef != result.image.sections.end()) {
                    result.image.functions.push_back(Function{
                        .id = ids.allocate(), .name = *name, .section = *sectionId,
                        .symbol = symbolId, .address = BinaryAddress{*value, AddressKind::Virtual},
                        .size = 0, .discovery = FunctionDiscovery::Symbol, .instructions = {},
                        .basicBlocks = {}, .entryBlock = std::nullopt,
                        .externallyVisible = (*type & 1U) != 0U, .complete = false, .lineage = {},
                    });
                }
            }
        }
    }
    if (result.image.segments.empty()) {
        return linked_failure("linked.macho_segments", "Mach-O image contains no segments");
    }
    return Result<LinkedImage, Diagnostic>::success(std::move(result));
}

} // namespace binobf::formats::detail

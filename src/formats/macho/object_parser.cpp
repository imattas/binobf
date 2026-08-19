#include "../object_parser_internal.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace binobf::formats::detail {
namespace {

constexpr std::uint32_t lcSegment64 = 0x19;
constexpr std::uint32_t lcSymtab = 0x2;
constexpr std::uint32_t sectionTypeMask = 0x000000ffU;
constexpr std::uint32_t sectionTypeZerofill = 0x1U;
constexpr std::uint8_t nTypeMask = 0x0eU;
constexpr std::uint8_t nTypeUndefined = 0x0U;
constexpr std::uint8_t nTypeAbsolute = 0x2U;
constexpr std::uint8_t nTypeSection = 0x0eU;
constexpr std::uint8_t nExt = 0x01U;

struct MachSection {
    std::string name;
    std::string segment;
    std::uint64_t address{0};
    std::uint64_t size{0};
    std::uint32_t offset{0};
    std::uint32_t alignment{0};
    std::uint32_t relocationOffset{0};
    std::uint32_t relocationCount{0};
    std::uint32_t flags{0};
};

struct MachSegment {
    std::string name;
    std::uint64_t address{0};
    std::uint64_t size{0};
    std::uint64_t fileOffset{0};
    std::uint64_t fileSize{0};
    std::uint32_t protections{0};
    std::vector<MachSection> sections;
};

struct MachSymtab {
    std::uint32_t symbolOffset{0};
    std::uint32_t symbolCount{0};
    std::uint32_t stringOffset{0};
    std::uint32_t stringSize{0};
};

auto fixed_string(const ByteReader& reader, std::size_t offset, std::size_t size)
    -> std::optional<std::string> {
    const auto bytes = reader.bytes(offset, size);
    if (!bytes.has_value()) return std::nullopt;
    std::string result;
    for (const auto byte : *bytes) {
        const auto value = std::to_integer<unsigned char>(byte);
        if (value == 0U) break;
        result.push_back(static_cast<char>(value));
    }
    return result;
}

auto section_kind(const MachSection& section) -> SectionKind {
    if (section.name.starts_with("__debug") || section.name.starts_with(".debug")) {
        return SectionKind::Debug;
    }
    if ((section.flags & sectionTypeMask) == sectionTypeZerofill || section.name == "__bss") {
        return SectionKind::UninitializedData;
    }
    if (section.name == "__text") return SectionKind::Code;
    return SectionKind::InitializedData;
}

auto symbol_kind(std::uint8_t type, std::string_view name) -> SymbolKind {
    if ((type & nTypeMask) == nTypeSection &&
        (name.starts_with("_") || name.starts_with("__"))) {
        return SymbolKind::Function;
    }
    if ((type & nTypeMask) == nTypeAbsolute) return SymbolKind::Object;
    return SymbolKind::Unknown;
}

auto relocation_kind(Architecture architecture, bool pcRelative, std::uint32_t type)
    -> RelocationKind {
    if (pcRelative) return RelocationKind::PcRelative;
    if (type == 0U || type == 1U || type == 2U) return RelocationKind::Absolute;
    static_cast<void>(architecture);
    return RelocationKind::ArchitectureSpecific;
}

auto parse_load_commands(
    const ByteReader& reader,
    std::uint32_t commandCount,
    std::uint32_t commandBytes,
    std::vector<MachSegment>& segments,
    std::optional<MachSymtab>& symtab) -> std::optional<Diagnostic> {
    constexpr std::size_t headerSize = 32U;
    if (commandCount > 4096U || commandBytes > reader.size() - headerSize ||
        !reader.bytes(headerSize, commandBytes).has_value()) {
        return Diagnostic{DiagnosticSeverity::Error, "macho.load_commands", 
                          "Mach-O load-command table is outside the input"};
    }
    std::size_t offset = headerSize;
    for (std::uint32_t index = 0; index < commandCount; ++index) {
        const auto command = reader.u32(offset);
        const auto size = reader.u32(offset + 4U);
        if (!command || !size || *size < 8U || *size > commandBytes ||
            offset > reader.size() || *size > reader.size() - offset) {
            return Diagnostic{DiagnosticSeverity::Error, "macho.load_command", 
                              "Mach-O load command is malformed"};
        }
        if (*command == lcSegment64) {
            if (*size < 72U) {
                return Diagnostic{DiagnosticSeverity::Error, "macho.segment", 
                                  "Mach-O 64-bit segment command is truncated"};
            }
            MachSegment segment;
            const auto name = fixed_string(reader, offset + 8U, 16U);
            const auto vmAddress = reader.u64(offset + 24U);
            const auto vmSize = reader.u64(offset + 32U);
            const auto fileOffset = reader.u64(offset + 40U);
            const auto fileSize = reader.u64(offset + 48U);
            const auto protections = reader.u32(offset + 60U);
            const auto sectionCount = reader.u32(offset + 64U);
            if (!name || !vmAddress || !vmSize || !fileOffset || !fileSize ||
                !protections || !sectionCount || *sectionCount > 4096U ||
                72U + static_cast<std::size_t>(*sectionCount) * 80U > *size) {
                return Diagnostic{DiagnosticSeverity::Error, "macho.segment", 
                                  "Mach-O segment command fields are invalid"};
            }
            segment.name = *name;
            segment.address = *vmAddress;
            segment.size = *vmSize;
            segment.fileOffset = *fileOffset;
            segment.fileSize = *fileSize;
            segment.protections = *protections;
            for (std::uint32_t sectionIndex = 0; sectionIndex < *sectionCount; ++sectionIndex) {
                const auto sectionOffset = offset + 72U + static_cast<std::size_t>(sectionIndex) * 80U;
                MachSection section;
                const auto sectionName = fixed_string(reader, sectionOffset, 16U);
                const auto sectionSegment = fixed_string(reader, sectionOffset + 16U, 16U);
                const auto address = reader.u64(sectionOffset + 32U);
                const auto sizeValue = reader.u64(sectionOffset + 40U);
                const auto dataOffset = reader.u32(sectionOffset + 48U);
                const auto alignment = reader.u32(sectionOffset + 52U);
                const auto relocationOffset = reader.u32(sectionOffset + 56U);
                const auto relocationCount = reader.u32(sectionOffset + 60U);
                const auto flags = reader.u32(sectionOffset + 64U);
                if (!sectionName || !sectionSegment || !address || !sizeValue || !dataOffset ||
                    !alignment || !relocationOffset || !relocationCount || !flags) {
                    return Diagnostic{DiagnosticSeverity::Error, "macho.section", 
                                      "Mach-O section record is truncated"};
                }
                section.name = *sectionName;
                section.segment = *sectionSegment;
                section.address = *address;
                section.size = *sizeValue;
                section.offset = *dataOffset;
                section.alignment = *alignment;
                section.relocationOffset = *relocationOffset;
                section.relocationCount = *relocationCount;
                section.flags = *flags;
                segment.sections.push_back(std::move(section));
            }
            segments.push_back(std::move(segment));
        } else if (*command == lcSymtab) {
            if (*size < 24U) {
                return Diagnostic{DiagnosticSeverity::Error, "macho.symtab", 
                                  "Mach-O symbol-table command is truncated"};
            }
            const auto symbolOffset = reader.u32(offset + 8U);
            const auto symbolCount = reader.u32(offset + 12U);
            const auto stringOffset = reader.u32(offset + 16U);
            const auto stringSize = reader.u32(offset + 20U);
            if (!symbolOffset || !symbolCount || !stringOffset || !stringSize) {
                return Diagnostic{DiagnosticSeverity::Error, "macho.symtab", 
                                  "Mach-O symbol-table command is malformed"};
            }
            symtab = MachSymtab{*symbolOffset, *symbolCount, *stringOffset, *stringSize};
        }
        offset += *size;
    }
    return std::nullopt;
}

} // namespace

auto parse_macho_object(std::span<const std::byte> bytes, const DetectionResult& detection)
    -> Result<BinaryImage, Diagnostic> {
    if (detection.format != BinaryFormat::MachO || detection.type != BinaryType::RelocatableObject) {
        return failure("macho.request", "Mach-O parser requires a relocatable Mach-O object");
    }
    const ByteReader reader(bytes);
    const auto commandCount = reader.u32(16U);
    const auto commandBytes = reader.u32(20U);
    const auto flags = reader.u32(24U);
    if (!commandCount || !commandBytes || !flags) {
        return failure("macho.header", "Mach-O header is truncated");
    }
    std::vector<MachSegment> segments;
    std::optional<MachSymtab> symtab;
    if (const auto diagnostic = parse_load_commands(
            reader, *commandCount, *commandBytes, segments, symtab)) {
        return Result<BinaryImage, Diagnostic>::failure(*diagnostic);
    }
    if (segments.empty() || std::all_of(segments.begin(), segments.end(),
                                        [](const auto& segment) { return segment.sections.empty(); })) {
        return failure("macho.sections", "Mach-O object contains no sections");
    }

    EntityIdAllocator ids;
    BinaryImage image;
    image.format = BinaryFormat::MachO;
    image.type = BinaryType::RelocatableObject;
    image.architecture = detection.architecture;
    image.objectMetadata.formatFlags = *flags;
    std::vector<EntityId> sectionIds;
    std::unordered_map<std::uint32_t, EntityId> sectionByIndex;
    for (const auto& segment : segments) {
        const auto segmentId = ids.allocate();
        image.segments.push_back(Segment{
            .id = segmentId,
            .name = segment.name,
            .address = BinaryAddress{segment.address, AddressKind::Virtual},
            .fileSize = segment.fileSize,
            .memorySize = segment.size,
            .readable = (segment.protections & 1U) != 0U,
            .writable = (segment.protections & 2U) != 0U,
            .executable = (segment.protections & 4U) != 0U,
            .lineage = {}});
        for (const auto& rawSection : segment.sections) {
            const auto sectionId = ids.allocate();
            const auto index = static_cast<std::uint32_t>(sectionIds.size() + 1U);
            const auto sectionType = rawSection.flags & sectionTypeMask;
            std::vector<std::byte> contents;
            if (sectionType != sectionTypeZerofill && rawSection.size != 0U) {
                const auto size = to_size(rawSection.size);
                if (!size || !reader.bytes(rawSection.offset, *size)) {
                    return failure("macho.section", "Mach-O section contents are outside the input");
                }
                contents.assign(reader.bytes(rawSection.offset, *size)->begin(),
                                reader.bytes(rawSection.offset, *size)->end());
            }
            const auto kind = section_kind(rawSection);
            image.sections.push_back(Section{
                .id = sectionId,
                .formatIndex = index,
                .formatType = sectionType,
                .formatFlags = rawSection.flags,
                .formatLink = 0,
                .formatInfo = 0,
                .formatEntrySize = 80,
                .isSectionNameTable = false,
                .name = rawSection.name,
                .kind = kind,
                .address = BinaryAddress{rawSection.address, AddressKind::Virtual},
                .logicalSize = rawSection.size,
                .alignment = rawSection.alignment >= 63U ? 1U : (UINT64_C(1) << rawSection.alignment),
                .readable = (segment.protections & 1U) != 0U,
                .writable = (segment.protections & 2U) != 0U,
                .executable = (segment.protections & 4U) != 0U,
                .contents = std::move(contents),
                .lineage = {}});
            sectionIds.push_back(sectionId);
            sectionByIndex.emplace(index, sectionId);
        }
    }

    std::vector<EntityId> symbolIds;
    if (symtab.has_value()) {
        const auto symbolBytes = checked_multiply(symtab->symbolCount, 16U);
        if (!symbolBytes || !reader.bytes(symtab->symbolOffset, *symbolBytes) ||
            !reader.bytes(symtab->stringOffset, symtab->stringSize)) {
            return failure("macho.symtab", "Mach-O symbol table is outside the input");
        }
        const auto strings = *reader.bytes(symtab->stringOffset, symtab->stringSize);
        for (std::uint32_t index = 0; index < symtab->symbolCount; ++index) {
            const auto offset = static_cast<std::size_t>(symtab->symbolOffset) + index * 16U;
            const auto stringIndex = reader.u32(offset);
            const auto type = reader.u8(offset + 4U);
            const auto section = reader.u8(offset + 5U);
            const auto description = reader.u16(offset + 6U);
            const auto value = reader.u64(offset + 8U);
            if (!stringIndex || !reader.bytes(offset, 16U).has_value()) {
                return failure("macho.symtab", "Mach-O symbol record is truncated");
            }
            const auto name = read_string(strings, *stringIndex);
            if (!name.has_value()) return failure("macho.symtab", "Mach-O symbol name is invalid");
            const auto symbolId = ids.allocate();
            const auto sectionIt = sectionByIndex.find(*section);
            const bool defined = (*type & nTypeMask) != nTypeUndefined;
            const auto kind = symbol_kind(*type, *name);
            image.symbols.push_back(Symbol{
                .id = symbolId,
                .formatIndex = index,
                .formatTableIndex = 0,
                .formatType = *type,
                .formatStorage = static_cast<std::uint8_t>((*type & nExt) != 0U),
                .formatOther = static_cast<std::uint8_t>(*description & 0xffU),
                .formatSectionIndex = *section,
                .auxiliaryData = {},
                .name = *name,
                .section = sectionIt == sectionByIndex.end() ? std::nullopt : std::optional{sectionIt->second},
                .address = BinaryAddress{*value, AddressKind::Virtual},
                .size = 0,
                .kind = kind,
                .visibility = (*type & nExt) != 0U ? SymbolVisibility::External : SymbolVisibility::Local,
                .defined = defined,
                .definition = !defined ? SymbolDefinitionKind::Undefined
                    : ((*type & nTypeMask) == nTypeAbsolute ? SymbolDefinitionKind::Absolute
                                                              : SymbolDefinitionKind::SectionRelative),
                .commonAlignment = 0,
                .tlsModel = TlsModel::None,
                .lineage = {}});
            symbolIds.push_back(symbolId);
        }
    }

    for (std::size_t sectionIndex = 0; sectionIndex < image.sections.size(); ++sectionIndex) {
        const auto& raw = [&]() -> const MachSection& {
            std::size_t seen = 0;
            for (const auto& segment : segments) {
                if (sectionIndex < seen + segment.sections.size()) {
                    return segment.sections[sectionIndex - seen];
                }
                seen += segment.sections.size();
            }
            return segments.front().sections.front();
        }();
        if (raw.relocationCount == 0U) continue;
        const auto bytesNeeded = checked_multiply(raw.relocationCount, 8U);
        if (!bytesNeeded || !reader.bytes(raw.relocationOffset, *bytesNeeded)) {
            return failure("macho.relocation", "Mach-O relocation table is outside the input");
        }
        for (std::uint32_t relocationIndex = 0; relocationIndex < raw.relocationCount; ++relocationIndex) {
            const auto offset = static_cast<std::size_t>(raw.relocationOffset) + relocationIndex * 8U;
            const auto address = reader.i32(offset);
            const auto info = reader.u32(offset + 4U);
            if (!address || !info) return failure("macho.relocation", "Mach-O relocation is truncated");
            const bool external = ((*info >> 27U) & 1U) != 0U;
            const bool pcRelative = ((*info >> 24U) & 1U) != 0U;
            const auto type = *info >> 28U;
            const auto symbolIndex = *info & 0x00ffffffU;
            std::optional<EntityId> target;
            if (external && symbolIndex < symbolIds.size()) target = symbolIds[symbolIndex];
            else if (!external) {
                const auto sectionIt = sectionByIndex.find(symbolIndex);
                if (sectionIt != sectionByIndex.end()) target = sectionIt->second;
            }
            image.relocations.push_back(Relocation{
                .id = ids.allocate(),
                .formatIndex = relocationIndex,
                .formatTableIndex = static_cast<std::uint32_t>(sectionIndex + 1U),
                .section = sectionIds[sectionIndex],
                .offset = static_cast<std::uint64_t>(*address),
                .kind = relocation_kind(detection.architecture, pcRelative, type),
                .rawType = type,
                .targetSymbol = target,
                .addend = 0,
                .lineage = {}});
        }
    }
    return Result<BinaryImage, Diagnostic>::success(std::move(image));
}

} // namespace binobf::formats::detail

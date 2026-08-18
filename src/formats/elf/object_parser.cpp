#include "../object_parser_internal.hpp"
#include "../../architecture/x86_fixups.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace binobf::formats::detail {
namespace {

constexpr std::uint32_t shtProgbits = 1;
constexpr std::uint32_t shtSymtab = 2;
constexpr std::uint32_t shtStrtab = 3;
constexpr std::uint32_t shtRela = 4;
constexpr std::uint32_t shtNobits = 8;
constexpr std::uint32_t shtRel = 9;
constexpr std::uint32_t shtDynsym = 11;
constexpr std::uint32_t shtGroup = 17;
constexpr std::uint32_t shtSymtabShndx = 18;
constexpr std::size_t maximumSectionCount = 16'384;
constexpr std::size_t maximumSymbolCount = 1'000'000;
constexpr std::size_t maximumRelocationCount = 4'000'000;

struct ElfSectionHeader {
    std::uint32_t name{0};
    std::uint32_t type{0};
    std::uint64_t flags{0};
    std::uint64_t address{0};
    std::uint64_t offset{0};
    std::uint64_t size{0};
    std::uint32_t link{0};
    std::uint32_t info{0};
    std::uint64_t alignment{0};
    std::uint64_t entrySize{0};
};

auto section_kind(std::uint32_t type, std::uint64_t flags, std::string_view name)
    -> SectionKind {
    if (name.starts_with(".debug") || name.starts_with(".zdebug")) {
        return SectionKind::Debug;
    }
    switch (type) {
    case shtProgbits:
        return (flags & 0x4U) != 0 ? SectionKind::Code : SectionKind::InitializedData;
    case shtNobits: return SectionKind::UninitializedData;
    case shtStrtab: return SectionKind::StringTable;
    case shtSymtab:
    case shtDynsym: return SectionKind::SymbolTable;
    case shtRel:
    case shtRela: return SectionKind::Relocation;
    default: return SectionKind::Metadata;
    }
}

auto symbol_kind(std::uint8_t info) noexcept -> SymbolKind {
    switch (info & 0x0fU) {
    case 1: return SymbolKind::Object;
    case 2: return SymbolKind::Function;
    case 3: return SymbolKind::Section;
    case 4: return SymbolKind::File;
    case 6: return SymbolKind::Tls;
    default: return SymbolKind::Unknown;
    }
}

auto symbol_visibility(std::uint8_t info, std::uint8_t other) noexcept
    -> SymbolVisibility {
    const auto visibility = static_cast<std::uint8_t>(other & 0x03U);
    if (visibility == 1 || visibility == 2) {
        return SymbolVisibility::Hidden;
    }
    const auto binding = static_cast<std::uint8_t>(info >> 4U);
    if (binding == 0) {
        return SymbolVisibility::Local;
    }
    if (binding == 1 || binding == 2) {
        return SymbolVisibility::External;
    }
    return SymbolVisibility::Unknown;
}

auto relocation_kind(Architecture architecture, std::uint64_t rawType) noexcept
    -> RelocationKind {
    switch (architecture) {
    case Architecture::X86:
        if (rawType == 1) return RelocationKind::Absolute;
        if (rawType == 2 || rawType == 4 || rawType == 10) {
            return RelocationKind::PcRelative;
        }
        break;
    case Architecture::X86_64:
        if (rawType == 1 || rawType == 10 || rawType == 11) {
            return RelocationKind::Absolute;
        }
        if (rawType == 2 || rawType == 4) return RelocationKind::PcRelative;
        break;
    case Architecture::ARM64:
        if (rawType == 257 || rawType == 258 || rawType == 259) {
            return RelocationKind::Absolute;
        }
        if (rawType == 260 || rawType == 261 || rawType == 262
            || rawType == 282 || rawType == 283) {
            return RelocationKind::PcRelative;
        }
        break;
    case Architecture::Unknown: break;
    }
    return RelocationKind::ArchitectureSpecific;
}

auto read_section_header(
    const ByteReader& reader,
    std::size_t offset,
    bool is64Bit) -> std::optional<ElfSectionHeader> {
    ElfSectionHeader header;
    const auto name = reader.u32(offset);
    const auto type = reader.u32(offset + 4);
    if (!name.has_value() || !type.has_value()) {
        return std::nullopt;
    }
    header.name = *name;
    header.type = *type;
    if (is64Bit) {
        const auto flags = reader.u64(offset + 8);
        const auto address = reader.u64(offset + 16);
        const auto fileOffset = reader.u64(offset + 24);
        const auto size = reader.u64(offset + 32);
        const auto link = reader.u32(offset + 40);
        const auto info = reader.u32(offset + 44);
        const auto alignment = reader.u64(offset + 48);
        const auto entrySize = reader.u64(offset + 56);
        if (!flags || !address || !fileOffset || !size || !link || !info || !alignment || !entrySize) {
            return std::nullopt;
        }
        header.flags = *flags;
        header.address = *address;
        header.offset = *fileOffset;
        header.size = *size;
        header.link = *link;
        header.info = *info;
        header.alignment = *alignment;
        header.entrySize = *entrySize;
    } else {
        const auto flags = reader.u32(offset + 8);
        const auto address = reader.u32(offset + 12);
        const auto fileOffset = reader.u32(offset + 16);
        const auto size = reader.u32(offset + 20);
        const auto link = reader.u32(offset + 24);
        const auto info = reader.u32(offset + 28);
        const auto alignment = reader.u32(offset + 32);
        const auto entrySize = reader.u32(offset + 36);
        if (!flags || !address || !fileOffset || !size || !link || !info || !alignment || !entrySize) {
            return std::nullopt;
        }
        header.flags = *flags;
        header.address = *address;
        header.offset = *fileOffset;
        header.size = *size;
        header.link = *link;
        header.info = *info;
        header.alignment = *alignment;
        header.entrySize = *entrySize;
    }
    return header;
}

auto section_bytes(const ByteReader& reader, const ElfSectionHeader& header)
    -> std::optional<std::span<const std::byte>> {
    const auto offset = to_size(header.offset);
    const auto size = to_size(header.size);
    if (!offset || !size) {
        return std::nullopt;
    }
    return reader.bytes(*offset, *size);
}

auto span_u32(std::span<const std::byte> bytes, std::size_t offset)
    -> std::optional<std::uint32_t> {
    if (offset > bytes.size() || 4U > bytes.size() - offset) return std::nullopt;
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(
            std::to_integer<std::uint8_t>(bytes[offset + index]))
            << static_cast<unsigned int>(index * 8U);
    }
    return value;
}

auto implicit_i386_addend(
    std::span<const std::byte> contents,
    std::uint64_t offset,
    std::uint64_t rawType) -> std::optional<std::int64_t> {
    const auto semantics = binobf::detail::x86_fixup_semantics(BinaryFormat::ELF, rawType);
    if (!semantics.has_value()) return std::nullopt;
    const auto hostOffset = to_size(offset);
    if (!hostOffset) return std::nullopt;
    const auto byteCount = static_cast<std::size_t>(semantics.value().bitWidth / 8U);
    if (*hostOffset > contents.size() || byteCount > contents.size() - *hostOffset) {
        return std::nullopt;
    }
    const auto decoded = binobf::detail::decode_x86_fixup(
        semantics.value(), contents.subspan(*hostOffset, byteCount));
    return decoded.has_value() ? std::optional{decoded.value()} : std::nullopt;
}

auto tls_model_for_i386_relocation(std::uint64_t rawType) noexcept
    -> std::optional<TlsModel> {
    switch (rawType) {
    case 18: return TlsModel::GeneralDynamic;
    case 19:
    case 32: return TlsModel::LocalDynamic;
    case 15:
    case 16:
    case 33: return TlsModel::InitialExec;
    case 14:
    case 17:
    case 34:
    case 37: return TlsModel::LocalExec;
    default: return std::nullopt;
    }
}

} // namespace

auto parse_elf_object(std::span<const std::byte> bytes, const DetectionResult& detection)
    -> Result<BinaryImage, Diagnostic> {
    const ByteReader reader{bytes};
    const auto elfClass = reader.u8(4);
    if (!elfClass || (*elfClass != 1 && *elfClass != 2)) {
        return failure("elf.invalid", "ELF class is invalid");
    }
    const bool is64Bit = *elfClass == 2;
    const auto objectType = reader.u16(16);
    const auto osAbi = reader.u8(7);
    const auto abiVersion = reader.u8(8);
    const auto formatFlags = is64Bit
        ? std::optional<std::uint64_t>{reader.u32(48)}
        : std::optional<std::uint64_t>{reader.u32(36)};
    if (!objectType || !osAbi || !abiVersion || !formatFlags) {
        return failure("elf.truncated", "ELF header is truncated");
    }
    if (*objectType != 1) {
        return failure("object.unsupported_type", "ELF input is not relocatable");
    }

    const auto sectionOffsetValue = is64Bit ? reader.u64(40)
        : std::optional<std::uint64_t>{reader.u32(32).value_or(0)};
    const auto sectionEntrySize = reader.u16(is64Bit ? 58 : 46);
    const auto sectionCountValue = reader.u16(is64Bit ? 60 : 48);
    const auto sectionNameIndexValue = reader.u16(is64Bit ? 62 : 50);
    if (!sectionOffsetValue || !sectionEntrySize || !sectionCountValue
        || !sectionNameIndexValue) {
        return failure("elf.truncated", "ELF section-table fields are truncated");
    }
    const auto expectedEntrySize = is64Bit ? std::size_t{64} : std::size_t{40};
    if (*sectionEntrySize < expectedEntrySize) {
        return failure("elf.invalid", "ELF section-table entry size is invalid");
    }
    const auto sectionOffset = to_size(*sectionOffsetValue);
    if (!sectionOffset) {
        return failure("elf.invalid", "ELF section-table offset exceeds host limits");
    }
    std::optional<ElfSectionHeader> sectionZero;
    const bool extendedSectionCount = *sectionCountValue == 0;
    const bool extendedSectionNameIndex = *sectionNameIndexValue == 0xffffU;
    if (extendedSectionCount || extendedSectionNameIndex) {
        sectionZero = read_section_header(reader, *sectionOffset, is64Bit);
        if (!sectionZero) {
            return failure("elf.truncated", "ELF extended section-zero header is truncated");
        }
    }
    const auto resolvedSectionCount = extendedSectionCount
        ? sectionZero->size
        : static_cast<std::uint64_t>(*sectionCountValue);
    const auto resolvedSectionNameIndex = extendedSectionNameIndex
        ? static_cast<std::uint64_t>(sectionZero->link)
        : static_cast<std::uint64_t>(*sectionNameIndexValue);
    const auto sectionCountSize = to_size(resolvedSectionCount);
    const auto sectionNameIndexSize = to_size(resolvedSectionNameIndex);
    if (!sectionCountSize || *sectionCountSize == 0
        || *sectionCountSize > maximumSectionCount || !sectionNameIndexSize) {
        return failure("elf.invalid", "ELF section-table dimensions are invalid");
    }
    const auto sectionCount = *sectionCountSize;
    const auto sectionNameIndex = *sectionNameIndexSize;
    const auto tableSize = checked_multiply(sectionCount, *sectionEntrySize);
    if (!tableSize || !contains_range(*sectionOffset, *tableSize, reader.size())) {
        return failure("elf.truncated", "ELF section table is truncated");
    }
    if (sectionNameIndex >= sectionCount) {
        return failure("elf.invalid", "ELF section-name table index is invalid");
    }

    std::vector<ElfSectionHeader> headers;
    headers.reserve(sectionCount);
    for (std::size_t index = 0; index < sectionCount; ++index) {
        const auto entryOffset = checked_add(
            *sectionOffset,
            index * static_cast<std::size_t>(*sectionEntrySize));
        if (!entryOffset) {
            return failure("elf.invalid", "ELF section-header offset overflows");
        }
        const auto header = read_section_header(reader, *entryOffset, is64Bit);
        if (!header) {
            return failure("elf.truncated", "ELF section header is truncated");
        }
        if (index != 0 && header->type != shtNobits
            && !section_bytes(reader, *header).has_value()) {
            return failure("elf.truncated", "ELF section contents are truncated");
        }
        headers.push_back(*header);
    }
    if (headers.front().type != 0U) {
        return failure("elf.invalid", "ELF section zero is not SHT_NULL");
    }

    const auto& sectionNameHeader = headers[sectionNameIndex];
    if (sectionNameHeader.type != shtStrtab) {
        return failure("elf.invalid", "ELF section-name table is not a string table");
    }
    const auto sectionNames = section_bytes(reader, sectionNameHeader);
    if (!sectionNames) {
        return failure("elf.truncated", "ELF section-name table is truncated");
    }

    BinaryImage image;
    image.format = BinaryFormat::ELF;
    image.type = BinaryType::RelocatableObject;
    image.architecture = detection.architecture;
    image.objectMetadata.osAbi = *osAbi;
    image.objectMetadata.abiVersion = *abiVersion;
    image.objectMetadata.formatFlags = *formatFlags;
    image.objectMetadata.elfExtendedSectionCount = extendedSectionCount;
    image.objectMetadata.elfExtendedSectionNameIndex = extendedSectionNameIndex;
    EntityIdAllocator ids;
    std::vector<std::optional<EntityId>> sectionIds(sectionCount);

    for (std::size_t index = 1; index < sectionCount; ++index) {
        const auto& header = headers[index];
        const auto name = read_string(*sectionNames, header.name);
        if (!name) {
            return failure("elf.invalid", "ELF section name offset is invalid");
        }
        const auto id = ids.allocate();
        sectionIds[index] = id;
        std::vector<std::byte> contents;
        if (header.type != shtNobits && header.size != 0) {
            const auto data = section_bytes(reader, header);
            if (!data) {
                return failure("elf.truncated", "ELF section contents are truncated");
            }
            contents.assign(data->begin(), data->end());
        }
        image.sections.push_back(Section{
            .id = id,
            .formatIndex = static_cast<std::uint32_t>(index),
            .formatType = header.type,
            .formatFlags = header.flags,
            .formatLink = header.link,
            .formatInfo = header.info,
            .formatEntrySize = header.entrySize,
            .isSectionNameTable = index == sectionNameIndex,
            .name = *name,
            .kind = section_kind(header.type, header.flags, *name),
            .address = BinaryAddress{header.address, AddressKind::RelativeVirtual},
            .logicalSize = header.size,
            .alignment = std::max<std::uint64_t>(header.alignment, 1),
            .readable = (header.flags & 0x2U) != 0,
            .writable = (header.flags & 0x1U) != 0,
            .executable = (header.flags & 0x4U) != 0,
            .contents = std::move(contents),
            .lineage = {},
        });
    }

    using SymbolMap = std::vector<std::optional<EntityId>>;
    std::vector<std::optional<SymbolMap>> symbolMaps(sectionCount);
    std::vector<std::optional<std::size_t>> extendedIndexSections(sectionCount);
    for (std::size_t sectionIndex = 1; sectionIndex < sectionCount; ++sectionIndex) {
        const auto& header = headers[sectionIndex];
        if (header.type != shtSymtabShndx) continue;
        if (header.link == 0 || header.link >= sectionCount
            || (headers[header.link].type != shtSymtab
                && headers[header.link].type != shtDynsym)
            || extendedIndexSections[header.link].has_value()
            || header.entrySize != 4U || header.size % 4U != 0U) {
            return failure("elf.invalid", "ELF extended-index companion is invalid");
        }
        extendedIndexSections[header.link] = sectionIndex;
    }
    for (std::size_t sectionIndex = 1; sectionIndex < sectionCount; ++sectionIndex) {
        const auto& header = headers[sectionIndex];
        if (header.type != shtSymtab && header.type != shtDynsym) {
            continue;
        }
        if (header.link >= sectionCount || headers[header.link].type != shtStrtab) {
            return failure("elf.invalid", "ELF symbol table has an invalid string-table link");
        }
        const auto expectedSymbolSize = is64Bit ? std::uint64_t{24} : std::uint64_t{16};
        if (header.entrySize != expectedSymbolSize || header.size % header.entrySize != 0) {
            return failure("elf.invalid", "ELF symbol table entry size is invalid");
        }
        const auto symbolCountValue = header.size / header.entrySize;
        if (symbolCountValue > maximumSymbolCount) {
            return failure("elf.invalid", "ELF symbol table exceeds the entry limit");
        }
        const auto symbolCount = static_cast<std::size_t>(symbolCountValue);
        SymbolMap map(symbolCount);
        const auto symbolData = section_bytes(reader, header);
        const auto stringData = section_bytes(reader, headers[header.link]);
        if (!symbolData || !stringData) {
            return failure("elf.truncated", "ELF symbol or string table is truncated");
        }
        std::optional<std::span<const std::byte>> extendedIndexData;
        std::optional<std::size_t> extendedIndexSection;
        if (extendedIndexSections[sectionIndex].has_value()) {
            extendedIndexSection = *extendedIndexSections[sectionIndex];
            const auto& companion = headers[*extendedIndexSection];
            if (companion.size / 4U != symbolCount) {
                return failure("elf.invalid", "ELF extended-index companion count is invalid");
            }
            extendedIndexData = section_bytes(reader, companion);
            if (!extendedIndexData) {
                return failure("elf.truncated", "ELF extended-index companion is truncated");
            }
        }
        const auto symbolBase = to_size(header.offset).value();
        for (std::size_t symbolIndex = 1; symbolIndex < symbolCount; ++symbolIndex) {
            const auto entryOffset = symbolBase + symbolIndex * static_cast<std::size_t>(header.entrySize);
            const auto nameOffset = reader.u32(entryOffset);
            std::optional<std::uint8_t> info;
            std::optional<std::uint8_t> other;
            std::optional<std::uint16_t> sectionIndexValue;
            std::optional<std::uint64_t> value;
            std::optional<std::uint64_t> size;
            if (is64Bit) {
                info = reader.u8(entryOffset + 4);
                other = reader.u8(entryOffset + 5);
                sectionIndexValue = reader.u16(entryOffset + 6);
                value = reader.u64(entryOffset + 8);
                size = reader.u64(entryOffset + 16);
            } else {
                value = reader.u32(entryOffset + 4);
                size = reader.u32(entryOffset + 8);
                info = reader.u8(entryOffset + 12);
                other = reader.u8(entryOffset + 13);
                sectionIndexValue = reader.u16(entryOffset + 14);
            }
            if (!nameOffset || !info || !other || !sectionIndexValue || !value || !size) {
                return failure("elf.truncated", "ELF symbol entry is truncated");
            }
            const auto name = read_string(*stringData, *nameOffset);
            if (!name) {
                return failure("elf.invalid", "ELF symbol name offset is invalid");
            }
            std::optional<EntityId> section;
            bool defined = *sectionIndexValue != 0;
            std::optional<SymbolDefinitionKind> definition;
            std::uint64_t commonAlignment = 0;
            std::uint32_t resolvedSectionIndex = *sectionIndexValue;
            if (*sectionIndexValue == 0xffffU) {
                if (!extendedIndexData || !extendedIndexSection) {
                    return failure(
                        "elf.invalid", "ELF extended symbol index has no companion table");
                }
                const auto extended = span_u32(*extendedIndexData, symbolIndex * 4U);
                if (!extended || *extended == 0U || *extended >= sectionCount) {
                    return failure("elf.invalid", "ELF extended symbol index is out of range");
                }
                resolvedSectionIndex = *extended;
            }
            if (resolvedSectionIndex > 0 && resolvedSectionIndex < sectionCount) {
                if (!sectionIds[resolvedSectionIndex].has_value()) {
                    return failure("elf.invalid", "ELF symbol section is unavailable");
                }
                section = sectionIds[resolvedSectionIndex];
                definition = SymbolDefinitionKind::SectionRelative;
            } else if (*sectionIndexValue == 0) {
                definition = SymbolDefinitionKind::Undefined;
                defined = false;
            } else if (*sectionIndexValue == 0xfff1U) {
                definition = SymbolDefinitionKind::Absolute;
            } else if (*sectionIndexValue == 0xfff2U) {
                definition = SymbolDefinitionKind::Common;
                commonAlignment = *value;
            } else if (*sectionIndexValue != 0 && *sectionIndexValue < 0xff00U) {
                return failure("elf.invalid", "ELF symbol section index is invalid");
            }
            const auto id = ids.allocate();
            map[symbolIndex] = id;
            const auto normalizedKind = symbol_kind(*info);
            image.symbols.push_back(Symbol{
                .id = id,
                .formatIndex = static_cast<std::uint32_t>(symbolIndex),
                .formatTableIndex = static_cast<std::uint32_t>(sectionIndex),
                .formatType = static_cast<std::uint32_t>(*info & 0x0fU),
                .formatStorage = static_cast<std::uint8_t>(*info >> 4U),
                .formatOther = *other,
                .formatSectionIndex = static_cast<std::int32_t>(*sectionIndexValue),
                .auxiliaryData = {},
                .name = *name,
                .section = section,
                .address = BinaryAddress{*value, AddressKind::RelativeVirtual},
                .size = *size,
                .kind = normalizedKind,
                .visibility = symbol_visibility(*info, *other),
                .defined = defined,
                .definition = definition,
                .commonAlignment = commonAlignment,
                .tlsModel = normalizedKind == SymbolKind::Tls
                    ? TlsModel::Unknown
                    : TlsModel::None,
                .lineage = {},
            });
            if (*sectionIndexValue == 0xffffU) {
                image.extendedSectionIndices.push_back(ExtendedSectionIndex{
                    .symbol = id,
                    .indexSection = *sectionIds[*extendedIndexSection],
                    .section = *section,
                    .rawSectionIndex = resolvedSectionIndex,
                });
            }
        }
        symbolMaps[sectionIndex] = std::move(map);
    }

    for (std::size_t sectionIndex = 1; sectionIndex < sectionCount; ++sectionIndex) {
        const auto& header = headers[sectionIndex];
        if (header.type != shtGroup) continue;
        if (header.link >= sectionCount || !symbolMaps[header.link].has_value()
            || header.entrySize != 4U || header.size < 8U || header.size % 4U != 0U) {
            return failure("elf.invalid", "ELF group layout is invalid");
        }
        const auto groupData = section_bytes(reader, header);
        if (!groupData) {
            return failure("elf.truncated", "ELF group contents are truncated");
        }
        const auto flags = span_u32(*groupData, 0);
        const auto& symbolMap = *symbolMaps[header.link];
        if (!flags || (*flags & 1U) == 0U || header.info == 0U
            || header.info >= symbolMap.size() || !symbolMap[header.info].has_value()) {
            return failure("elf.invalid", "ELF group signature or flags are invalid");
        }
        std::vector<EntityId> members;
        std::unordered_set<std::uint32_t> memberIndices;
        const auto memberCount = static_cast<std::size_t>(header.size / 4U) - 1U;
        members.reserve(memberCount);
        for (std::size_t member = 0; member < memberCount; ++member) {
            const auto rawIndex = span_u32(*groupData, (member + 1U) * 4U);
            if (!rawIndex || *rawIndex == 0U || *rawIndex >= sectionCount
                || !sectionIds[*rawIndex].has_value()
                || !memberIndices.insert(*rawIndex).second) {
                return failure("elf.invalid", "ELF group member index is invalid");
            }
            members.push_back(*sectionIds[*rawIndex]);
        }
        image.sectionAssociations.push_back(SectionAssociation{
            .section = *sectionIds[sectionIndex],
            .kind = SectionAssociationKind::ElfGroup,
            .coffSelection = CoffComdatSelection::None,
            .signatureSymbol = *symbolMap[header.info],
            .parentSection = std::nullopt,
            .members = std::move(members),
        });
    }

    std::unordered_map<std::uint64_t, Symbol*> symbolsById;
    for (auto& symbol : image.symbols) {
        symbolsById.emplace(symbol.id.value(), &symbol);
    }

    for (std::size_t sectionIndex = 1; sectionIndex < sectionCount; ++sectionIndex) {
        const auto& header = headers[sectionIndex];
        if (header.type != shtRel && header.type != shtRela) {
            continue;
        }
        if (header.info == 0 || header.info >= sectionCount
            || !sectionIds[header.info].has_value()) {
            return failure("elf.invalid", "ELF relocation target section is invalid");
        }
        if (header.link >= sectionCount || !symbolMaps[header.link].has_value()) {
            return failure("elf.invalid", "ELF relocation symbol-table link is invalid");
        }
        const auto expectedRelocationSize = is64Bit
            ? (header.type == shtRela ? std::uint64_t{24} : std::uint64_t{16})
            : (header.type == shtRela ? std::uint64_t{12} : std::uint64_t{8});
        if (header.entrySize != expectedRelocationSize || header.size % header.entrySize != 0) {
            return failure("elf.invalid", "ELF relocation entry size is invalid");
        }
        const auto relocationCountValue = header.size / header.entrySize;
        if (relocationCountValue > maximumRelocationCount) {
            return failure("elf.invalid", "ELF relocation table exceeds the entry limit");
        }
        const auto relocationCount = static_cast<std::size_t>(relocationCountValue);
        const auto relocationBase = to_size(header.offset).value();
        const auto& symbolMap = *symbolMaps[header.link];
        for (std::size_t index = 0; index < relocationCount; ++index) {
            const auto entryOffset = relocationBase + index * static_cast<std::size_t>(header.entrySize);
            std::uint64_t offset = 0;
            std::uint64_t information = 0;
            std::int64_t addend = 0;
            if (is64Bit) {
                const auto readOffset = reader.u64(entryOffset);
                const auto readInformation = reader.u64(entryOffset + 8);
                if (!readOffset || !readInformation) {
                    return failure("elf.truncated", "ELF relocation entry is truncated");
                }
                offset = *readOffset;
                information = *readInformation;
                if (header.type == shtRela) {
                    const auto readAddend = reader.i64(entryOffset + 16);
                    if (!readAddend) {
                        return failure("elf.truncated", "ELF relocation addend is truncated");
                    }
                    addend = *readAddend;
                }
            } else {
                const auto readOffset = reader.u32(entryOffset);
                const auto readInformation = reader.u32(entryOffset + 4);
                if (!readOffset || !readInformation) {
                    return failure("elf.truncated", "ELF relocation entry is truncated");
                }
                offset = *readOffset;
                information = *readInformation;
                if (header.type == shtRela) {
                    const auto readAddend = reader.i32(entryOffset + 8);
                    if (!readAddend) {
                        return failure("elf.truncated", "ELF relocation addend is truncated");
                    }
                    addend = *readAddend;
                }
            }
            const auto symbolIndex = is64Bit
                ? static_cast<std::size_t>(information >> 32U)
                : static_cast<std::size_t>(information >> 8U);
            const auto rawType = is64Bit
                ? (information & UINT64_C(0xffffffff))
                : (information & UINT64_C(0xff));
            if (!is64Bit && header.type == shtRel) {
                const auto targetContents = section_bytes(reader, headers[header.info]);
                const auto implicit = targetContents
                    ? implicit_i386_addend(*targetContents, offset, rawType)
                    : std::nullopt;
                if (!implicit) {
                    return failure("elf.invalid", "ELF REL implicit addend is out of range");
                }
                addend = *implicit;
            }
            if (symbolIndex >= symbolMap.size()) {
                return failure("elf.invalid", "ELF relocation symbol index is invalid");
            }
            std::optional<EntityId> targetSymbol;
            if (symbolIndex != 0) {
                if (!symbolMap[symbolIndex].has_value()) {
                    return failure("elf.invalid", "ELF relocation references an unavailable symbol");
                }
                targetSymbol = symbolMap[symbolIndex];
            }
            if (targetSymbol.has_value()) {
                const auto target = symbolsById.find(targetSymbol->value());
                const auto model = tls_model_for_i386_relocation(rawType);
                if (target != symbolsById.end() && target->second->kind == SymbolKind::Tls
                    && model.has_value()) {
                    if (target->second->tlsModel == TlsModel::Unknown
                        || target->second->tlsModel == *model) {
                        target->second->tlsModel = *model;
                    } else {
                        target->second->tlsModel = TlsModel::Unknown;
                    }
                }
            }
            image.relocations.push_back(Relocation{
                .id = ids.allocate(),
                .formatIndex = static_cast<std::uint32_t>(index),
                .formatTableIndex = static_cast<std::uint32_t>(sectionIndex),
                .section = *sectionIds[header.info],
                .offset = offset,
                .kind = relocation_kind(detection.architecture, rawType),
                .rawType = rawType,
                .targetSymbol = targetSymbol,
                .addend = addend,
                .lineage = {},
            });
        }
    }
    return Result<BinaryImage, Diagnostic>::success(std::move(image));
}

} // namespace binobf::formats::detail

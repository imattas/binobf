#include "../object_parser_internal.hpp"
#include "../../architecture/x86_fixups.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace binobf::formats::detail {
namespace {

constexpr std::size_t coffHeaderSize = 20;
constexpr std::size_t coffBigObjHeaderSize = 56;
constexpr std::size_t sectionHeaderSize = 40;
constexpr std::size_t classicSymbolEntrySize = 18;
constexpr std::size_t bigObjSymbolEntrySize = 20;
constexpr std::size_t relocationEntrySize = 10;
constexpr std::size_t maximumSectionCount = 65'536;
constexpr std::size_t maximumSymbolCount = 1'000'000;
constexpr std::size_t maximumRelocationCount = 4'000'000;

struct CoffSectionHeader {
    std::array<std::byte, 8> encodedName{};
    std::uint32_t virtualSize{0};
    std::uint32_t rawSize{0};
    std::uint32_t rawOffset{0};
    std::uint32_t relocationOffset{0};
    std::uint16_t rawRelocationCount{0};
    std::uint32_t relocationCount{0};
    bool relocationOverflow{false};
    std::uint32_t characteristics{0};
};

struct CoffObjectLayout {
    bool bigObj{false};
    std::size_t headerSize{0};
    std::size_t sectionCount{0};
    std::size_t symbolOffset{0};
    std::size_t symbolCount{0};
    std::size_t symbolEntrySize{0};
    bool wideSectionNumbers{false};
    std::uint16_t characteristics{0};
};

auto read_inline_name(std::span<const std::byte> encoded) -> std::string {
    std::string name;
    name.reserve(encoded.size());
    for (const auto byte : encoded) {
        if (byte == std::byte{0}) {
            break;
        }
        name.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
    }
    return name;
}

auto resolve_section_name(
    const CoffSectionHeader& header,
    std::optional<std::span<const std::byte>> stringTable) -> std::optional<std::string> {
    const auto inlineName = read_inline_name(header.encodedName);
    if (inlineName.empty() || inlineName.front() != '/') {
        return inlineName;
    }
    if (!stringTable.has_value() || inlineName.size() == 1) {
        return std::nullopt;
    }
    std::uint64_t offset = 0;
    const auto first = inlineName.data() + 1;
    const auto last = inlineName.data() + inlineName.size();
    const auto parsed = std::from_chars(first, last, offset, 10);
    if (parsed.ec != std::errc{} || parsed.ptr != last) {
        return std::nullopt;
    }
    return read_string(*stringTable, offset);
}

auto resolve_symbol_name(
    const ByteReader& reader,
    std::size_t entryOffset,
    std::optional<std::span<const std::byte>> stringTable) -> std::optional<std::string> {
    const auto zeroes = reader.u32(entryOffset);
    const auto offset = reader.u32(entryOffset + 4);
    if (!zeroes || !offset) {
        return std::nullopt;
    }
    if (*zeroes == 0) {
        if (!stringTable.has_value()) {
            return std::nullopt;
        }
        return read_string(*stringTable, *offset);
    }
    const auto encoded = reader.bytes(entryOffset, 8);
    return encoded.has_value() ? std::optional{read_inline_name(*encoded)} : std::nullopt;
}

auto section_alignment(std::uint32_t characteristics) noexcept -> std::uint64_t {
    const auto code = static_cast<std::uint32_t>((characteristics >> 20U) & 0x0fU);
    if (code == 0) {
        return 1;
    }
    return UINT64_C(1) << (code - 1U);
}

auto section_kind(std::string_view name, std::uint32_t characteristics) -> SectionKind {
    if (name.starts_with(".debug")) return SectionKind::Debug;
    if ((characteristics & 0x00000020U) != 0 || (characteristics & 0x20000000U) != 0) {
        return SectionKind::Code;
    }
    if ((characteristics & 0x00000080U) != 0) return SectionKind::UninitializedData;
    if ((characteristics & 0x00000040U) != 0) return SectionKind::InitializedData;
    return SectionKind::Metadata;
}

auto symbol_kind(
    std::string_view name,
    std::uint16_t type,
    std::uint8_t storageClass,
    std::int32_t sectionNumber) -> SymbolKind {
    if (storageClass == 103) return SymbolKind::File;
    if ((type & 0x20U) != 0) return SymbolKind::Function;
    if (storageClass == 3 && sectionNumber > 0 && name.starts_with('.')) {
        return SymbolKind::Section;
    }
    return SymbolKind::Object;
}

auto symbol_visibility(std::uint8_t storageClass) noexcept -> SymbolVisibility {
    if (storageClass == 2 || storageClass == 105) return SymbolVisibility::External;
    if (storageClass == 3 || storageClass == 6 || storageClass == 103) {
        return SymbolVisibility::Local;
    }
    return SymbolVisibility::Unknown;
}

auto relocation_kind(Architecture architecture, std::uint16_t rawType) noexcept
    -> RelocationKind {
    switch (architecture) {
    case Architecture::X86:
        if (rawType == 0x0001 || rawType == 0x0006 || rawType == 0x0009) {
            return RelocationKind::Absolute;
        }
        if (rawType == 0x0002 || rawType == 0x0014) return RelocationKind::PcRelative;
        if (rawType == 0x0007) return RelocationKind::ImageRelative;
        break;
    case Architecture::X86_64:
        if (rawType == 0x0001 || rawType == 0x0002) return RelocationKind::Absolute;
        if (rawType == 0x0003) return RelocationKind::ImageRelative;
        if (rawType >= 0x0004 && rawType <= 0x0009) return RelocationKind::PcRelative;
        break;
    case Architecture::ARM64:
        if (rawType == 0x0001) return RelocationKind::Absolute;
        if (rawType == 0x0002) return RelocationKind::ImageRelative;
        if (rawType >= 0x0003 && rawType <= 0x0008) return RelocationKind::PcRelative;
        break;
    case Architecture::Unknown: break;
    }
    return RelocationKind::ArchitectureSpecific;
}

auto comdat_selection(std::uint8_t raw) -> std::optional<CoffComdatSelection> {
    switch (raw) {
    case 0: return CoffComdatSelection::None;
    case 1: return CoffComdatSelection::NoDuplicates;
    case 2: return CoffComdatSelection::Any;
    case 3: return CoffComdatSelection::SameSize;
    case 4: return CoffComdatSelection::ExactMatch;
    case 5: return CoffComdatSelection::Associative;
    case 6: return CoffComdatSelection::Largest;
    case 7: return CoffComdatSelection::Newest;
    default: return std::nullopt;
    }
}

auto auxiliary_u16(std::span<const std::byte> bytes, std::size_t offset)
    -> std::optional<std::uint16_t> {
    if (offset > bytes.size() || 2U > bytes.size() - offset) return std::nullopt;
    return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[offset]))
        | static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[offset + 1U]))
            << 8U);
}

auto read_section_header(const ByteReader& reader, std::size_t offset)
    -> std::optional<CoffSectionHeader> {
    CoffSectionHeader header;
    const auto name = reader.bytes(offset, 8);
    const auto virtualSize = reader.u32(offset + 8);
    const auto rawSize = reader.u32(offset + 16);
    const auto rawOffset = reader.u32(offset + 20);
    const auto relocationOffset = reader.u32(offset + 24);
    const auto relocationCount = reader.u16(offset + 32);
    const auto characteristics = reader.u32(offset + 36);
    if (!name || !virtualSize || !rawSize || !rawOffset || !relocationOffset
        || !relocationCount || !characteristics) {
        return std::nullopt;
    }
    std::copy(name->begin(), name->end(), header.encodedName.begin());
    header.virtualSize = *virtualSize;
    header.rawSize = *rawSize;
    header.rawOffset = *rawOffset;
    header.relocationOffset = *relocationOffset;
    header.rawRelocationCount = *relocationCount;
    header.relocationCount = *relocationCount;
    header.characteristics = *characteristics;
    return header;
}

} // namespace

auto parse_coff_object(std::span<const std::byte> bytes, const DetectionResult& detection)
    -> Result<BinaryImage, Diagnostic> {
    const ByteReader reader{bytes};
    const bool bigObj = reader.u16(0) == 0U && reader.u16(2) == 0xffffU;
    std::optional<std::uint32_t> sectionCountValue;
    std::optional<std::uint32_t> symbolOffsetValue;
    std::optional<std::uint32_t> symbolCountValue;
    std::uint16_t characteristics = 0;
    if (bigObj) {
        if (reader.u16(4) != 2U || !contains_range(0, coffBigObjHeaderSize, reader.size())) {
            return failure("coff.invalid", "COFF bigobj header is invalid");
        }
        sectionCountValue = reader.u32(44);
        symbolOffsetValue = reader.u32(48);
        symbolCountValue = reader.u32(52);
    } else {
        const auto classicSectionCount = reader.u16(2);
        const auto optionalHeaderSize = reader.u16(16);
        const auto classicCharacteristics = reader.u16(18);
        if (!classicSectionCount || !optionalHeaderSize || !classicCharacteristics) {
            return failure("coff.truncated", "COFF header is truncated");
        }
        if (*optionalHeaderSize != 0) {
            return failure("coff.invalid", "COFF object has an unexpected optional header");
        }
        sectionCountValue = *classicSectionCount;
        symbolOffsetValue = reader.u32(8);
        symbolCountValue = reader.u32(12);
        characteristics = *classicCharacteristics;
    }
    if (!sectionCountValue || !symbolOffsetValue || !symbolCountValue) {
        return failure("coff.truncated", "COFF object layout is truncated");
    }
    CoffObjectLayout layout{
        .bigObj = bigObj,
        .headerSize = bigObj ? coffBigObjHeaderSize : coffHeaderSize,
        .sectionCount = static_cast<std::size_t>(*sectionCountValue),
        .symbolOffset = static_cast<std::size_t>(*symbolOffsetValue),
        .symbolCount = static_cast<std::size_t>(*symbolCountValue),
        .symbolEntrySize = bigObj ? bigObjSymbolEntrySize : classicSymbolEntrySize,
        .wideSectionNumbers = bigObj,
        .characteristics = characteristics,
    };
    if (layout.sectionCount == 0 || layout.sectionCount > maximumSectionCount) {
        return failure("coff.invalid", "COFF section count is invalid");
    }
    const auto sectionTableSize = checked_multiply(layout.sectionCount, sectionHeaderSize);
    if (!sectionTableSize
        || !contains_range(layout.headerSize, *sectionTableSize, reader.size())) {
        return failure("coff.truncated", "COFF section table is truncated");
    }

    if (layout.symbolCount > maximumSymbolCount) {
        return failure("coff.invalid", "COFF symbol count exceeds the entry limit");
    }
    std::optional<std::span<const std::byte>> stringTable;
    if (layout.symbolCount != 0 || layout.symbolOffset != 0) {
        const auto symbolTableSize = checked_multiply(
            layout.symbolCount, layout.symbolEntrySize);
        if (!symbolTableSize
            || !contains_range(layout.symbolOffset, *symbolTableSize, reader.size())) {
            return failure("coff.truncated", "COFF symbol table is truncated");
        }
        const auto stringOffset = checked_add(layout.symbolOffset, *symbolTableSize);
        if (!stringOffset || !contains_range(*stringOffset, 4, reader.size())) {
            return failure("coff.truncated", "COFF string-table length is truncated");
        }
        const auto stringLength = reader.u32(*stringOffset).value();
        if (stringLength < 4) {
            return failure("coff.invalid", "COFF string-table length is invalid");
        }
        if (!contains_range(*stringOffset, stringLength, reader.size())) {
            return failure("coff.truncated", "COFF string table is truncated");
        }
        stringTable = reader.bytes(*stringOffset, stringLength);
    }

    std::vector<CoffSectionHeader> headers;
    headers.reserve(layout.sectionCount);
    std::size_t cumulativeRelocationCount = 0;
    for (std::size_t index = 0; index < layout.sectionCount; ++index) {
        const auto headerOffset = layout.headerSize + index * sectionHeaderSize;
        const auto header = read_section_header(reader, headerOffset);
        if (!header) {
            return failure("coff.truncated", "COFF section header is truncated");
        }
        if (header->rawSize != 0
            && !contains_range(header->rawOffset, header->rawSize, reader.size())) {
            return failure("coff.truncated", "COFF section contents are truncated");
        }
        const bool overflowFlag = (header->characteristics & 0x01000000U) != 0U;
        if (overflowFlag && header->rawRelocationCount != 0xffffU) {
            return failure(
                "coff.invalid",
                "COFF relocation-overflow section does not use the 0xffff header count");
        }
        auto tableEntryCount = static_cast<std::uint64_t>(header->rawRelocationCount);
        auto normalizedHeader = *header;
        if (overflowFlag) {
            const auto sentinelCount = reader.u32(header->relocationOffset);
            const auto sentinelSymbol = reader.u32(header->relocationOffset + 4U);
            const auto sentinelType = reader.u16(header->relocationOffset + 8U);
            if (!sentinelCount || !sentinelSymbol || !sentinelType
                || *sentinelCount == 0U || *sentinelSymbol != 0U || *sentinelType != 0U) {
                return failure("coff.invalid", "COFF relocation-overflow sentinel is invalid");
            }
            tableEntryCount = *sentinelCount;
            normalizedHeader.relocationCount = *sentinelCount - 1U;
            normalizedHeader.relocationOverflow = true;
        }
        if (normalizedHeader.relocationCount > maximumRelocationCount
            || cumulativeRelocationCount > maximumRelocationCount
                - normalizedHeader.relocationCount) {
            return failure("coff.invalid", "COFF relocation count exceeds the parser limit");
        }
        cumulativeRelocationCount += normalizedHeader.relocationCount;
        const auto relocationSize = checked_multiply(
            static_cast<std::size_t>(tableEntryCount), relocationEntrySize);
        if (!relocationSize
            || (header->relocationCount != 0
                && !contains_range(header->relocationOffset, *relocationSize, reader.size()))) {
            return failure("coff.truncated", "COFF relocation table is truncated");
        }
        headers.push_back(normalizedHeader);
    }

    BinaryImage image;
    image.format = BinaryFormat::COFF;
    image.type = BinaryType::RelocatableObject;
    image.architecture = detection.architecture;
    image.objectMetadata.characteristics = layout.characteristics;
    image.objectMetadata.coffBigObj = layout.bigObj;
    EntityIdAllocator ids;
    std::vector<EntityId> sectionIds;
    sectionIds.reserve(layout.sectionCount);
    for (std::size_t index = 0; index < layout.sectionCount; ++index) {
        const auto& header = headers[index];
        const auto name = resolve_section_name(header, stringTable);
        if (!name) {
            return failure("coff.invalid", "COFF section name is invalid");
        }
        const auto id = ids.allocate();
        sectionIds.push_back(id);
        std::vector<std::byte> contents;
        if (header.rawSize != 0) {
            const auto data = reader.bytes(header.rawOffset, header.rawSize);
            if (!data) {
                return failure("coff.truncated", "COFF section contents are truncated");
            }
            contents.assign(data->begin(), data->end());
        }
        image.sections.push_back(Section{
            .id = id,
            .formatIndex = static_cast<std::uint32_t>(index + 1),
            .formatType = 0,
            .formatFlags = header.characteristics,
            .formatLink = 0,
            .formatInfo = 0,
            .formatEntrySize = 0,
            .isSectionNameTable = false,
            .name = *name,
            .kind = section_kind(*name, header.characteristics),
            .address = BinaryAddress{0, AddressKind::RelativeVirtual},
            .logicalSize = std::max(header.rawSize, header.virtualSize),
            .alignment = section_alignment(header.characteristics),
            .readable = (header.characteristics & 0x40000000U) != 0,
            .writable = (header.characteristics & 0x80000000U) != 0,
            .executable = (header.characteristics & 0x20000000U) != 0,
            .contents = std::move(contents),
            .lineage = {},
        });
    }

    std::vector<std::optional<EntityId>> symbolIds(layout.symbolCount);
    for (std::size_t index = 0; index < layout.symbolCount;) {
        const auto entryOffset = layout.symbolOffset + index * layout.symbolEntrySize;
        const auto name = resolve_symbol_name(reader, entryOffset, stringTable);
        const auto value = reader.u32(entryOffset + 8);
        const auto sectionNumber = layout.wideSectionNumbers
            ? reader.i32(entryOffset + 12)
            : std::optional<std::int32_t>{reader.i16(entryOffset + 12)};
        const auto typeOffset = layout.wideSectionNumbers ? std::size_t{16} : std::size_t{14};
        const auto storageOffset = layout.wideSectionNumbers ? std::size_t{18} : std::size_t{16};
        const auto auxiliaryOffsetInSymbol = layout.wideSectionNumbers
            ? std::size_t{19}
            : std::size_t{17};
        const auto type = reader.u16(entryOffset + typeOffset);
        const auto storageClass = reader.u8(entryOffset + storageOffset);
        const auto auxiliaryCount = reader.u8(entryOffset + auxiliaryOffsetInSymbol);
        if (!name || !value || !sectionNumber || !type || !storageClass || !auxiliaryCount) {
            return failure("coff.invalid", "COFF symbol entry is invalid");
        }
        const auto recordCount = std::size_t{1} + *auxiliaryCount;
        if (recordCount > layout.symbolCount - index) {
            return failure("coff.invalid", "COFF auxiliary symbol count exceeds the table");
        }
        std::vector<std::byte> auxiliaryData;
        if (*auxiliaryCount != 0) {
            const auto auxiliarySize = checked_multiply(
                *auxiliaryCount, layout.symbolEntrySize);
            const auto auxiliaryOffset = checked_add(entryOffset, layout.symbolEntrySize);
            if (!auxiliarySize || !auxiliaryOffset) {
                return failure("coff.invalid", "COFF auxiliary symbol range overflows");
            }
            const auto auxiliaryBytes = reader.bytes(*auxiliaryOffset, *auxiliarySize);
            if (!auxiliaryBytes.has_value()) {
                return failure("coff.truncated", "COFF auxiliary symbol data is truncated");
            }
            auxiliaryData.assign(auxiliaryBytes->begin(), auxiliaryBytes->end());
        }
        std::optional<EntityId> section;
        bool defined = *sectionNumber != 0;
        std::optional<SymbolDefinitionKind> definition;
        std::uint64_t commonAlignment = 0;
        if (*sectionNumber > 0) {
            const auto sectionIndex = static_cast<std::size_t>(*sectionNumber - 1);
            if (sectionIndex >= sectionIds.size()) {
                return failure("coff.invalid", "COFF symbol section index is invalid");
            }
            section = sectionIds[sectionIndex];
            definition = SymbolDefinitionKind::SectionRelative;
        } else if (*sectionNumber == -1) {
            definition = SymbolDefinitionKind::Absolute;
        } else if (*sectionNumber == 0 && *value != 0U && *storageClass == 2U) {
            definition = SymbolDefinitionKind::Common;
            commonAlignment = 1;
            defined = true;
        } else if (*sectionNumber == 0) {
            definition = SymbolDefinitionKind::Undefined;
        } else if (*sectionNumber < -2) {
            return failure("coff.invalid", "COFF symbol special section number is invalid");
        }
        const auto id = ids.allocate();
        symbolIds[index] = id;
        std::uint64_t normalizedSize = 0;
        if ((*type & 0x30U) == 0x20U && *sectionNumber > 0
            && auxiliaryData.size() >= 8) {
            for (std::size_t byteIndex = 0; byteIndex < 4; ++byteIndex) {
                normalizedSize |= static_cast<std::uint64_t>(
                    std::to_integer<std::uint8_t>(auxiliaryData[4 + byteIndex]))
                    << (byteIndex * 8U);
            }
        }
        const auto normalizedKind = symbol_kind(
            *name, *type, *storageClass, *sectionNumber);
        image.symbols.push_back(Symbol{
            .id = id,
            .formatIndex = static_cast<std::uint32_t>(index),
            .formatTableIndex = 0,
            .formatType = *type,
            .formatStorage = *storageClass,
            .formatOther = 0,
            .formatSectionIndex = *sectionNumber,
            .auxiliaryData = std::move(auxiliaryData),
            .name = *name,
            .section = section,
            .address = BinaryAddress{*value, AddressKind::RelativeVirtual},
            .size = normalizedSize,
            .kind = normalizedKind,
            .visibility = symbol_visibility(*storageClass),
            .defined = defined,
            .definition = definition,
            .commonAlignment = commonAlignment,
            .tlsModel = normalizedKind == SymbolKind::Tls
                ? TlsModel::CoffStatic
                : TlsModel::None,
            .lineage = {},
        });
        index += recordCount;
    }

    std::vector<bool> associatedSections(layout.sectionCount, false);
    for (const auto& symbol : image.symbols) {
        if (symbol.kind != SymbolKind::Section || !symbol.section.has_value()
            || symbol.formatStorage != 3U || symbol.auxiliaryData.size() < 18U) {
            continue;
        }
        const auto rawSelection = std::to_integer<std::uint8_t>(symbol.auxiliaryData[14]);
        const auto selection = comdat_selection(rawSelection);
        if (!selection.has_value()) {
            return failure("coff.invalid", "COFF COMDAT selection value is invalid");
        }
        if (*selection == CoffComdatSelection::None) continue;
        const auto owned = std::find(sectionIds.begin(), sectionIds.end(), *symbol.section);
        if (owned == sectionIds.end()) {
            return failure("coff.invalid", "COFF COMDAT section owner is missing");
        }
        const auto ownedIndex = static_cast<std::size_t>(
            std::distance(sectionIds.begin(), owned));
        if (associatedSections[ownedIndex]
            || (headers[ownedIndex].characteristics & 0x00001000U) == 0U) {
            return failure("coff.invalid", "COFF COMDAT ownership is duplicated or unmarked");
        }
        associatedSections[ownedIndex] = true;
        std::optional<EntityId> parent;
        auto kind = SectionAssociationKind::CoffComdat;
        if (*selection == CoffComdatSelection::Associative) {
            const auto low = auxiliary_u16(symbol.auxiliaryData, 12);
            const auto high = auxiliary_u16(symbol.auxiliaryData, 16);
            if (!low || !high) {
                return failure("coff.invalid", "COFF associative COMDAT auxiliary data is truncated");
            }
            const auto parentIndex = static_cast<std::uint32_t>(*low)
                | (static_cast<std::uint32_t>(*high) << 16U);
            if (parentIndex == 0U || parentIndex > sectionIds.size()) {
                return failure("coff.invalid", "COFF associative COMDAT parent is invalid");
            }
            parent = sectionIds[parentIndex - 1U];
            kind = SectionAssociationKind::CoffAssociativeComdat;
        }
        image.sectionAssociations.push_back(SectionAssociation{
            .section = *symbol.section,
            .kind = kind,
            .coffSelection = *selection,
            .signatureSymbol = symbol.id,
            .parentSection = parent,
            .members = {},
        });
    }
    for (std::size_t index = 0; index < layout.sectionCount; ++index) {
        if ((headers[index].characteristics & 0x00001000U) != 0U
            && !associatedSections[index]) {
            return failure("coff.invalid", "COFF COMDAT section has no section-definition owner");
        }
    }

    for (std::size_t sectionIndex = 0; sectionIndex < image.sections.size(); ++sectionIndex) {
        const auto& section = image.sections[sectionIndex];
        if (section.name != ".sxdata") continue;
        if (section.contents.size() % 4U != 0U) {
            return failure("coff.invalid", "COFF .sxdata size is not a symbol-index array");
        }
        for (std::size_t index = 0; index < section.contents.size() / 4U; ++index) {
            const auto entryOffset = index * 4U;
            const auto rawIndex = static_cast<std::uint32_t>(
                std::to_integer<std::uint8_t>(section.contents[entryOffset]))
                | (static_cast<std::uint32_t>(
                       std::to_integer<std::uint8_t>(section.contents[entryOffset + 1U]))
                   << 8U)
                | (static_cast<std::uint32_t>(
                       std::to_integer<std::uint8_t>(section.contents[entryOffset + 2U]))
                   << 16U)
                | (static_cast<std::uint32_t>(
                       std::to_integer<std::uint8_t>(section.contents[entryOffset + 3U]))
                   << 24U);
            if (rawIndex >= symbolIds.size() || !symbolIds[rawIndex].has_value()) {
                return failure("coff.invalid", "COFF .sxdata handler symbol index is invalid");
            }
            image.coffSafeSehEntries.push_back(CoffSafeSehEntry{
                .section = section.id,
                .symbol = *symbolIds[rawIndex],
                .formatIndex = static_cast<std::uint32_t>(index),
            });
        }
    }

    std::uint32_t relocationIndex = 0;
    for (std::size_t sectionIndex = 0; sectionIndex < layout.sectionCount; ++sectionIndex) {
        const auto& header = headers[sectionIndex];
        if (header.relocationOverflow) {
            image.relocationTableEncodings.push_back(RelocationTableEncoding{
                .section = sectionIds[sectionIndex],
                .coffOverflow = true,
                .declaredCount = header.relocationCount,
            });
        }
        for (std::size_t index = 0; index < header.relocationCount; ++index) {
            const auto entryOffset = static_cast<std::size_t>(header.relocationOffset)
                + (index + (header.relocationOverflow ? 1U : 0U)) * relocationEntrySize;
            const auto offset = reader.u32(entryOffset);
            const auto symbolIndexValue = reader.u32(entryOffset + 4);
            const auto rawType = reader.u16(entryOffset + 8);
            if (!offset || !symbolIndexValue || !rawType) {
                return failure("coff.truncated", "COFF relocation entry is truncated");
            }
            const auto symbolIndex = static_cast<std::size_t>(*symbolIndexValue);
            if (symbolIndex >= symbolIds.size() || !symbolIds[symbolIndex].has_value()) {
                return failure("coff.invalid", "COFF relocation symbol index is invalid");
            }
            std::int64_t addend = 0;
            if (detection.architecture == Architecture::X86) {
                const auto semantics = binobf::detail::x86_fixup_semantics(
                    BinaryFormat::COFF, *rawType);
                if (semantics.has_value()) {
                    const auto byteCount = static_cast<std::size_t>(
                        semantics.value().bitWidth / 8U);
                    const auto& contents = image.sections[sectionIndex].contents;
                    if (*offset > contents.size() || byteCount > contents.size() - *offset) {
                        return failure("coff.invalid", "COFF relocation field is out of range");
                    }
                    const auto decoded = binobf::detail::decode_x86_fixup(
                        semantics.value(),
                        std::span<const std::byte>{contents}.subspan(*offset, byteCount));
                    if (!decoded.has_value()) {
                        return failure("coff.invalid", decoded.error().message);
                    }
                    addend = decoded.value();
                }
            }
            image.relocations.push_back(Relocation{
                .id = ids.allocate(),
                .formatIndex = relocationIndex++,
                .formatTableIndex = static_cast<std::uint32_t>(sectionIndex + 1),
                .section = sectionIds[sectionIndex],
                .offset = *offset,
                .kind = relocation_kind(detection.architecture, *rawType),
                .rawType = *rawType,
                .targetSymbol = symbolIds[symbolIndex],
                .addend = addend,
                .lineage = {},
            });
        }
    }
    return Result<BinaryImage, Diagnostic>::success(std::move(image));
}

} // namespace binobf::formats::detail

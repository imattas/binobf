#include "../object_parser_internal.hpp"

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
constexpr std::size_t sectionHeaderSize = 40;
constexpr std::size_t symbolEntrySize = 18;
constexpr std::size_t relocationEntrySize = 10;
constexpr std::size_t maximumSectionCount = 16'384;
constexpr std::size_t maximumSymbolCount = 1'000'000;

struct CoffSectionHeader {
    std::array<std::byte, 8> encodedName{};
    std::uint32_t virtualSize{0};
    std::uint32_t rawSize{0};
    std::uint32_t rawOffset{0};
    std::uint32_t relocationOffset{0};
    std::uint16_t relocationCount{0};
    std::uint32_t characteristics{0};
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
    std::int16_t sectionNumber) -> SymbolKind {
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
        if (rawType == 0x0006) return RelocationKind::Absolute;
        if (rawType == 0x0007) return RelocationKind::ImageRelative;
        if (rawType == 0x0014) return RelocationKind::PcRelative;
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
    header.relocationCount = *relocationCount;
    header.characteristics = *characteristics;
    return header;
}

} // namespace

auto parse_coff_object(std::span<const std::byte> bytes, const DetectionResult& detection)
    -> Result<BinaryImage, Diagnostic> {
    const ByteReader reader{bytes};
    const auto sectionCountValue = reader.u16(2);
    const auto symbolOffsetValue = reader.u32(8);
    const auto symbolCountValue = reader.u32(12);
    const auto optionalHeaderSize = reader.u16(16);
    const auto characteristics = reader.u16(18);
    if (!sectionCountValue || !symbolOffsetValue || !symbolCountValue || !optionalHeaderSize
        || !characteristics) {
        return failure("coff.truncated", "COFF header is truncated");
    }
    if (*optionalHeaderSize != 0) {
        return failure("coff.invalid", "COFF object has an unexpected optional header");
    }
    const auto sectionCount = static_cast<std::size_t>(*sectionCountValue);
    if (sectionCount == 0 || sectionCount > maximumSectionCount) {
        return failure("coff.invalid", "COFF section count is invalid");
    }
    const auto sectionTableSize = checked_multiply(sectionCount, sectionHeaderSize);
    if (!sectionTableSize || !contains_range(coffHeaderSize, *sectionTableSize, reader.size())) {
        return failure("coff.truncated", "COFF section table is truncated");
    }

    const auto symbolCount = static_cast<std::size_t>(*symbolCountValue);
    if (symbolCount > maximumSymbolCount) {
        return failure("coff.invalid", "COFF symbol count exceeds the entry limit");
    }
    std::optional<std::span<const std::byte>> stringTable;
    std::size_t symbolOffset = 0;
    if (symbolCount != 0 || *symbolOffsetValue != 0) {
        symbolOffset = static_cast<std::size_t>(*symbolOffsetValue);
        const auto symbolTableSize = checked_multiply(symbolCount, symbolEntrySize);
        if (!symbolTableSize || !contains_range(symbolOffset, *symbolTableSize, reader.size())) {
            return failure("coff.truncated", "COFF symbol table is truncated");
        }
        const auto stringOffset = checked_add(symbolOffset, *symbolTableSize);
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
    headers.reserve(sectionCount);
    for (std::size_t index = 0; index < sectionCount; ++index) {
        const auto headerOffset = coffHeaderSize + index * sectionHeaderSize;
        const auto header = read_section_header(reader, headerOffset);
        if (!header) {
            return failure("coff.truncated", "COFF section header is truncated");
        }
        if (header->rawSize != 0
            && !contains_range(header->rawOffset, header->rawSize, reader.size())) {
            return failure("coff.truncated", "COFF section contents are truncated");
        }
        const auto relocationSize = checked_multiply(header->relocationCount, relocationEntrySize);
        if (!relocationSize
            || (header->relocationCount != 0
                && !contains_range(header->relocationOffset, *relocationSize, reader.size()))) {
            return failure("coff.truncated", "COFF relocation table is truncated");
        }
        if ((header->characteristics & 0x01000000U) != 0) {
            return failure("coff.unsupported", "COFF relocation-overflow encoding is unsupported");
        }
        headers.push_back(*header);
    }

    BinaryImage image;
    image.format = BinaryFormat::COFF;
    image.type = BinaryType::RelocatableObject;
    image.architecture = detection.architecture;
    image.objectMetadata.characteristics = *characteristics;
    EntityIdAllocator ids;
    std::vector<EntityId> sectionIds;
    sectionIds.reserve(sectionCount);
    for (std::size_t index = 0; index < sectionCount; ++index) {
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

    std::vector<std::optional<EntityId>> symbolIds(symbolCount);
    for (std::size_t index = 0; index < symbolCount;) {
        const auto entryOffset = symbolOffset + index * symbolEntrySize;
        const auto name = resolve_symbol_name(reader, entryOffset, stringTable);
        const auto value = reader.u32(entryOffset + 8);
        const auto sectionNumber = reader.i16(entryOffset + 12);
        const auto type = reader.u16(entryOffset + 14);
        const auto storageClass = reader.u8(entryOffset + 16);
        const auto auxiliaryCount = reader.u8(entryOffset + 17);
        if (!name || !value || !sectionNumber || !type || !storageClass || !auxiliaryCount) {
            return failure("coff.invalid", "COFF symbol entry is invalid");
        }
        const auto recordCount = std::size_t{1} + *auxiliaryCount;
        if (recordCount > symbolCount - index) {
            return failure("coff.invalid", "COFF auxiliary symbol count exceeds the table");
        }
        std::vector<std::byte> auxiliaryData;
        if (*auxiliaryCount != 0) {
            const auto auxiliarySize = checked_multiply(*auxiliaryCount, symbolEntrySize);
            const auto auxiliaryOffset = checked_add(entryOffset, symbolEntrySize);
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
        if (*sectionNumber > 0) {
            const auto sectionIndex = static_cast<std::size_t>(*sectionNumber - 1);
            if (sectionIndex >= sectionIds.size()) {
                return failure("coff.invalid", "COFF symbol section index is invalid");
            }
            section = sectionIds[sectionIndex];
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
            .kind = symbol_kind(*name, *type, *storageClass, *sectionNumber),
            .visibility = symbol_visibility(*storageClass),
            .defined = defined,
            .lineage = {},
        });
        index += recordCount;
    }

    std::uint32_t relocationIndex = 0;
    for (std::size_t sectionIndex = 0; sectionIndex < sectionCount; ++sectionIndex) {
        const auto& header = headers[sectionIndex];
        for (std::size_t index = 0; index < header.relocationCount; ++index) {
            const auto entryOffset = static_cast<std::size_t>(header.relocationOffset)
                + index * relocationEntrySize;
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
            image.relocations.push_back(Relocation{
                .id = ids.allocate(),
                .formatIndex = relocationIndex++,
                .formatTableIndex = static_cast<std::uint32_t>(sectionIndex + 1),
                .section = sectionIds[sectionIndex],
                .offset = *offset,
                .kind = relocation_kind(detection.architecture, *rawType),
                .rawType = *rawType,
                .targetSymbol = symbolIds[symbolIndex],
                .addend = 0,
                .lineage = {},
            });
        }
    }
    return Result<BinaryImage, Diagnostic>::success(std::move(image));
}

} // namespace binobf::formats::detail

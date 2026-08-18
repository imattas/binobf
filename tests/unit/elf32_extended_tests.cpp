#include "../test_support.hpp"

#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

void put_u32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        bytes.at(offset + index) = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

void put_i32(std::vector<std::byte>& bytes, std::size_t offset, std::int32_t value) {
    put_u32(bytes, offset, std::bit_cast<std::uint32_t>(value));
}

auto read_u16(const std::vector<std::byte>& bytes, std::size_t offset) -> std::uint16_t {
    return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes.at(offset)))
        | static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes.at(offset + 1U)))
            << 8U);
}

auto read_u32(const std::vector<std::byte>& bytes, std::size_t offset) -> std::uint32_t {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(
            std::to_integer<std::uint8_t>(bytes.at(offset + index)))
            << static_cast<unsigned int>(index * 8U);
    }
    return value;
}

auto make_section(
    std::uint64_t id,
    std::uint32_t index,
    std::uint64_t type,
    std::string name,
    std::uint64_t flags = 0,
    std::uint64_t alignment = 1) -> binobf::Section {
    return binobf::Section{
        .id = binobf::EntityId{id},
        .formatIndex = index,
        .formatType = type,
        .formatFlags = flags,
        .formatLink = 0,
        .formatInfo = 0,
        .formatEntrySize = 0,
        .isSectionNameTable = false,
        .name = std::move(name),
        .kind = type == 3 ? binobf::SectionKind::StringTable
            : type == 2 ? binobf::SectionKind::SymbolTable
            : type == 9 || type == 4 ? binobf::SectionKind::Relocation
            : (flags & 4U) != 0 ? binobf::SectionKind::Code
            : binobf::SectionKind::Metadata,
        .address = {},
        .logicalSize = 0,
        .alignment = alignment,
        .readable = (flags & 2U) != 0,
        .writable = (flags & 1U) != 0,
        .executable = (flags & 4U) != 0,
        .contents = {},
        .lineage = {},
    };
}

auto make_symbol(
    std::uint64_t id,
    std::uint32_t index,
    std::string name,
    std::uint32_t type,
    std::uint8_t binding,
    std::int32_t rawSection,
    std::optional<binobf::EntityId> section) -> binobf::Symbol {
    return binobf::Symbol{
        .id = binobf::EntityId{id},
        .formatIndex = index,
        .formatTableIndex = 4,
        .formatType = type,
        .formatStorage = binding,
        .formatOther = 0,
        .formatSectionIndex = rawSection,
        .auxiliaryData = {},
        .name = std::move(name),
        .section = section,
        .address = {},
        .size = 0,
        .kind = type == 2 ? binobf::SymbolKind::Function
            : type == 3 ? binobf::SymbolKind::Section
            : type == 6 ? binobf::SymbolKind::Tls
            : binobf::SymbolKind::Object,
        .visibility = binding == 0
            ? binobf::SymbolVisibility::Local
            : binobf::SymbolVisibility::External,
        .defined = rawSection != 0,
        .definition = section.has_value()
            ? std::optional{binobf::SymbolDefinitionKind::SectionRelative}
            : std::optional{binobf::SymbolDefinitionKind::Undefined},
        .commonAlignment = 0,
        .tlsModel = type == 6 ? binobf::TlsModel::Unknown : binobf::TlsModel::None,
        .lineage = {},
    };
}

auto extended_image() -> binobf::BinaryImage {
    binobf::BinaryImage image;
    image.format = binobf::BinaryFormat::ELF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86;
    image.objectMetadata.elfExtendedSectionCount = true;
    image.objectMetadata.elfExtendedSectionNameIndex = true;

    auto text = make_section(1, 1, 1, ".text", 6, 4);
    text.contents.resize(24, std::byte{0});
    text.logicalSize = text.contents.size();
    for (std::size_t index = 0; index < 5; ++index) {
        put_i32(text.contents, index * 4U, -static_cast<std::int32_t>(index + 1U));
    }
    auto tls = make_section(2, 2, 1, ".tdata", 0x403, 4);
    tls.contents.resize(4, std::byte{0});
    tls.logicalSize = tls.contents.size();
    auto strings = make_section(3, 3, 3, ".strtab");
    auto symbols = make_section(4, 4, 2, ".symtab", 0, 4);
    symbols.formatLink = 3;
    symbols.formatInfo = 2;
    symbols.formatEntrySize = 16;
    auto sectionNames = make_section(5, 5, 3, ".shstrtab");
    sectionNames.isSectionNameTable = true;
    auto rel = make_section(6, 6, 9, ".rel.text", 0, 4);
    rel.formatLink = 4;
    rel.formatInfo = 1;
    rel.formatEntrySize = 8;
    auto rela = make_section(7, 7, 4, ".rela.text", 0, 4);
    rela.formatLink = 4;
    rela.formatInfo = 1;
    rela.formatEntrySize = 12;
    auto group = make_section(8, 8, 17, ".group", 0, 4);
    group.formatLink = 4;
    group.formatInfo = 1;
    group.formatEntrySize = 4;
    group.contents.resize(12, std::byte{0});
    put_u32(group.contents, 0, 5U);
    group.logicalSize = group.contents.size();
    auto indices = make_section(9, 9, 18, ".symtab_shndx", 0, 4);
    indices.formatLink = 4;
    indices.formatEntrySize = 4;
    indices.contents.resize(20, std::byte{0});
    indices.logicalSize = indices.contents.size();
    image.sections = {
        std::move(text), std::move(tls), std::move(strings), std::move(symbols),
        std::move(sectionNames), std::move(rel), std::move(rela), std::move(group),
        std::move(indices),
    };

    image.symbols.push_back(make_symbol(
        20, 1, "group_signature", 3, 0, 1, binobf::EntityId{1}));
    image.symbols.push_back(make_symbol(
        21, 2, "extended_function", 2, 1, 0xffff, binobf::EntityId{1}));
    auto common = make_symbol(22, 3, "common_buffer", 1, 1, 0xfff2, std::nullopt);
    common.defined = true;
    common.definition = binobf::SymbolDefinitionKind::Common;
    common.address.value = 16;
    common.size = 32;
    common.commonAlignment = 16;
    image.symbols.push_back(std::move(common));
    image.symbols.push_back(make_symbol(
        23, 4, "tls_value", 6, 1, 2, binobf::EntityId{2}));

    image.extendedSectionIndices.push_back(binobf::ExtendedSectionIndex{
        .symbol = binobf::EntityId{21},
        .indexSection = binobf::EntityId{9},
        .section = binobf::EntityId{1},
        .rawSectionIndex = 1,
    });
    image.sectionAssociations.push_back(binobf::SectionAssociation{
        .section = binobf::EntityId{8},
        .kind = binobf::SectionAssociationKind::ElfGroup,
        .coffSelection = binobf::CoffComdatSelection::None,
        .signatureSymbol = binobf::EntityId{20},
        .parentSection = std::nullopt,
        .members = {binobf::EntityId{1}, binobf::EntityId{2}},
    });

    constexpr std::array<std::uint64_t, 5> relTypes{3, 4, 9, 10, 18};
    for (std::size_t index = 0; index < relTypes.size(); ++index) {
        image.relocations.push_back(binobf::Relocation{
            .id = binobf::EntityId{100U + index},
            .formatIndex = static_cast<std::uint32_t>(index),
            .formatTableIndex = 6,
            .section = binobf::EntityId{1},
            .offset = index * 4U,
            .kind = relTypes[index] == 4 || relTypes[index] == 10
                ? binobf::RelocationKind::PcRelative
                : binobf::RelocationKind::ArchitectureSpecific,
            .rawType = relTypes[index],
            .targetSymbol = relTypes[index] == 18
                ? std::optional{binobf::EntityId{23}}
                : std::optional{binobf::EntityId{21}},
            .addend = -static_cast<std::int64_t>(index + 1U),
            .lineage = {},
        });
    }
    image.relocations.push_back(binobf::Relocation{
        .id = binobf::EntityId{110},
        .formatIndex = 0,
        .formatTableIndex = 7,
        .section = binobf::EntityId{1},
        .offset = 20,
        .kind = binobf::RelocationKind::Absolute,
        .rawType = 1,
        .targetSymbol = binobf::EntityId{22},
        .addend = -7,
        .lineage = {},
    });
    return image;
}

auto write_extended() -> std::vector<std::byte> {
    const auto written = binobf::write_object(extended_image());
    if (!written.has_value()) {
        throw std::runtime_error(written.error().code + ": " + written.error().message);
    }
    return written.value();
}

auto find_symbol(const binobf::BinaryImage& image, std::string_view name)
    -> const binobf::Symbol& {
    for (const auto& symbol : image.symbols) {
        if (symbol.name == name) return symbol;
    }
    throw std::runtime_error("missing symbol");
}

} // namespace

TEST_CASE(elf32_extended_metadata_groups_symbols_and_relocations_round_trip) {
    const auto bytes = write_extended();
    REQUIRE_EQ(read_u16(bytes, 48), std::uint16_t{0});
    REQUIRE_EQ(read_u16(bytes, 50), std::uint16_t{0xffff});
    const auto sectionTableOffset = read_u32(bytes, 32);
    REQUIRE_EQ(read_u32(bytes, sectionTableOffset + 20U), std::uint32_t{10});
    REQUIRE_EQ(read_u32(bytes, sectionTableOffset + 24U), std::uint32_t{5});

    const auto parsed = binobf::parse_object(bytes, "extended-i386.o");
    REQUIRE(parsed.has_value());
    REQUIRE(parsed.value().objectMetadata.elfExtendedSectionCount);
    REQUIRE(parsed.value().objectMetadata.elfExtendedSectionNameIndex);
    REQUIRE_EQ(parsed.value().extendedSectionIndices.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().sectionAssociations.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().sectionAssociations[0].members.size(), std::size_t{2});
    REQUIRE_EQ(find_symbol(parsed.value(), "common_buffer").commonAlignment, UINT64_C(16));
    REQUIRE_EQ(find_symbol(parsed.value(), "common_buffer").size, UINT64_C(32));
    REQUIRE_EQ(find_symbol(parsed.value(), "tls_value").tlsModel,
               binobf::TlsModel::GeneralDynamic);
    REQUIRE_EQ(parsed.value().relocations.size(), std::size_t{6});
    constexpr std::array<std::uint64_t, 6> expectedTypes{3, 4, 9, 10, 18, 1};
    for (std::size_t index = 0; index < 5; ++index) {
        REQUIRE_EQ(parsed.value().relocations[index].rawType, expectedTypes[index]);
        REQUIRE_EQ(parsed.value().relocations[index].addend,
                   -static_cast<std::int64_t>(index + 1U));
    }
    REQUIRE_EQ(parsed.value().relocations.back().rawType, expectedTypes.back());
    REQUIRE_EQ(parsed.value().relocations.back().addend, INT64_C(-7));

    const auto symtabHeader = sectionTableOffset + 4U * 40U;
    REQUIRE_EQ(read_u32(bytes, symtabHeader + 28U), std::uint32_t{2});
    const auto groupDataOffset = read_u32(bytes, sectionTableOffset + 8U * 40U + 16U);
    REQUIRE_EQ(read_u32(bytes, groupDataOffset), std::uint32_t{5});

    const auto rewritten = binobf::write_object(parsed.value());
    REQUIRE(rewritten.has_value());
    REQUIRE_EQ(rewritten.value(), bytes);
    REQUIRE_EQ(read_u16(rewritten.value(), 48), std::uint16_t{0});
    REQUIRE_EQ(read_u16(rewritten.value(), 50), std::uint16_t{0xffff});
    const auto reparsed = binobf::parse_object(rewritten.value(), "rewritten-i386.o");
    REQUIRE(reparsed.has_value());
    REQUIRE_EQ(reparsed.value().extendedSectionIndices.size(), std::size_t{1});
    REQUIRE_EQ(reparsed.value().sectionAssociations.size(), std::size_t{1});
    REQUIRE_EQ(reparsed.value().relocations.size(), std::size_t{6});
}

TEST_CASE(elf32_extended_symbol_indices_require_one_valid_companion) {
    const auto bytes = write_extended();
    const auto sectionTableOffset = read_u32(bytes, 32);

    auto missingCompanion = bytes;
    put_u32(missingCompanion, sectionTableOffset + 9U * 40U + 4U, 1U);
    const auto missing = binobf::parse_object(missingCompanion, "missing-shndx.o");
    REQUIRE(!missing.has_value());
    REQUIRE_EQ(missing.error().code, "elf.invalid");

    auto outOfRange = bytes;
    const auto indexDataOffset = read_u32(outOfRange, sectionTableOffset + 9U * 40U + 16U);
    put_u32(outOfRange, indexDataOffset + 2U * 4U, 99U);
    const auto invalid = binobf::parse_object(outOfRange, "bad-shndx.o");
    REQUIRE(!invalid.has_value());
    REQUIRE_EQ(invalid.error().code, "elf.invalid");

    auto duplicateCompanion = bytes;
    put_u32(duplicateCompanion, sectionTableOffset + 8U * 40U + 4U, 18U);
    const auto duplicate =
        binobf::parse_object(duplicateCompanion, "duplicate-shndx.o");
    REQUIRE(!duplicate.has_value());
    REQUIRE_EQ(duplicate.error().code, "elf.invalid");
}

TEST_CASE(elf32_groups_reject_out_of_range_members) {
    auto bytes = write_extended();
    const auto sectionTableOffset = read_u32(bytes, 32);
    const auto groupDataOffset = read_u32(bytes, sectionTableOffset + 8U * 40U + 16U);
    put_u32(bytes, groupDataOffset + 4U, 99U);
    const auto parsed = binobf::parse_object(bytes, "bad-group.o");
    REQUIRE(!parsed.has_value());
    REQUIRE_EQ(parsed.error().code, "elf.invalid");
}

TEST_CASE(elf32_extended_section_zero_must_be_complete) {
    auto bytes = write_extended();
    const auto sectionTableOffset = read_u32(bytes, 32);
    bytes.resize(sectionTableOffset + 20U);
    const auto parsed = binobf::parse_object(bytes, "truncated-section-zero.o");
    REQUIRE(!parsed.has_value());
    REQUIRE_EQ(parsed.error().code, "elf.truncated");
}

int main() {
    return binobf::test::run_all();
}

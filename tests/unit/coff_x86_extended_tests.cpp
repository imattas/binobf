#include "../test_support.hpp"

#include <binobf/formats/detector.hpp>
#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr std::uint32_t codeFlags = 0x60500020U;
constexpr std::uint32_t dataFlags = 0x40300040U;
constexpr std::uint32_t relocationOverflowFlag = 0x01000000U;

void put_u16(std::vector<std::byte>& bytes, std::size_t offset, std::uint16_t value) {
    bytes.at(offset) = static_cast<std::byte>(value & 0xffU);
    bytes.at(offset + 1U) = static_cast<std::byte>((value >> 8U) & 0xffU);
}

void put_u32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        bytes.at(offset + index) = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

auto read_u32(const std::vector<std::byte>& bytes, std::size_t offset) -> std::uint32_t {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(
            bytes.at(offset + index))) << static_cast<unsigned int>(index * 8U);
    }
    return value;
}

auto section(
    std::uint64_t id,
    std::uint32_t index,
    std::string name,
    std::uint32_t flags,
    std::vector<std::byte> contents = {std::byte{0xc3}}) -> binobf::Section {
    return binobf::Section{
        .id = binobf::EntityId{id},
        .formatIndex = index,
        .formatType = 0,
        .formatFlags = flags,
        .formatLink = 0,
        .formatInfo = 0,
        .formatEntrySize = 0,
        .isSectionNameTable = false,
        .name = std::move(name),
        .kind = (flags & 0x20U) != 0
            ? binobf::SectionKind::Code
            : binobf::SectionKind::InitializedData,
        .address = {},
        .logicalSize = contents.size(),
        .alignment = 4,
        .readable = true,
        .writable = false,
        .executable = (flags & 0x20000000U) != 0,
        .contents = std::move(contents),
        .lineage = {},
    };
}

auto defined_symbol(
    std::uint64_t id,
    std::uint32_t rawIndex,
    std::string name,
    binobf::EntityId owner,
    std::int32_t rawSection,
    std::uint16_t type = 0x20,
    std::uint8_t storage = 2,
    std::vector<std::byte> auxiliary = {}) -> binobf::Symbol {
    return binobf::Symbol{
        .id = binobf::EntityId{id},
        .formatIndex = rawIndex,
        .formatTableIndex = 0,
        .formatType = type,
        .formatStorage = storage,
        .formatOther = 0,
        .formatSectionIndex = rawSection,
        .auxiliaryData = std::move(auxiliary),
        .name = std::move(name),
        .section = owner,
        .address = {},
        .size = 0,
        .kind = type == 0x20 ? binobf::SymbolKind::Function : binobf::SymbolKind::Section,
        .visibility = storage == 2
            ? binobf::SymbolVisibility::External
            : binobf::SymbolVisibility::Local,
        .defined = true,
        .definition = binobf::SymbolDefinitionKind::SectionRelative,
        .commonAlignment = 0,
        .tlsModel = binobf::TlsModel::None,
        .lineage = {},
    };
}

auto undefined_symbol(std::uint64_t id, std::uint32_t rawIndex, std::string name)
    -> binobf::Symbol {
    return binobf::Symbol{
        .id = binobf::EntityId{id},
        .formatIndex = rawIndex,
        .formatTableIndex = 0,
        .formatType = 0,
        .formatStorage = 2,
        .formatOther = 0,
        .formatSectionIndex = 0,
        .auxiliaryData = {},
        .name = std::move(name),
        .section = std::nullopt,
        .address = {},
        .size = 0,
        .kind = binobf::SymbolKind::Object,
        .visibility = binobf::SymbolVisibility::External,
        .defined = false,
        .definition = binobf::SymbolDefinitionKind::Undefined,
        .commonAlignment = 0,
        .tlsModel = binobf::TlsModel::None,
        .lineage = {},
    };
}

auto base_image() -> binobf::BinaryImage {
    binobf::BinaryImage image;
    image.format = binobf::BinaryFormat::COFF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86;
    image.sections.push_back(section(1, 1, ".text", codeFlags));
    image.symbols.push_back(defined_symbol(2, 0, "entry", binobf::EntityId{1}, 1));
    return image;
}

auto round_trip(const binobf::BinaryImage& image) -> binobf::BinaryImage {
    const auto written = binobf::write_object(image);
    if (!written.has_value()) {
        throw std::runtime_error(written.error().code + ": " + written.error().message);
    }
    const auto parsed = binobf::parse_object(written.value(), "fixture.obj");
    if (!parsed.has_value()) {
        throw std::runtime_error(parsed.error().code + ": " + parsed.error().message);
    }
    return parsed.value();
}

auto section_aux(
    std::uint8_t selection,
    std::uint32_t parent,
    std::size_t entrySize = 18) -> std::vector<std::byte> {
    std::vector<std::byte> result(entrySize, std::byte{0});
    put_u16(result, 12, static_cast<std::uint16_t>(parent & 0xffffU));
    result[14] = static_cast<std::byte>(selection);
    put_u16(result, 16, static_cast<std::uint16_t>((parent >> 16U) & 0xffffU));
    return result;
}

auto find_symbol(const binobf::BinaryImage& image, std::string_view name)
    -> const binobf::Symbol& {
    for (const auto& symbol : image.symbols) {
        if (symbol.name == name) return symbol;
    }
    throw std::runtime_error("missing symbol");
}

} // namespace

TEST_CASE(coff_x86_bigobj_is_detected_and_round_trips_20_byte_symbols) {
    auto image = base_image();
    image.objectMetadata.coffBigObj = true;
    image.sections[0].name = ".text$very_long_bigobj_section";
    image.symbols.clear();
    std::vector<std::byte> unknownAuxiliary(20, std::byte{0xa5});
    auto file = binobf::Symbol{
        .id = binobf::EntityId{2},
        .formatIndex = 0,
        .formatTableIndex = 0,
        .formatType = 0,
        .formatStorage = 103,
        .formatOther = 0,
        .formatSectionIndex = -2,
        .auxiliaryData = unknownAuxiliary,
        .name = "a_very_long_source_file_name.cpp",
        .section = std::nullopt,
        .address = {},
        .size = 0,
        .kind = binobf::SymbolKind::File,
        .visibility = binobf::SymbolVisibility::Local,
        .defined = true,
        .definition = std::nullopt,
        .commonAlignment = 0,
        .tlsModel = binobf::TlsModel::None,
        .lineage = {},
    };
    image.symbols.push_back(std::move(file));

    const auto written = binobf::write_object(image);
    REQUIRE(written.has_value());
    REQUIRE_EQ(written.value()[0], std::byte{0});
    REQUIRE_EQ(written.value()[1], std::byte{0});
    REQUIRE_EQ(written.value()[2], std::byte{0xff});
    REQUIRE_EQ(written.value()[3], std::byte{0xff});
    const auto detected = binobf::detect_binary(written.value(), "fixture.obj");
    REQUIRE(detected.has_value());
    REQUIRE_EQ(detected.value().format, binobf::BinaryFormat::COFF);
    REQUIRE_EQ(detected.value().architecture, binobf::Architecture::X86);

    const auto parsed = binobf::parse_object(written.value(), "fixture.obj");
    REQUIRE(parsed.has_value());
    REQUIRE(parsed.value().objectMetadata.coffBigObj);
    REQUIRE_EQ(parsed.value().sections[0].name, image.sections[0].name);
    REQUIRE_EQ(parsed.value().symbols[0].name, image.symbols[0].name);
    REQUIRE_EQ(parsed.value().symbols[0].auxiliaryData, unknownAuxiliary);

    auto invalidClassId = written.value();
    invalidClassId[12] ^= std::byte{0xff};
    const auto rejected = binobf::detect_binary(invalidClassId, "invalid-bigobj.obj");
    REQUIRE(!rejected.has_value());
    REQUIRE_EQ(rejected.error().code, "format.invalid");
}

TEST_CASE(coff_x86_bigobj_round_trips_a_section_number_above_int16) {
    binobf::BinaryImage image;
    image.format = binobf::BinaryFormat::COFF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86;
    constexpr std::uint32_t sectionCount = 32'768;
    image.sections.reserve(sectionCount);
    for (std::uint32_t index = 1; index <= sectionCount; ++index) {
        image.sections.push_back(section(
            index, index, ".s" + std::to_string(index), dataFlags, {}));
    }
    image.symbols.push_back(defined_symbol(
        100'000, 0, "high_section", binobf::EntityId{sectionCount},
        static_cast<std::int32_t>(sectionCount), 0, 3));

    const auto parsed = round_trip(image);
    REQUIRE(parsed.objectMetadata.coffBigObj);
    REQUIRE_EQ(parsed.sections.size(), static_cast<std::size_t>(sectionCount));
    REQUIRE_EQ(find_symbol(parsed, "high_section").formatSectionIndex,
               static_cast<std::int32_t>(sectionCount));
}

TEST_CASE(coff_x86_all_defined_relocation_types_round_trip_without_loss) {
    auto image = base_image();
    image.sections[0].contents.resize(44, std::byte{0});
    image.sections[0].logicalSize = 44;
    image.symbols.push_back(undefined_symbol(3, 1, "target"));
    constexpr std::array<std::uint16_t, 11> rawTypes{
        0x0000, 0x0001, 0x0002, 0x0006, 0x0007, 0x0009,
        0x000a, 0x000b, 0x000c, 0x000d, 0x0014,
    };
    for (std::size_t index = 0; index < rawTypes.size(); ++index) {
        image.relocations.push_back(binobf::Relocation{
            .id = binobf::EntityId{10U + index},
            .formatIndex = static_cast<std::uint32_t>(index),
            .formatTableIndex = 1,
            .section = binobf::EntityId{1},
            .offset = static_cast<std::uint64_t>(index * 4U),
            .kind = binobf::RelocationKind::ArchitectureSpecific,
            .rawType = rawTypes[index],
            .targetSymbol = binobf::EntityId{3},
            .addend = 0,
            .lineage = {},
        });
    }

    const auto parsed = round_trip(image);
    REQUIRE_EQ(parsed.relocations.size(), rawTypes.size());
    for (std::size_t index = 0; index < rawTypes.size(); ++index) {
        REQUIRE_EQ(parsed.relocations[index].rawType,
                   static_cast<std::uint64_t>(rawTypes[index]));
        REQUIRE_EQ(parsed.relocations[index].addend, INT64_C(0));
    }
}

TEST_CASE(coff_x86_pc_relative_bias_is_inverse_across_write_and_parse) {
    auto image = base_image();
    image.sections[0].contents.assign(4, std::byte{0xff});
    image.sections[0].logicalSize = image.sections[0].contents.size();
    image.symbols.push_back(undefined_symbol(3, 1, "target"));
    image.relocations.push_back(binobf::Relocation{
        .id = binobf::EntityId{10},
        .formatIndex = 0,
        .formatTableIndex = 1,
        .section = binobf::EntityId{1},
        .offset = 0,
        .kind = binobf::RelocationKind::PcRelative,
        .rawType = 0x0014,
        .targetSymbol = binobf::EntityId{3},
        .addend = -4,
        .lineage = {},
    });

    const auto parsed = round_trip(image);
    REQUIRE_EQ(parsed.relocations.size(), std::size_t{1});
    REQUIRE_EQ(parsed.relocations[0].addend, INT64_C(-4));
    REQUIRE_EQ(parsed.sections[0].contents,
               std::vector<std::byte>(4, std::byte{0}));
}

TEST_CASE(coff_x86_unknown_relocation_round_trips_without_rewriting_its_field) {
    auto image = base_image();
    image.sections[0].contents = {
        std::byte{0x12}, std::byte{0x34}, std::byte{0x56}, std::byte{0x78}};
    image.sections[0].logicalSize = image.sections[0].contents.size();
    image.symbols.push_back(undefined_symbol(3, 1, "vendor_target"));
    image.relocations.push_back(binobf::Relocation{
        .id = binobf::EntityId{10},
        .formatIndex = 0,
        .formatTableIndex = 1,
        .section = binobf::EntityId{1},
        .offset = 0,
        .kind = binobf::RelocationKind::ArchitectureSpecific,
        .rawType = 0x00ff,
        .targetSymbol = binobf::EntityId{3},
        .addend = 0,
        .lineage = {},
    });

    const auto parsed = round_trip(image);
    REQUIRE_EQ(parsed.relocations.size(), std::size_t{1});
    REQUIRE_EQ(parsed.relocations[0].rawType, UINT64_C(0x00ff));
    REQUIRE_EQ(parsed.sections[0].contents, image.sections[0].contents);
}

TEST_CASE(coff_x86_relocation_overflow_round_trips_65536_real_entries) {
    auto image = base_image();
    image.sections[0].contents.resize(4, std::byte{0});
    image.sections[0].logicalSize = image.sections[0].contents.size();
    image.sections[0].formatFlags |= relocationOverflowFlag;
    image.symbols.push_back(undefined_symbol(3, 1, "target"));
    constexpr std::size_t relocationCount = 65'536;
    image.relocations.reserve(relocationCount);
    for (std::size_t index = 0; index < relocationCount; ++index) {
        image.relocations.push_back(binobf::Relocation{
            .id = binobf::EntityId{10U + index},
            .formatIndex = static_cast<std::uint32_t>(index),
            .formatTableIndex = 1,
            .section = binobf::EntityId{1},
            .offset = 0,
            .kind = binobf::RelocationKind::PcRelative,
            .rawType = 0x0014,
            .targetSymbol = binobf::EntityId{3},
            .addend = 0,
            .lineage = {},
        });
    }
    image.relocationTableEncodings.push_back(binobf::RelocationTableEncoding{
        .section = binobf::EntityId{1},
        .coffOverflow = true,
        .declaredCount = relocationCount,
    });

    const auto parsed = round_trip(image);
    REQUIRE_EQ(parsed.relocations.size(), relocationCount);
    REQUIRE_EQ(parsed.relocationTableEncodings.size(), std::size_t{1});
    REQUIRE(parsed.relocationTableEncodings[0].coffOverflow);
    REQUIRE_EQ(parsed.relocationTableEncodings[0].declaredCount,
               static_cast<std::uint64_t>(relocationCount));

    const auto written = binobf::write_object(image);
    REQUIRE(written.has_value());
    auto malformed = written.value();
    const auto relocationOffset = read_u32(malformed, 20U + 24U);
    malformed.at(relocationOffset) = std::byte{0};
    malformed.at(relocationOffset + 1U) = std::byte{0};
    malformed.at(relocationOffset + 2U) = std::byte{0};
    malformed.at(relocationOffset + 3U) = std::byte{0};
    const auto rejected = binobf::parse_object(malformed, "bad-overflow.obj");
    REQUIRE(!rejected.has_value());
    REQUIRE_EQ(rejected.error().code, "coff.invalid");

    auto oversized = written.value();
    put_u32(oversized, relocationOffset, 4'000'002U);
    const auto limited = binobf::parse_object(oversized, "oversized-overflow.obj");
    REQUIRE(!limited.has_value());
    REQUIRE_EQ(limited.error().code, "coff.invalid");
    REQUIRE(limited.error().message.find("parser limit") != std::string::npos);
}

TEST_CASE(coff_x86_all_primary_comdat_selections_round_trip) {
    constexpr std::array selections{
        std::pair{binobf::CoffComdatSelection::NoDuplicates, std::uint8_t{1}},
        std::pair{binobf::CoffComdatSelection::Any, std::uint8_t{2}},
        std::pair{binobf::CoffComdatSelection::SameSize, std::uint8_t{3}},
        std::pair{binobf::CoffComdatSelection::ExactMatch, std::uint8_t{4}},
        std::pair{binobf::CoffComdatSelection::Largest, std::uint8_t{6}},
        std::pair{binobf::CoffComdatSelection::Newest, std::uint8_t{7}},
    };
    for (const auto& [selection, raw] : selections) {
        auto image = base_image();
        image.sections[0].formatFlags |= 0x00001000U;
        image.symbols[0] = defined_symbol(
            2, 0, ".text", binobf::EntityId{1}, 1, 0, 3, section_aux(raw, 0));
        image.sectionAssociations.push_back(binobf::SectionAssociation{
            .section = binobf::EntityId{1},
            .kind = binobf::SectionAssociationKind::CoffComdat,
            .coffSelection = selection,
            .signatureSymbol = binobf::EntityId{2},
            .parentSection = std::nullopt,
            .members = {},
        });

        const auto parsed = round_trip(image);
        REQUIRE_EQ(parsed.sectionAssociations.size(), std::size_t{1});
        REQUIRE_EQ(parsed.sectionAssociations[0].coffSelection, selection);
    }
}

TEST_CASE(coff_x86_common_symbols_preserve_allocation_size_and_alignment) {
    auto image = base_image();
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{3},
        .formatIndex = 1,
        .formatTableIndex = 0,
        .formatType = 0,
        .formatStorage = 2,
        .formatOther = 0,
        .formatSectionIndex = 0,
        .auxiliaryData = {},
        .name = "common_buffer",
        .section = std::nullopt,
        .address = binobf::BinaryAddress{16, binobf::AddressKind::RelativeVirtual},
        .size = 16,
        .kind = binobf::SymbolKind::Object,
        .visibility = binobf::SymbolVisibility::External,
        .defined = true,
        .definition = binobf::SymbolDefinitionKind::Common,
        .commonAlignment = 1,
        .tlsModel = binobf::TlsModel::None,
        .lineage = {},
    });

    const auto parsed = round_trip(image);
    const auto& common = find_symbol(parsed, "common_buffer");
    REQUIRE_EQ(common.definition, binobf::SymbolDefinitionKind::Common);
    REQUIRE_EQ(common.address.value, UINT64_C(16));
    REQUIRE_EQ(common.commonAlignment, UINT64_C(1));
}

TEST_CASE(coff_x86_comdat_association_and_safeseh_indices_are_repaired) {
    auto image = base_image();
    image.sections[0].formatFlags |= 0x00001000U;
    image.sections.push_back(section(3, 2, ".text$child", codeFlags));
    image.sections[1].formatFlags |= 0x00001000U;
    image.sections.push_back(section(4, 3, ".sxdata", dataFlags,
                                     std::vector<std::byte>(4, std::byte{0})));
    image.symbols.clear();
    image.symbols.push_back(defined_symbol(
        10, 0, ".text", binobf::EntityId{1}, 1, 0, 3, section_aux(2, 0)));
    image.symbols.push_back(defined_symbol(
        11, 2, ".text$child", binobf::EntityId{3}, 2, 0, 3, section_aux(5, 1)));
    image.symbols.push_back(defined_symbol(
        12, 4, "handler", binobf::EntityId{1}, 1));
    image.sectionAssociations = {
        binobf::SectionAssociation{
            .section = binobf::EntityId{1},
            .kind = binobf::SectionAssociationKind::CoffComdat,
            .coffSelection = binobf::CoffComdatSelection::Any,
            .signatureSymbol = binobf::EntityId{10},
            .parentSection = std::nullopt,
            .members = {},
        },
        binobf::SectionAssociation{
            .section = binobf::EntityId{3},
            .kind = binobf::SectionAssociationKind::CoffAssociativeComdat,
            .coffSelection = binobf::CoffComdatSelection::Associative,
            .signatureSymbol = binobf::EntityId{11},
            .parentSection = binobf::EntityId{1},
            .members = {},
        },
    };
    image.coffSafeSehEntries.push_back(binobf::CoffSafeSehEntry{
        .section = binobf::EntityId{4},
        .symbol = binobf::EntityId{12},
        .formatIndex = 0,
    });

    const auto parsed = round_trip(image);
    REQUIRE_EQ(parsed.sectionAssociations.size(), std::size_t{2});
    REQUIRE_EQ(parsed.sectionAssociations[0].coffSelection,
               binobf::CoffComdatSelection::Any);
    REQUIRE_EQ(parsed.sectionAssociations[1].kind,
               binobf::SectionAssociationKind::CoffAssociativeComdat);
    REQUIRE_EQ(parsed.sectionAssociations[1].parentSection,
               parsed.sectionAssociations[0].section);
    REQUIRE_EQ(parsed.coffSafeSehEntries.size(), std::size_t{1});
    REQUIRE_EQ(find_symbol(parsed, "handler").id,
               parsed.coffSafeSehEntries[0].symbol);

    const auto written = binobf::write_object(image);
    REQUIRE(written.has_value());
    const auto symbolTableOffset = read_u32(written.value(), 8U);

    auto invalidAssociation = written.value();
    constexpr std::size_t childAuxiliaryRawIndex = 3;
    put_u16(invalidAssociation,
            symbolTableOffset + childAuxiliaryRawIndex * 18U + 12U, 99U);
    const auto rejectedAssociation =
        binobf::parse_object(invalidAssociation, "bad-association.obj");
    REQUIRE(!rejectedAssociation.has_value());
    REQUIRE_EQ(rejectedAssociation.error().code, "coff.invalid");

    auto invalidSafeSeh = written.value();
    constexpr std::size_t safeSehSectionHeader = 20U + 2U * 40U;
    const auto safeSehDataOffset = read_u32(invalidSafeSeh, safeSehSectionHeader + 20U);
    put_u32(invalidSafeSeh, safeSehDataOffset, 99U);
    const auto rejectedSafeSeh =
        binobf::parse_object(invalidSafeSeh, "bad-safeseh-index.obj");
    REQUIRE(!rejectedSafeSeh.has_value());
    REQUIRE_EQ(rejectedSafeSeh.error().code, "coff.invalid");
}

int main() {
    return binobf::test::run_all();
}

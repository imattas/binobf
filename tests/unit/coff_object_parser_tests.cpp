#include "../test_support.hpp"

#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace {

struct CoffFixture {
    std::vector<std::byte> bytes;
    std::size_t firstSectionHeader{20};
    std::size_t relocationOffset{0};
    std::size_t symbolOffset{0};
    std::size_t stringTableOffset{0};
};

void put_u16(std::vector<std::byte>& bytes, std::size_t offset, std::uint16_t value) {
    bytes.at(offset) = static_cast<std::byte>(value & 0xffU);
    bytes.at(offset + 1) = static_cast<std::byte>((value >> 8U) & 0xffU);
}

void put_i16(std::vector<std::byte>& bytes, std::size_t offset, std::int16_t value) {
    put_u16(bytes, offset, static_cast<std::uint16_t>(value));
}

void put_u32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        bytes.at(offset + index) = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

void put_name(std::vector<std::byte>& bytes, std::size_t offset, std::string_view name) {
    for (std::size_t index = 0; index < 8; ++index) {
        bytes.at(offset + index) = index < name.size()
            ? static_cast<std::byte>(name[index])
            : std::byte{0};
    }
}

auto make_coff_object() -> CoffFixture {
    CoffFixture fixture;
    constexpr std::size_t sectionTableSize = 2 * 40;
    constexpr std::size_t textOffset = 20 + sectionTableSize;
    constexpr std::size_t dataOffset = textOffset + 4;
    fixture.relocationOffset = dataOffset + 4;
    fixture.symbolOffset = fixture.relocationOffset + 10;
    fixture.stringTableOffset = fixture.symbolOffset + 3 * 18;
    fixture.bytes.resize(fixture.stringTableOffset + 26);
    auto& bytes = fixture.bytes;

    put_u16(bytes, 0, 0x8664);
    put_u16(bytes, 2, 2);
    put_u32(bytes, 8, static_cast<std::uint32_t>(fixture.symbolOffset));
    put_u32(bytes, 12, 3);
    put_u16(bytes, 16, 0);

    put_name(bytes, 20, ".text");
    put_u32(bytes, 20 + 16, 4);
    put_u32(bytes, 20 + 20, static_cast<std::uint32_t>(textOffset));
    put_u32(bytes, 20 + 24, static_cast<std::uint32_t>(fixture.relocationOffset));
    put_u16(bytes, 20 + 32, 1);
    put_u32(bytes, 20 + 36, 0x60500020U);

    put_name(bytes, 60, "/16");
    put_u32(bytes, 60 + 16, 4);
    put_u32(bytes, 60 + 20, static_cast<std::uint32_t>(dataOffset));
    put_u32(bytes, 60 + 36, 0xc0300040U);

    bytes[textOffset] = std::byte{0x90};
    bytes[textOffset + 1] = std::byte{0x90};
    bytes[textOffset + 2] = std::byte{0x90};
    bytes[textOffset + 3] = std::byte{0x90};
    bytes[dataOffset] = std::byte{1};
    bytes[dataOffset + 1] = std::byte{2};
    bytes[dataOffset + 2] = std::byte{3};
    bytes[dataOffset + 3] = std::byte{4};

    put_u32(bytes, fixture.relocationOffset, 0);
    put_u32(bytes, fixture.relocationOffset + 4, 2);
    put_u16(bytes, fixture.relocationOffset + 8, 0x0004);

    put_u32(bytes, fixture.symbolOffset, 0);
    put_u32(bytes, fixture.symbolOffset + 4, 4);
    put_u32(bytes, fixture.symbolOffset + 8, 0);
    put_i16(bytes, fixture.symbolOffset + 12, 1);
    put_u16(bytes, fixture.symbolOffset + 14, 0x20);
    bytes[fixture.symbolOffset + 16] = std::byte{2};
    bytes[fixture.symbolOffset + 17] = std::byte{1};
    put_u32(bytes, fixture.symbolOffset + 18 + 4, 4);

    const auto externalOffset = fixture.symbolOffset + 2 * 18;
    put_name(bytes, externalOffset, "external");
    put_i16(bytes, externalOffset + 12, 0);
    put_u16(bytes, externalOffset + 14, 0x20);
    bytes[externalOffset + 16] = std::byte{2};

    put_u32(bytes, fixture.stringTableOffset, 26);
    constexpr char names[] = "fixture_add\0.longdata\0";
    for (std::size_t index = 0; index < sizeof(names) - 1; ++index) {
        bytes[fixture.stringTableOffset + 4 + index] = static_cast<std::byte>(names[index]);
    }
    return fixture;
}

template <typename Entity>
auto find_named(const std::vector<Entity>& entities, std::string_view name) -> const Entity* {
    const auto found = std::find_if(entities.begin(), entities.end(), [name](const auto& entity) {
        return entity.name == name;
    });
    return found == entities.end() ? nullptr : &*found;
}

void require_error(const CoffFixture& fixture, std::string_view code) {
    const auto parsed = binobf::parse_object(fixture.bytes, "broken.obj");
    REQUIRE(!parsed.has_value());
    REQUIRE_EQ(parsed.error().code, code);
}

} // namespace

TEST_CASE(coff_object_normalizes_sections_primary_symbols_and_relocations) {
    const auto fixture = make_coff_object();
    const auto parsed = binobf::parse_object(fixture.bytes, "fixture.obj");
    REQUIRE(parsed.has_value());
    const auto& image = parsed.value();
    REQUIRE_EQ(image.format, binobf::BinaryFormat::COFF);
    REQUIRE_EQ(image.architecture, binobf::Architecture::X86_64);
    REQUIRE_EQ(image.objectMetadata.characteristics, 0U);
    REQUIRE_EQ(image.sections.size(), std::size_t{2});
    REQUIRE_EQ(image.symbols.size(), std::size_t{2});
    REQUIRE_EQ(image.relocations.size(), std::size_t{1});

    const auto* text = find_named(image.sections, ".text");
    const auto* data = find_named(image.sections, ".longdata");
    const auto* function = find_named(image.symbols, "fixture_add");
    const auto* external = find_named(image.symbols, "external");
    REQUIRE(text != nullptr);
    REQUIRE(data != nullptr);
    REQUIRE(function != nullptr);
    REQUIRE(external != nullptr);
    REQUIRE_EQ(text->id, binobf::EntityId{1});
    REQUIRE_EQ(text->kind, binobf::SectionKind::Code);
    REQUIRE_EQ(text->formatType, UINT64_C(0));
    REQUIRE_EQ(text->formatFlags, UINT64_C(0x60500020));
    REQUIRE_EQ(text->alignment, UINT64_C(16));
    REQUIRE(text->readable);
    REQUIRE(text->executable);
    REQUIRE(!text->writable);
    REQUIRE_EQ(data->kind, binobf::SectionKind::InitializedData);
    REQUIRE_EQ(data->alignment, UINT64_C(4));
    REQUIRE(data->writable);
    REQUIRE_EQ(function->id, binobf::EntityId{3});
    REQUIRE_EQ(function->formatIndex, 0U);
    REQUIRE_EQ(function->formatTableIndex, 0U);
    REQUIRE_EQ(function->formatType, 0x20U);
    REQUIRE_EQ(function->formatStorage, 2U);
    REQUIRE_EQ(function->formatOther, 0U);
    REQUIRE_EQ(function->formatSectionIndex, 1);
    REQUIRE_EQ(function->auxiliaryData.size(), std::size_t{18});
    REQUIRE_EQ(function->size, UINT64_C(4));
    REQUIRE_EQ(function->kind, binobf::SymbolKind::Function);
    REQUIRE(function->defined);
    REQUIRE_EQ(function->section, std::optional{text->id});
    REQUIRE_EQ(external->formatIndex, 2U);
    REQUIRE(!external->defined);

    const auto& relocation = image.relocations.front();
    REQUIRE_EQ(relocation.id, binobf::EntityId{5});
    REQUIRE_EQ(relocation.section, text->id);
    REQUIRE_EQ(relocation.targetSymbol, std::optional{external->id});
    REQUIRE_EQ(relocation.rawType, UINT64_C(4));
    REQUIRE_EQ(relocation.formatTableIndex, 1U);
    REQUIRE_EQ(relocation.kind, binobf::RelocationKind::PcRelative);
}

TEST_CASE(coff_object_parser_rejects_malformed_ranges_and_indices) {
    auto badRawData = make_coff_object();
    put_u32(badRawData.bytes, badRawData.firstSectionHeader + 20, 0xfffffff0U);
    require_error(badRawData, "coff.truncated");

    auto badRelocations = make_coff_object();
    put_u32(badRelocations.bytes, badRelocations.firstSectionHeader + 24, 0xfffffff0U);
    require_error(badRelocations, "coff.truncated");

    auto badSymbols = make_coff_object();
    put_u32(badSymbols.bytes, 8, 0xfffffff0U);
    require_error(badSymbols, "coff.truncated");

    auto badStringLength = make_coff_object();
    put_u32(badStringLength.bytes, badStringLength.stringTableOffset, 3);
    require_error(badStringLength, "coff.invalid");

    auto badAuxiliaryCount = make_coff_object();
    badAuxiliaryCount.bytes[badAuxiliaryCount.symbolOffset + 17] = std::byte{4};
    require_error(badAuxiliaryCount, "coff.invalid");

    auto relocationToAuxiliary = make_coff_object();
    put_u32(relocationToAuxiliary.bytes, relocationToAuxiliary.relocationOffset + 4, 1);
    require_error(relocationToAuxiliary, "coff.invalid");

    auto badLongName = make_coff_object();
    put_u32(badLongName.bytes, badLongName.symbolOffset + 4, 999);
    require_error(badLongName, "coff.invalid");
}

TEST_CASE(coff_object_round_trip_preserves_long_names_aux_gaps_and_relocations) {
    const auto fixture = make_coff_object();
    const auto parsed = binobf::parse_object(fixture.bytes, "fixture.obj");
    REQUIRE(parsed.has_value());

    const auto first = binobf::write_object(parsed.value());
    REQUIRE(first.has_value());
    const auto second = binobf::write_object(parsed.value());
    REQUIRE(second.has_value());
    REQUIRE_EQ(first.value(), second.value());
    REQUIRE(first.value() != fixture.bytes);

    const auto reparsed = binobf::parse_object(first.value(), "roundtrip.obj");
    REQUIRE(reparsed.has_value());
    REQUIRE_EQ(reparsed.value().sections.size(), std::size_t{2});
    REQUIRE_EQ(reparsed.value().symbols.size(), std::size_t{2});
    REQUIRE_EQ(reparsed.value().relocations.size(), std::size_t{1});
    const auto* data = find_named(reparsed.value().sections, ".longdata");
    const auto* function = find_named(reparsed.value().symbols, "fixture_add");
    const auto* external = find_named(reparsed.value().symbols, "external");
    REQUIRE(data != nullptr);
    REQUIRE(function != nullptr);
    REQUIRE(external != nullptr);
    REQUIRE_EQ(function->formatIndex, 0U);
    REQUIRE_EQ(function->auxiliaryData.size(), std::size_t{18});
    REQUIRE_EQ(external->formatIndex, 2U);
    REQUIRE_EQ(reparsed.value().relocations.front().targetSymbol, std::optional{external->id});
}

TEST_CASE(coff_object_writer_rejects_invalid_auxiliary_record_sizes) {
    const auto fixture = make_coff_object();
    auto parsed = binobf::parse_object(fixture.bytes, "fixture.obj");
    REQUIRE(parsed.has_value());
    parsed.value().symbols.front().auxiliaryData.push_back(std::byte{0});
    const auto output = binobf::write_object(parsed.value());
    REQUIRE(!output.has_value());
    REQUIRE_EQ(output.error().code, "object.model_invalid");
}

int main() {
    return binobf::test::run_all();
}

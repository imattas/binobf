#include "../test_support.hpp"

#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

using namespace std::string_view_literals;

namespace {

struct ElfFixture {
    std::vector<std::byte> bytes;
    std::size_t sectionTableOffset{0};
    std::size_t relocationDataOffset{0};
};

void put_u16(std::vector<std::byte>& bytes, std::size_t offset, std::uint16_t value) {
    bytes.at(offset) = static_cast<std::byte>(value & 0xffU);
    bytes.at(offset + 1) = static_cast<std::byte>((value >> 8U) & 0xffU);
}

void put_u32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        bytes.at(offset + index) = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

void put_u64(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value) {
    for (std::size_t index = 0; index < 8; ++index) {
        bytes.at(offset + index) = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

auto append_bytes(std::vector<std::byte>& bytes, std::string_view value) -> std::size_t {
    const auto offset = bytes.size();
    for (const char character : value) {
        bytes.push_back(static_cast<std::byte>(character));
    }
    return offset;
}

void align_to(std::vector<std::byte>& bytes, std::size_t alignment) {
    while (bytes.size() % alignment != 0) {
        bytes.push_back(std::byte{0});
    }
}

void write_elf64_section(
    std::vector<std::byte>& bytes,
    std::size_t sectionTable,
    std::size_t index,
    std::uint32_t name,
    std::uint32_t type,
    std::uint64_t flags,
    std::uint64_t offset,
    std::uint64_t size,
    std::uint32_t link,
    std::uint32_t info,
    std::uint64_t alignment,
    std::uint64_t entrySize) {
    const auto base = sectionTable + index * 64;
    put_u32(bytes, base, name);
    put_u32(bytes, base + 4, type);
    put_u64(bytes, base + 8, flags);
    put_u64(bytes, base + 24, offset);
    put_u64(bytes, base + 32, size);
    put_u32(bytes, base + 40, link);
    put_u32(bytes, base + 44, info);
    put_u64(bytes, base + 48, alignment);
    put_u64(bytes, base + 56, entrySize);
}

auto make_elf64_object() -> ElfFixture {
    ElfFixture fixture;
    fixture.bytes.resize(64);
    auto& bytes = fixture.bytes;

    const auto textOffset = append_bytes(bytes, "\x55\x48\x89\xe5");
    const auto stringOffset = append_bytes(bytes, "\0fixture_add\0external\0"sv);
    align_to(bytes, 8);
    const auto symbolOffset = bytes.size();
    bytes.resize(bytes.size() + 72);
    put_u32(bytes, symbolOffset + 24, 1);
    bytes[symbolOffset + 28] = std::byte{0x12};
    put_u16(bytes, symbolOffset + 30, 1);
    put_u64(bytes, symbolOffset + 40, 4);
    put_u32(bytes, symbolOffset + 48, 13);
    bytes[symbolOffset + 52] = std::byte{0x12};

    align_to(bytes, 8);
    fixture.relocationDataOffset = bytes.size();
    bytes.resize(bytes.size() + 24);
    put_u64(bytes, fixture.relocationDataOffset, 0);
    put_u64(bytes, fixture.relocationDataOffset + 8, (UINT64_C(2) << 32U) | 2U);
    put_u64(bytes, fixture.relocationDataOffset + 16, UINT64_C(0xfffffffffffffffc));

    const auto sectionStringOffset = append_bytes(
        bytes, "\0.text\0.bss\0.strtab\0.symtab\0.rela.text\0.shstrtab\0"sv);
    align_to(bytes, 8);
    fixture.sectionTableOffset = bytes.size();
    bytes.resize(bytes.size() + 7 * 64);

    bytes[0] = std::byte{0x7f};
    bytes[1] = std::byte{'E'};
    bytes[2] = std::byte{'L'};
    bytes[3] = std::byte{'F'};
    bytes[4] = std::byte{2};
    bytes[5] = std::byte{1};
    bytes[6] = std::byte{1};
    bytes[7] = std::byte{3};
    bytes[8] = std::byte{1};
    put_u16(bytes, 16, 1);
    put_u16(bytes, 18, 62);
    put_u32(bytes, 20, 1);
    put_u32(bytes, 48, 0x1234U);
    put_u64(bytes, 40, fixture.sectionTableOffset);
    put_u16(bytes, 52, 64);
    put_u16(bytes, 58, 64);
    put_u16(bytes, 60, 7);
    put_u16(bytes, 62, 6);

    write_elf64_section(bytes, fixture.sectionTableOffset, 1, 1, 1, 6,
                        textOffset, 4, 0, 0, 1, 0);
    write_elf64_section(bytes, fixture.sectionTableOffset, 2, 7, 8, 3,
                        0, 16, 0, 0, 8, 0);
    write_elf64_section(bytes, fixture.sectionTableOffset, 3, 12, 3, 0,
                        stringOffset, 22, 0, 0, 1, 0);
    write_elf64_section(bytes, fixture.sectionTableOffset, 4, 20, 2, 0,
                        symbolOffset, 72, 3, 1, 8, 24);
    write_elf64_section(bytes, fixture.sectionTableOffset, 5, 28, 4, 0,
                        fixture.relocationDataOffset, 24, 4, 1, 8, 24);
    write_elf64_section(bytes, fixture.sectionTableOffset, 6, 39, 3, 0,
                        sectionStringOffset, 49, 0, 0, 1, 0);
    return fixture;
}

void write_elf32_section(
    std::vector<std::byte>& bytes,
    std::size_t sectionTable,
    std::size_t index,
    std::uint32_t name,
    std::uint32_t type,
    std::uint32_t flags,
    std::uint32_t offset,
    std::uint32_t size,
    std::uint32_t link,
    std::uint32_t info,
    std::uint32_t alignment,
    std::uint32_t entrySize) {
    const auto base = sectionTable + index * 40;
    put_u32(bytes, base, name);
    put_u32(bytes, base + 4, type);
    put_u32(bytes, base + 8, flags);
    put_u32(bytes, base + 16, offset);
    put_u32(bytes, base + 20, size);
    put_u32(bytes, base + 24, link);
    put_u32(bytes, base + 28, info);
    put_u32(bytes, base + 32, alignment);
    put_u32(bytes, base + 36, entrySize);
}

auto make_elf32_object() -> ElfFixture {
    ElfFixture fixture;
    fixture.bytes.resize(52);
    auto& bytes = fixture.bytes;
    const auto textOffset = append_bytes(bytes, "\x90\x90\x90\x90");
    const auto stringOffset = append_bytes(bytes, "\0fixture_add\0external\0"sv);
    align_to(bytes, 4);
    const auto symbolOffset = bytes.size();
    bytes.resize(bytes.size() + 48);
    put_u32(bytes, symbolOffset + 16, 1);
    put_u32(bytes, symbolOffset + 20, 0);
    put_u32(bytes, symbolOffset + 24, 4);
    bytes[symbolOffset + 28] = std::byte{0x12};
    put_u16(bytes, symbolOffset + 30, 1);
    put_u32(bytes, symbolOffset + 32, 13);
    bytes[symbolOffset + 44] = std::byte{0x12};

    align_to(bytes, 4);
    fixture.relocationDataOffset = bytes.size();
    bytes.resize(bytes.size() + 8);
    put_u32(bytes, fixture.relocationDataOffset, 0);
    put_u32(bytes, fixture.relocationDataOffset + 4, (2U << 8U) | 2U);
    const auto sectionStringOffset = append_bytes(
        bytes, "\0.text\0.strtab\0.symtab\0.rel.text\0.shstrtab\0"sv);
    align_to(bytes, 4);
    fixture.sectionTableOffset = bytes.size();
    bytes.resize(bytes.size() + 6 * 40);

    bytes[0] = std::byte{0x7f};
    bytes[1] = std::byte{'E'};
    bytes[2] = std::byte{'L'};
    bytes[3] = std::byte{'F'};
    bytes[4] = std::byte{1};
    bytes[5] = std::byte{1};
    bytes[6] = std::byte{1};
    put_u16(bytes, 16, 1);
    put_u16(bytes, 18, 3);
    put_u32(bytes, 20, 1);
    put_u32(bytes, 32, static_cast<std::uint32_t>(fixture.sectionTableOffset));
    put_u16(bytes, 40, 52);
    put_u16(bytes, 46, 40);
    put_u16(bytes, 48, 6);
    put_u16(bytes, 50, 5);

    write_elf32_section(bytes, fixture.sectionTableOffset, 1, 1, 1, 6,
                        static_cast<std::uint32_t>(textOffset), 4, 0, 0, 1, 0);
    write_elf32_section(bytes, fixture.sectionTableOffset, 2, 7, 3, 0,
                        static_cast<std::uint32_t>(stringOffset), 22, 0, 0, 1, 0);
    write_elf32_section(bytes, fixture.sectionTableOffset, 3, 15, 2, 0,
                        static_cast<std::uint32_t>(symbolOffset), 48, 2, 1, 4, 16);
    write_elf32_section(bytes, fixture.sectionTableOffset, 4, 23, 9, 0,
                        static_cast<std::uint32_t>(fixture.relocationDataOffset), 8,
                        3, 1, 4, 8);
    write_elf32_section(bytes, fixture.sectionTableOffset, 5, 33, 3, 0,
                        static_cast<std::uint32_t>(sectionStringOffset), 43, 0, 0, 1, 0);
    return fixture;
}

template <typename Entity>
auto find_named(const std::vector<Entity>& entities, std::string_view name) -> const Entity* {
    const auto found = std::find_if(entities.begin(), entities.end(), [name](const auto& entity) {
        return entity.name == name;
    });
    return found == entities.end() ? nullptr : &*found;
}

void require_error(const ElfFixture& fixture, std::string_view code) {
    const auto parsed = binobf::parse_object(fixture.bytes, "broken.o");
    REQUIRE(!parsed.has_value());
    REQUIRE_EQ(parsed.error().code, code);
}

} // namespace

TEST_CASE(elf64_object_normalizes_sections_symbols_and_rela) {
    const auto fixture = make_elf64_object();
    const auto parsed = binobf::parse_object(fixture.bytes, "fixture.o");
    REQUIRE(parsed.has_value());
    const auto& image = parsed.value();
    REQUIRE_EQ(image.format, binobf::BinaryFormat::ELF);
    REQUIRE_EQ(image.type, binobf::BinaryType::RelocatableObject);
    REQUIRE_EQ(image.architecture, binobf::Architecture::X86_64);
    REQUIRE_EQ(image.objectMetadata.osAbi, 3U);
    REQUIRE_EQ(image.objectMetadata.abiVersion, 1U);
    REQUIRE_EQ(image.objectMetadata.formatFlags, UINT64_C(0x1234));
    REQUIRE_EQ(image.sections.size(), std::size_t{6});
    REQUIRE_EQ(image.symbols.size(), std::size_t{2});
    REQUIRE_EQ(image.relocations.size(), std::size_t{1});

    const auto* text = find_named(image.sections, ".text");
    const auto* bss = find_named(image.sections, ".bss");
    const auto* symtab = find_named(image.sections, ".symtab");
    const auto* sectionNames = find_named(image.sections, ".shstrtab");
    const auto* function = find_named(image.symbols, "fixture_add");
    const auto* external = find_named(image.symbols, "external");
    REQUIRE(text != nullptr);
    REQUIRE(bss != nullptr);
    REQUIRE(symtab != nullptr);
    REQUIRE(sectionNames != nullptr);
    REQUIRE(function != nullptr);
    REQUIRE(external != nullptr);
    REQUIRE_EQ(text->id, binobf::EntityId{1});
    REQUIRE_EQ(text->kind, binobf::SectionKind::Code);
    REQUIRE_EQ(text->formatType, UINT64_C(1));
    REQUIRE_EQ(text->formatFlags, UINT64_C(6));
    REQUIRE(text->executable);
    REQUIRE_EQ(bss->kind, binobf::SectionKind::UninitializedData);
    REQUIRE_EQ(bss->logicalSize, UINT64_C(16));
    REQUIRE(bss->contents.empty());
    REQUIRE_EQ(symtab->formatLink, 3U);
    REQUIRE_EQ(symtab->formatInfo, 1U);
    REQUIRE_EQ(symtab->formatEntrySize, UINT64_C(24));
    REQUIRE(sectionNames->isSectionNameTable);
    REQUIRE(function->defined);
    REQUIRE_EQ(function->kind, binobf::SymbolKind::Function);
    REQUIRE_EQ(function->formatTableIndex, 4U);
    REQUIRE_EQ(function->formatType, 2U);
    REQUIRE_EQ(function->formatStorage, 1U);
    REQUIRE_EQ(function->formatOther, 0U);
    REQUIRE_EQ(function->formatSectionIndex, 1);
    REQUIRE(function->auxiliaryData.empty());
    REQUIRE_EQ(function->section, std::optional{text->id});
    REQUIRE(!external->defined);
    REQUIRE(!external->section.has_value());

    const auto& relocation = image.relocations.front();
    REQUIRE_EQ(relocation.id, binobf::EntityId{9});
    REQUIRE_EQ(relocation.section, text->id);
    REQUIRE_EQ(relocation.kind, binobf::RelocationKind::PcRelative);
    REQUIRE_EQ(relocation.rawType, UINT64_C(2));
    REQUIRE_EQ(relocation.formatTableIndex, 5U);
    REQUIRE_EQ(relocation.targetSymbol, std::optional{external->id});
    REQUIRE_EQ(relocation.addend, INT64_C(-4));
}

TEST_CASE(elf32_rel_entries_have_implicit_zero_addends) {
    const auto fixture = make_elf32_object();
    const auto parsed = binobf::parse_object(fixture.bytes, "fixture.o");
    REQUIRE(parsed.has_value());
    REQUIRE_EQ(parsed.value().architecture, binobf::Architecture::X86);
    REQUIRE_EQ(parsed.value().relocations.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().relocations.front().rawType, UINT64_C(2));
    REQUIRE_EQ(parsed.value().relocations.front().addend, INT64_C(0));
    REQUIRE_EQ(parsed.value().relocations.front().kind, binobf::RelocationKind::PcRelative);
}

TEST_CASE(elf64_object_round_trip_rebuilds_tables_deterministically) {
    const auto fixture = make_elf64_object();
    const auto parsed = binobf::parse_object(fixture.bytes, "fixture.o");
    REQUIRE(parsed.has_value());

    const auto first = binobf::write_object(parsed.value());
    REQUIRE(first.has_value());
    const auto second = binobf::write_object(parsed.value());
    REQUIRE(second.has_value());
    REQUIRE_EQ(first.value(), second.value());
    REQUIRE(first.value() != fixture.bytes);

    const auto reparsed = binobf::parse_object(first.value(), "roundtrip.o");
    REQUIRE(reparsed.has_value());
    REQUIRE_EQ(reparsed.value().architecture, binobf::Architecture::X86_64);
    REQUIRE_EQ(reparsed.value().sections.size(), parsed.value().sections.size());
    REQUIRE_EQ(reparsed.value().symbols.size(), parsed.value().symbols.size());
    REQUIRE_EQ(reparsed.value().relocations.size(), parsed.value().relocations.size());
    const auto* function = find_named(reparsed.value().symbols, "fixture_add");
    const auto* external = find_named(reparsed.value().symbols, "external");
    REQUIRE(function != nullptr);
    REQUIRE(external != nullptr);
    REQUIRE(function->defined);
    REQUIRE(!external->defined);
    REQUIRE_EQ(reparsed.value().relocations.front().targetSymbol, std::optional{external->id});
    REQUIRE_EQ(reparsed.value().relocations.front().addend, INT64_C(-4));
}

TEST_CASE(elf32_object_round_trip_rebuilds_rel_entries) {
    const auto fixture = make_elf32_object();
    const auto parsed = binobf::parse_object(fixture.bytes, "fixture32.o");
    REQUIRE(parsed.has_value());
    const auto output = binobf::write_object(parsed.value());
    REQUIRE(output.has_value());
    const auto reparsed = binobf::parse_object(output.value(), "roundtrip32.o");
    REQUIRE(reparsed.has_value());
    REQUIRE_EQ(reparsed.value().architecture, binobf::Architecture::X86);
    REQUIRE_EQ(reparsed.value().relocations.size(), std::size_t{1});
    REQUIRE_EQ(reparsed.value().relocations.front().addend, INT64_C(0));
}

TEST_CASE(elf_object_parser_rejects_linked_or_malformed_inputs) {
    auto linked = make_elf64_object();
    put_u16(linked.bytes, 16, 2);
    require_error(linked, "object.unsupported_type");

    auto truncated = make_elf64_object();
    truncated.bytes.resize(truncated.sectionTableOffset + 10);
    require_error(truncated, "elf.truncated");

    auto badStringTable = make_elf64_object();
    put_u64(
        badStringTable.bytes,
        badStringTable.sectionTableOffset + 6 * 64 + 24,
        static_cast<std::uint64_t>(badStringTable.bytes.size() + 1));
    require_error(badStringTable, "elf.truncated");

    auto badSymbolLink = make_elf64_object();
    put_u32(badSymbolLink.bytes, badSymbolLink.sectionTableOffset + 4 * 64 + 40, 99);
    require_error(badSymbolLink, "elf.invalid");

    auto badRelocationSymbol = make_elf64_object();
    put_u64(
        badRelocationSymbol.bytes,
        badRelocationSymbol.relocationDataOffset + 8,
        (UINT64_C(99) << 32U) | 2U);
    require_error(badRelocationSymbol, "elf.invalid");
}

int main() {
    return binobf::test::run_all();
}

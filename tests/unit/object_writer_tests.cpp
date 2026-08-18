#include "../test_support.hpp"

#include <binobf/formats/object_writer.hpp>
#include <binobf/formats/object_parser.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>

namespace {

auto make_valid_elf_image() -> binobf::BinaryImage {
    binobf::BinaryImage image;
    image.format = binobf::BinaryFormat::ELF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86_64;
    image.sections = {
        binobf::Section{
            .id = binobf::EntityId{1}, .formatIndex = 1, .formatType = 1,
            .formatFlags = 6, .name = ".text", .kind = binobf::SectionKind::Code,
            .address = {}, .logicalSize = 1, .alignment = 1, .readable = true,
            .executable = true, .contents = {std::byte{0x90}}, .lineage = {}},
        binobf::Section{
            .id = binobf::EntityId{2}, .formatIndex = 2, .formatType = 3,
            .name = ".strtab", .kind = binobf::SectionKind::StringTable,
            .address = {}, .alignment = 1, .contents = {}, .lineage = {}},
        binobf::Section{
            .id = binobf::EntityId{3}, .formatIndex = 3, .formatType = 2,
            .formatLink = 2, .formatInfo = 1, .formatEntrySize = 24,
            .name = ".symtab", .kind = binobf::SectionKind::SymbolTable,
            .address = {}, .alignment = 8, .contents = {}, .lineage = {}},
        binobf::Section{
            .id = binobf::EntityId{4}, .formatIndex = 4, .formatType = 3,
            .isSectionNameTable = true, .name = ".shstrtab",
            .kind = binobf::SectionKind::StringTable, .address = {}, .alignment = 1,
            .contents = {}, .lineage = {}},
        binobf::Section{
            .id = binobf::EntityId{5}, .formatIndex = 5, .formatType = 4,
            .formatLink = 3, .formatInfo = 1, .formatEntrySize = 24,
            .name = ".rela.text", .kind = binobf::SectionKind::Relocation,
            .address = {}, .alignment = 8, .contents = {}, .lineage = {}},
    };
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{6}, .formatIndex = 1, .formatTableIndex = 3,
        .formatType = 2, .formatStorage = 1, .formatSectionIndex = 1,
        .auxiliaryData = {},
        .name = "fixture", .section = binobf::EntityId{1}, .address = {},
        .size = 1, .kind = binobf::SymbolKind::Function,
        .visibility = binobf::SymbolVisibility::External, .defined = true, .lineage = {}});
    image.relocations.push_back(binobf::Relocation{
        .id = binobf::EntityId{7}, .formatIndex = 0, .formatTableIndex = 5,
        .section = binobf::EntityId{1}, .offset = 0,
        .kind = binobf::RelocationKind::PcRelative, .rawType = 2,
        .targetSymbol = binobf::EntityId{6}, .addend = -4, .lineage = {}});
    return image;
}

void require_error(const binobf::BinaryImage& image, std::string_view code) {
    const auto result = binobf::write_object(image);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, code);
}

} // namespace

TEST_CASE(object_writer_rejects_unsupported_formats) {
    auto image = make_valid_elf_image();
    image.format = binobf::BinaryFormat::PE;
    require_error(image, "object.unsupported_format");
}

TEST_CASE(object_writer_rejects_duplicate_ids_and_indices) {
    auto duplicateId = make_valid_elf_image();
    duplicateId.symbols.front().id = duplicateId.sections.front().id;
    require_error(duplicateId, "object.model_invalid");

    auto duplicateSectionIndex = make_valid_elf_image();
    duplicateSectionIndex.sections.at(1).formatIndex = 1;
    require_error(duplicateSectionIndex, "object.model_invalid");

    auto duplicateSymbolIndex = make_valid_elf_image();
    auto duplicate = duplicateSymbolIndex.symbols.front();
    duplicate.id = binobf::EntityId{99};
    duplicateSymbolIndex.symbols.push_back(duplicate);
    require_error(duplicateSymbolIndex, "object.model_invalid");
}

TEST_CASE(object_writer_rejects_dangling_references_and_table_owners) {
    auto danglingSection = make_valid_elf_image();
    danglingSection.symbols.front().section = binobf::EntityId{99};
    require_error(danglingSection, "object.model_invalid");

    auto danglingSymbol = make_valid_elf_image();
    danglingSymbol.relocations.front().targetSymbol = binobf::EntityId{99};
    require_error(danglingSymbol, "object.model_invalid");

    auto missingOwner = make_valid_elf_image();
    missingOwner.symbols.front().formatTableIndex = 99;
    require_error(missingOwner, "object.model_invalid");
}

TEST_CASE(object_writer_enforces_format_size_limits) {
    binobf::BinaryImage image;
    image.format = binobf::BinaryFormat::COFF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86_64;
    image.sections.push_back(binobf::Section{
        .id = binobf::EntityId{1}, .formatIndex = 1,
        .formatFlags = 0x40000040, .name = ".data",
        .kind = binobf::SectionKind::InitializedData, .address = {},
        .logicalSize = static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()) + 1,
        .alignment = 1, .readable = true, .contents = {}, .lineage = {}});
    require_error(image, "object.size_limit");
}

TEST_CASE(object_writer_does_not_mutate_input_during_emission) {
    const auto image = make_valid_elf_image();
    const auto sectionName = image.sections.front().name;
    const auto sectionBytes = image.sections.front().contents;
    const auto symbolId = image.symbols.front().id;
    const auto result = binobf::write_object(image);
    REQUIRE(result.has_value());
    REQUIRE_EQ(image.sections.front().name, sectionName);
    REQUIRE_EQ(image.sections.front().contents, sectionBytes);
    REQUIRE_EQ(image.symbols.front().id, symbolId);
    REQUIRE_EQ(image.sections.size(), std::size_t{5});
}

TEST_CASE(coff_long_section_names_round_trip_without_symbols) {
    binobf::BinaryImage image;
    image.format = binobf::BinaryFormat::COFF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86_64;
    image.sections.push_back(binobf::Section{
        .id = binobf::EntityId{1}, .formatIndex = 1,
        .formatFlags = 0x40300040, .name = ".long_section_name",
        .kind = binobf::SectionKind::InitializedData, .address = {},
        .logicalSize = 1, .alignment = 4, .readable = true,
        .contents = {std::byte{0x2a}}, .lineage = {}});
    const auto written = binobf::write_object(image);
    REQUIRE(written.has_value());
    const auto reparsed = binobf::parse_object(written.value(), "long-name.obj");
    REQUIRE(reparsed.has_value());
    REQUIRE_EQ(reparsed.value().sections.front().name, ".long_section_name");
    REQUIRE(reparsed.value().symbols.empty());
}

int main() {
    return binobf::test::run_all();
}

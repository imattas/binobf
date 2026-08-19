#include "../test_support.hpp"

#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/verify/structural_verifier.hpp>

#include <cstddef>
#include <cstdint>

TEST_CASE(macho_object_writer_and_parser_round_trip_x86_64_code_and_symbol) {
    binobf::BinaryImage image{};
    image.format = binobf::BinaryFormat::MachO;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86_64;
    const auto sectionId = binobf::EntityId{1};
    image.sections.push_back(binobf::Section{
        .id = sectionId,
        .formatIndex = 1,
        .formatFlags = 0x80000400U,
        .name = "__text",
        .kind = binobf::SectionKind::Code,
        .address = binobf::BinaryAddress{0},
        .logicalSize = 5,
        .alignment = 1,
        .readable = true,
        .executable = true,
        .contents = {std::byte{0xe8}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}},
        .lineage = {},
    });
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{2},
        .formatIndex = 0,
        .formatTableIndex = 0,
        .formatType = 0x0f,
        .formatStorage = 1,
        .formatOther = 0,
        .formatSectionIndex = 1,
        .auxiliaryData = {},
        .name = "_entry",
        .section = sectionId,
        .address = binobf::BinaryAddress{0},
        .size = 5,
        .kind = binobf::SymbolKind::Function,
        .visibility = binobf::SymbolVisibility::External,
        .defined = true,
        .definition = binobf::SymbolDefinitionKind::SectionRelative,
        .tlsModel = binobf::TlsModel::None,
        .lineage = {},
    });
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{3},
        .formatIndex = 1,
        .formatTableIndex = 0,
        .formatType = 0,
        .formatStorage = 1,
        .formatSectionIndex = 0,
        .auxiliaryData = {},
        .name = "_runtime",
        .section = std::nullopt,
        .address = {},
        .size = 0,
        .kind = binobf::SymbolKind::Function,
        .visibility = binobf::SymbolVisibility::External,
        .defined = false,
        .definition = binobf::SymbolDefinitionKind::Undefined,
        .tlsModel = binobf::TlsModel::None,
        .lineage = {},
    });
    image.relocations.push_back(binobf::Relocation{
        .id = binobf::EntityId{4},
        .formatIndex = 0,
        .formatTableIndex = 1,
        .section = sectionId,
        .offset = 1,
        .kind = binobf::RelocationKind::PcRelative,
        .rawType = 2,
        .targetSymbol = binobf::EntityId{3},
        .addend = 0,
        .lineage = {},
    });

    const auto written = binobf::write_object(image);
    REQUIRE(written.has_value());
    const auto parsed = binobf::parse_object(written.value(), "fixture.macho.o");
    REQUIRE(parsed.has_value());
    REQUIRE_EQ(parsed.value().format, binobf::BinaryFormat::MachO);
    REQUIRE_EQ(parsed.value().architecture, binobf::Architecture::X86_64);
    REQUIRE_EQ(parsed.value().sections.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().sections.front().contents, image.sections.front().contents);
    REQUIRE_EQ(parsed.value().symbols.size(), std::size_t{2});
    REQUIRE_EQ(parsed.value().symbols.front().name, "_entry");
    REQUIRE_EQ(parsed.value().relocations.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().relocations.front().rawType, UINT64_C(2));
    const auto verified = binobf::verify_object(written.value(), "fixture.macho.o");
    REQUIRE(verified.has_value());
}

TEST_CASE(macho_object_writer_rejects_32_bit_x86) {
    binobf::BinaryImage image{};
    image.format = binobf::BinaryFormat::MachO;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86;
    image.sections.push_back(binobf::Section{
        .id = binobf::EntityId{1}, .formatIndex = 1, .name = "__text",
        .kind = binobf::SectionKind::Code, .logicalSize = 1,
        .readable = true, .executable = true, .contents = {std::byte{0xc3}},
    });
    const auto written = binobf::write_object(image);
    REQUIRE(!written.has_value());
    REQUIRE_EQ(written.error().code, "macho.architecture");
}

int main() {
    return binobf::test::run_all();
}

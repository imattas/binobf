#include "../test_support.hpp"

#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

namespace {

void put_word(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t word) {
    for (std::size_t index = 0; index < 4U; ++index) {
        bytes.at(offset + index) = static_cast<std::byte>((word >> (index * 8U)) & 0xffU);
    }
}

auto section_aux(std::uint8_t selection) -> std::vector<std::byte> {
    std::vector<std::byte> result(18, std::byte{0});
    result[14] = static_cast<std::byte>(selection);
    return result;
}

auto image() -> binobf::BinaryImage {
    binobf::BinaryImage result{};
    result.format = binobf::BinaryFormat::COFF;
    result.type = binobf::BinaryType::RelocatableObject;
    result.architecture = binobf::Architecture::ARM64;
    binobf::Section text{};
    text.id = binobf::EntityId{1};
    text.formatIndex = 1;
    text.formatFlags = 0x60501020U;
    text.name = ".text";
    text.kind = binobf::SectionKind::Code;
    text.logicalSize = 18U * 8U;
    text.alignment = 4;
    text.readable = true;
    text.executable = true;
    text.contents.resize(static_cast<std::size_t>(text.logicalSize));
    constexpr std::array opcodes{UINT32_C(0),          UINT32_C(0),          UINT32_C(0),
                                 UINT32_C(0x94000000), UINT32_C(0x90000000), UINT32_C(0x10000000),
                                 UINT32_C(0x91000000), UINT32_C(0xf9400000), UINT32_C(0),
                                 UINT32_C(0x91000000), UINT32_C(0x91000000), UINT32_C(0xf9400000),
                                 UINT32_C(0),          UINT32_C(0),          UINT32_C(0),
                                 UINT32_C(0x54000000), UINT32_C(0x36000000), UINT32_C(0)};
    for (std::size_t index = 0; index < opcodes.size(); ++index) {
        put_word(text.contents, index * 8U, opcodes[index]);
    }
    result.sections.push_back(std::move(text));

    result.symbols.push_back(
        binobf::Symbol{.id = binobf::EntityId{2},
                       .formatIndex = 0,
                       .formatType = 0x20,
                       .formatStorage = 2,
                       .formatSectionIndex = 1,
                       .auxiliaryData = {},
                       .name = "entry",
                       .section = binobf::EntityId{1},
                       .address = {},
                       .size = 4,
                       .kind = binobf::SymbolKind::Function,
                       .visibility = binobf::SymbolVisibility::External,
                       .defined = true,
                       .definition = binobf::SymbolDefinitionKind::SectionRelative,
                       .tlsModel = binobf::TlsModel::None,
                       .lineage = {}});
    result.symbols.push_back(
        binobf::Symbol{.id = binobf::EntityId{4},
                       .formatIndex = 2,
                       .formatType = 0,
                       .formatStorage = 3,
                       .formatSectionIndex = 1,
                       .auxiliaryData = section_aux(2),
                       .name = ".text",
                       .section = binobf::EntityId{1},
                       .address = {},
                       .size = 0,
                       .kind = binobf::SymbolKind::Section,
                       .visibility = binobf::SymbolVisibility::Local,
                       .defined = true,
                       .definition = binobf::SymbolDefinitionKind::SectionRelative,
                       .commonAlignment = 0,
                       .tlsModel = binobf::TlsModel::None,
                       .lineage = {}});
    result.sectionAssociations.push_back(
        binobf::SectionAssociation{.section = binobf::EntityId{1},
                                   .kind = binobf::SectionAssociationKind::CoffComdat,
                                   .coffSelection = binobf::CoffComdatSelection::Any,
                                   .signatureSymbol = binobf::EntityId{4},
                                   .parentSection = {},
                                   .members = {}});
    result.symbols.push_back(binobf::Symbol{.id = binobf::EntityId{3},
                                            .formatIndex = 1,
                                            .formatStorage = 2,
                                            .formatSectionIndex = 0,
                                            .auxiliaryData = {},
                                            .name = "target",
                                            .section = {},
                                            .address = {},
                                            .size = 0,
                                            .kind = binobf::SymbolKind::Object,
                                            .visibility = binobf::SymbolVisibility::External,
                                            .defined = false,
                                            .definition = binobf::SymbolDefinitionKind::Undefined,
                                            .tlsModel = binobf::TlsModel::None,
                                            .lineage = {}});

    constexpr std::array<std::int64_t, 18> addends{0,     0x1234, 0x2345, 4,     0x1000,   4,
                                                   0x120, 0x128,  0x345,  0x234, 0x123000, 0x238,
                                                   0x456, 3,      0x5678, 4,     4,        -4};
    for (std::size_t index = 0; index < addends.size(); ++index) {
        result.relocations.push_back(binobf::Relocation{
            .id = binobf::EntityId{10U + index},
            .formatIndex = static_cast<std::uint32_t>(index),
            .formatTableIndex = 1,
            .section = binobf::EntityId{1},
            .offset = index * 8U,
            .kind = binobf::RelocationKind::ArchitectureSpecific,
            .rawType = index,
            .targetSymbol = index == 8U ? binobf::EntityId{4} : binobf::EntityId{3},
            .addend = addends[index],
            .lineage = {}});
    }
    return result;
}

auto round_trip(const binobf::BinaryImage& input) -> binobf::BinaryImage {
    const auto written = binobf::write_object(input);
    if (!written.has_value()) {
        throw std::runtime_error(written.error().code + ": " + written.error().message);
    }
    const auto parsed = binobf::parse_object(written.value(), "arm64.obj");
    if (!parsed.has_value()) {
        throw std::runtime_error(parsed.error().code + ": " + parsed.error().message);
    }
    return parsed.value();
}

auto pdata_image(bool sectionSymbol, bool unknownRecord = false)
        -> binobf::BinaryImage {
    binobf::BinaryImage result{};
    result.format = binobf::BinaryFormat::COFF;
    result.type = binobf::BinaryType::RelocatableObject;
    result.architecture = binobf::Architecture::ARM64;
    binobf::Section text{};
    text.id = binobf::EntityId{1};
    text.formatIndex = 1;
    text.formatFlags = 0x60000020U;
    text.name = ".text";
    text.kind = binobf::SectionKind::Code;
    text.logicalSize = 32;
    text.alignment = 4;
    text.readable = true;
    text.executable = true;
    text.contents.resize(32, std::byte{0});
    binobf::Section pdata{};
    pdata.id = binobf::EntityId{2};
    pdata.formatIndex = 2;
    pdata.formatFlags = 0x40000040U;
    pdata.name = ".pdata";
    pdata.kind = binobf::SectionKind::InitializedData;
    pdata.logicalSize = 8;
    pdata.alignment = 4;
    pdata.readable = true;
    pdata.contents.resize(8, std::byte{0});
    if (!unknownRecord) {
        const auto packed = UINT32_C(1) | (UINT32_C(7) << 2U) |
                                                (UINT32_C(3) << 21U) | (UINT32_C(2) << 23U);
        put_word(pdata.contents, 4, packed);
    }
    result.sections = {std::move(text), std::move(pdata)};
    result.symbols.push_back(binobf::Symbol{
            .id = binobf::EntityId{3},
            .formatIndex = 0,
            .formatType = 0x20,
            .formatStorage = 2,
            .formatSectionIndex = 1,
            .auxiliaryData = {},
            .name = "owned_function",
            .section = binobf::EntityId{1},
            .address = {4, binobf::AddressKind::RelativeVirtual},
            .size = 28,
            .kind = binobf::SymbolKind::Function,
            .visibility = binobf::SymbolVisibility::External,
            .defined = true,
            .definition = binobf::SymbolDefinitionKind::SectionRelative,
            .tlsModel = binobf::TlsModel::None,
            .lineage = {},
    });
    result.symbols.push_back(binobf::Symbol{
            .id = binobf::EntityId{4},
            .formatIndex = 1,
            .formatType = 0,
            .formatStorage = 3,
            .formatSectionIndex = 1,
            .auxiliaryData = {},
            .name = ".text",
            .section = binobf::EntityId{1},
            .address = {},
            .kind = binobf::SymbolKind::Section,
            .visibility = binobf::SymbolVisibility::Local,
            .defined = true,
            .definition = binobf::SymbolDefinitionKind::SectionRelative,
            .tlsModel = binobf::TlsModel::None,
            .lineage = {},
    });
    if (!unknownRecord) {
        result.relocations.push_back(binobf::Relocation{
                .id = binobf::EntityId{5},
                .formatIndex = 0,
                .formatTableIndex = 2,
                .section = binobf::EntityId{2},
                .offset = 0,
                .kind = binobf::RelocationKind::ImageRelative,
                .rawType = 0x0002,
                .targetSymbol =
                        sectionSymbol ? binobf::EntityId{4} : binobf::EntityId{3},
                .addend = sectionSymbol ? 4 : 0,
                .lineage = {},
        });
    }
    return result;
}

} // namespace

TEST_CASE(coff_arm64_all_defined_relocations_round_trip_addends_and_opcode_bits) {
    const auto source = image();
    const auto parsed = round_trip(source);
    REQUIRE_EQ(parsed.architecture, binobf::Architecture::ARM64);
    REQUIRE_EQ(parsed.relocations.size(), std::size_t{18});
    REQUIRE_EQ(parsed.sectionAssociations.size(), std::size_t{1});
    REQUIRE_EQ(parsed.sectionAssociations.front().kind, binobf::SectionAssociationKind::CoffComdat);
    REQUIRE_EQ(parsed.sectionAssociations.front().coffSelection, binobf::CoffComdatSelection::Any);
    for (std::size_t index = 0; index < parsed.relocations.size(); ++index) {
        REQUIRE_EQ(parsed.relocations[index].rawType, static_cast<std::uint64_t>(index));
        REQUIRE_EQ(parsed.relocations[index].addend, source.relocations[index].addend);
    }
    const auto sectionTarget = std::ranges::find(
        parsed.symbols, parsed.relocations[8].targetSymbol.value(), &binobf::Symbol::id);
    REQUIRE(sectionTarget != parsed.symbols.end());
    REQUIRE_EQ(sectionTarget->kind, binobf::SymbolKind::Section);
    REQUIRE_EQ(static_cast<std::uint8_t>(
                   std::to_integer<std::uint8_t>(parsed.sections.front().contents[3U * 8U + 3U]) &
                   UINT8_C(0xfc)),
               UINT8_C(0x94));
    REQUIRE_EQ(static_cast<std::uint8_t>(
                   std::to_integer<std::uint8_t>(parsed.sections.front().contents[4U * 8U + 3U]) &
                   UINT8_C(0x9f)),
               UINT8_C(0x90));
}

TEST_CASE(coff_arm64_unknown_relocations_preserve_fields_byte_for_byte) {
    auto source = image();
    source.relocations.clear();
    source.sections.front().contents = {std::byte{0x12}, std::byte{0x34}, std::byte{0x56},
                                        std::byte{0x78}};
    source.sections.front().logicalSize = 4;
    source.relocations.push_back(
        binobf::Relocation{.id = binobf::EntityId{10},
                           .formatIndex = 0,
                           .formatTableIndex = 1,
                           .section = binobf::EntityId{1},
                           .offset = 0,
                           .kind = binobf::RelocationKind::ArchitectureSpecific,
                           .rawType = 0xffff,
                           .targetSymbol = binobf::EntityId{3},
                           .addend = 0,
                           .lineage = {}});
    const auto parsed = round_trip(source);
    REQUIRE_EQ(parsed.sections.front().contents, source.sections.front().contents);
    REQUIRE_EQ(parsed.relocations.front().rawType, UINT64_C(0xffff));
}

TEST_CASE(coff_arm64_rejects_unaligned_and_truncated_instruction_fields) {
    auto source = image();
    source.relocations.resize(1);
    source.relocations.front().rawType = 3;
    source.relocations.front().offset = 2;
    const auto unaligned = binobf::write_object(source);
    REQUIRE(!unaligned.has_value());
    REQUIRE_EQ(unaligned.error().code, "object.model_invalid");

    source = image();
    const auto written = binobf::write_object(source);
    REQUIRE(written.has_value());
    auto truncated = written.value();
    truncated.pop_back();
    const auto parsed = binobf::parse_object(truncated, "truncated.obj");
    REQUIRE(!parsed.has_value());
}

TEST_CASE(coff_arm64_normalizes_packed_pdata_function_and_section_owners) {
    for (const bool sectionSymbol : {false, true}) {
        const auto parsed = round_trip(pdata_image(sectionSymbol));
        REQUIRE_EQ(parsed.unwindInfo.size(), std::size_t{1});
        const auto &unwind = parsed.unwindInfo.front();
        REQUIRE_EQ(unwind.format, binobf::UnwindFormat::WindowsARM64);
        REQUIRE_EQ(unwind.codeOffset, UINT64_C(4));
        REQUIRE_EQ(unwind.codeSize, UINT64_C(28));
        REQUIRE_EQ(unwind.encoded.size(), std::size_t{8});
        REQUIRE_EQ(unwind.relocations.size(), std::size_t{1});
        REQUIRE_EQ(unwind.rewriteState, binobf::UnwindRewriteState::Unchanged);
    }
}

TEST_CASE(coff_arm64_preserves_unowned_pdata_as_unknown) {
    const auto parsed = round_trip(pdata_image(false, true));
    REQUIRE_EQ(parsed.unwindInfo.size(), std::size_t{1});
    REQUIRE_EQ(parsed.unwindInfo.front().format, binobf::UnwindFormat::Unknown);
    REQUIRE_EQ(parsed.unwindInfo.front().rewriteState,
                          binobf::UnwindRewriteState::Opaque);
    REQUIRE_EQ(parsed.unwindInfo.front().encoded.size(), std::size_t{8});
}

TEST_CASE(coff_arm64_refuses_nonzero_direct_function_addends) {
    auto source = pdata_image(false);
    source.relocations.front().addend = 4;
    const auto parsed = round_trip(source);
    REQUIRE_EQ(parsed.unwindInfo.size(), std::size_t{1});
    REQUIRE_EQ(parsed.unwindInfo.front().format, binobf::UnwindFormat::Unknown);
}

TEST_CASE(coff_arm64_rejects_invalid_packed_register_fields) {
    auto source = pdata_image(false);
    const auto packed = UINT32_C(1) | (UINT32_C(7) << 2U) |
                                            (UINT32_C(15) << 16U) | (UINT32_C(3) << 21U) |
                                            (UINT32_C(2) << 23U);
    put_word(source.sections[1].contents, 4, packed);
    const auto parsed = round_trip(source);
    REQUIRE_EQ(parsed.unwindInfo.size(), std::size_t{1});
    REQUIRE_EQ(parsed.unwindInfo.front().format, binobf::UnwindFormat::Unknown);
}

TEST_CASE(coff_arm64_retains_owned_xdata_as_opaque) {
    auto source = pdata_image(false, true);
    binobf::Section xdata{};
    xdata.id = binobf::EntityId{6};
    xdata.formatIndex = 3;
    xdata.formatFlags = 0x40000040U;
    xdata.name = ".xdata";
    xdata.kind = binobf::SectionKind::InitializedData;
    xdata.logicalSize = 4;
    xdata.alignment = 4;
    xdata.readable = true;
    xdata.contents = {std::byte{0xe4}, std::byte{0xe3}, std::byte{0xe3},
                                        std::byte{0xe3}};
    source.sections.push_back(std::move(xdata));
    source.symbols.push_back(binobf::Symbol{
            .id = binobf::EntityId{7},
            .formatIndex = 2,
            .formatType = 0,
            .formatStorage = 3,
            .formatSectionIndex = 3,
            .auxiliaryData = {},
            .name = ".xdata",
            .section = binobf::EntityId{6},
            .address = {},
            .kind = binobf::SymbolKind::Section,
            .visibility = binobf::SymbolVisibility::Local,
            .defined = true,
            .definition = binobf::SymbolDefinitionKind::SectionRelative,
            .tlsModel = binobf::TlsModel::None,
            .lineage = {},
    });
    source.relocations = {
            binobf::Relocation{.id = binobf::EntityId{5},
                                                  .formatIndex = 0,
                                                  .formatTableIndex = 2,
                                                  .section = binobf::EntityId{2},
                                                  .offset = 0,
                                                  .kind = binobf::RelocationKind::ImageRelative,
                                                  .rawType = 0x0002,
                                                  .targetSymbol = binobf::EntityId{3},
                                                  .addend = 0,
                                                  .lineage = {}},
            binobf::Relocation{.id = binobf::EntityId{8},
                                                  .formatIndex = 1,
                                                  .formatTableIndex = 2,
                                                  .section = binobf::EntityId{2},
                                                  .offset = 4,
                                                  .kind = binobf::RelocationKind::ImageRelative,
                                                  .rawType = 0x0002,
                                                  .targetSymbol = binobf::EntityId{7},
                                                  .addend = 0,
                                                  .lineage = {}},
    };
    const auto parsed = round_trip(source);
    REQUIRE_EQ(parsed.unwindInfo.size(), std::size_t{1});
    REQUIRE_EQ(parsed.unwindInfo.front().format,
                          binobf::UnwindFormat::WindowsARM64);
    REQUIRE_EQ(parsed.unwindInfo.front().rewriteState,
                          binobf::UnwindRewriteState::Opaque);
    REQUIRE_EQ(parsed.unwindInfo.front().relocations.size(), std::size_t{2});
}

int main() {
    return binobf::test::run_all();
}

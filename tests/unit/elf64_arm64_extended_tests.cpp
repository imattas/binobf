#include "../test_support.hpp"

#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>

#include <algorithm>
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

auto section(std::uint64_t id, std::uint32_t index, std::uint64_t type, std::string name,
             std::uint64_t flags = 0, std::uint64_t alignment = 1) -> binobf::Section {
    return binobf::Section{.id = binobf::EntityId{id},
                           .formatIndex = index,
                           .formatType = type,
                           .formatFlags = flags,
                           .name = std::move(name),
                           .kind = type == 3            ? binobf::SectionKind::StringTable
                                   : type == 2          ? binobf::SectionKind::SymbolTable
                                   : type == 4          ? binobf::SectionKind::Relocation
                                   : (flags & 4U) != 0U ? binobf::SectionKind::Code
                                                        : binobf::SectionKind::InitializedData,
                           .address = {},
                           .logicalSize = 0,
                           .alignment = alignment,
                           .readable = (flags & 2U) != 0U,
                           .writable = (flags & 1U) != 0U,
                           .executable = (flags & 4U) != 0U,
                           .contents = {},
                           .lineage = {}};
}

auto symbol(std::uint64_t id, std::uint32_t index, std::string name, std::uint32_t type,
            std::uint8_t binding, std::int32_t rawSection, std::optional<binobf::EntityId> owner)
    -> binobf::Symbol {
    return binobf::Symbol{
        .id = binobf::EntityId{id},
        .formatIndex = index,
        .formatTableIndex = 4,
        .formatType = type,
        .formatStorage = binding,
        .formatSectionIndex = rawSection,
        .auxiliaryData = {},
        .name = std::move(name),
        .section = owner,
        .address = {},
        .size = 0,
        .kind = type == 2   ? binobf::SymbolKind::Function
                : type == 6 ? binobf::SymbolKind::Tls
                            : binobf::SymbolKind::Unknown,
        .visibility =
            binding == 0 ? binobf::SymbolVisibility::Local : binobf::SymbolVisibility::External,
        .defined = rawSection != 0,
        .definition = owner.has_value()
                          ? std::optional{binobf::SymbolDefinitionKind::SectionRelative}
                          : std::optional{binobf::SymbolDefinitionKind::Undefined},
        .tlsModel = type == 6 ? binobf::TlsModel::Unknown : binobf::TlsModel::None,
        .lineage = {}};
}

auto image() -> binobf::BinaryImage {
    binobf::BinaryImage result{};
    result.format = binobf::BinaryFormat::ELF;
    result.type = binobf::BinaryType::RelocatableObject;
    result.architecture = binobf::Architecture::ARM64;
    auto text = section(1, 1, 1, ".text", 6, 4);
    text.contents.resize(48, std::byte{0});
    text.logicalSize = text.contents.size();
    auto tls = section(2, 2, 1, ".tdata", 0x403, 8);
    tls.contents.resize(8, std::byte{0});
    tls.logicalSize = tls.contents.size();
    auto strings = section(3, 3, 3, ".strtab");
    auto symbols = section(4, 4, 2, ".symtab", 0, 8);
    symbols.formatLink = 3;
    symbols.formatInfo = 2;
    symbols.formatEntrySize = 24;
    auto sectionNames = section(5, 5, 3, ".shstrtab");
    sectionNames.isSectionNameTable = true;
    auto relocations = section(6, 6, 4, ".rela.text", 0, 8);
    relocations.formatLink = 4;
    relocations.formatInfo = 1;
    relocations.formatEntrySize = 24;
    auto group = section(7, 7, 17, ".group", 0, 4);
    group.formatLink = 4;
    group.formatInfo = 2;
    group.formatEntrySize = 4;
    result.sections = {std::move(text),    std::move(tls),          std::move(strings),
                       std::move(symbols), std::move(sectionNames), std::move(relocations),
                       std::move(group)};

    result.symbols.push_back(symbol(10, 1, "$x", 0, 0, 1, binobf::EntityId{1}));
    auto entry = symbol(11, 2, "entry", 2, 1, 1, binobf::EntityId{1});
    entry.size = 48;
    result.symbols.push_back(std::move(entry));
    result.symbols.push_back(symbol(12, 3, "target", 0, 1, 0, std::nullopt));
    result.symbols.push_back(symbol(13, 4, "tls_value", 6, 1, 2, binobf::EntityId{2}));
    auto common = symbol(14, 5, "common_value", 1, 1, 0xfff2, std::nullopt);
    common.defined = true;
    common.definition = binobf::SymbolDefinitionKind::Common;
    common.address.value = 8;
    common.commonAlignment = 8;
    common.size = 16;
    common.kind = binobf::SymbolKind::Object;
    result.symbols.push_back(std::move(common));
    result.sectionAssociations.push_back(
        binobf::SectionAssociation{.section = binobf::EntityId{7},
                                   .kind = binobf::SectionAssociationKind::ElfGroup,
                                   .coffSelection = binobf::CoffComdatSelection::None,
                                   .signatureSymbol = binobf::EntityId{11},
                                   .parentSection = {},
                                   .members = {binobf::EntityId{1}, binobf::EntityId{2}}});

    struct Reloc {
        std::uint64_t type;
        std::int64_t addend;
        binobf::EntityId symbol;
    };
    constexpr std::array values{
        Reloc{0x101, 0x1234, binobf::EntityId{12}},  Reloc{0x105, -4, binobf::EntityId{12}},
        Reloc{0x11a, 4, binobf::EntityId{12}},       Reloc{0x113, 0x1000, binobf::EntityId{12}},
        Reloc{0x115, 0x120, binobf::EntityId{12}},   Reloc{0x137, 0x2000, binobf::EntityId{12}},
        Reloc{0x201, 0x3000, binobf::EntityId{13}},  Reloc{0x202, 0x128, binobf::EntityId{13}},
        Reloc{0x232, -0x1000, binobf::EntityId{13}},
    };
    for (std::size_t index = 0; index < values.size(); ++index) {
        result.relocations.push_back(
            binobf::Relocation{.id = binobf::EntityId{20U + index},
                               .formatIndex = static_cast<std::uint32_t>(index),
                               .formatTableIndex = 6,
                               .section = binobf::EntityId{1},
                               .offset = index * 4U,
                               .kind = binobf::RelocationKind::ArchitectureSpecific,
                               .rawType = values[index].type,
                               .targetSymbol = values[index].symbol,
                               .addend = values[index].addend,
                               .lineage = {}});
    }
    return result;
}

auto round_trip(const binobf::BinaryImage& input) -> binobf::BinaryImage {
    const auto written = binobf::write_object(input);
    if (!written.has_value()) {
        throw std::runtime_error(written.error().code + ": " + written.error().message);
    }
    const auto parsed = binobf::parse_object(written.value(), "arm64.o");
    if (!parsed.has_value()) {
        throw std::runtime_error(parsed.error().code + ": " + parsed.error().message);
    }
    return parsed.value();
}

auto find_symbol(const binobf::BinaryImage& input, std::string_view name) -> const binobf::Symbol& {
    const auto found = std::ranges::find(input.symbols, name, &binobf::Symbol::name);
    if (found == input.symbols.end()) throw std::runtime_error("missing symbol");
    return *found;
}

} // namespace

TEST_CASE(elf64_arm64_rela_tls_common_and_mapping_metadata_round_trip) {
    const auto source = image();
    const auto parsed = round_trip(source);
    REQUIRE_EQ(parsed.architecture, binobf::Architecture::ARM64);
    REQUIRE_EQ(parsed.relocations.size(), source.relocations.size());
    for (std::size_t index = 0; index < source.relocations.size(); ++index) {
        REQUIRE_EQ(parsed.relocations[index].rawType, source.relocations[index].rawType);
        REQUIRE_EQ(parsed.relocations[index].addend, source.relocations[index].addend);
    }
    REQUIRE_EQ(find_symbol(parsed, "$x").kind, binobf::SymbolKind::Unknown);
    REQUIRE_EQ(find_symbol(parsed, "entry").size, UINT64_C(48));
    REQUIRE_EQ(find_symbol(parsed, "common_value").definition,
               binobf::SymbolDefinitionKind::Common);
    REQUIRE_EQ(find_symbol(parsed, "common_value").commonAlignment, UINT64_C(8));
    REQUIRE_EQ(find_symbol(parsed, "tls_value").tlsModel, binobf::TlsModel::GeneralDynamic);
    REQUIRE_EQ(parsed.sectionAssociations.size(), std::size_t{1});
    REQUIRE_EQ(parsed.sectionAssociations.front().kind, binobf::SectionAssociationKind::ElfGroup);
    REQUIRE_EQ(parsed.sectionAssociations.front().members.size(), std::size_t{2});
}

TEST_CASE(elf64_arm64_unknown_rela_types_and_debug_sections_round_trip) {
    auto source = image();
    const std::vector debugBytes{std::byte{0xaa}, std::byte{0xbb}};
    source.sections.push_back(section(30, 8, 1, ".debug_info", 0, 1));
    source.sections.back().contents = debugBytes;
    source.sections.back().logicalSize = 2;
    auto debugRelocations = section(31, 9, 4, ".rela.debug_info", 0, 8);
    debugRelocations.formatLink = 4;
    debugRelocations.formatInfo = 8;
    debugRelocations.formatEntrySize = 24;
    source.sections.push_back(std::move(debugRelocations));
    source.relocations.push_back(
        binobf::Relocation{.id = binobf::EntityId{32},
                           .formatIndex = 0,
                           .formatTableIndex = 9,
                           .section = binobf::EntityId{30},
                           .offset = 0,
                           .kind = binobf::RelocationKind::ArchitectureSpecific,
                           .rawType = 0x3ff,
                           .targetSymbol = binobf::EntityId{12},
                           .addend = 7,
                           .lineage = {}});
    const auto parsed = round_trip(source);
    REQUIRE_EQ(parsed.relocations.back().rawType, UINT64_C(0x3ff));
    REQUIRE_EQ(parsed.relocations.back().addend, INT64_C(7));
    const auto debug = std::ranges::find(parsed.sections, ".debug_info", &binobf::Section::name);
    REQUIRE(debug != parsed.sections.end());
    REQUIRE_EQ(debug->kind, binobf::SectionKind::Debug);
    REQUIRE_EQ(debug->contents, debugBytes);
}

TEST_CASE(elf64_arm64_rejects_unaligned_known_instruction_relocations) {
    auto source = image();
    source.relocations.front().rawType = 0x11a;
    source.relocations.front().offset = 2;
    const auto written = binobf::write_object(source);
    REQUIRE(!written.has_value());
    REQUIRE_EQ(written.error().code, "object.model_invalid");
}

int main() {
    return binobf::test::run_all();
}

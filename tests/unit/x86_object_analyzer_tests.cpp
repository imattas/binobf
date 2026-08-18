#include <binobf/analysis/object_analyzer.hpp>

#include "../test_support.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string_view>
#include <vector>

namespace {

auto bytes(std::initializer_list<unsigned int> values) -> std::vector<std::byte> {
    std::vector<std::byte> result;
    result.reserve(values.size());
    for (const auto value : values) result.push_back(static_cast<std::byte>(value));
    return result;
}

auto make_x86_object() -> binobf::BinaryImage {
    binobf::BinaryImage image;
    image.format = binobf::BinaryFormat::COFF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86;
    image.sections.push_back(binobf::Section{
        .id = binobf::EntityId{1},
        .formatIndex = 1,
        .formatType = 0,
        .formatFlags = 0x60500020U,
        .formatLink = 0,
        .formatInfo = 0,
        .formatEntrySize = 0,
        .isSectionNameTable = false,
        .name = ".text",
        .kind = binobf::SectionKind::Code,
        .address = binobf::BinaryAddress{0, binobf::AddressKind::RelativeVirtual},
        .logicalSize = 18,
        .alignment = 16,
        .readable = true,
        .writable = false,
        .executable = true,
        .contents = bytes({
            0x8b, 0x44, 0x24, 0x04,
            0x83, 0xf8, 0x00,
            0x74, 0x06,
            0xe8, 0x00, 0x00, 0x00, 0x00,
            0xc3,
            0x31, 0xc0,
            0xc3,
        }),
        .lineage = {},
    });
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{2},
        .formatIndex = 0,
        .formatTableIndex = 0,
        .formatType = 0x20,
        .formatStorage = 2,
        .formatOther = 0,
        .formatSectionIndex = 1,
        .auxiliaryData = {},
        .name = "x86_branch_call",
        .section = binobf::EntityId{1},
        .address = binobf::BinaryAddress{0, binobf::AddressKind::RelativeVirtual},
        .size = 18,
        .kind = binobf::SymbolKind::Function,
        .visibility = binobf::SymbolVisibility::External,
        .defined = true,
        .definition = binobf::SymbolDefinitionKind::SectionRelative,
        .commonAlignment = 0,
        .tlsModel = binobf::TlsModel::None,
        .lineage = {},
    });
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{3},
        .formatIndex = 1,
        .formatTableIndex = 0,
        .formatType = 0,
        .formatStorage = 2,
        .formatOther = 0,
        .formatSectionIndex = 0,
        .auxiliaryData = {},
        .name = "external_target",
        .section = std::nullopt,
        .address = {},
        .size = 0,
        .kind = binobf::SymbolKind::Function,
        .visibility = binobf::SymbolVisibility::External,
        .defined = false,
        .definition = binobf::SymbolDefinitionKind::Undefined,
        .commonAlignment = 0,
        .tlsModel = binobf::TlsModel::None,
        .lineage = {},
    });
    image.relocations.push_back(binobf::Relocation{
        .id = binobf::EntityId{4},
        .formatIndex = 0,
        .formatTableIndex = 1,
        .section = binobf::EntityId{1},
        .offset = 10,
        .kind = binobf::RelocationKind::PcRelative,
        .rawType = 0x14,
        .targetSymbol = binobf::EntityId{3},
        .addend = 0,
        .lineage = {},
    });
    return image;
}

} // namespace

TEST_CASE(x86_object_analysis_recovers_exact_cfg_and_external_call_reference) {
    const auto analyzed = binobf::analyze_object(make_x86_object());

    REQUIRE(analyzed.has_value());
    REQUIRE_EQ(analyzed.value().image.functions.size(), std::size_t{1});
    const auto& function = analyzed.value().image.functions.front();
    REQUIRE(function.complete);
    REQUIRE_EQ(function.size, UINT64_C(18));
    REQUIRE_EQ(function.instructions.size(), std::size_t{7});
    REQUIRE_EQ(function.basicBlocks.size(), std::size_t{4});

    const auto call = std::ranges::find_if(
        analyzed.value().image.instructions,
        [](const auto& instruction) {
            return instruction.kind == binobf::InstructionKind::DirectCall;
        });
    REQUIRE(call != analyzed.value().image.instructions.end());
    REQUIRE_EQ(call->references.size(), std::size_t{1});
    REQUIRE_EQ(call->references.front().relocation, binobf::EntityId{4});
    REQUIRE_EQ(call->references.front().symbol, binobf::EntityId{3});
    REQUIRE(!call->directTarget.has_value());
}

TEST_CASE(x86_object_analysis_preserves_branch_edges_and_register_liveness) {
    const auto analyzed = binobf::analyze_object(make_x86_object());
    REQUIRE(analyzed.has_value());

    const auto conditional = std::ranges::find_if(
        analyzed.value().image.instructions,
        [](const auto& instruction) {
            return instruction.kind == binobf::InstructionKind::ConditionalBranch;
        });
    REQUIRE(conditional != analyzed.value().image.instructions.end());
    REQUIRE(conditional->directTarget.has_value());
    REQUIRE_EQ(conditional->directTarget->value, UINT64_C(15));

    const auto& entry = analyzed.value().image.basicBlocks.front();
    REQUIRE_EQ(entry.edges.size(), std::size_t{2});
    REQUIRE(std::ranges::any_of(entry.liveIn, [](const auto& access) {
        return std::string_view{access.name} == "esp";
    }));
}

TEST_CASE(x86_object_analysis_bounds_a_zero_sized_symbol_at_the_next_owned_symbol) {
    auto image = make_x86_object();
    image.sections[0].contents.push_back(std::byte{0x31});
    image.sections[0].contents.push_back(std::byte{0xc0});
    image.sections[0].contents.push_back(std::byte{0xc3});
    image.sections[0].logicalSize = image.sections[0].contents.size();
    image.symbols[0].size = 0;
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{5},
        .formatIndex = 2,
        .formatTableIndex = 0,
        .formatType = 0x20,
        .formatStorage = 2,
        .formatOther = 0,
        .formatSectionIndex = 1,
        .auxiliaryData = {},
        .name = "next_function",
        .section = binobf::EntityId{1},
        .address = binobf::BinaryAddress{18, binobf::AddressKind::RelativeVirtual},
        .size = 3,
        .kind = binobf::SymbolKind::Function,
        .visibility = binobf::SymbolVisibility::External,
        .defined = true,
        .definition = binobf::SymbolDefinitionKind::SectionRelative,
        .commonAlignment = 0,
        .tlsModel = binobf::TlsModel::None,
        .lineage = {},
    });

    const auto analyzed = binobf::analyze_object(image);

    REQUIRE(analyzed.has_value());
    REQUIRE_EQ(analyzed.value().image.functions.size(), std::size_t{2});
    const auto first = std::ranges::find_if(
        analyzed.value().image.functions,
        [](const auto& function) { return function.name == "x86_branch_call"; });
    const auto second = std::ranges::find_if(
        analyzed.value().image.functions,
        [](const auto& function) { return function.name == "next_function"; });
    REQUIRE(first != analyzed.value().image.functions.end());
    REQUIRE(second != analyzed.value().image.functions.end());
    REQUIRE_EQ(first->size, UINT64_C(18));
    REQUIRE_EQ(second->size, UINT64_C(3));
    REQUIRE(std::ranges::none_of(first->instructions, [&](const auto instructionId) {
        const auto instruction = std::ranges::find_if(
            analyzed.value().image.instructions,
            [&](const auto& candidate) { return candidate.id == instructionId; });
        return instruction != analyzed.value().image.instructions.end()
            && instruction->sectionOffset >= 18;
    }));
}

int main() {
    return binobf::test::run_all();
}

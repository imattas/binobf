#include "../test_support.hpp"

#include <binobf/analysis/object_analyzer.hpp>

#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <string_view>

namespace {

auto make_image(std::vector<std::byte> code) -> binobf::BinaryImage {
    binobf::BinaryImage image;
    image.format = binobf::BinaryFormat::COFF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86_64;
    image.sections.push_back(binobf::Section{
        .id = binobf::EntityId{1}, .formatIndex = 1,
        .formatFlags = 0x60500020, .name = ".text",
        .kind = binobf::SectionKind::Code, .address = {},
        .logicalSize = code.size(), .alignment = 16,
        .readable = true, .executable = true,
        .contents = std::move(code), .lineage = {}});
    return image;
}

void add_function(
    binobf::BinaryImage& image,
    std::uint64_t id,
    std::string name,
    std::uint64_t offset,
    std::uint64_t size) {
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{id},
        .formatIndex = static_cast<std::uint32_t>(id - 2), .formatTableIndex = 0,
        .formatType = 0x20, .formatStorage = 3, .formatSectionIndex = 1,
        .auxiliaryData = {}, .name = std::move(name), .section = binobf::EntityId{1},
        .address = binobf::BinaryAddress{offset, binobf::AddressKind::RelativeVirtual},
        .size = size, .kind = binobf::SymbolKind::Function,
        .visibility = binobf::SymbolVisibility::Local, .defined = true,
        .definition = binobf::SymbolDefinitionKind::SectionRelative,
        .commonAlignment = 0, .tlsModel = binobf::TlsModel::None, .lineage = {}});
}

auto find_function(const binobf::BinaryImage& image, std::string_view name)
    -> const binobf::Function& {
    const auto found = std::find_if(image.functions.begin(), image.functions.end(), [name](const auto& function) {
        return function.name == name;
    });
    if (found == image.functions.end()) throw std::runtime_error("missing function");
    return *found;
}

auto has_diagnostic(const binobf::AnalysisReport& report, std::string_view code) -> bool {
    return std::any_of(report.diagnostics.begin(), report.diagnostics.end(), [code](const auto& diagnostic) {
        return diagnostic.code == code;
    });
}

auto find_block(const binobf::BinaryImage& image, const binobf::Function& function, std::uint64_t offset)
    -> const binobf::BasicBlock& {
    const auto found = std::find_if(image.basicBlocks.begin(), image.basicBlocks.end(), [&](const auto& block) {
        return block.function == function.id && block.sectionOffset == offset;
    });
    if (found == image.basicBlocks.end()) throw std::runtime_error("missing basic block");
    return *found;
}

auto has_edge(
    const binobf::BasicBlock& block,
    binobf::ControlFlowEdgeKind kind,
    std::optional<binobf::EntityId> target) -> bool {
    return std::any_of(block.edges.begin(), block.edges.end(), [&](const auto& edge) {
        return edge.kind == kind && edge.targetBlock == target;
    });
}

auto find_instruction_at(const binobf::BinaryImage& image, std::uint64_t offset)
    -> const binobf::Instruction& {
    const auto found = std::find_if(image.instructions.begin(), image.instructions.end(), [offset](const auto& instruction) {
        return instruction.sectionOffset == offset;
    });
    if (found == image.instructions.end()) throw std::runtime_error("missing instruction");
    return *found;
}

auto has_register_name(const std::vector<binobf::RegisterAccess>& values, std::string_view name)
    -> bool {
    return std::any_of(values.begin(), values.end(), [name](const auto& value) {
        return value.name == name;
    });
}

} // namespace

TEST_CASE(object_analyzer_discovers_symbol_functions_and_infers_zero_sizes) {
    auto image = make_image({
        std::byte{0x48}, std::byte{0x01}, std::byte{0xd8}, std::byte{0xc3},
        std::byte{0x90}, std::byte{0xc3},
    });
    add_function(image, 2, "first", 0, 4);
    add_function(image, 3, "second", 4, 0);

    const auto analyzed = binobf::analyze_object(image);

    REQUIRE(analyzed.has_value());
    REQUIRE_EQ(analyzed.value().image.functions.size(), std::size_t{2});
    REQUIRE_EQ(analyzed.value().image.instructions.size(), std::size_t{4});
    const auto& first = find_function(analyzed.value().image, "first");
    const auto& second = find_function(analyzed.value().image, "second");
    REQUIRE_EQ(first.size, UINT64_C(4));
    REQUIRE_EQ(first.instructions.size(), std::size_t{2});
    REQUIRE(first.complete);
    REQUIRE_EQ(second.size, UINT64_C(2));
    REQUIRE_EQ(second.instructions.size(), std::size_t{2});
    REQUIRE(second.complete);
    REQUIRE_EQ(first.discovery, binobf::FunctionDiscovery::Symbol);
    REQUIRE_EQ(first.symbol, std::optional{binobf::EntityId{2}});
    REQUIRE_EQ(first.lineage.parents.front().source, binobf::EntityId{2});
    REQUIRE(analyzed.value().diagnostics.empty());
}

TEST_CASE(object_analyzer_truncates_overlapping_function_ranges_conservatively) {
    auto image = make_image({
        std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0xc3},
        std::byte{0x90}, std::byte{0xc3},
    });
    add_function(image, 2, "overlap", 0, 6);
    add_function(image, 3, "next", 4, 2);

    const auto analyzed = binobf::analyze_object(image);

    REQUIRE(analyzed.has_value());
    const auto& overlap = find_function(analyzed.value().image, "overlap");
    REQUIRE_EQ(overlap.size, UINT64_C(4));
    REQUIRE(!overlap.complete);
    REQUIRE(has_diagnostic(analyzed.value(), "analysis.overlapping_functions"));
}

TEST_CASE(object_analyzer_uses_opaque_fallback_for_undecodable_bytes) {
    auto image = make_image({std::byte{0x0f}, std::byte{0xc3}});
    add_function(image, 2, "opaque", 0, 2);

    const auto analyzed = binobf::analyze_object(image);

    REQUIRE(analyzed.has_value());
    const auto& function = find_function(analyzed.value().image, "opaque");
    REQUIRE(!function.complete);
    REQUIRE_EQ(function.instructions.size(), std::size_t{2});
    REQUIRE_EQ(analyzed.value().image.instructions.front().kind, binobf::InstructionKind::Opaque);
    REQUIRE_EQ(analyzed.value().image.instructions.front().encoding.size(), std::size_t{1});
    REQUIRE_EQ(analyzed.value().image.instructions.back().kind, binobf::InstructionKind::Return);
    REQUIRE(has_diagnostic(analyzed.value(), "analysis.decode_failed"));
}

TEST_CASE(object_analyzer_reports_out_of_range_symbols_without_guessing) {
    auto image = make_image({std::byte{0xc3}});
    add_function(image, 2, "outside", 99, 1);

    const auto analyzed = binobf::analyze_object(image);

    REQUIRE(analyzed.has_value());
    const auto& function = find_function(analyzed.value().image, "outside");
    REQUIRE(!function.complete);
    REQUIRE(function.instructions.empty());
    REQUIRE(has_diagnostic(analyzed.value(), "analysis.function_out_of_range"));
}

TEST_CASE(object_analyzer_clamps_inferred_ranges_before_out_of_range_symbols) {
    auto image = make_image({std::byte{0x90}, std::byte{0xc3}});
    add_function(image, 2, "valid", 0, 0);
    add_function(image, 3, "outside", 99, 0);

    const auto analyzed = binobf::analyze_object(image);

    REQUIRE(analyzed.has_value());
    const auto& valid = find_function(analyzed.value().image, "valid");
    const auto& outside = find_function(analyzed.value().image, "outside");
    REQUIRE_EQ(valid.size, UINT64_C(2));
    REQUIRE_EQ(valid.instructions.size(), std::size_t{2});
    REQUIRE(valid.complete);
    REQUIRE(outside.instructions.empty());
    REQUIRE(!outside.complete);
    REQUIRE(has_diagnostic(analyzed.value(), "analysis.function_out_of_range"));
}

TEST_CASE(object_analyzer_recovers_direct_conditional_and_fallthrough_cfg_edges) {
    auto image = make_image({
        std::byte{0x75}, std::byte{0x03},
        std::byte{0x90},
        std::byte{0xeb}, std::byte{0x02},
        std::byte{0x90}, std::byte{0xc3},
        std::byte{0xc3},
    });
    add_function(image, 2, "branches", 0, 8);

    const auto analyzed = binobf::analyze_object(image);

    REQUIRE(analyzed.has_value());
    const auto& function = find_function(analyzed.value().image, "branches");
    REQUIRE_EQ(function.basicBlocks.size(), std::size_t{4});
    REQUIRE(function.entryBlock.has_value());
    const auto& entry = find_block(analyzed.value().image, function, 0);
    const auto& fallthrough = find_block(analyzed.value().image, function, 2);
    const auto& taken = find_block(analyzed.value().image, function, 5);
    const auto& jumpTarget = find_block(analyzed.value().image, function, 7);
    REQUIRE_EQ(*function.entryBlock, entry.id);
    REQUIRE(has_edge(entry, binobf::ControlFlowEdgeKind::BranchTaken, taken.id));
    REQUIRE(has_edge(entry, binobf::ControlFlowEdgeKind::Fallthrough, fallthrough.id));
    REQUIRE(has_edge(fallthrough, binobf::ControlFlowEdgeKind::DirectBranch, jumpTarget.id));
    REQUIRE(taken.edges.empty());
    REQUIRE(jumpTarget.edges.empty());
}

TEST_CASE(object_analyzer_records_calls_and_unresolved_indirect_flow_explicitly) {
    auto directImage = make_image({
        std::byte{0xe8}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0xc3},
    });
    add_function(directImage, 2, "caller", 0, 6);
    const auto direct = binobf::analyze_object(directImage);
    REQUIRE(direct.has_value());
    const auto& caller = find_function(direct.value().image, "caller");
    REQUIRE_EQ(caller.basicBlocks.size(), std::size_t{2});
    const auto& callBlock = find_block(direct.value().image, caller, 0);
    const auto& returnBlock = find_block(direct.value().image, caller, 5);
    REQUIRE(has_edge(callBlock, binobf::ControlFlowEdgeKind::DirectCall, returnBlock.id));
    REQUIRE(has_edge(callBlock, binobf::ControlFlowEdgeKind::Fallthrough, returnBlock.id));

    auto indirectImage = make_image({std::byte{0xff}, std::byte{0xe0}});
    add_function(indirectImage, 2, "indirect", 0, 2);
    const auto indirect = binobf::analyze_object(indirectImage);
    REQUIRE(indirect.has_value());
    const auto& function = find_function(indirect.value().image, "indirect");
    const auto& block = find_block(indirect.value().image, function, 0);
    REQUIRE(!function.complete);
    REQUIRE(block.hasUnresolvedSuccessor);
    REQUIRE(has_edge(block, binobf::ControlFlowEdgeKind::UnresolvedIndirect, std::nullopt));
    REQUIRE(has_diagnostic(indirect.value(), "analysis.unresolved_indirect_flow"));
}

TEST_CASE(object_analyzer_replaces_placeholder_call_targets_with_relocation_references) {
    auto image = make_image({
        std::byte{0xe8}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0xc3},
    });
    add_function(image, 2, "caller", 0, 6);
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{3}, .formatIndex = 1, .formatTableIndex = 0,
        .formatType = 0x20, .formatStorage = 2, .formatSectionIndex = 0,
        .auxiliaryData = {}, .name = "external_target", .section = std::nullopt,
        .address = {}, .kind = binobf::SymbolKind::Function,
        .visibility = binobf::SymbolVisibility::External, .defined = false,
        .definition = binobf::SymbolDefinitionKind::Undefined,
        .commonAlignment = 0, .tlsModel = binobf::TlsModel::None, .lineage = {}});
    image.relocations.push_back(binobf::Relocation{
        .id = binobf::EntityId{4}, .formatIndex = 0, .formatTableIndex = 1,
        .section = binobf::EntityId{1}, .offset = 1,
        .kind = binobf::RelocationKind::PcRelative, .rawType = 4,
        .targetSymbol = binobf::EntityId{3}, .addend = 0, .lineage = {}});

    const auto analyzed = binobf::analyze_object(image);

    REQUIRE(analyzed.has_value());
    const auto& call = find_instruction_at(analyzed.value().image, 0);
    REQUIRE_EQ(call.kind, binobf::InstructionKind::DirectCall);
    REQUIRE(!call.directTarget.has_value());
    REQUIRE_EQ(call.references.size(), std::size_t{1});
    REQUIRE_EQ(call.references.front().kind, binobf::InstructionReferenceKind::CallTarget);
    REQUIRE_EQ(call.references.front().relocation, std::optional{binobf::EntityId{4}});
    REQUIRE_EQ(call.references.front().symbol, std::optional{binobf::EntityId{3}});
    REQUIRE(!call.references.front().address.has_value());
}

TEST_CASE(object_analyzer_computes_backward_register_liveness_across_branches) {
    auto image = make_image({
        std::byte{0x85}, std::byte{0xc0},
        std::byte{0x74}, std::byte{0x03},
        std::byte{0x89}, std::byte{0xd8},
        std::byte{0xc3},
        std::byte{0x89}, std::byte{0xc8},
        std::byte{0xc3},
    });
    add_function(image, 2, "liveness", 0, 10);

    const auto analyzed = binobf::analyze_object(image);

    REQUIRE(analyzed.has_value());
    const auto& function = find_function(analyzed.value().image, "liveness");
    const auto& entry = find_block(analyzed.value().image, function, 0);
    const auto& fallthrough = find_block(analyzed.value().image, function, 4);
    const auto& taken = find_block(analyzed.value().image, function, 7);
    REQUIRE(has_register_name(fallthrough.liveIn, "ebx"));
    REQUIRE(has_register_name(taken.liveIn, "ecx"));
    REQUIRE(has_register_name(entry.liveOut, "ebx"));
    REQUIRE(has_register_name(entry.liveOut, "ecx"));
    REQUIRE(has_register_name(entry.liveIn, "eax"));
}

int main() {
    return binobf::test::run_all();
}

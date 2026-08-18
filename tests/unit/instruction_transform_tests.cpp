#include "../test_support.hpp"

#include <binobf/analysis/object_analyzer.hpp>
#include <binobf/transforms/instruction.hpp>
#include <binobf/transforms/pass_manager.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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
        .formatIndex = static_cast<std::uint32_t>(image.symbols.size()),
        .formatTableIndex = 0, .formatType = 0x20, .formatStorage = 3,
        .formatSectionIndex = 1, .auxiliaryData = {}, .name = std::move(name),
        .section = binobf::EntityId{1},
        .address = binobf::BinaryAddress{offset, binobf::AddressKind::RelativeVirtual},
        .size = size, .kind = binobf::SymbolKind::Function,
        .visibility = binobf::SymbolVisibility::Local,
        .defined = true,
        .definition = binobf::SymbolDefinitionKind::SectionRelative,
        .commonAlignment = 0, .tlsModel = binobf::TlsModel::None, .lineage = {}});
}

auto add_external_symbol(binobf::BinaryImage& image, std::string name)
    -> binobf::EntityId {
    const auto id = binobf::EntityId{100 + image.symbols.size()};
    image.symbols.push_back(binobf::Symbol{
        .id = id,
        .formatIndex = static_cast<std::uint32_t>(image.symbols.size()),
        .formatTableIndex = 0, .formatType = 0, .formatStorage = 2,
        .formatSectionIndex = 0, .auxiliaryData = {}, .name = std::move(name),
        .section = std::nullopt, .address = {}, .size = 0,
        .kind = binobf::SymbolKind::Object,
        .visibility = binobf::SymbolVisibility::External,
        .defined = false,
        .definition = binobf::SymbolDefinitionKind::Undefined,
        .commonAlignment = 0, .tlsModel = binobf::TlsModel::None, .lineage = {}});
    return id;
}

void add_relocation(
    binobf::BinaryImage& image,
    std::uint32_t index,
    std::uint64_t offset,
    binobf::EntityId target) {
    image.relocations.push_back(binobf::Relocation{
        .id = binobf::EntityId{200 + index}, .formatIndex = index,
        .formatTableIndex = 1, .section = binobf::EntityId{1}, .offset = offset,
        .kind = binobf::RelocationKind::PcRelative, .rawType = 4,
        .targetSymbol = target, .addend = 0, .lineage = {}});
}

auto run_pass(
    binobf::BinaryImage image,
    std::unique_ptr<binobf::TransformPass> pass,
    std::uint64_t seed = 7) -> binobf::TransformationOutcome {
    binobf::PassManager manager;
    REQUIRE(manager.add(std::move(pass)).has_value());
    binobf::TransformContext context{seed, false};
    auto outcome = manager.run(context, image);
    if (!outcome.has_value()) {
        throw std::runtime_error(outcome.error().code + ": " + outcome.error().message);
    }
    return std::move(outcome).value();
}

auto bytes(std::initializer_list<unsigned int> values) -> std::vector<std::byte> {
    std::vector<std::byte> result;
    result.reserve(values.size());
    for (const auto value : values) result.push_back(static_cast<std::byte>(value));
    return result;
}

auto symbol_named(const binobf::BinaryImage& image, std::string_view name)
    -> const binobf::Symbol& {
    const auto found = std::find_if(
        image.symbols.begin(), image.symbols.end(), [name](const auto& symbol) {
            return symbol.name == name;
        });
    if (found == image.symbols.end()) throw std::runtime_error("missing symbol");
    return *found;
}

} // namespace

TEST_CASE(instruction_substitution_changes_only_a_validated_multibyte_nop) {
    auto image = make_image(bytes({0x0f, 0x1f, 0x00, 0xc3}));
    add_function(image, 2, "substitute", 0, 4);
    const auto original = image.sections.front().contents;

    const auto outcome = run_pass(image, binobf::make_instruction_substitution_pass(), 11);

    REQUIRE(outcome.changed);
    REQUIRE_EQ(outcome.reports.front().statistics.changed, std::size_t{1});
    REQUIRE(outcome.image.sections.front().contents != original);
    REQUIRE_EQ(outcome.image.sections.front().contents.size(), original.size());
    const auto analyzed = binobf::analyze_object(outcome.image);
    REQUIRE(analyzed.has_value());
    REQUIRE(analyzed.value().image.functions.front().complete);
    REQUIRE_EQ(analyzed.value().image.instructions.front().mnemonic, "nop");
}

TEST_CASE(instruction_substitution_honors_function_selection) {
    auto image = make_image(bytes({
        0x0f, 0x1f, 0x00, 0xc3,
        0x0f, 0x1f, 0x00, 0xc3}));
    add_function(image, 2, "selected", 0, 4);
    add_function(image, 3, "excluded", 4, 4);
    const auto original = image.sections.front().contents;

    binobf::PassManager manager;
    REQUIRE(manager.add(binobf::make_instruction_substitution_pass()).has_value());
    binobf::TransformContext context{11, false};
    binobf::FunctionSelectionPolicy policy;
    policy.includeNames = {"selected"};
    REQUIRE(context.set_function_selection(std::move(policy)).has_value());
    const auto transformed = manager.run(context, image);
    REQUIRE(transformed.has_value());
    REQUIRE(transformed.value().changed);
    const auto& output = transformed.value().image.sections.front().contents;
    REQUIRE(!std::equal(output.begin(), output.begin() + 4, original.begin()));
    REQUIRE(std::equal(output.begin() + 4, output.end(), original.begin() + 4));
}

TEST_CASE(constant_rewriting_preserves_a_sign_extended_mov_value_and_size) {
    auto image = make_image(bytes({
        0x48, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc3}));
    add_function(image, 2, "constant", 0, 11);

    const auto outcome = run_pass(image, binobf::make_constant_rewriting_pass(), 19);

    REQUIRE(outcome.changed);
    REQUIRE_EQ(outcome.image.sections.front().contents.size(), std::size_t{11});
    REQUIRE_EQ(outcome.image.sections.front().contents.at(0), std::byte{0x48});
    REQUIRE_EQ(outcome.image.sections.front().contents.at(1), std::byte{0xc7});
    const auto analyzed = binobf::analyze_object(outcome.image);
    REQUIRE(analyzed.has_value());
    REQUIRE(analyzed.value().image.functions.front().complete);
    REQUIRE_EQ(analyzed.value().image.instructions.front().mnemonic, "mov");
    REQUIRE_CONTAINS(analyzed.value().image.instructions.front().operands, "0x2a");
}

TEST_CASE(constant_rewriting_uses_an_untargeted_nop_for_a_32_bit_alternate_encoding) {
    auto image = make_image(bytes({0xb8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xc3}));
    add_function(image, 2, "constant32", 0, 7);

    const auto outcome = run_pass(image, binobf::make_constant_rewriting_pass());

    REQUIRE(outcome.changed);
    REQUIRE_EQ(outcome.image.sections.front().contents,
        bytes({0xc7, 0xc0, 0x78, 0x56, 0x34, 0x12, 0xc3}));
    const auto analyzed = binobf::analyze_object(outcome.image);
    REQUIRE(analyzed.has_value());
    REQUIRE(analyzed.value().image.functions.front().complete);
}

TEST_CASE(branch_inversion_exchanges_direct_targets_without_changing_size) {
    auto image = make_image(bytes({0x74, 0x02, 0xeb, 0x01, 0xc3, 0xc3}));
    add_function(image, 2, "branch", 0, 6);

    const auto outcome = run_pass(image, binobf::make_branch_inversion_pass());

    REQUIRE(outcome.changed);
    REQUIRE_EQ(outcome.image.sections.front().contents,
        bytes({0x75, 0x03, 0xeb, 0x00, 0xc3, 0xc3}));
    const auto analyzed = binobf::analyze_object(outcome.image);
    REQUIRE(analyzed.has_value());
    REQUIRE(analyzed.value().image.functions.front().complete);
}

TEST_CASE(branch_inversion_declines_a_relocated_branch_operand) {
    auto image = make_image(bytes({0x74, 0x02, 0xeb, 0x01, 0xc3, 0xc3}));
    add_function(image, 2, "relocated_branch", 0, 6);
    const auto external = add_external_symbol(image, "external_target");
    add_relocation(image, 0, 1, external);
    const auto original = image.sections.front().contents;

    const auto outcome = run_pass(image, binobf::make_branch_inversion_pass());

    REQUIRE(!outcome.changed);
    REQUIRE_EQ(outcome.image.sections.front().contents, original);
    REQUIRE_EQ(outcome.reports.front().statistics.changed, std::size_t{0});
}

TEST_CASE(branch_inversion_declines_a_pair_whose_second_jump_has_an_incoming_edge) {
    auto image = make_image(bytes({
        0xeb, 0x02, 0x74, 0x02, 0xeb, 0x01, 0xc3, 0xc3}));
    add_function(image, 2, "incoming", 0, 8);
    const auto original = image.sections.front().contents;

    const auto outcome = run_pass(image, binobf::make_branch_inversion_pass());

    REQUIRE(!outcome.changed);
    REQUIRE_EQ(outcome.image.sections.front().contents, original);
}

TEST_CASE(block_splitting_materializes_a_real_jump_to_the_next_boundary) {
    auto image = make_image(bytes({0x31, 0xc0, 0x0f, 0x1f, 0x00, 0x83, 0xc0, 0x01, 0xc3}));
    add_function(image, 2, "split", 0, 9);
    const auto before = binobf::analyze_object(image);
    REQUIRE(before.has_value());

    const auto outcome = run_pass(image, binobf::make_block_splitting_pass());

    REQUIRE(outcome.changed);
    REQUIRE_EQ(outcome.image.sections.front().contents.at(2), std::byte{0xeb});
    REQUIRE_EQ(outcome.image.sections.front().contents.at(3), std::byte{0x00});
    const auto after = binobf::analyze_object(outcome.image);
    REQUIRE(after.has_value());
    REQUIRE(after.value().image.functions.front().complete);
    REQUIRE(after.value().image.basicBlocks.size() > before.value().image.basicBlocks.size());
}

TEST_CASE(dead_code_insertion_materializes_a_valid_unreachable_nop_region) {
    auto image = make_image(bytes({
        0x31, 0xc0, 0x0f, 0x1f, 0x00, 0x83, 0xc0, 0x01, 0xc3}));
    add_function(image, 2, "dead_code", 0, 9);

    const auto outcome = run_pass(image, binobf::make_dead_code_insertion_pass(), 31);

    REQUIRE(outcome.changed);
    REQUIRE_EQ(outcome.image.sections.front().contents.at(2), std::byte{0xeb});
    REQUIRE_EQ(outcome.image.sections.front().contents.at(3), std::byte{0x01});
    REQUIRE_EQ(outcome.image.sections.front().contents.at(4), std::byte{0x90});
    REQUIRE_EQ(outcome.image.sections.front().lineage.parents.back().passName,
        "dead-code-insertion");
    const auto analyzed = binobf::analyze_object(outcome.image);
    REQUIRE(analyzed.has_value());
    REQUIRE(analyzed.value().image.functions.front().complete);
    const auto jump = std::find_if(
        analyzed.value().image.instructions.begin(),
        analyzed.value().image.instructions.end(), [](const auto& instruction) {
            return instruction.sectionOffset == 2;
        });
    REQUIRE(jump != analyzed.value().image.instructions.end());
    REQUIRE_EQ(jump->kind, binobf::InstructionKind::DirectBranch);
    REQUIRE(jump->directTarget.has_value());
    REQUIRE_EQ(jump->directTarget->value, UINT64_C(5));
}

TEST_CASE(dead_code_insertion_declines_relocation_overlapped_nop_regions) {
    auto image = make_image(bytes({0x31, 0xc0, 0x0f, 0x1f, 0x00, 0xc3}));
    add_function(image, 2, "relocated_dead_code", 0, 6);
    const auto external = add_external_symbol(image, "external_target");
    add_relocation(image, 0, 3, external);
    const auto original = image.sections.front().contents;

    const auto outcome = run_pass(image, binobf::make_dead_code_insertion_pass(), 31);

    REQUIRE(!outcome.changed);
    REQUIRE_EQ(outcome.image.sections.front().contents, original);
}

TEST_CASE(block_reordering_moves_nonentry_blocks_and_repairs_short_branches) {
    auto image = make_image(bytes({
        0x31, 0xc0, 0xeb, 0x05,
        0x83, 0xc0, 0x02, 0xeb, 0x05,
        0x83, 0xc0, 0x28, 0xeb, 0xf6,
        0xc3}));
    add_function(image, 2, "reorder_blocks", 0, 15);
    const auto original = image.sections.front().contents;

    const auto first = run_pass(image, binobf::make_block_reordering_pass(), 91);
    const auto repeated = run_pass(image, binobf::make_block_reordering_pass(), 91);

    REQUIRE(first.changed);
    REQUIRE_EQ(first.image.sections.front().lineage.parents.back().passName,
        "block-reordering");
    REQUIRE(first.image.sections.front().contents != original);
    REQUIRE_EQ(first.image.sections.front().contents,
        repeated.image.sections.front().contents);
    const auto analyzed = binobf::analyze_object(first.image);
    REQUIRE(analyzed.has_value());
    REQUIRE(analyzed.value().image.functions.front().complete);
    REQUIRE_EQ(analyzed.value().image.functions.front().basicBlocks.size(),
        std::size_t{4});
    for (const auto instructionId : analyzed.value().image.functions.front().instructions) {
        const auto instruction = std::find_if(
            analyzed.value().image.instructions.begin(),
            analyzed.value().image.instructions.end(), [&](const auto& candidate) {
                return candidate.id == instructionId;
            });
        REQUIRE(instruction != analyzed.value().image.instructions.end());
        if (instruction->kind == binobf::InstructionKind::DirectBranch) {
            REQUIRE(instruction->directTarget.has_value());
            REQUIRE(instruction->directTarget->value < UINT64_C(15));
        }
    }
}

TEST_CASE(block_reordering_repairs_near_branches_and_declines_fallthrough_cfgs) {
    auto nearImage = make_image(bytes({
        0xe9, 0x05, 0x00, 0x00, 0x00,
        0xe9, 0x05, 0x00, 0x00, 0x00,
        0xe9, 0xf6, 0xff, 0xff, 0xff,
        0xc3}));
    add_function(nearImage, 2, "near_blocks", 0, 16);
    const auto reordered = run_pass(
        nearImage, binobf::make_block_reordering_pass(), 17);
    REQUIRE(reordered.changed);
    const auto analyzed = binobf::analyze_object(reordered.image);
    REQUIRE(analyzed.has_value());
    REQUIRE(analyzed.value().image.functions.front().complete);

    auto fallthrough = make_image(bytes({
        0x31, 0xc0, 0x74, 0x02, 0x40, 0xc3, 0xc3}));
    add_function(fallthrough, 2, "fallthrough", 0, 7);
    const auto original = fallthrough.sections.front().contents;
    const auto refused = run_pass(
        fallthrough, binobf::make_block_reordering_pass(), 17);
    REQUIRE(!refused.changed);
    REQUIRE_EQ(refused.image.sections.front().contents, original);
}

TEST_CASE(function_reordering_moves_whole_chunks_and_repairs_symbols_deterministically) {
    auto image = make_image(bytes({
        0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x90, 0x90,
        0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3}));
    add_function(image, 2, "first", 0, 6);
    add_function(image, 3, "second", 8, 6);

    const auto first = run_pass(image, binobf::make_function_reordering_pass(), 23);
    const auto repeated = run_pass(image, binobf::make_function_reordering_pass(), 23);

    REQUIRE(first.changed);
    REQUIRE_EQ(first.image.sections.front().contents, repeated.image.sections.front().contents);
    REQUIRE_EQ(symbol_named(first.image, "second").address.value, UINT64_C(0));
    REQUIRE_EQ(symbol_named(first.image, "first").address.value, UINT64_C(6));
    REQUIRE_EQ(first.image.sections.front().contents.at(1), std::byte{0x02});
    REQUIRE_EQ(first.image.sections.front().contents.at(7), std::byte{0x01});
}

TEST_CASE(function_reordering_keeps_excluded_function_slots_fixed) {
    auto image = make_image(bytes({
        0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x90, 0x90,
        0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3, 0x90, 0x90,
        0xb8, 0x03, 0x00, 0x00, 0x00, 0xc3}));
    add_function(image, 2, "selected_one", 0, 6);
    add_function(image, 3, "selected_two", 8, 6);
    add_function(image, 4, "excluded", 16, 6);
    const auto excluded = std::vector<std::byte>(
        image.sections.front().contents.begin() + 16,
        image.sections.front().contents.end());

    binobf::PassManager manager;
    REQUIRE(manager.add(binobf::make_function_reordering_pass()).has_value());
    binobf::TransformContext context{23, false};
    binobf::FunctionSelectionPolicy policy;
    policy.includeRegex = {"^selected_.*$"};
    REQUIRE(context.set_function_selection(std::move(policy)).has_value());
    const auto transformed = manager.run(context, image);
    REQUIRE(transformed.has_value());
    REQUIRE(transformed.value().changed);
    REQUIRE_EQ(symbol_named(transformed.value().image, "excluded").address.value, UINT64_C(16));
    REQUIRE(std::equal(
        transformed.value().image.sections.front().contents.begin() + 16,
        transformed.value().image.sections.front().contents.end(), excluded.begin()));
}

TEST_CASE(function_reordering_repairs_relocation_sites_that_move_with_functions) {
    auto image = make_image(bytes({
        0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x90, 0x90,
        0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3}));
    add_function(image, 2, "first", 0, 6);
    add_function(image, 3, "second", 8, 6);
    const auto external = add_external_symbol(image, "external_data");
    add_relocation(image, 0, 2, external);
    add_relocation(image, 1, 10, external);

    const auto outcome = run_pass(image, binobf::make_function_reordering_pass(), 23);

    REQUIRE(outcome.changed);
    REQUIRE_EQ(outcome.image.relocations.at(0).offset, UINT64_C(8));
    REQUIRE_EQ(outcome.image.relocations.at(1).offset, UINT64_C(2));
}

TEST_CASE(function_reordering_declines_unrelocated_cross_function_direct_calls) {
    auto image = make_image(bytes({
        0xe8, 0x03, 0x00, 0x00, 0x00, 0xc3, 0x90, 0x90,
        0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3}));
    add_function(image, 2, "caller", 0, 6);
    add_function(image, 3, "callee", 8, 6);
    const auto original = image.sections.front().contents;

    const auto outcome = run_pass(image, binobf::make_function_reordering_pass(), 23);

    REQUIRE(!outcome.changed);
    REQUIRE_EQ(outcome.image.sections.front().contents, original);
}

TEST_CASE(instruction_passes_decline_unsupported_architectures_and_report_medium_risk) {
    auto image = make_image(bytes({0x90, 0xc3}));
    image.architecture = binobf::Architecture::ARM64;
    add_function(image, 2, "unsupported", 0, 2);
    auto pass = binobf::make_instruction_substitution_pass();
    const auto requirements = pass->requirements();
    REQUIRE_EQ(requirements.risk, binobf::PassRisk::Medium);
    REQUIRE(std::ranges::find(requirements.architectures, binobf::Architecture::X86)
            != requirements.architectures.end());
    REQUIRE(std::ranges::find(requirements.architectures, binobf::Architecture::X86_64)
            != requirements.architectures.end());

    const auto outcome = run_pass(image, std::move(pass));

    REQUIRE(!outcome.changed);
    REQUIRE_EQ(outcome.reports.front().status, binobf::PassStatus::Unsupported);
}

int main() {
    return binobf::test::run_all();
}

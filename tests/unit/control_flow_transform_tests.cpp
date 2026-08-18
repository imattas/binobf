#include "../test_support.hpp"

#include <binobf/ir/control_flow.hpp>
#include <binobf/ir/vm_lowering.hpp>
#include <binobf/vm/runtime.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <set>
#include <stdexcept>
#include <variant>
#include <utility>

namespace {

auto branching_function() -> binobf::ir::IrFunction {
    using namespace binobf::ir;
    return IrFunction{
        .sourceFunction = binobf::EntityId{10},
        .name = "branching",
        .arguments = {
            IrArgumentBinding{0, IrVariable{0}, IrWidth::U32},
            IrArgumentBinding{1, IrVariable{1}, IrWidth::U32},
        },
        .returnType = IrWidth::U32,
        .variableTypes = {IrWidth::U32, IrWidth::U32, IrWidth::U32},
        .storageLocations = {},
        .signature = IrFunctionSignature{
            .callingConvention = IrCallingConvention::C,
            .parameterTypes = {IrWidth::U32, IrWidth::U32},
            .returnType = IrWidth::U32,
            .variadic = false,
            .parameterBindings = {},
            .returnBinding = std::nullopt,
            .clobbers = {},
            .mayUnwind = false,
        },
        .entry = IrBlockId{0},
        .blocks = {
            IrBlock{IrBlockId{0}, binobf::EntityId{20}, {
                IrMove{IrWidth::U32, IrVariable{2}, IrVariableOperand{IrVariable{0}},
                       binobf::EntityId{30}},
                IrCompare{IrWidth::U32, IrVariable{0}, IrVariableOperand{IrVariable{1}},
                          binobf::EntityId{31}},
                IrConditionalJump{IrCondition::SignedLess, IrBlockId{1}, IrBlockId{2},
                                  binobf::EntityId{32}},
            }},
            IrBlock{IrBlockId{1}, binobf::EntityId{21}, {
                IrBinaryOperation{IrBinaryOpcode::Add, IrWidth::U32, IrVariable{2},
                                  IrVariableOperand{IrVariable{1}}, binobf::EntityId{33}},
                IrReturn{IrWidth::U32, IrVariable{2}, binobf::EntityId{34}},
            }},
            IrBlock{IrBlockId{2}, binobf::EntityId{22}, {
                IrBinaryOperation{IrBinaryOpcode::Subtract, IrWidth::U32, IrVariable{2},
                                  IrVariableOperand{IrVariable{1}}, binobf::EntityId{35}},
                IrReturn{IrWidth::U32, IrVariable{2}, binobf::EntityId{36}},
            }},
        },
        .unwindRegions = {},
    };
}

auto execute(
    const binobf::ir::IrFunction& function,
    std::uint32_t left,
    std::uint32_t right) -> std::uint64_t {
    const auto lowered = binobf::ir::lower_to_vm(function);
    if (!lowered.has_value()) {
        throw std::runtime_error(lowered.error().code + ": " + lowered.error().message);
    }
    binobf::vm::LinearVmMemory memory{0};
    binobf::vm::RejectingVmNativeCallBridge bridge;
    const auto result = binobf::vm::execute_program(
        lowered.value().program, memory, bridge,
        binobf::vm::VmExecutionInput{{
            binobf::vm::VmValue::from_bits(binobf::vm::VmWidth::U32, left),
            binobf::vm::VmValue::from_bits(binobf::vm::VmWidth::U32, right),
        }});
    if (!result.has_value()) {
        throw std::runtime_error(result.error().code + ": " + result.error().message);
    }
    return result.value().returnValue.bits();
}

} // namespace

TEST_CASE(cfg_flattening_is_deterministic_for_a_seed_and_varies_across_seeds) {
    const auto first = binobf::ir::flatten_control_flow(branching_function(), 71);
    const auto second = binobf::ir::flatten_control_flow(branching_function(), 71);
    const auto varied = binobf::ir::flatten_control_flow(branching_function(), 72);
    REQUIRE(first.has_value());
    REQUIRE(second.has_value());
    REQUIRE(varied.has_value());
    REQUIRE_EQ(first.value(), second.value());
    REQUIRE(!(first.value() == varied.value()));
    REQUIRE(binobf::ir::validate_function(first.value().function).has_value());
    REQUIRE(!binobf::ir::function_contains_fallback(first.value().function));
}

TEST_CASE(cfg_flattening_builds_unique_cases_dispatchers_and_transitions) {
    const auto flattened = binobf::ir::flatten_control_flow(branching_function(), 99);
    REQUIRE(flattened.has_value());
    REQUIRE_EQ(flattened.value().cases.size(), std::size_t{3});
    std::set<std::uint32_t> values;
    for (const auto& item : flattened.value().cases) values.insert(item.value);
    REQUIRE_EQ(values.size(), flattened.value().cases.size());
    REQUIRE_EQ(flattened.value().statistics.originalBlocks, std::size_t{3});
    REQUIRE_EQ(flattened.value().statistics.dispatcherBlocks, std::size_t{3});
    REQUIRE_EQ(flattened.value().statistics.transitionBlocks, std::size_t{2});
    REQUIRE_EQ(flattened.value().statistics.bogusBlocks, std::size_t{1});
    REQUIRE_EQ(flattened.value().function.blocks.size(), std::size_t{10});
}

TEST_CASE(cfg_flattening_bogus_edges_are_fixed_program_local_and_side_effect_free) {
    using namespace binobf::ir;
    const auto flattened = flatten_control_flow(branching_function(), 123);
    REQUIRE(flattened.has_value());
    const auto bogus = std::find_if(
        flattened.value().function.blocks.begin(), flattened.value().function.blocks.end(),
        [&](const auto& block) { return block.id == flattened.value().bogusBlock; });
    REQUIRE(bogus != flattened.value().function.blocks.end());
    REQUIRE_EQ(bogus->instructions.size(), std::size_t{1});
    REQUIRE(std::holds_alternative<IrJump>(bogus->instructions[0]));

    std::size_t opaqueEdges = 0;
    for (const auto& block : flattened.value().function.blocks) {
        if (block.instructions.size() < 2) continue;
        const auto* compare = std::get_if<IrCompare>(
            &block.instructions[block.instructions.size() - 2]);
        const auto* branch = std::get_if<IrConditionalJump>(&block.instructions.back());
        if (compare == nullptr || branch == nullptr
            || branch->falseTarget != flattened.value().bogusBlock) {
            continue;
        }
        const auto* right = std::get_if<IrVariableOperand>(&compare->right);
        if (right == nullptr) continue;
        REQUIRE_EQ(compare->left, flattened.value().dispatcherState);
        REQUIRE_EQ(right->variable, flattened.value().dispatcherState);
        REQUIRE_EQ(branch->condition, IrCondition::Equal);
        REQUIRE_EQ(branch->trueTarget, flattened.value().dispatcherEntry);
        ++opaqueEdges;
    }
    REQUIRE_EQ(opaqueEdges, std::size_t{3});
}

TEST_CASE(cfg_flattening_preserves_vm_semantics_for_signed_and_wrapping_inputs) {
    const auto original = branching_function();
    const auto flattened = binobf::ir::flatten_control_flow(original, UINT64_C(0x9f17));
    REQUIRE(flattened.has_value());
    constexpr std::array inputs{
        std::pair{UINT32_C(0), UINT32_C(0)},
        std::pair{UINT32_C(2), UINT32_C(5)},
        std::pair{UINT32_C(9), UINT32_C(4)},
        std::pair{UINT32_C(0xffffffff), UINT32_C(1)},
        std::pair{UINT32_C(0x80000000), UINT32_C(0x7fffffff)},
    };
    for (const auto [left, right] : inputs) {
        REQUIRE_EQ(
            execute(flattened.value().function, left, right),
            execute(original, left, right));
    }
}

TEST_CASE(cfg_flattening_rejects_fallbacks_and_resource_exhaustion) {
    auto fallback = branching_function();
    fallback.blocks[0].instructions.insert(
        fallback.blocks[0].instructions.begin(),
        binobf::ir::IrFallback{
            binobf::EntityId{29}, {}, "unsupported",
            binobf::ir::IrFallbackEffects{{}, {}, {}, true, true, true, true, true},
            std::nullopt});
    auto result = binobf::ir::flatten_control_flow(fallback, 1);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.fallback_blocks_transform");

    binobf::ir::IrLimits limits;
    limits.maxBlocks = 5;
    result = binobf::ir::flatten_control_flow(branching_function(), 1, limits);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.block_limit");
}

int main() {
    return binobf::test::run_all();
}

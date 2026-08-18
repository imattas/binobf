#include "../test_support.hpp"

#include <binobf/ir/outlining.hpp>
#include <binobf/ir/vm_lowering.hpp>
#include <binobf/vm/runtime.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
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
        .returnWidth = IrWidth::U32,
        .variableWidths = {IrWidth::U32, IrWidth::U32, IrWidth::U32},
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
    };
}

auto execute(
    const binobf::vm::VmProgram& program,
    std::uint32_t left,
    std::uint32_t right) -> std::uint64_t {
    binobf::vm::LinearVmMemory memory{0};
    binobf::vm::RejectingVmNativeCallBridge bridge;
    const auto result = binobf::vm::execute_program(
        program, memory, bridge,
        binobf::vm::VmExecutionInput{{
            binobf::vm::VmValue::from_bits(binobf::vm::VmWidth::U32, left),
            binobf::vm::VmValue::from_bits(binobf::vm::VmWidth::U32, right),
        }});
    if (!result.has_value()) {
        throw std::runtime_error(result.error().code + ": " + result.error().message);
    }
    return result.value().returnValue.bits();
}

auto execute_function(
    const binobf::ir::IrFunction& function,
    std::uint32_t left,
    std::uint32_t right) -> std::uint64_t {
    const auto lowered = binobf::ir::lower_to_vm(function);
    if (!lowered.has_value()) throw std::runtime_error(lowered.error().message);
    return execute(lowered.value().program, left, right);
}

auto execute_module(
    const binobf::ir::IrModule& module,
    std::uint32_t left,
    std::uint32_t right) -> std::uint64_t {
    const auto lowered = binobf::ir::lower_module_to_vm(module);
    if (!lowered.has_value()) throw std::runtime_error(lowered.error().message);
    return execute(lowered.value().program, left, right);
}

} // namespace

TEST_CASE(function_splitting_creates_a_real_wrapper_and_internal_helper) {
    using namespace binobf::ir;
    const auto split = split_function(branching_function(), 77);
    REQUIRE(split.has_value());
    REQUIRE(validate_module(split.value().module).has_value());
    REQUIRE_EQ(split.value().module.functions.size(), std::size_t{2});
    REQUIRE_EQ(split.value().statistics.movedBlocks, std::size_t{3});
    REQUIRE_EQ(split.value().module.functions[0].sourceFunction, binobf::EntityId{10});
    REQUIRE_EQ(split.value().module.functions[1].sourceFunction, split.value().helperFunction);
    const auto& wrapperInstructions = split.value().module.functions[0].blocks[0].instructions;
    REQUIRE_EQ(wrapperInstructions.size(), std::size_t{2});
    REQUIRE(std::holds_alternative<IrInternalCall>(wrapperInstructions[0]));
    REQUIRE(std::holds_alternative<IrReturn>(wrapperInstructions[1]));
}

TEST_CASE(function_splitting_is_seeded_and_preserves_execution) {
    const auto source = branching_function();
    const auto first = binobf::ir::split_function(source, 100);
    const auto repeated = binobf::ir::split_function(source, 100);
    const auto varied = binobf::ir::split_function(source, 101);
    REQUIRE(first.has_value());
    REQUIRE(repeated.has_value());
    REQUIRE(varied.has_value());
    REQUIRE_EQ(first.value(), repeated.value());
    REQUIRE(first.value().helperFunction != varied.value().helperFunction);
    constexpr std::array inputs{
        std::pair{UINT32_C(2), UINT32_C(5)},
        std::pair{UINT32_C(9), UINT32_C(4)},
        std::pair{UINT32_C(0xffffffff), UINT32_C(1)},
    };
    for (const auto [left, right] : inputs) {
        REQUIRE_EQ(execute_module(first.value().module, left, right),
                   execute_function(source, left, right));
    }
}

TEST_CASE(block_outlining_computes_live_ins_and_replaces_only_the_selected_return_block) {
    using namespace binobf::ir;
    const auto outlined = outline_block(branching_function(), IrBlockId{1}, 33);
    REQUIRE(outlined.has_value());
    REQUIRE(validate_module(outlined.value().module).has_value());
    REQUIRE_EQ(outlined.value().statistics.movedBlocks, std::size_t{1});
    REQUIRE_EQ(outlined.value().statistics.liveInVariables, std::size_t{2});
    const auto& main = outlined.value().module.functions[0];
    const auto selected = std::find_if(main.blocks.begin(), main.blocks.end(),
        [](const auto& block) { return block.id == IrBlockId{1}; });
    REQUIRE(selected != main.blocks.end());
    REQUIRE_EQ(selected->instructions.size(), std::size_t{2});
    REQUIRE(std::holds_alternative<IrInternalCall>(selected->instructions[0]));
    REQUIRE(std::holds_alternative<IrReturn>(selected->instructions[1]));
    REQUIRE_EQ(outlined.value().module.functions[1].arguments.size(), std::size_t{2});
}

TEST_CASE(block_outlining_preserves_taken_and_non_taken_execution_paths) {
    const auto source = branching_function();
    const auto outlined = binobf::ir::outline_block(source, binobf::ir::IrBlockId{1}, 44);
    REQUIRE(outlined.has_value());
    REQUIRE_EQ(execute_module(outlined.value().module, 2, 5),
               execute_function(source, 2, 5));
    REQUIRE_EQ(execute_module(outlined.value().module, 9, 4),
               execute_function(source, 9, 4));
}

TEST_CASE(block_outlining_rejects_entry_non_return_and_fallback_blocks) {
    auto result = binobf::ir::outline_block(
        branching_function(), binobf::ir::IrBlockId{0}, 1);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.outline_entry_block");

    result = binobf::ir::outline_block(
        branching_function(), binobf::ir::IrBlockId{99}, 1);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.outline_block_missing");

    auto fallback = branching_function();
    fallback.blocks[1].instructions.insert(
        fallback.blocks[1].instructions.begin(),
        binobf::ir::IrFallback{binobf::EntityId{39}, {}, "unsupported"});
    result = binobf::ir::outline_block(fallback, binobf::ir::IrBlockId{1}, 1);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.fallback_not_transformable");
}

int main() {
    return binobf::test::run_all();
}

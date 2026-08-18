#include "../test_support.hpp"

#include <binobf/ir/vm_lowering.hpp>
#include <binobf/vm/bytecode.hpp>
#include <binobf/vm/runtime.hpp>

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <variant>

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

auto internal_call_module() -> binobf::ir::IrModule {
    using namespace binobf::ir;
    auto helper = branching_function();
    helper.sourceFunction = binobf::EntityId{11};
    helper.name = "helper";
    IrFunction wrapper{
        .sourceFunction = binobf::EntityId{10},
        .name = "wrapper",
        .arguments = {
            IrArgumentBinding{0, IrVariable{0}, IrWidth::U32},
            IrArgumentBinding{1, IrVariable{1}, IrWidth::U32},
        },
        .returnWidth = IrWidth::U32,
        .variableWidths = {IrWidth::U32, IrWidth::U32, IrWidth::U32},
        .entry = IrBlockId{0},
        .blocks = {IrBlock{IrBlockId{0}, binobf::EntityId{50}, {
            IrInternalCall{
                helper.sourceFunction, IrWidth::U32, IrVariable{2},
                {IrVariableOperand{IrVariable{0}}, IrVariableOperand{IrVariable{1}}},
                binobf::EntityId{51}},
            IrReturn{IrWidth::U32, IrVariable{2}, binobf::EntityId{52}},
        }}},
    };
    return IrModule{
        .entryFunction = wrapper.sourceFunction,
        .functions = {std::move(wrapper), std::move(helper)},
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

} // namespace

TEST_CASE(vm_lowering_preserves_two_way_control_flow) {
    const auto lowered = binobf::ir::lower_to_vm(branching_function());
    REQUIRE(lowered.has_value());
    REQUIRE(binobf::vm::validate_program(lowered.value().program).has_value());
    REQUIRE_EQ(execute(lowered.value().program, 2, 5), UINT64_C(7));
    REQUIRE_EQ(execute(lowered.value().program, 9, 4), UINT64_C(5));
    REQUIRE(!lowered.value().lineage.empty());
    REQUIRE_EQ(lowered.value().lineage.size(), lowered.value().program.instructions.size());
}

TEST_CASE(vm_lowering_is_deterministic_and_survives_bytecode_round_trip) {
    const auto first = binobf::ir::lower_to_vm(branching_function());
    const auto second = binobf::ir::lower_to_vm(branching_function());
    REQUIRE(first.has_value());
    REQUIRE(second.has_value());
    REQUIRE_EQ(first.value().program, second.value().program);
    REQUIRE_EQ(first.value().lineage, second.value().lineage);

    const auto assembled = binobf::vm::assemble_program(
        first.value().program, binobf::vm::VmAssemblyOptions{UINT64_C(0x8128)});
    REQUIRE(assembled.has_value());
    const auto decoded = binobf::vm::decode_program(assembled.value());
    REQUIRE(decoded.has_value());
    REQUIRE_EQ(execute(decoded.value().program, 0xffffffffU, 1), UINT64_C(0));
}

TEST_CASE(vm_lowering_materializes_immediates_and_preserves_wrapping_width) {
    auto function = branching_function();
    function.blocks = {binobf::ir::IrBlock{
        binobf::ir::IrBlockId{0}, binobf::EntityId{20}, {
            binobf::ir::IrMove{
                binobf::ir::IrWidth::U32, binobf::ir::IrVariable{2},
                binobf::ir::IrVariableOperand{binobf::ir::IrVariable{0}},
                binobf::EntityId{30}},
            binobf::ir::IrBinaryOperation{
                binobf::ir::IrBinaryOpcode::Add, binobf::ir::IrWidth::U32,
                binobf::ir::IrVariable{2},
                binobf::ir::IrImmediateOperand{binobf::ir::IrWidth::U32, 7},
                binobf::EntityId{31}},
            binobf::ir::IrReturn{
                binobf::ir::IrWidth::U32, binobf::ir::IrVariable{2},
                binobf::EntityId{32}},
        }}};
    const auto lowered = binobf::ir::lower_to_vm(function);
    REQUIRE(lowered.has_value());
    REQUIRE_EQ(execute(lowered.value().program, 0xfffffffeU, 0), UINT64_C(5));
}

TEST_CASE(vm_lowering_rejects_fallbacks_and_invalid_ir) {
    auto fallback = branching_function();
    fallback.blocks[0].instructions.insert(
        fallback.blocks[0].instructions.begin(),
        binobf::ir::IrFallback{binobf::EntityId{29}, {}, "unsupported"});
    auto result = binobf::ir::lower_to_vm(fallback);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.fallback_not_lowerable");

    auto invalid = branching_function();
    invalid.blocks[0].instructions.pop_back();
    result = binobf::ir::lower_to_vm(invalid);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.block_unterminated");
}

TEST_CASE(vm_module_lowering_resolves_internal_calls_and_fresh_frames) {
    const auto lowered = binobf::ir::lower_module_to_vm(internal_call_module());
    REQUIRE(lowered.has_value());
    REQUIRE(binobf::vm::validate_program(lowered.value().program).has_value());
    REQUIRE_EQ(execute(lowered.value().program, 2, 5), UINT64_C(7));
    REQUIRE_EQ(execute(lowered.value().program, 9, 4), UINT64_C(5));
    REQUIRE_EQ(lowered.value().lineage.size(), lowered.value().program.instructions.size());

    const auto assembled = binobf::vm::assemble_program(
        lowered.value().program, binobf::vm::VmAssemblyOptions{991});
    REQUIRE(assembled.has_value());
    const auto decoded = binobf::vm::decode_program(assembled.value());
    REQUIRE(decoded.has_value());
    REQUIRE_EQ(execute(decoded.value().program, 0xffffffffU, 1), UINT64_C(0));
}

TEST_CASE(single_function_lowering_rejects_internal_calls_without_a_module) {
    auto module = internal_call_module();
    const auto result = binobf::ir::lower_to_vm(module.functions.front());
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.internal_call_requires_module");
}

int main() {
    return binobf::test::run_all();
}

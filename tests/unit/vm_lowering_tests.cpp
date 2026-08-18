#include "../test_support.hpp"

#include <binobf/ir/vm_lowering.hpp>
#include <binobf/vm/bytecode.hpp>
#include <binobf/vm/runtime.hpp>

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
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
        .returnType = IrWidth::U32,
        .variableTypes = {IrWidth::U32, IrWidth::U32, IrWidth::U32},
        .storageLocations = {},
        .signature = helper.signature,
        .entry = IrBlockId{0},
        .blocks = {IrBlock{IrBlockId{0}, binobf::EntityId{50}, {
            IrInternalCall{
                helper.sourceFunction, IrWidth::U32, IrVariable{2},
                {IrVariableOperand{IrVariable{0}}, IrVariableOperand{IrVariable{1}}},
                binobf::EntityId{51}, std::nullopt},
            IrReturn{IrWidth::U32, IrVariable{2}, binobf::EntityId{52}},
        }}},
        .unwindRegions = {},
    };
    return IrModule{
        .entryFunction = wrapper.sourceFunction,
        .declarations = {},
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

void require_unsupported(
    const binobf::ir::IrFunction& function,
    std::string_view node,
    std::uint64_t source) {
    const auto result = binobf::ir::lower_to_vm(function);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "vm.unsupported_native_ir");
    REQUIRE(result.error().message.find(node) != std::string::npos);
    REQUIRE(result.error().message.find(std::to_string(source)) != std::string::npos);
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
        binobf::ir::IrFallback{
            binobf::EntityId{29}, {}, "unsupported",
            binobf::ir::IrFallbackEffects{{}, {}, {}, true, true, true, true, true},
            std::nullopt});
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

TEST_CASE(vm_lowering_rejects_float_vector_and_memory_nodes_explicitly) {
    using namespace binobf::ir;
    for (const auto type : {
             IrType{IrTypeKind::FloatingPoint, 32U},
             IrType{IrTypeKind::Vector, 32U, 2U}}) {
        auto function = branching_function();
        function.variableTypes[2] = type;
        function.blocks = {IrBlock{
            IrBlockId{0}, binobf::EntityId{20}, {
                IrMove{type, IrVariable{2}, IrImmediateOperand{type, 0U},
                       binobf::EntityId{70}},
                IrReturn{IrWidth::U32, IrVariable{0}, binobf::EntityId{71}},
            }}};
        require_unsupported(function, "IrMove", 70U);
    }

    auto memory = branching_function();
    const IrType pointer{IrTypeKind::Pointer, 64U};
    memory.arguments.push_back(IrArgumentBinding{2U, IrVariable{3}, pointer});
    memory.signature.parameterTypes.push_back(pointer);
    memory.variableTypes.push_back(pointer);
    memory.blocks = {IrBlock{
        IrBlockId{0}, binobf::EntityId{20}, {
            IrLoad{IrWidth::U32, IrVariable{2},
                   IrAddress{IrVariable{3}, std::nullopt, 1U, 0, 0U, 4U},
                   IrByteOrder::Little, false, IrAtomicOrdering::None,
                   binobf::EntityId{72}, std::nullopt},
            IrReturn{IrWidth::U32, IrVariable{2}, binobf::EntityId{73}},
        }}};
    require_unsupported(memory, "IrLoad", 72U);
}

TEST_CASE(vm_lowering_rejects_advanced_control_calls_and_unwind_explicitly) {
    using namespace binobf::ir;
    auto switched = branching_function();
    switched.blocks[0].instructions.back() = IrSwitch{
        IrVariable{2}, {IrSwitchCase{1U, IrBlockId{1}}}, IrBlockId{2},
        binobf::EntityId{80}};
    require_unsupported(switched, "IrSwitch", 80U);

    auto indirect = branching_function();
    indirect.blocks[0].instructions.back() = IrIndirectJump{
        IrVariable{2}, {IrBlockId{1}, IrBlockId{2}}, binobf::EntityId{81}};
    require_unsupported(indirect, "IrIndirectJump", 81U);

    auto external = branching_function();
    external.blocks = {IrBlock{IrBlockId{0}, binobf::EntityId{20}, {
        IrExternalCall{"external", external.signature, IrVariable{2},
                       {IrVariableOperand{IrVariable{0}},
                        IrVariableOperand{IrVariable{1}}},
                       binobf::EntityId{82}, std::nullopt},
        IrReturn{IrWidth::U32, IrVariable{2}, binobf::EntityId{83}},
    }}};
    require_unsupported(external, "IrExternalCall", 82U);

    auto tail = branching_function();
    tail.blocks = {IrBlock{
        IrBlockId{0}, binobf::EntityId{20}, {
            IrTailCall{IrCallTarget{binobf::EntityId{11}}, tail.signature,
                       {IrVariableOperand{IrVariable{0}},
                        IrVariableOperand{IrVariable{1}}},
                       binobf::EntityId{84}, std::nullopt},
        }}};
    require_unsupported(tail, "IrTailCall", 84U);

    auto unwind = branching_function();
    unwind.unwindRegions = {
        IrUnwindRegion{1U, IrUnwindRegionKind::Cleanup, std::nullopt,
                       IrBlockId{2}, {IrBlockId{1}}, {"cleanup"}},
    };
    require_unsupported(unwind, "IrUnwindRegion", 10U);
}

int main() {
    return binobf::test::run_all();
}

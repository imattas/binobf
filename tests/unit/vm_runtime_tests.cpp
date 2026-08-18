#include "../test_support.hpp"

#include <binobf/vm/bytecode.hpp>
#include <binobf/vm/native_runtime.hpp>
#include <binobf/vm/runtime.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace {

class SumBridge final : public binobf::vm::VmNativeCallBridge {
public:
    auto invoke(
        std::uint32_t functionId,
        std::span<const binobf::vm::VmValue> arguments)
        -> binobf::Result<binobf::vm::VmValue, binobf::Diagnostic> override {
        if (functionId != 7 || arguments.size() != 2) {
            return binobf::Result<binobf::vm::VmValue, binobf::Diagnostic>::failure(
                binobf::Diagnostic{binobf::DiagnosticSeverity::Error,
                                   "test.native_rejected", "unexpected native call"});
        }
        return binobf::Result<binobf::vm::VmValue, binobf::Diagnostic>::success(
            binobf::vm::VmValue::from_bits(
                binobf::vm::VmWidth::U64,
                arguments[0].bits() + arguments[1].bits()));
    }
};

auto execute(
    binobf::vm::VmProgram program,
    binobf::vm::VmMemory& memory,
    binobf::vm::VmNativeCallBridge& bridge,
    const binobf::vm::VmExecutionInput& input = {},
    const binobf::vm::VmLimits& limits = {}) -> binobf::vm::VmExecutionResult {
    const auto result = binobf::vm::execute_program(program, memory, bridge, input, limits);
    if (!result.has_value()) {
        throw std::runtime_error(result.error().code + ": " + result.error().message);
    }
    return result.value();
}

auto binary_program(
    binobf::vm::VmBinaryOpcode opcode,
    std::uint64_t left,
    std::uint64_t right,
    binobf::vm::VmWidth width = binobf::vm::VmWidth::U64)
    -> binobf::vm::VmProgram {
    using namespace binobf::vm;
    return VmProgram{
        .version = currentVmVersion,
        .registerCount = 3,
        .slotCount = 0,
        .localMemorySize = 0,
        .instructions = {
            VmLoadConstant{VmRegister{0}, VmValue::from_bits(width, left)},
            VmLoadConstant{VmRegister{1}, VmValue::from_bits(width, right)},
            VmBinaryOperation{opcode, width, VmRegister{2}, VmRegister{0}, VmRegister{1}},
            VmReturn{VmRegister{2}},
        },
    };
}

auto condition_program(
    binobf::vm::VmCondition condition,
    std::uint64_t left,
    std::uint64_t right,
    binobf::vm::VmWidth width = binobf::vm::VmWidth::U8)
    -> binobf::vm::VmProgram {
    using namespace binobf::vm;
    return VmProgram{
        .version = currentVmVersion, .registerCount = 3, .slotCount = 0,
        .localMemorySize = 0,
        .instructions = {
            VmLoadConstant{VmRegister{0}, VmValue::from_bits(width, left)},
            VmLoadConstant{VmRegister{1}, VmValue::from_bits(width, right)},
            VmCompare{width, VmRegister{0}, VmRegister{1}},
            VmConditionalJump{condition, 6},
            VmLoadConstant{VmRegister{2}, VmValue::from_bits(VmWidth::U8, 0)},
            VmJump{7},
            VmLoadConstant{VmRegister{2}, VmValue::from_bits(VmWidth::U8, 1)},
            VmReturn{VmRegister{2}},
        }};
}

} // namespace

TEST_CASE(vm_registers_and_frame_slots_are_bounded_and_require_initialization) {
    using namespace binobf::vm;
    VmRegisterFile registers{2};
    REQUIRE(!registers.read(VmRegister{0}).has_value());
    REQUIRE(registers.write(VmRegister{1}, VmValue::from_bits(VmWidth::U16, 9)).has_value());
    REQUIRE_EQ(registers.read(VmRegister{1}).value().bits(), UINT64_C(9));
    REQUIRE(!registers.write(VmRegister{2}, VmValue::from_bits(VmWidth::U8, 1)).has_value());

    VmFrameStack stack{2, 2};
    REQUIRE(!stack.load(VmSlot{0}).has_value());
    REQUIRE(stack.store(VmSlot{0}, VmValue::from_bits(VmWidth::U32, 17)).has_value());
    REQUIRE_EQ(stack.load(VmSlot{0}).value().bits(), UINT64_C(17));
    REQUIRE(stack.push_frame().has_value());
    REQUIRE(!stack.load(VmSlot{0}).has_value());
    REQUIRE(!stack.push_frame().has_value());
    REQUIRE(stack.pop_frame().has_value());
    REQUIRE(!stack.pop_frame().has_value());
}

TEST_CASE(vm_internal_calls_use_fresh_frames_and_return_to_the_caller) {
    using namespace binobf::vm;
    const VmProgram program{
        .version = currentVmVersion,
        .registerCount = 3,
        .slotCount = 2,
        .localMemorySize = 0,
        .instructions = {
            VmLoadConstant{VmRegister{0}, VmValue::from_bits(VmWidth::U32, 20)},
            VmLoadConstant{VmRegister{1}, VmValue::from_bits(VmWidth::U32, 22)},
            VmCall{VmRegister{2}, 6, {VmRegister{0}, VmRegister{1}}},
            VmBinaryOperation{VmBinaryOpcode::Add, VmWidth::U32,
                              VmRegister{2}, VmRegister{2}, VmRegister{0}},
            VmReturn{VmRegister{2}},
            VmReturn{VmRegister{0}},
            VmLoadSlot{VmWidth::U32, VmRegister{0}, VmSlot{0}},
            VmLoadSlot{VmWidth::U32, VmRegister{1}, VmSlot{1}},
            VmBinaryOperation{VmBinaryOpcode::Add, VmWidth::U32,
                              VmRegister{2}, VmRegister{0}, VmRegister{1}},
            VmReturn{VmRegister{2}},
        },
    };
    LinearVmMemory memory{0};
    RejectingVmNativeCallBridge bridge;
    const auto result = execute(program, memory, bridge);
    REQUIRE_EQ(result.returnValue.bits(), UINT64_C(62));
    REQUIRE_EQ(result.returnValue.width(), VmWidth::U32);
}

TEST_CASE(vm_internal_calls_enforce_frame_depth_and_argument_bounds) {
    using namespace binobf::vm;
    VmProgram program{
        .version = currentVmVersion,
        .registerCount = 1,
        .slotCount = 1,
        .localMemorySize = 0,
        .instructions = {
            VmLoadConstant{VmRegister{0}, VmValue::from_bits(VmWidth::U32, 1)},
            VmCall{VmRegister{0}, 3, {VmRegister{0}}},
            VmReturn{VmRegister{0}},
            VmLoadSlot{VmWidth::U32, VmRegister{0}, VmSlot{0}},
            VmReturn{VmRegister{0}},
        },
    };
    LinearVmMemory memory{0};
    RejectingVmNativeCallBridge bridge;
    VmLimits limits;
    limits.maxFrameDepth = 1;
    const auto depth = execute_program(program, memory, bridge, {}, limits);
    REQUIRE(!depth.has_value());
    REQUIRE_EQ(depth.error().code, "vm.frame_depth_exceeded");

    program.instructions[1] = VmCall{VmRegister{0}, 3, {VmRegister{0}, VmRegister{0}}};
    const auto arguments = validate_program(program);
    REQUIRE(!arguments.has_value());
    REQUIRE_EQ(arguments.error().code, "vm.internal_argument_slots");
}

TEST_CASE(vm_linear_memory_is_little_endian_and_strictly_bounded) {
    using namespace binobf::vm;
    LinearVmMemory memory{8};
    REQUIRE(memory.store(2, VmValue::from_bits(VmWidth::U32, UINT64_C(0x12345678))).has_value());
    REQUIRE_EQ(memory.load(2, VmWidth::U32).value().bits(), UINT64_C(0x12345678));
    REQUIRE_EQ(memory.bytes()[2], std::byte{0x78});
    REQUIRE_EQ(memory.bytes()[5], std::byte{0x12});
    REQUIRE(!memory.load(6, VmWidth::U32).has_value());
    REQUIRE(!memory.store(8, VmValue::from_bits(VmWidth::U8, 1)).has_value());
    for (const auto width : {VmWidth::U8, VmWidth::U16, VmWidth::U32,
                             VmWidth::U64, VmWidth::Pointer}) {
        LinearVmMemory roundTrip{8};
        const auto value = VmValue::from_bits(width, UINT64_C(0xfedcba9876543210));
        REQUIRE(roundTrip.store(0, value).has_value());
        REQUIRE_EQ(roundTrip.load(0, width).value(), value);
    }
}

TEST_CASE(vm_interpreter_implements_every_condition_for_true_and_false_paths) {
    using namespace binobf::vm;
    struct Case {
        VmCondition condition;
        std::uint64_t trueLeft;
        std::uint64_t trueRight;
        std::uint64_t falseLeft;
        std::uint64_t falseRight;
    };
    const std::array cases{
        Case{VmCondition::Equal, 5, 5, 5, 6},
        Case{VmCondition::NotEqual, 5, 6, 5, 5},
        Case{VmCondition::UnsignedBelow, 1, 2, 2, 1},
        Case{VmCondition::UnsignedAboveOrEqual, 2, 1, 1, 2},
        Case{VmCondition::SignedLess, 0xff, 1, 1, 0xff},
        Case{VmCondition::SignedGreaterOrEqual, 1, 0xff, 0xff, 1},
        Case{VmCondition::Zero, 9, 9, 9, 8},
        Case{VmCondition::Nonzero, 9, 8, 9, 9},
    };
    LinearVmMemory memory{0};
    RejectingVmNativeCallBridge bridge;
    for (const auto& item : cases) {
        REQUIRE_EQ(execute(
            condition_program(item.condition, item.trueLeft, item.trueRight),
            memory, bridge).returnValue.bits(), UINT64_C(1));
        REQUIRE_EQ(execute(
            condition_program(item.condition, item.falseLeft, item.falseRight),
            memory, bridge).returnValue.bits(), UINT64_C(0));
    }
}

TEST_CASE(vm_arithmetic_flags_are_width_correct_for_carry_overflow_zero_and_sign) {
    using namespace binobf::vm;
    LinearVmMemory memory{0};
    RejectingVmNativeCallBridge bridge;
    const auto carried = execute(
        binary_program(VmBinaryOpcode::Add, 0xff, 1, VmWidth::U8), memory, bridge);
    REQUIRE(carried.flags.carry);
    REQUIRE(carried.flags.zero);
    REQUIRE(!carried.flags.overflow);
    const auto overflowed = execute(
        binary_program(VmBinaryOpcode::Add, 0x7f, 1, VmWidth::U8), memory, bridge);
    REQUIRE(overflowed.flags.overflow);
    REQUIRE(overflowed.flags.sign);
    const auto borrowed = execute(
        binary_program(VmBinaryOpcode::Subtract, 0, 1, VmWidth::U8), memory, bridge);
    REQUIRE(borrowed.flags.carry);
    REQUIRE(borrowed.flags.sign);
    const auto multiplied = execute(
        binary_program(VmBinaryOpcode::Multiply, 200, 2, VmWidth::U8), memory, bridge);
    REQUIRE(multiplied.flags.carry);
    REQUIRE(multiplied.flags.overflow);
}

TEST_CASE(vm_interpreter_executes_every_binary_and_unary_operation_with_width_wrapping) {
    using namespace binobf::vm;
    RejectingVmNativeCallBridge bridge;
    LinearVmMemory memory{0};
    const std::array cases{
        std::pair{VmBinaryOpcode::Add, UINT64_C(12)},
        std::pair{VmBinaryOpcode::Subtract, UINT64_C(8)},
        std::pair{VmBinaryOpcode::Multiply, UINT64_C(20)},
        std::pair{VmBinaryOpcode::Divide, UINT64_C(5)},
        std::pair{VmBinaryOpcode::And, UINT64_C(2)},
        std::pair{VmBinaryOpcode::Or, UINT64_C(10)},
        std::pair{VmBinaryOpcode::Xor, UINT64_C(8)},
        std::pair{VmBinaryOpcode::ShiftLeft, UINT64_C(40)},
        std::pair{VmBinaryOpcode::ShiftRight, UINT64_C(2)},
    };
    for (const auto& [opcode, expected] : cases) {
        REQUIRE_EQ(execute(binary_program(opcode, 10, 2), memory, bridge).returnValue.bits(),
                   expected);
    }
    auto unary = VmProgram{
        .version = currentVmVersion, .registerCount = 3, .slotCount = 0,
        .localMemorySize = 0,
        .instructions = {
            VmLoadConstant{VmRegister{0}, VmValue::from_bits(VmWidth::U8, 0x0f)},
            VmUnaryOperation{VmUnaryOpcode::Not, VmWidth::U8,
                             VmRegister{1}, VmRegister{0}},
            VmMove{VmWidth::U8, VmRegister{2}, VmRegister{1}},
            VmReturn{VmRegister{2}},
        }};
    REQUIRE_EQ(execute(unary, memory, bridge).returnValue.bits(), UINT64_C(0xf0));
    REQUIRE_EQ(execute(binary_program(VmBinaryOpcode::Add, 255, 1, VmWidth::U8),
                       memory, bridge).returnValue.bits(), UINT64_C(0));
}

TEST_CASE(vm_interpreter_moves_values_through_arguments_slots_and_local_memory) {
    using namespace binobf::vm;
    VmProgram program{
        .version = currentVmVersion, .registerCount = 4, .slotCount = 2,
        .localMemorySize = 16,
        .instructions = {
            VmLoadSlot{VmWidth::U32, VmRegister{0}, VmSlot{0}},
            VmStoreSlot{VmWidth::U32, VmSlot{1}, VmRegister{0}},
            VmLoadConstant{VmRegister{1}, VmValue::from_bits(VmWidth::Pointer, 4)},
            VmStoreMemory{VmWidth::U32, VmRegister{1}, VmRegister{0}},
            VmLoadMemory{VmWidth::U32, VmRegister{2}, VmRegister{1}},
            VmLoadSlot{VmWidth::U32, VmRegister{3}, VmSlot{1}},
            VmBinaryOperation{VmBinaryOpcode::Add, VmWidth::U32,
                              VmRegister{2}, VmRegister{2}, VmRegister{3}},
            VmReturn{VmRegister{2}},
        }};
    LinearVmMemory memory{16};
    RejectingVmNativeCallBridge bridge;
    const VmExecutionInput input{{VmValue::from_bits(VmWidth::U32, 21)}};
    REQUIRE_EQ(execute(program, memory, bridge, input).returnValue.bits(), UINT64_C(42));
    REQUIRE_EQ(memory.load(4, VmWidth::U32).value().bits(), UINT64_C(21));
}

TEST_CASE(vm_comparisons_tests_and_both_branch_forms_use_explicit_flags) {
    using namespace binobf::vm;
    VmProgram program{
        .version = currentVmVersion, .registerCount = 4, .slotCount = 0,
        .localMemorySize = 0,
        .instructions = {
            VmLoadConstant{VmRegister{0}, VmValue::from_bits(VmWidth::U32, 7)},
            VmLoadConstant{VmRegister{1}, VmValue::from_bits(VmWidth::U32, 9)},
            VmCompare{VmWidth::U32, VmRegister{0}, VmRegister{1}},
            VmConditionalJump{VmCondition::UnsignedBelow, 6},
            VmLoadConstant{VmRegister{2}, VmValue::from_bits(VmWidth::U32, 0)},
            VmJump{7},
            VmLoadConstant{VmRegister{2}, VmValue::from_bits(VmWidth::U32, 1)},
            VmTest{VmWidth::U32, VmRegister{2}, VmRegister{2}},
            VmConditionalJump{VmCondition::Nonzero, 10},
            VmLoadConstant{VmRegister{3}, VmValue::from_bits(VmWidth::U32, 99)},
            VmReturn{VmRegister{2}},
        }};
    LinearVmMemory memory{0};
    RejectingVmNativeCallBridge bridge;
    const auto result = execute(program, memory, bridge);
    REQUIRE_EQ(result.returnValue.bits(), UINT64_C(1));
    REQUIRE(!result.flags.zero);
}

TEST_CASE(vm_native_calls_are_explicit_and_rejecting_is_the_default_policy) {
    using namespace binobf::vm;
    VmProgram program{
        .version = currentVmVersion, .registerCount = 3, .slotCount = 0,
        .localMemorySize = 0,
        .instructions = {
            VmLoadConstant{VmRegister{0}, VmValue::from_bits(VmWidth::U64, 20)},
            VmLoadConstant{VmRegister{1}, VmValue::from_bits(VmWidth::U64, 22)},
            VmNativeCall{VmWidth::U64, VmRegister{2}, 7,
                         {VmRegister{0}, VmRegister{1}}},
            VmReturn{VmRegister{2}},
        }};
    LinearVmMemory memory{0};
    SumBridge sum;
    REQUIRE_EQ(execute(program, memory, sum).returnValue.bits(), UINT64_C(42));
    RejectingVmNativeCallBridge rejecting;
    const auto rejected = execute_program(program, memory, rejecting);
    REQUIRE(!rejected.has_value());
    REQUIRE_EQ(rejected.error().code, "vm.native_call_rejected");
}

TEST_CASE(vm_interpreter_rejects_division_shift_memory_and_step_failures_deterministically) {
    using namespace binobf::vm;
    LinearVmMemory emptyMemory{0};
    RejectingVmNativeCallBridge bridge;
    const auto division = execute_program(
        binary_program(VmBinaryOpcode::Divide, 1, 0), emptyMemory, bridge);
    REQUIRE(!division.has_value());
    REQUIRE_EQ(division.error().code, "vm.division_by_zero");
    const auto shift = execute_program(
        binary_program(VmBinaryOpcode::ShiftLeft, 1, 64), emptyMemory, bridge);
    REQUIRE(!shift.has_value());
    REQUIRE_EQ(shift.error().code, "vm.invalid_shift");

    VmProgram loop{
        .version = currentVmVersion, .registerCount = 1, .slotCount = 0,
        .localMemorySize = 0,
        .instructions = {VmJump{0}, VmReturn{VmRegister{0}}}};
    VmLimits limits;
    limits.maxSteps = 5;
    const auto exhausted = execute_program(loop, emptyMemory, bridge, {}, limits);
    REQUIRE(!exhausted.has_value());
    REQUIRE_EQ(exhausted.error().code, "vm.step_limit");

    VmProgram uninitialized{
        .version = currentVmVersion, .registerCount = 1, .slotCount = 0,
        .localMemorySize = 0, .instructions = {VmReturn{VmRegister{0}}}};
    const auto missing = execute_program(uninitialized, emptyMemory, bridge);
    REQUIRE(!missing.has_value());
    REQUIRE_EQ(missing.error().code, "vm.uninitialized_register");
}

TEST_CASE(embedded_vm_runtime_executes_u32_arguments_and_clears_errors) {
    using namespace binobf::vm;
    const VmProgram program{
        .version = currentVmVersion, .registerCount = 3, .slotCount = 2,
        .localMemorySize = 0,
        .instructions = {
            VmLoadSlot{VmWidth::U32, VmRegister{0}, VmSlot{0}},
            VmLoadSlot{VmWidth::U32, VmRegister{1}, VmSlot{1}},
            VmBinaryOperation{VmBinaryOpcode::Add, VmWidth::U32,
                              VmRegister{2}, VmRegister{0}, VmRegister{1}},
            VmReturn{VmRegister{2}},
        }};
    const auto bytecode = assemble_program(program, VmAssemblyOptions{616});
    REQUIRE(bytecode.has_value());
    const std::array<std::uint32_t, 2> arguments{20, 22};

    REQUIRE_EQ(binobf_vm_execute_embedded_u32(
        reinterpret_cast<const std::uint8_t*>(bytecode.value().data()),
        bytecode.value().size(), arguments.data(), arguments.size()), UINT32_C(42));
    REQUIRE_EQ(std::string_view{binobf_vm_embedded_last_error()}, std::string_view{});
}

TEST_CASE(embedded_vm_runtime_contains_failures_at_the_c_boundary) {
    const std::array malformed{std::uint8_t{'B'}};
    REQUIRE_EQ(binobf_vm_execute_embedded_u32(
        malformed.data(), malformed.size(), nullptr, 0), UINT32_C(0));
    REQUIRE_CONTAINS(
        std::string{binobf_vm_embedded_last_error()}, "vm.truncated_bytecode");

    REQUIRE_EQ(binobf_vm_execute_embedded_u32(
        malformed.data(), malformed.size(), nullptr, 1), UINT32_C(0));
    REQUIRE_CONTAINS(
        std::string{binobf_vm_embedded_last_error()}, "vm.native_arguments");
}

int main() {
    return binobf::test::run_all();
}

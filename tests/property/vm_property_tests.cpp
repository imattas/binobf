#include "../test_support.hpp"

#include <binobf/support/deterministic_rng.hpp>
#include <binobf/vm/bytecode.hpp>
#include <binobf/vm/runtime.hpp>

#include <array>
#include <cstddef>
#include <cstdint>

namespace {

using namespace binobf::vm;

constexpr std::array widths{
    VmWidth::U8, VmWidth::U16, VmWidth::U32, VmWidth::U64};
constexpr std::array binaryOpcodes{
    VmBinaryOpcode::Add,
    VmBinaryOpcode::Subtract,
    VmBinaryOpcode::Multiply,
    VmBinaryOpcode::Divide,
    VmBinaryOpcode::And,
    VmBinaryOpcode::Or,
    VmBinaryOpcode::Xor,
    VmBinaryOpcode::ShiftLeft,
    VmBinaryOpcode::ShiftRight,
};
constexpr std::array conditions{
    VmCondition::Equal,
    VmCondition::NotEqual,
    VmCondition::UnsignedBelow,
    VmCondition::UnsignedAboveOrEqual,
    VmCondition::SignedLess,
    VmCondition::SignedGreaterOrEqual,
    VmCondition::Zero,
    VmCondition::Nonzero,
};

auto mask_for(VmWidth width) -> std::uint64_t {
    const auto bits = vm_width_bits(width);
    return bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1U;
}

auto binary_oracle(
    VmBinaryOpcode opcode,
    VmWidth width,
    std::uint64_t left,
    std::uint64_t right) -> std::uint64_t {
    const auto mask = mask_for(width);
    left &= mask;
    right &= mask;
    switch (opcode) {
    case VmBinaryOpcode::Add: return (left + right) & mask;
    case VmBinaryOpcode::Subtract: return (left - right) & mask;
    case VmBinaryOpcode::Multiply: return (left * right) & mask;
    case VmBinaryOpcode::Divide: return left / right;
    case VmBinaryOpcode::And: return left & right;
    case VmBinaryOpcode::Or: return left | right;
    case VmBinaryOpcode::Xor: return left ^ right;
    case VmBinaryOpcode::ShiftLeft: return (left << right) & mask;
    case VmBinaryOpcode::ShiftRight: return left >> right;
    }
    return 0;
}

auto execute_round_trip(const VmProgram& program, std::uint64_t seed)
    -> binobf::Result<VmExecutionResult, binobf::Diagnostic> {
    const auto assembled = assemble_program(program, VmAssemblyOptions{seed});
    if (!assembled.has_value()) {
        return binobf::Result<VmExecutionResult, binobf::Diagnostic>::failure(
            assembled.error());
    }
    const auto replay = assemble_program(program, VmAssemblyOptions{seed});
    if (!replay.has_value() || replay.value() != assembled.value()) {
        return binobf::Result<VmExecutionResult, binobf::Diagnostic>::failure(
            binobf::Diagnostic{
                binobf::DiagnosticSeverity::Error,
                "property.nondeterministic_assembly",
                "identical VM program and seed produced different bytecode",
            });
    }
    const auto decoded = decode_program(assembled.value());
    if (!decoded.has_value()) {
        return binobf::Result<VmExecutionResult, binobf::Diagnostic>::failure(
            decoded.error());
    }
    if (decoded.value().program != program || decoded.value().encodingSeed != seed) {
        return binobf::Result<VmExecutionResult, binobf::Diagnostic>::failure(
            binobf::Diagnostic{
                binobf::DiagnosticSeverity::Error,
                "property.bytecode_roundtrip",
                "decoded VM bytecode differs from the generated program",
            });
    }
    LinearVmMemory memory{program.localMemorySize};
    RejectingVmNativeCallBridge bridge;
    return execute_program(decoded.value().program, memory, bridge);
}

auto compare_flags(VmWidth width, std::uint64_t left, std::uint64_t right) -> VmFlags {
    const auto mask = mask_for(width);
    left &= mask;
    right &= mask;
    const auto result = (left - right) & mask;
    const auto sign = UINT64_C(1) << (vm_width_bits(width) - 1U);
    return VmFlags{
        .zero = result == 0,
        .sign = (result & sign) != 0,
        .carry = left < right,
        .overflow = ((left ^ right) & (left ^ result) & sign) != 0,
    };
}

auto condition_oracle(VmCondition condition, const VmFlags& flags) -> bool {
    switch (condition) {
    case VmCondition::Equal:
    case VmCondition::Zero: return flags.zero;
    case VmCondition::NotEqual:
    case VmCondition::Nonzero: return !flags.zero;
    case VmCondition::UnsignedBelow: return flags.carry;
    case VmCondition::UnsignedAboveOrEqual: return !flags.carry;
    case VmCondition::SignedLess: return flags.sign != flags.overflow;
    case VmCondition::SignedGreaterOrEqual: return flags.sign == flags.overflow;
    }
    return false;
}

} // namespace

TEST_CASE(generated_vm_arithmetic_boolean_and_constant_properties_hold) {
    binobf::DeterministicRng rng{UINT64_C(0x70524f5045525459)};
    for (std::size_t iteration = 0; iteration < 4096; ++iteration) {
        const auto width = widths[rng.uniform(widths.size())];
        const auto opcode = binaryOpcodes[rng.uniform(binaryOpcodes.size())];
        auto left = rng.next_u64() & mask_for(width);
        auto right = rng.next_u64() & mask_for(width);
        if (opcode == VmBinaryOpcode::Divide && right == 0) right = 1;
        if (opcode == VmBinaryOpcode::ShiftLeft || opcode == VmBinaryOpcode::ShiftRight) {
            right %= vm_width_bits(width);
        }
        const VmProgram program{
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
        const auto executed = execute_round_trip(program, rng.next_u64());
        REQUIRE(executed.has_value());
        REQUIRE_EQ(executed.value().returnValue.width(), width);
        REQUIRE_EQ(executed.value().returnValue.bits(), binary_oracle(opcode, width, left, right));
    }
}

TEST_CASE(generated_vm_register_slot_memory_and_branch_properties_hold) {
    binobf::DeterministicRng rng{UINT64_C(0x4252414e43484553)};
    for (std::size_t iteration = 0; iteration < 2048; ++iteration) {
        const auto width = widths[rng.uniform(widths.size())];
        const auto value = rng.next_u64() & mask_for(width);
        const auto maxOffset = 32U - vm_width_bytes(width);
        const auto offset = rng.uniform(maxOffset + 1U);
        const VmProgram storage{
            .version = currentVmVersion,
            .registerCount = 4,
            .slotCount = 1,
            .localMemorySize = 32,
            .instructions = {
                VmLoadConstant{VmRegister{0}, VmValue::from_bits(VmWidth::Pointer, offset)},
                VmLoadConstant{VmRegister{1}, VmValue::from_bits(width, value)},
                VmStoreMemory{width, VmRegister{0}, VmRegister{1}},
                VmLoadMemory{width, VmRegister{2}, VmRegister{0}},
                VmStoreSlot{width, VmSlot{0}, VmRegister{2}},
                VmLoadSlot{width, VmRegister{3}, VmSlot{0}},
                VmReturn{VmRegister{3}},
            },
        };
        const auto stored = execute_round_trip(storage, rng.next_u64());
        REQUIRE(stored.has_value());
        REQUIRE_EQ(stored.value().returnValue.bits(), value);

        const auto left = rng.next_u64() & mask_for(width);
        const auto right = rng.next_u64() & mask_for(width);
        const auto condition = conditions[rng.uniform(conditions.size())];
        const auto expected = condition_oracle(condition, compare_flags(width, left, right));
        const VmProgram branch{
            .version = currentVmVersion,
            .registerCount = 3,
            .slotCount = 0,
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
            },
        };
        const auto branched = execute_round_trip(branch, rng.next_u64());
        REQUIRE(branched.has_value());
        REQUIRE_EQ(branched.value().returnValue.bits(), expected ? UINT64_C(1) : UINT64_C(0));
    }
}

TEST_CASE(generated_invalid_division_shifts_and_limits_fail_closed) {
    for (const auto width : widths) {
        for (const auto opcode : {
                 VmBinaryOpcode::Divide,
                 VmBinaryOpcode::ShiftLeft,
                 VmBinaryOpcode::ShiftRight}) {
            const auto right = opcode == VmBinaryOpcode::Divide
                ? UINT64_C(0) : vm_width_bits(width);
            const VmProgram program{
                .version = currentVmVersion,
                .registerCount = 3,
                .slotCount = 0,
                .localMemorySize = 0,
                .instructions = {
                    VmLoadConstant{VmRegister{0}, VmValue::from_bits(width, 9)},
                    VmLoadConstant{VmRegister{1}, VmValue::from_bits(width, right)},
                    VmBinaryOperation{opcode, width, VmRegister{2}, VmRegister{0}, VmRegister{1}},
                    VmReturn{VmRegister{2}},
                },
            };
            LinearVmMemory memory{0};
            RejectingVmNativeCallBridge bridge;
            const auto executed = execute_program(program, memory, bridge);
            REQUIRE(!executed.has_value());
            REQUIRE_EQ(
                executed.error().code,
                opcode == VmBinaryOpcode::Divide ? "vm.division_by_zero" : "vm.invalid_shift");
        }
    }

    const VmProgram tooManyRegisters{
        .version = currentVmVersion,
        .registerCount = 3,
        .slotCount = 0,
        .localMemorySize = 0,
        .instructions = {
            VmLoadConstant{VmRegister{2}, VmValue::from_bits(VmWidth::U32, 1)},
            VmReturn{VmRegister{2}},
        },
    };
    auto limits = VmLimits{};
    limits.maxRegisters = 2;
    const auto validation = validate_program(tooManyRegisters, limits);
    REQUIRE(!validation.has_value());
    REQUIRE_EQ(validation.error().code, "vm.register_limit");
}

int main() {
    return binobf::test::run_all();
}

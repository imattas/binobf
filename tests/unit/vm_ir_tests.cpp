#include "../test_support.hpp"

#include <binobf/vm/ir.hpp>

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace {

auto simple_program() -> binobf::vm::VmProgram {
    using namespace binobf::vm;
    return VmProgram{
        .version = currentVmVersion,
        .registerCount = 2,
        .slotCount = 1,
        .localMemorySize = 32,
        .instructions = {
            VmLoadConstant{VmRegister{0}, VmValue::from_bits(VmWidth::U32, 42)},
            VmMove{VmWidth::U32, VmRegister{1}, VmRegister{0}},
            VmReturn{VmRegister{1}},
        },
    };
}

} // namespace

TEST_CASE(vm_values_normalize_bits_to_their_explicit_width) {
    using namespace binobf::vm;
    REQUIRE_EQ(VmValue::from_bits(VmWidth::U8, UINT64_C(0x1234)).bits(), UINT64_C(0x34));
    REQUIRE_EQ(VmValue::from_bits(VmWidth::U16, UINT64_C(0x12345)).bits(), UINT64_C(0x2345));
    REQUIRE_EQ(VmValue::from_bits(VmWidth::U32, UINT64_C(0x100000001)).bits(), UINT64_C(1));
    REQUIRE_EQ(VmValue::from_bits(VmWidth::U64, UINT64_MAX).bits(), UINT64_MAX);
    REQUIRE_EQ(VmValue::from_bits(VmWidth::Pointer, UINT64_MAX).bits(), UINT64_MAX);
    REQUIRE_EQ(vm_width_bytes(VmWidth::Pointer), std::size_t{8});
}

TEST_CASE(vm_validator_accepts_a_bounded_typed_program) {
    const auto validated = binobf::vm::validate_program(simple_program());
    REQUIRE(validated.has_value());
    REQUIRE_EQ(validated.value(), std::size_t{3});
}

TEST_CASE(vm_validator_rejects_incompatible_versions_and_missing_returns) {
    auto incompatible = simple_program();
    incompatible.version.major = 2;
    const auto versionResult = binobf::vm::validate_program(incompatible);
    REQUIRE(!versionResult.has_value());
    REQUIRE_EQ(versionResult.error().code, "vm.incompatible_version");

    auto olderMinor = simple_program();
    olderMinor.version.minor = 0;
    const auto minorResult = binobf::vm::validate_program(olderMinor);
    REQUIRE(!minorResult.has_value());
    REQUIRE_EQ(minorResult.error().code, "vm.incompatible_version");

    auto noReturn = simple_program();
    noReturn.instructions.pop_back();
    const auto returnResult = binobf::vm::validate_program(noReturn);
    REQUIRE(!returnResult.has_value());
    REQUIRE_EQ(returnResult.error().code, "vm.missing_return");
}

TEST_CASE(vm_validator_rejects_register_slot_branch_and_native_argument_overflow) {
    using namespace binobf::vm;
    auto badRegister = simple_program();
    badRegister.instructions[1] = VmMove{VmWidth::U32, VmRegister{2}, VmRegister{0}};
    const auto registerResult = validate_program(badRegister);
    REQUIRE(!registerResult.has_value());
    REQUIRE_EQ(registerResult.error().code, "vm.register_out_of_range");

    auto badSlot = simple_program();
    badSlot.instructions.insert(
        badSlot.instructions.begin() + 1,
        VmLoadSlot{VmWidth::U32, VmRegister{1}, VmSlot{1}});
    const auto slotResult = validate_program(badSlot);
    REQUIRE(!slotResult.has_value());
    REQUIRE_EQ(slotResult.error().code, "vm.slot_out_of_range");

    auto badBranch = simple_program();
    badBranch.instructions.insert(badBranch.instructions.begin() + 1, VmJump{99});
    const auto branchResult = validate_program(badBranch);
    REQUIRE(!branchResult.has_value());
    REQUIRE_EQ(branchResult.error().code, "vm.branch_out_of_range");

    auto badNative = simple_program();
    badNative.instructions.insert(
        badNative.instructions.begin() + 1,
        VmNativeCall{VmWidth::U32, VmRegister{1}, 7,
                     {VmRegister{0}, VmRegister{0}}});
    VmLimits limits;
    limits.maxNativeArguments = 1;
    const auto nativeResult = validate_program(badNative, limits);
    REQUIRE(!nativeResult.has_value());
    REQUIRE_EQ(nativeResult.error().code, "vm.native_argument_limit");
}

TEST_CASE(vm_validator_enforces_global_resource_limits_before_allocation) {
    using namespace binobf::vm;
    auto program = simple_program();
    VmLimits limits;
    limits.maxInstructions = 2;
    auto result = validate_program(program, limits);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "vm.instruction_limit");
    limits.maxInstructions = 10;
    limits.maxRegisters = 1;
    result = validate_program(program, limits);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "vm.register_limit");
    limits.maxRegisters = 10;
    limits.maxSlots = 0;
    result = validate_program(program, limits);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "vm.slot_limit");
    limits.maxSlots = 10;
    limits.maxMemoryBytes = 16;
    result = validate_program(program, limits);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "vm.memory_limit");
}

int main() {
    return binobf::test::run_all();
}

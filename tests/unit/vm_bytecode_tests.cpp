#include "../test_support.hpp"

#include <binobf/vm/bytecode.hpp>
#include <binobf/vm/runtime.hpp>

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace {

auto representative_program() -> binobf::vm::VmProgram {
    using namespace binobf::vm;
    return VmProgram{
        .version = currentVmVersion,
        .registerCount = 6,
        .slotCount = 2,
        .localMemorySize = 64,
        .instructions = {
            VmLoadConstant{VmRegister{0}, VmValue::from_bits(VmWidth::U64, 40)},
            VmLoadConstant{VmRegister{1}, VmValue::from_bits(VmWidth::U64, 2)},
            VmMove{VmWidth::U64, VmRegister{2}, VmRegister{0}},
            VmStoreSlot{VmWidth::U64, VmSlot{0}, VmRegister{2}},
            VmLoadSlot{VmWidth::U64, VmRegister{3}, VmSlot{0}},
            VmLoadConstant{VmRegister{4}, VmValue::from_bits(VmWidth::Pointer, 8)},
            VmStoreMemory{VmWidth::U64, VmRegister{4}, VmRegister{3}},
            VmLoadMemory{VmWidth::U64, VmRegister{5}, VmRegister{4}},
            VmBinaryOperation{VmBinaryOpcode::Add, VmWidth::U64,
                              VmRegister{5}, VmRegister{5}, VmRegister{1}},
            VmBinaryOperation{VmBinaryOpcode::Subtract, VmWidth::U64,
                              VmRegister{5}, VmRegister{5}, VmRegister{1}},
            VmBinaryOperation{VmBinaryOpcode::Multiply, VmWidth::U64,
                              VmRegister{5}, VmRegister{5}, VmRegister{1}},
            VmBinaryOperation{VmBinaryOpcode::Divide, VmWidth::U64,
                              VmRegister{5}, VmRegister{5}, VmRegister{1}},
            VmBinaryOperation{VmBinaryOpcode::And, VmWidth::U64,
                              VmRegister{5}, VmRegister{5}, VmRegister{0}},
            VmBinaryOperation{VmBinaryOpcode::Or, VmWidth::U64,
                              VmRegister{5}, VmRegister{5}, VmRegister{1}},
            VmBinaryOperation{VmBinaryOpcode::Xor, VmWidth::U64,
                              VmRegister{5}, VmRegister{5}, VmRegister{1}},
            VmUnaryOperation{VmUnaryOpcode::Not, VmWidth::U64,
                             VmRegister{5}, VmRegister{5}},
            VmBinaryOperation{VmBinaryOpcode::ShiftLeft, VmWidth::U64,
                              VmRegister{5}, VmRegister{5}, VmRegister{1}},
            VmBinaryOperation{VmBinaryOpcode::ShiftRight, VmWidth::U64,
                              VmRegister{5}, VmRegister{5}, VmRegister{1}},
            VmCompare{VmWidth::U64, VmRegister{0}, VmRegister{1}},
            VmConditionalJump{VmCondition::UnsignedAboveOrEqual, 21},
            VmJump{22},
            VmTest{VmWidth::U64, VmRegister{0}, VmRegister{0}},
            VmCall{VmRegister{5}, 24, {VmRegister{0}, VmRegister{1}}},
            VmNativeCall{VmWidth::U64, VmRegister{5}, 7,
                         {VmRegister{0}, VmRegister{1}}},
            VmReturn{VmRegister{5}},
        },
    };
}

} // namespace

TEST_CASE(vm_bytecode_round_trips_every_opcode_and_is_stable_for_the_same_seed) {
    using namespace binobf::vm;
    const auto program = representative_program();
    const auto first = assemble_program(program, VmAssemblyOptions{12345});
    const auto repeated = assemble_program(program, VmAssemblyOptions{12345});
    REQUIRE(first.has_value());
    REQUIRE(repeated.has_value());
    REQUIRE_EQ(first.value(), repeated.value());
    const auto decoded = decode_program(first.value());
    REQUIRE(decoded.has_value());
    REQUIRE_EQ(decoded.value().encodingSeed, UINT64_C(12345));
    REQUIRE_EQ(decoded.value().program, program);
    const auto reassembled = assemble_program(
        decoded.value().program, VmAssemblyOptions{decoded.value().encodingSeed});
    REQUIRE(reassembled.has_value());
    REQUIRE_EQ(reassembled.value(), first.value());
}

TEST_CASE(vm_bytecode_seed_changes_encoding_without_changing_decoded_semantics) {
    using namespace binobf::vm;
    const auto program = representative_program();
    const auto first = assemble_program(program, VmAssemblyOptions{1});
    const auto second = assemble_program(program, VmAssemblyOptions{2});
    REQUIRE(first.has_value());
    REQUIRE(second.has_value());
    REQUIRE(first.value() != second.value());
    const auto firstDecoded = decode_program(first.value());
    const auto secondDecoded = decode_program(second.value());
    REQUIRE(firstDecoded.has_value());
    REQUIRE(secondDecoded.has_value());
    REQUIRE_EQ(firstDecoded.value().program, secondDecoded.value().program);
}

TEST_CASE(vm_decoder_rejects_magic_version_mapping_truncation_and_trailing_bytes) {
    using namespace binobf::vm;
    const auto assembled = assemble_program(representative_program(), VmAssemblyOptions{77});
    REQUIRE(assembled.has_value());

    auto badMagic = assembled.value();
    badMagic[0] = std::byte{'X'};
    const auto magicResult = decode_program(badMagic);
    REQUIRE(!magicResult.has_value());
    REQUIRE_EQ(magicResult.error().code, "vm.bad_magic");

    auto badVersion = assembled.value();
    badVersion[4] = std::byte{2};
    const auto versionResult = decode_program(badVersion);
    REQUIRE(!versionResult.has_value());
    REQUIRE_EQ(versionResult.error().code, "vm.incompatible_version");

    auto badMapping = assembled.value();
    constexpr std::size_t mappingOffset = 29;
    badMapping[mappingOffset + 1] = badMapping[mappingOffset];
    const auto mappingResult = decode_program(badMapping);
    REQUIRE(!mappingResult.has_value());
    REQUIRE_EQ(mappingResult.error().code, "vm.invalid_opcode_mapping");

    for (std::size_t size = 0; size < assembled.value().size(); ++size) {
        const auto decoded = decode_program(
            std::span<const std::byte>{assembled.value()}.first(size));
        REQUIRE(!decoded.has_value());
    }

    auto trailing = assembled.value();
    trailing.push_back(std::byte{0});
    const auto trailingResult = decode_program(trailing);
    REQUIRE(!trailingResult.has_value());
    REQUIRE_EQ(trailingResult.error().code, "vm.trailing_bytecode");
}

TEST_CASE(vm_decoder_rejects_malformed_instruction_lengths_widths_and_registers) {
    using namespace binobf::vm;
    const auto assembled = assemble_program(representative_program(), VmAssemblyOptions{55});
    REQUIRE(assembled.has_value());
    constexpr std::size_t firstRecord = 29 + vmOpcodeCount;
    constexpr std::size_t firstPayload = firstRecord + 3;

    auto badLength = assembled.value();
    badLength[firstRecord + 1] = std::byte{0xff};
    badLength[firstRecord + 2] = std::byte{0x7f};
    const auto lengthResult = decode_program(badLength);
    REQUIRE(!lengthResult.has_value());
    REQUIRE_EQ(lengthResult.error().code, "vm.truncated_bytecode");

    auto badWidth = assembled.value();
    badWidth[firstPayload] = std::byte{0xff};
    const auto widthResult = decode_program(badWidth);
    REQUIRE(!widthResult.has_value());
    REQUIRE_EQ(widthResult.error().code, "vm.malformed_instruction");

    auto badRegister = assembled.value();
    badRegister[firstPayload + 1] = std::byte{0xff};
    badRegister[firstPayload + 2] = std::byte{0xff};
    const auto registerResult = decode_program(badRegister);
    REQUIRE(!registerResult.has_value());
    REQUIRE_EQ(registerResult.error().code, "vm.malformed_instruction");
}

TEST_CASE(vm_decoder_enforces_bytecode_and_declared_resource_limits_before_allocation) {
    using namespace binobf::vm;
    const auto assembled = assemble_program(representative_program(), VmAssemblyOptions{9});
    REQUIRE(assembled.has_value());
    VmLimits limits;
    limits.maxBytecodeBytes = assembled.value().size() - 1;
    const auto byteLimit = decode_program(assembled.value(), limits);
    REQUIRE(!byteLimit.has_value());
    REQUIRE_EQ(byteLimit.error().code, "vm.bytecode_limit");
    limits.maxBytecodeBytes = assembled.value().size();
    limits.maxRegisters = 1;
    const auto registerLimit = decode_program(assembled.value(), limits);
    REQUIRE(!registerLimit.has_value());
    REQUIRE_EQ(registerLimit.error().code, "vm.register_limit");
}

TEST_CASE(vm_disassembler_is_stable_and_reports_typed_operands_and_targets) {
    using namespace binobf::vm;
    const auto text = disassemble_program(representative_program());
    REQUIRE(text.has_value());
    REQUIRE_CONTAINS(text.value(), "0000 LOAD_CONST v0, u64 0x28");
    REQUIRE_CONTAINS(text.value(), "0008 ADD v5, v5, v1, u64");
    REQUIRE_CONTAINS(text.value(), "0019 JCC unsigned-above-or-equal, @21");
    REQUIRE_CONTAINS(text.value(), "0022 CALL v5, @24, (v0, v1)");
    REQUIRE_CONTAINS(text.value(), "0023 CALL_NATIVE v5, #7, (v0, v1), u64");
    REQUIRE_CONTAINS(text.value(), "0024 RET v5");
    const auto assembled = assemble_program(representative_program(), VmAssemblyOptions{4});
    REQUIRE(assembled.has_value());
    const auto decodedText = disassemble_bytecode(assembled.value());
    REQUIRE(decodedText.has_value());
    REQUIRE_EQ(decodedText.value(), text.value());
}

TEST_CASE(vm_decoded_program_executes_with_the_same_semantics_as_its_source_ir) {
    using namespace binobf::vm;
    const VmProgram program{
        .version = currentVmVersion, .registerCount = 3, .slotCount = 0,
        .localMemorySize = 0,
        .instructions = {
            VmLoadConstant{VmRegister{0}, VmValue::from_bits(VmWidth::U32, 19)},
            VmLoadConstant{VmRegister{1}, VmValue::from_bits(VmWidth::U32, 23)},
            VmBinaryOperation{VmBinaryOpcode::Add, VmWidth::U32,
                              VmRegister{2}, VmRegister{0}, VmRegister{1}},
            VmReturn{VmRegister{2}},
        }};
    const auto assembled = assemble_program(program, VmAssemblyOptions{9876});
    REQUIRE(assembled.has_value());
    const auto decoded = decode_program(assembled.value());
    REQUIRE(decoded.has_value());
    LinearVmMemory sourceMemory{0};
    LinearVmMemory decodedMemory{0};
    RejectingVmNativeCallBridge bridge;
    const auto sourceResult = execute_program(program, sourceMemory, bridge);
    const auto decodedResult = execute_program(decoded.value().program, decodedMemory, bridge);
    REQUIRE(sourceResult.has_value());
    REQUIRE(decodedResult.has_value());
    REQUIRE_EQ(decodedResult.value().returnValue, sourceResult.value().returnValue);
    REQUIRE_EQ(decodedResult.value().flags, sourceResult.value().flags);
}

TEST_CASE(vm_internal_calls_survive_bytecode_round_trip_and_execute) {
    using namespace binobf::vm;
    const VmProgram program{
        .version = currentVmVersion, .registerCount = 3, .slotCount = 2,
        .localMemorySize = 0,
        .instructions = {
            VmLoadConstant{VmRegister{0}, VmValue::from_bits(VmWidth::U32, 20)},
            VmLoadConstant{VmRegister{1}, VmValue::from_bits(VmWidth::U32, 22)},
            VmCall{VmRegister{2}, 4, {VmRegister{0}, VmRegister{1}}},
            VmReturn{VmRegister{2}},
            VmLoadSlot{VmWidth::U32, VmRegister{0}, VmSlot{0}},
            VmLoadSlot{VmWidth::U32, VmRegister{1}, VmSlot{1}},
            VmBinaryOperation{VmBinaryOpcode::Add, VmWidth::U32,
                              VmRegister{2}, VmRegister{0}, VmRegister{1}},
            VmReturn{VmRegister{2}},
        }};
    const auto assembled = assemble_program(program, VmAssemblyOptions{441});
    REQUIRE(assembled.has_value());
    const auto decoded = decode_program(assembled.value());
    REQUIRE(decoded.has_value());
    REQUIRE_EQ(decoded.value().program, program);
    LinearVmMemory memory{0};
    RejectingVmNativeCallBridge bridge;
    const auto executed = execute_program(decoded.value().program, memory, bridge);
    REQUIRE(executed.has_value());
    REQUIRE_EQ(executed.value().returnValue.bits(), UINT64_C(42));
}

int main() {
    return binobf::test::run_all();
}

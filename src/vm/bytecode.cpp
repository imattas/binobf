#include <binobf/vm/bytecode.hpp>

#include <binobf/support/deterministic_rng.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace binobf::vm {
namespace {

constexpr std::array magic{std::byte{'B'}, std::byte{'V'}, std::byte{'M'}, std::byte{'1'}};
constexpr std::size_t fixedHeaderSize = 29;
constexpr std::size_t completeHeaderSize = fixedHeaderSize + vmOpcodeCount;
constexpr std::uint64_t opcodeSalt = UINT64_C(0x6f70636f64652d76);
constexpr std::uint64_t registerSalt = UINT64_C(0x7265676973746572);

template <typename Value>
auto failure(std::string code, std::string message) -> Result<Value, Diagnostic> {
    return Result<Value, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

void append_u8(std::vector<std::byte>& output, std::uint8_t value) {
    output.push_back(static_cast<std::byte>(value));
}

void append_u16(std::vector<std::byte>& output, std::uint16_t value) {
    append_u8(output, static_cast<std::uint8_t>(value & 0xffU));
    append_u8(output, static_cast<std::uint8_t>((value >> 8U) & 0xffU));
}

void append_u32(std::vector<std::byte>& output, std::uint32_t value) {
    for (std::uint32_t shift = 0; shift < 32; shift += 8) {
        append_u8(output, static_cast<std::uint8_t>((value >> shift) & 0xffU));
    }
}

void append_u64(std::vector<std::byte>& output, std::uint64_t value) {
    for (std::uint32_t shift = 0; shift < 64; shift += 8) {
        append_u8(output, static_cast<std::uint8_t>((value >> shift) & 0xffU));
    }
}

class Reader final {
public:
    explicit Reader(std::span<const std::byte> bytes) : bytes_(bytes) {}

    auto u8() -> std::optional<std::uint8_t> {
        if (remaining() < 1) return std::nullopt;
        return std::to_integer<std::uint8_t>(bytes_[cursor_++]);
    }
    auto u16() -> std::optional<std::uint16_t> {
        const auto low = u8();
        const auto high = u8();
        if (!low || !high) return std::nullopt;
        return static_cast<std::uint16_t>(*low | (static_cast<std::uint16_t>(*high) << 8U));
    }
    auto u32() -> std::optional<std::uint32_t> {
        std::uint32_t value = 0;
        for (std::uint32_t shift = 0; shift < 32; shift += 8) {
            const auto byte = u8();
            if (!byte) return std::nullopt;
            value |= static_cast<std::uint32_t>(*byte) << shift;
        }
        return value;
    }
    auto u64() -> std::optional<std::uint64_t> {
        std::uint64_t value = 0;
        for (std::uint32_t shift = 0; shift < 64; shift += 8) {
            const auto byte = u8();
            if (!byte) return std::nullopt;
            value |= static_cast<std::uint64_t>(*byte) << shift;
        }
        return value;
    }
    auto take(std::size_t count) -> std::optional<std::span<const std::byte>> {
        if (count > remaining()) return std::nullopt;
        const auto result = bytes_.subspan(cursor_, count);
        cursor_ += count;
        return result;
    }
    [[nodiscard]] auto remaining() const noexcept -> std::size_t {
        return bytes_.size() - cursor_;
    }

private:
    std::span<const std::byte> bytes_;
    std::size_t cursor_{0};
};

auto opcode_of(const VmInstruction& instruction) -> VmOpcode {
    if (std::holds_alternative<VmMove>(instruction)) return VmOpcode::Move;
    if (std::holds_alternative<VmLoadConstant>(instruction)) return VmOpcode::LoadConstant;
    if (std::holds_alternative<VmLoadSlot>(instruction)) return VmOpcode::LoadSlot;
    if (std::holds_alternative<VmStoreSlot>(instruction)) return VmOpcode::StoreSlot;
    if (std::holds_alternative<VmLoadMemory>(instruction)) return VmOpcode::LoadMemory;
    if (std::holds_alternative<VmStoreMemory>(instruction)) return VmOpcode::StoreMemory;
    if (const auto* binary = std::get_if<VmBinaryOperation>(&instruction)) {
        switch (binary->opcode) {
        case VmBinaryOpcode::Add: return VmOpcode::Add;
        case VmBinaryOpcode::Subtract: return VmOpcode::Subtract;
        case VmBinaryOpcode::Multiply: return VmOpcode::Multiply;
        case VmBinaryOpcode::Divide: return VmOpcode::Divide;
        case VmBinaryOpcode::And: return VmOpcode::And;
        case VmBinaryOpcode::Or: return VmOpcode::Or;
        case VmBinaryOpcode::Xor: return VmOpcode::Xor;
        case VmBinaryOpcode::ShiftLeft: return VmOpcode::ShiftLeft;
        case VmBinaryOpcode::ShiftRight: return VmOpcode::ShiftRight;
        }
    }
    if (std::holds_alternative<VmUnaryOperation>(instruction)) return VmOpcode::Not;
    if (std::holds_alternative<VmCompare>(instruction)) return VmOpcode::Compare;
    if (std::holds_alternative<VmTest>(instruction)) return VmOpcode::Test;
    if (std::holds_alternative<VmJump>(instruction)) return VmOpcode::Jump;
    if (std::holds_alternative<VmConditionalJump>(instruction)) {
        return VmOpcode::ConditionalJump;
    }
    if (std::holds_alternative<VmCall>(instruction)) return VmOpcode::Call;
    if (std::holds_alternative<VmNativeCall>(instruction)) return VmOpcode::NativeCall;
    return VmOpcode::Return;
}

auto make_opcode_mapping(std::uint64_t seed) -> std::array<std::uint8_t, vmOpcodeCount> {
    std::array<std::uint8_t, vmOpcodeCount> mapping{};
    for (std::size_t index = 0; index < mapping.size(); ++index) {
        mapping[index] = static_cast<std::uint8_t>(index + 1);
    }
    DeterministicRng rng{seed ^ opcodeSalt};
    rng.shuffle(mapping);
    return mapping;
}

auto make_register_mapping(std::uint16_t count, std::uint64_t seed)
    -> std::vector<std::uint16_t> {
    std::vector<std::uint16_t> mapping(count);
    for (std::size_t index = 0; index < mapping.size(); ++index) {
        mapping[index] = static_cast<std::uint16_t>(index);
    }
    DeterministicRng rng{seed ^ registerSalt};
    rng.shuffle(mapping);
    return mapping;
}

auto width_from_byte(std::uint8_t value) -> std::optional<VmWidth> {
    if (value > static_cast<std::uint8_t>(VmWidth::Pointer)) return std::nullopt;
    return static_cast<VmWidth>(value);
}

auto condition_from_byte(std::uint8_t value) -> std::optional<VmCondition> {
    if (value > static_cast<std::uint8_t>(VmCondition::Nonzero)) return std::nullopt;
    return static_cast<VmCondition>(value);
}

auto binary_from_opcode(VmOpcode opcode) -> std::optional<VmBinaryOpcode> {
    switch (opcode) {
    case VmOpcode::Add: return VmBinaryOpcode::Add;
    case VmOpcode::Subtract: return VmBinaryOpcode::Subtract;
    case VmOpcode::Multiply: return VmBinaryOpcode::Multiply;
    case VmOpcode::Divide: return VmBinaryOpcode::Divide;
    case VmOpcode::And: return VmBinaryOpcode::And;
    case VmOpcode::Or: return VmBinaryOpcode::Or;
    case VmOpcode::Xor: return VmBinaryOpcode::Xor;
    case VmOpcode::ShiftLeft: return VmBinaryOpcode::ShiftLeft;
    case VmOpcode::ShiftRight: return VmBinaryOpcode::ShiftRight;
    default: return std::nullopt;
    }
}

void append_register(
    std::vector<std::byte>& output,
    VmRegister value,
    std::span<const std::uint16_t> mapping) {
    append_u16(output, mapping[value.index]);
}

auto encode_payload(
    const VmInstruction& instruction,
    std::span<const std::uint16_t> registers) -> std::vector<std::byte> {
    std::vector<std::byte> output;
    const auto width = [&](VmWidth value) {
        append_u8(output, static_cast<std::uint8_t>(value));
    };
    if (const auto* moveOp = std::get_if<VmMove>(&instruction)) {
        width(moveOp->width);
        append_register(output, moveOp->destination, registers);
        append_register(output, moveOp->source, registers);
    } else if (const auto* loadConstantOp = std::get_if<VmLoadConstant>(&instruction)) {
        width(loadConstantOp->value.width());
        append_register(output, loadConstantOp->destination, registers);
        append_u64(output, loadConstantOp->value.bits());
    } else if (const auto* loadSlotOp = std::get_if<VmLoadSlot>(&instruction)) {
        width(loadSlotOp->width);
        append_register(output, loadSlotOp->destination, registers);
        append_u16(output, loadSlotOp->slot.index);
    } else if (const auto* storeSlotOp = std::get_if<VmStoreSlot>(&instruction)) {
        width(storeSlotOp->width);
        append_u16(output, storeSlotOp->slot.index);
        append_register(output, storeSlotOp->source, registers);
    } else if (const auto* loadMemoryOp = std::get_if<VmLoadMemory>(&instruction)) {
        width(loadMemoryOp->width);
        append_register(output, loadMemoryOp->destination, registers);
        append_register(output, loadMemoryOp->address, registers);
    } else if (const auto* storeMemoryOp = std::get_if<VmStoreMemory>(&instruction)) {
        width(storeMemoryOp->width);
        append_register(output, storeMemoryOp->address, registers);
        append_register(output, storeMemoryOp->source, registers);
    } else if (const auto* binaryOp = std::get_if<VmBinaryOperation>(&instruction)) {
        width(binaryOp->width);
        append_register(output, binaryOp->destination, registers);
        append_register(output, binaryOp->left, registers);
        append_register(output, binaryOp->right, registers);
    } else if (const auto* unaryOp = std::get_if<VmUnaryOperation>(&instruction)) {
        width(unaryOp->width);
        append_register(output, unaryOp->destination, registers);
        append_register(output, unaryOp->source, registers);
    } else if (const auto* compareOp = std::get_if<VmCompare>(&instruction)) {
        width(compareOp->width);
        append_register(output, compareOp->left, registers);
        append_register(output, compareOp->right, registers);
    } else if (const auto* testOp = std::get_if<VmTest>(&instruction)) {
        width(testOp->width);
        append_register(output, testOp->left, registers);
        append_register(output, testOp->right, registers);
    } else if (const auto* jumpOp = std::get_if<VmJump>(&instruction)) {
        append_u32(output, jumpOp->target);
    } else if (const auto* conditionalJumpOp = std::get_if<VmConditionalJump>(&instruction)) {
        append_u8(output, static_cast<std::uint8_t>(conditionalJumpOp->condition));
        append_u32(output, conditionalJumpOp->target);
    } else if (const auto* callOp = std::get_if<VmCall>(&instruction)) {
        append_register(output, callOp->destination, registers);
        append_u32(output, callOp->target);
        append_u16(output, static_cast<std::uint16_t>(callOp->arguments.size()));
        for (const auto argument : callOp->arguments) {
            append_register(output, argument, registers);
        }
    } else if (const auto* nativeCallOp = std::get_if<VmNativeCall>(&instruction)) {
        width(nativeCallOp->resultWidth);
        append_register(output, nativeCallOp->destination, registers);
        append_u32(output, nativeCallOp->functionId);
        append_u16(output, static_cast<std::uint16_t>(nativeCallOp->arguments.size()));
        for (const auto argument : nativeCallOp->arguments) {
            append_register(output, argument, registers);
        }
    } else if (const auto* returnOp = std::get_if<VmReturn>(&instruction)) {
        append_register(output, returnOp->source, registers);
    }
    return output;
}

auto width_name(VmWidth width) noexcept -> std::string_view {
    switch (width) {
    case VmWidth::U8: return "u8";
    case VmWidth::U16: return "u16";
    case VmWidth::U32: return "u32";
    case VmWidth::U64: return "u64";
    case VmWidth::Pointer: return "ptr";
    }
    return "invalid";
}

auto condition_name(VmCondition condition) noexcept -> std::string_view {
    switch (condition) {
    case VmCondition::Equal: return "equal";
    case VmCondition::NotEqual: return "not-equal";
    case VmCondition::UnsignedBelow: return "unsigned-below";
    case VmCondition::UnsignedAboveOrEqual: return "unsigned-above-or-equal";
    case VmCondition::SignedLess: return "signed-less";
    case VmCondition::SignedGreaterOrEqual: return "signed-greater-or-equal";
    case VmCondition::Zero: return "zero";
    case VmCondition::Nonzero: return "nonzero";
    }
    return "invalid";
}

auto opcode_name(VmOpcode opcode) noexcept -> std::string_view {
    switch (opcode) {
    case VmOpcode::Move: return "MOV";
    case VmOpcode::LoadConstant: return "LOAD_CONST";
    case VmOpcode::LoadSlot: return "LOAD_SLOT";
    case VmOpcode::StoreSlot: return "STORE_SLOT";
    case VmOpcode::LoadMemory: return "LOAD_MEM";
    case VmOpcode::StoreMemory: return "STORE_MEM";
    case VmOpcode::Add: return "ADD";
    case VmOpcode::Subtract: return "SUB";
    case VmOpcode::Multiply: return "MUL";
    case VmOpcode::Divide: return "DIV";
    case VmOpcode::And: return "AND";
    case VmOpcode::Or: return "OR";
    case VmOpcode::Xor: return "XOR";
    case VmOpcode::Not: return "NOT";
    case VmOpcode::ShiftLeft: return "SHL";
    case VmOpcode::ShiftRight: return "SHR";
    case VmOpcode::Compare: return "CMP";
    case VmOpcode::Test: return "TEST";
    case VmOpcode::Jump: return "JMP";
    case VmOpcode::ConditionalJump: return "JCC";
    case VmOpcode::Call: return "CALL";
    case VmOpcode::NativeCall: return "CALL_NATIVE";
    case VmOpcode::Return: return "RET";
    }
    return "INVALID";
}

} // namespace

auto assemble_program(
    const VmProgram& program,
    const VmAssemblyOptions& options,
    const VmLimits& limits) -> Result<std::vector<std::byte>, Diagnostic> {
    const auto validated = validate_program(program, limits);
    if (!validated.has_value()) {
        return Result<std::vector<std::byte>, Diagnostic>::failure(validated.error());
    }
    if (program.instructions.size() > std::numeric_limits<std::uint32_t>::max()) {
        return failure<std::vector<std::byte>>(
            "vm.instruction_limit", "VM instruction count exceeds the bytecode field");
    }
    const auto opcodeMapping = make_opcode_mapping(options.seed);
    const auto registerMapping = make_register_mapping(program.registerCount, options.seed);
    std::vector<std::byte> output;
    output.reserve(completeHeaderSize + program.instructions.size() * 8U);
    output.insert(output.end(), magic.begin(), magic.end());
    append_u16(output, program.version.major);
    append_u16(output, program.version.minor);
    append_u32(output, static_cast<std::uint32_t>(program.instructions.size()));
    append_u16(output, program.registerCount);
    append_u16(output, program.slotCount);
    append_u32(output, program.localMemorySize);
    append_u64(output, options.seed);
    append_u8(output, static_cast<std::uint8_t>(vmOpcodeCount));
    for (const auto value : opcodeMapping) append_u8(output, value);

    for (const auto& instruction : program.instructions) {
        const auto opcode = opcode_of(instruction);
        const auto payload = encode_payload(instruction, registerMapping);
        if (payload.size() > std::numeric_limits<std::uint16_t>::max()) {
            return failure<std::vector<std::byte>>(
                "vm.instruction_size_limit", "VM instruction payload exceeds 16 bits");
        }
        append_u8(output, opcodeMapping[static_cast<std::size_t>(opcode)]);
        append_u16(output, static_cast<std::uint16_t>(payload.size()));
        output.insert(output.end(), payload.begin(), payload.end());
        if (output.size() > limits.maxBytecodeBytes) {
            return failure<std::vector<std::byte>>(
                "vm.bytecode_limit", "VM bytecode size limit exceeded");
        }
    }
    return Result<std::vector<std::byte>, Diagnostic>::success(std::move(output));
}

auto decode_program(std::span<const std::byte> bytecode, const VmLimits& limits)
    -> Result<VmDecodedProgram, Diagnostic> {
    if (bytecode.size() > limits.maxBytecodeBytes) {
        return failure<VmDecodedProgram>("vm.bytecode_limit", "VM bytecode size limit exceeded");
    }
    if (bytecode.size() < magic.size()) {
        return failure<VmDecodedProgram>("vm.truncated_bytecode", "VM bytecode header is truncated");
    }
    if (!std::equal(magic.begin(), magic.end(), bytecode.begin())) {
        return failure<VmDecodedProgram>("vm.bad_magic", "VM bytecode magic is invalid");
    }
    if (bytecode.size() < completeHeaderSize) {
        return failure<VmDecodedProgram>("vm.truncated_bytecode", "VM bytecode header is truncated");
    }
    Reader reader{bytecode.subspan(magic.size())};
    const auto major = reader.u16();
    const auto minor = reader.u16();
    const auto instructionCount = reader.u32();
    const auto registerCount = reader.u16();
    const auto slotCount = reader.u16();
    const auto memorySize = reader.u32();
    const auto seed = reader.u64();
    const auto opcodeCount = reader.u8();
    if (!major || !minor || !instructionCount || !registerCount || !slotCount
        || !memorySize || !seed || !opcodeCount) {
        return failure<VmDecodedProgram>("vm.truncated_bytecode", "VM bytecode header is truncated");
    }
    if (*major != currentVmVersion.major || *minor != currentVmVersion.minor) {
        return failure<VmDecodedProgram>(
            "vm.incompatible_version", "VM bytecode version is incompatible");
    }
    if (*opcodeCount != vmOpcodeCount) {
        return failure<VmDecodedProgram>(
            "vm.invalid_opcode_mapping", "VM opcode mapping has the wrong size");
    }
    if (*instructionCount > limits.maxInstructions) {
        return failure<VmDecodedProgram>("vm.instruction_limit", "VM instruction limit exceeded");
    }
    if (*registerCount > limits.maxRegisters) {
        return failure<VmDecodedProgram>("vm.register_limit", "VM register limit exceeded");
    }
    if (*slotCount > limits.maxSlots) {
        return failure<VmDecodedProgram>("vm.slot_limit", "VM slot limit exceeded");
    }
    if (*memorySize > limits.maxMemoryBytes) {
        return failure<VmDecodedProgram>("vm.memory_limit", "VM memory limit exceeded");
    }

    std::array<std::int16_t, 256> opcodeInverse{};
    opcodeInverse.fill(-1);
    for (std::size_t index = 0; index < vmOpcodeCount; ++index) {
        const auto encoded = reader.u8();
        if (!encoded || *encoded == 0 || opcodeInverse[*encoded] != -1) {
            return failure<VmDecodedProgram>(
                "vm.invalid_opcode_mapping", "VM opcode mapping is not a bijection");
        }
        opcodeInverse[*encoded] = static_cast<std::int16_t>(index);
    }
    const auto registerMapping = make_register_mapping(*registerCount, *seed);
    std::vector<std::uint16_t> registerInverse(registerMapping.size());
    for (std::size_t logical = 0; logical < registerMapping.size(); ++logical) {
        registerInverse[registerMapping[logical]] = static_cast<std::uint16_t>(logical);
    }

    VmProgram program{
        .version = VmVersion{*major, *minor},
        .registerCount = *registerCount,
        .slotCount = *slotCount,
        .localMemorySize = *memorySize,
        .instructions = {},
    };
    program.instructions.reserve(*instructionCount);
    const auto malformed = [] {
        return failure<VmDecodedProgram>(
            "vm.malformed_instruction", "VM instruction payload is malformed");
    };
    for (std::uint32_t instructionIndex = 0; instructionIndex < *instructionCount;
         ++instructionIndex) {
        const auto encodedOpcode = reader.u8();
        const auto payloadSize = reader.u16();
        if (!encodedOpcode || !payloadSize) {
            return failure<VmDecodedProgram>(
                "vm.truncated_bytecode", "VM instruction record is truncated");
        }
        const auto payloadBytes = reader.take(*payloadSize);
        if (!payloadBytes) {
            return failure<VmDecodedProgram>(
                "vm.truncated_bytecode", "VM instruction payload is truncated");
        }
        if (opcodeInverse[*encodedOpcode] < 0) {
            return failure<VmDecodedProgram>(
                "vm.unknown_opcode", "VM instruction uses an unmapped opcode");
        }
        const auto opcode = static_cast<VmOpcode>(opcodeInverse[*encodedOpcode]);
        Reader payload{*payloadBytes};
        const auto readWidth = [&]() -> std::optional<VmWidth> {
            const auto value = payload.u8();
            return value ? width_from_byte(*value) : std::nullopt;
        };
        const auto readRegister = [&]() -> std::optional<VmRegister> {
            const auto encoded = payload.u16();
            if (!encoded || *encoded >= registerInverse.size()) return std::nullopt;
            return VmRegister{registerInverse[*encoded]};
        };
        const auto readSlot = [&]() -> std::optional<VmSlot> {
            const auto slot = payload.u16();
            if (!slot) return std::nullopt;
            return VmSlot{*slot};
        };

        const auto binaryOpcode = binary_from_opcode(opcode);
        if (opcode == VmOpcode::Move) {
            const auto width = readWidth();
            const auto destination = readRegister();
            const auto source = readRegister();
            if (!width || !destination || !source) return malformed();
            program.instructions.push_back(VmMove{*width, *destination, *source});
        } else if (opcode == VmOpcode::LoadConstant) {
            const auto width = readWidth();
            const auto destination = readRegister();
            const auto value = payload.u64();
            if (!width || !destination || !value) return malformed();
            program.instructions.push_back(
                VmLoadConstant{*destination, VmValue::from_bits(*width, *value)});
        } else if (opcode == VmOpcode::LoadSlot) {
            const auto width = readWidth();
            const auto destination = readRegister();
            const auto slot = readSlot();
            if (!width || !destination || !slot) return malformed();
            program.instructions.push_back(VmLoadSlot{*width, *destination, *slot});
        } else if (opcode == VmOpcode::StoreSlot) {
            const auto width = readWidth();
            const auto slot = readSlot();
            const auto source = readRegister();
            if (!width || !slot || !source) return malformed();
            program.instructions.push_back(VmStoreSlot{*width, *slot, *source});
        } else if (opcode == VmOpcode::LoadMemory) {
            const auto width = readWidth();
            const auto destination = readRegister();
            const auto address = readRegister();
            if (!width || !destination || !address) return malformed();
            program.instructions.push_back(VmLoadMemory{*width, *destination, *address});
        } else if (opcode == VmOpcode::StoreMemory) {
            const auto width = readWidth();
            const auto address = readRegister();
            const auto source = readRegister();
            if (!width || !address || !source) return malformed();
            program.instructions.push_back(VmStoreMemory{*width, *address, *source});
        } else if (binaryOpcode.has_value()) {
            const auto width = readWidth();
            const auto destination = readRegister();
            const auto left = readRegister();
            const auto right = readRegister();
            if (!width || !destination || !left || !right) return malformed();
            program.instructions.push_back(
                VmBinaryOperation{*binaryOpcode, *width, *destination, *left, *right});
        } else if (opcode == VmOpcode::Not) {
            const auto width = readWidth();
            const auto destination = readRegister();
            const auto source = readRegister();
            if (!width || !destination || !source) return malformed();
            program.instructions.push_back(
                VmUnaryOperation{VmUnaryOpcode::Not, *width, *destination, *source});
        } else if (opcode == VmOpcode::Compare || opcode == VmOpcode::Test) {
            const auto width = readWidth();
            const auto left = readRegister();
            const auto right = readRegister();
            if (!width || !left || !right) return malformed();
            if (opcode == VmOpcode::Compare) {
                program.instructions.push_back(VmCompare{*width, *left, *right});
            } else {
                program.instructions.push_back(VmTest{*width, *left, *right});
            }
        } else if (opcode == VmOpcode::Jump) {
            const auto target = payload.u32();
            if (!target) return malformed();
            program.instructions.push_back(VmJump{*target});
        } else if (opcode == VmOpcode::ConditionalJump) {
            const auto conditionByte = payload.u8();
            const auto target = payload.u32();
            if (!conditionByte || !target) return malformed();
            const auto condition = condition_from_byte(*conditionByte);
            if (!condition) return malformed();
            program.instructions.push_back(VmConditionalJump{*condition, *target});
        } else if (opcode == VmOpcode::Call) {
            const auto destination = readRegister();
            const auto target = payload.u32();
            const auto argumentCount = payload.u16();
            if (!destination || !target || !argumentCount
                || *argumentCount > limits.maxInternalArguments) return malformed();
            std::vector<VmRegister> arguments;
            arguments.reserve(*argumentCount);
            for (std::uint16_t index = 0; index < *argumentCount; ++index) {
                const auto argument = readRegister();
                if (!argument) return malformed();
                arguments.push_back(*argument);
            }
            program.instructions.push_back(
                VmCall{*destination, *target, std::move(arguments)});
        } else if (opcode == VmOpcode::NativeCall) {
            const auto width = readWidth();
            const auto destination = readRegister();
            const auto functionId = payload.u32();
            const auto argumentCount = payload.u16();
            if (!width || !destination || !functionId || !argumentCount
                || *argumentCount > limits.maxNativeArguments) return malformed();
            std::vector<VmRegister> arguments;
            arguments.reserve(*argumentCount);
            for (std::uint16_t index = 0; index < *argumentCount; ++index) {
                const auto argument = readRegister();
                if (!argument) return malformed();
                arguments.push_back(*argument);
            }
            program.instructions.push_back(
                VmNativeCall{*width, *destination, *functionId, std::move(arguments)});
        } else if (opcode == VmOpcode::Return) {
            const auto source = readRegister();
            if (!source) return malformed();
            program.instructions.push_back(VmReturn{*source});
        } else {
            return failure<VmDecodedProgram>("vm.unknown_opcode", "VM opcode is unknown");
        }
        if (payload.remaining() != 0) return malformed();
    }
    if (reader.remaining() != 0) {
        return failure<VmDecodedProgram>(
            "vm.trailing_bytecode", "VM bytecode has trailing bytes");
    }
    const auto validated = validate_program(program, limits);
    if (!validated.has_value()) {
        return Result<VmDecodedProgram, Diagnostic>::failure(validated.error());
    }
    return Result<VmDecodedProgram, Diagnostic>::success(VmDecodedProgram{
        .program = std::move(program), .encodingSeed = *seed});
}

auto disassemble_program(const VmProgram& program) -> Result<std::string, Diagnostic> {
    const auto validated = validate_program(program);
    if (!validated.has_value()) {
        return Result<std::string, Diagnostic>::failure(validated.error());
    }
    std::ostringstream output;
    const auto reg = [](VmRegister value) { return "v" + std::to_string(value.index); };
    const auto slot = [](VmSlot value) { return "s" + std::to_string(value.index); };
    for (std::size_t index = 0; index < program.instructions.size(); ++index) {
        const auto& instruction = program.instructions[index];
        const auto opcode = opcode_of(instruction);
        output << std::setfill('0') << std::setw(4) << index << ' '
               << opcode_name(opcode);
        if (const auto* moveOp = std::get_if<VmMove>(&instruction)) {
            output << ' ' << reg(moveOp->destination) << ", " << reg(moveOp->source)
                   << ", " << width_name(moveOp->width);
        } else if (const auto* loadConstantOp = std::get_if<VmLoadConstant>(&instruction)) {
            output << ' ' << reg(loadConstantOp->destination) << ", "
                   << width_name(loadConstantOp->value.width()) << " 0x" << std::hex
                   << loadConstantOp->value.bits() << std::dec;
        } else if (const auto* loadSlotOp = std::get_if<VmLoadSlot>(&instruction)) {
            output << ' ' << reg(loadSlotOp->destination) << ", " << slot(loadSlotOp->slot)
                   << ", " << width_name(loadSlotOp->width);
        } else if (const auto* storeSlotOp = std::get_if<VmStoreSlot>(&instruction)) {
            output << ' ' << slot(storeSlotOp->slot) << ", " << reg(storeSlotOp->source)
                   << ", " << width_name(storeSlotOp->width);
        } else if (const auto* loadMemoryOp = std::get_if<VmLoadMemory>(&instruction)) {
            output << ' ' << reg(loadMemoryOp->destination) << ", [" << reg(loadMemoryOp->address)
                   << "], " << width_name(loadMemoryOp->width);
        } else if (const auto* storeMemoryOp = std::get_if<VmStoreMemory>(&instruction)) {
            output << " [" << reg(storeMemoryOp->address) << "], " << reg(storeMemoryOp->source)
                   << ", " << width_name(storeMemoryOp->width);
        } else if (const auto* binaryOp = std::get_if<VmBinaryOperation>(&instruction)) {
            output << ' ' << reg(binaryOp->destination) << ", " << reg(binaryOp->left)
                   << ", " << reg(binaryOp->right) << ", " << width_name(binaryOp->width);
        } else if (const auto* unaryOp = std::get_if<VmUnaryOperation>(&instruction)) {
            output << ' ' << reg(unaryOp->destination) << ", " << reg(unaryOp->source)
                   << ", " << width_name(unaryOp->width);
        } else if (const auto* compareOp = std::get_if<VmCompare>(&instruction)) {
            output << ' ' << reg(compareOp->left) << ", " << reg(compareOp->right)
                   << ", " << width_name(compareOp->width);
        } else if (const auto* testOp = std::get_if<VmTest>(&instruction)) {
            output << ' ' << reg(testOp->left) << ", " << reg(testOp->right)
                   << ", " << width_name(testOp->width);
        } else if (const auto* jumpOp = std::get_if<VmJump>(&instruction)) {
            output << " @" << jumpOp->target;
        } else if (const auto* conditionalJumpOp = std::get_if<VmConditionalJump>(&instruction)) {
            output << ' ' << condition_name(conditionalJumpOp->condition)
                   << ", @" << conditionalJumpOp->target;
        } else if (const auto* callOp = std::get_if<VmCall>(&instruction)) {
            output << ' ' << reg(callOp->destination) << ", @" << callOp->target << ", (";
            for (std::size_t argument = 0; argument < callOp->arguments.size(); ++argument) {
                if (argument != 0) output << ", ";
                output << reg(callOp->arguments[argument]);
            }
            output << ')';
        } else if (const auto* nativeCallOp = std::get_if<VmNativeCall>(&instruction)) {
            output << ' ' << reg(nativeCallOp->destination) << ", #"
                   << nativeCallOp->functionId << ", (";
            for (std::size_t argument = 0; argument < nativeCallOp->arguments.size(); ++argument) {
                if (argument != 0) output << ", ";
                output << reg(nativeCallOp->arguments[argument]);
            }
            output << "), " << width_name(nativeCallOp->resultWidth);
        } else if (const auto* returnOp = std::get_if<VmReturn>(&instruction)) {
            output << ' ' << reg(returnOp->source);
        }
        output << '\n';
    }
    return Result<std::string, Diagnostic>::success(output.str());
}

auto disassemble_bytecode(std::span<const std::byte> bytecode, const VmLimits& limits)
    -> Result<std::string, Diagnostic> {
    const auto decoded = decode_program(bytecode, limits);
    if (!decoded.has_value()) {
        return Result<std::string, Diagnostic>::failure(decoded.error());
    }
    return disassemble_program(decoded.value().program);
}

} // namespace binobf::vm

#include <binobf/vm/ir.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>

namespace binobf::vm {
namespace {

template <typename... Functions>
struct Overloaded : Functions... {
    using Functions::operator()...;
};

auto failure(std::string code, std::string message)
    -> Result<std::size_t, Diagnostic> {
    return Result<std::size_t, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

auto valid_width(VmWidth width) noexcept -> bool {
    return vm_width_bits(width) != 0;
}

auto valid_binary_opcode(VmBinaryOpcode opcode) noexcept -> bool {
    return static_cast<std::uint8_t>(opcode)
        <= static_cast<std::uint8_t>(VmBinaryOpcode::ShiftRight);
}

auto valid_unary_opcode(VmUnaryOpcode opcode) noexcept -> bool {
    return opcode == VmUnaryOpcode::Not;
}

auto valid_condition(VmCondition condition) noexcept -> bool {
    return static_cast<std::uint8_t>(condition)
        <= static_cast<std::uint8_t>(VmCondition::Nonzero);
}

} // namespace

auto vm_width_bits(VmWidth width) noexcept -> std::uint32_t {
    switch (width) {
    case VmWidth::U8: return 8;
    case VmWidth::U16: return 16;
    case VmWidth::U32: return 32;
    case VmWidth::U64:
    case VmWidth::Pointer: return 64;
    }
    return 0;
}

auto vm_width_bytes(VmWidth width) noexcept -> std::size_t {
    return static_cast<std::size_t>(vm_width_bits(width) / 8U);
}

auto VmValue::from_bits(VmWidth width, std::uint64_t bits) noexcept -> VmValue {
    const auto widthBits = vm_width_bits(width);
    if (widthBits != 0 && widthBits < 64) {
        bits &= (UINT64_C(1) << widthBits) - 1U;
    }
    return VmValue{width, bits};
}

auto validate_program(const VmProgram& program, const VmLimits& limits)
    -> Result<std::size_t, Diagnostic> {
    if (program.version.major != currentVmVersion.major
        || program.version.minor != currentVmVersion.minor) {
        return failure(
            "vm.incompatible_version",
            "VM program version is not compatible with this interpreter");
    }
    if (program.instructions.size() > limits.maxInstructions) {
        return failure("vm.instruction_limit", "VM instruction limit exceeded");
    }
    if (program.registerCount > limits.maxRegisters) {
        return failure("vm.register_limit", "VM register limit exceeded");
    }
    if (program.slotCount > limits.maxSlots) {
        return failure("vm.slot_limit", "VM slot limit exceeded");
    }
    if (program.localMemorySize > limits.maxMemoryBytes) {
        return failure("vm.memory_limit", "VM local-memory limit exceeded");
    }

    bool hasReturn = false;
    const auto checkRegister = [&program](VmRegister value) -> bool {
        return value.index < program.registerCount;
    };
    const auto checkSlot = [&program](VmSlot value) -> bool {
        return value.index < program.slotCount;
    };

    for (std::size_t index = 0; index < program.instructions.size(); ++index) {
        std::string errorCode;
        std::string errorMessage;
        const auto badRegister = [&]() {
            errorCode = "vm.register_out_of_range";
            errorMessage = "VM instruction " + std::to_string(index)
                + " references a register outside the declared file";
        };
        const auto badSlot = [&]() {
            errorCode = "vm.slot_out_of_range";
            errorMessage = "VM instruction " + std::to_string(index)
                + " references a slot outside the declared frame";
        };
        const auto badWidth = [&]() {
            errorCode = "vm.invalid_width";
            errorMessage = "VM instruction " + std::to_string(index)
                + " has an invalid value width";
        };

        std::visit(Overloaded{
            [&](const VmMove& operation) {
                if (!valid_width(operation.width)) badWidth();
                else if (!checkRegister(operation.destination)
                         || !checkRegister(operation.source)) badRegister();
            },
            [&](const VmLoadConstant& operation) {
                if (!valid_width(operation.value.width())) badWidth();
                else if (!checkRegister(operation.destination)) badRegister();
            },
            [&](const VmLoadSlot& operation) {
                if (!valid_width(operation.width)) badWidth();
                else if (!checkRegister(operation.destination)) badRegister();
                else if (!checkSlot(operation.slot)) badSlot();
            },
            [&](const VmStoreSlot& operation) {
                if (!valid_width(operation.width)) badWidth();
                else if (!checkRegister(operation.source)) badRegister();
                else if (!checkSlot(operation.slot)) badSlot();
            },
            [&](const VmLoadMemory& operation) {
                if (!valid_width(operation.width)) badWidth();
                else if (!checkRegister(operation.destination)
                         || !checkRegister(operation.address)) badRegister();
            },
            [&](const VmStoreMemory& operation) {
                if (!valid_width(operation.width)) badWidth();
                else if (!checkRegister(operation.address)
                         || !checkRegister(operation.source)) badRegister();
            },
            [&](const VmBinaryOperation& operation) {
                if (!valid_binary_opcode(operation.opcode)) {
                    errorCode = "vm.invalid_opcode";
                    errorMessage = "VM binary opcode is invalid";
                } else if (!valid_width(operation.width)) badWidth();
                else if (!checkRegister(operation.destination)
                         || !checkRegister(operation.left)
                         || !checkRegister(operation.right)) badRegister();
            },
            [&](const VmUnaryOperation& operation) {
                if (!valid_unary_opcode(operation.opcode)) {
                    errorCode = "vm.invalid_opcode";
                    errorMessage = "VM unary opcode is invalid";
                } else if (!valid_width(operation.width)) badWidth();
                else if (!checkRegister(operation.destination)
                         || !checkRegister(operation.source)) badRegister();
            },
            [&](const VmCompare& operation) {
                if (!valid_width(operation.width)) badWidth();
                else if (!checkRegister(operation.left)
                         || !checkRegister(operation.right)) badRegister();
            },
            [&](const VmTest& operation) {
                if (!valid_width(operation.width)) badWidth();
                else if (!checkRegister(operation.left)
                         || !checkRegister(operation.right)) badRegister();
            },
            [&](const VmJump& operation) {
                if (operation.target >= program.instructions.size()) {
                    errorCode = "vm.branch_out_of_range";
                    errorMessage = "VM jump target is outside the program";
                }
            },
            [&](const VmConditionalJump& operation) {
                if (!valid_condition(operation.condition)) {
                    errorCode = "vm.invalid_condition";
                    errorMessage = "VM branch condition is invalid";
                } else if (operation.target >= program.instructions.size()) {
                    errorCode = "vm.branch_out_of_range";
                    errorMessage = "VM conditional target is outside the program";
                }
            },
            [&](const VmCall& operation) {
                if (!checkRegister(operation.destination)) badRegister();
                else if (operation.target >= program.instructions.size()) {
                    errorCode = "vm.call_target_out_of_range";
                    errorMessage = "VM internal-call target is outside the program";
                } else if (operation.arguments.size() > limits.maxInternalArguments) {
                    errorCode = "vm.internal_argument_limit";
                    errorMessage = "VM internal-call argument limit exceeded";
                } else if (operation.arguments.size()
                    > std::numeric_limits<std::uint16_t>::max()) {
                    errorCode = "vm.argument_encoding_limit";
                    errorMessage = "VM internal-call argument count exceeds the bytecode field";
                } else if (operation.arguments.size() > program.slotCount) {
                    errorCode = "vm.internal_argument_slots";
                    errorMessage = "VM internal call has more arguments than frame slots";
                } else if (std::any_of(
                               operation.arguments.begin(), operation.arguments.end(),
                               [&](VmRegister argument) { return !checkRegister(argument); })) {
                    badRegister();
                }
            },
            [&](const VmNativeCall& operation) {
                if (!valid_width(operation.resultWidth)) badWidth();
                else if (!checkRegister(operation.destination)) badRegister();
                else if (operation.arguments.size() > limits.maxNativeArguments) {
                    errorCode = "vm.native_argument_limit";
                    errorMessage = "VM native-call argument limit exceeded";
                } else if (operation.arguments.size()
                    > std::numeric_limits<std::uint16_t>::max()) {
                    errorCode = "vm.argument_encoding_limit";
                    errorMessage = "VM native-call argument count exceeds the bytecode field";
                } else if (std::any_of(
                               operation.arguments.begin(), operation.arguments.end(),
                               [&](VmRegister argument) { return !checkRegister(argument); })) {
                    badRegister();
                }
            },
            [&](const VmReturn& operation) {
                hasReturn = true;
                if (!checkRegister(operation.source)) badRegister();
            },
        }, program.instructions[index]);
        if (!errorCode.empty()) return failure(std::move(errorCode), std::move(errorMessage));
    }
    if (!hasReturn) {
        return failure("vm.missing_return", "VM program does not contain a return instruction");
    }
    return Result<std::size_t, Diagnostic>::success(program.instructions.size());
}

} // namespace binobf::vm

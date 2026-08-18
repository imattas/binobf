#include <binobf/vm/runtime.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace binobf::vm {
namespace {

template <typename Value>
auto failure(std::string code, std::string message) -> Result<Value, Diagnostic> {
    return Result<Value, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

template <typename Value>
auto propagate(const Diagnostic& diagnostic) -> Result<Value, Diagnostic> {
    return Result<Value, Diagnostic>::failure(diagnostic);
}

auto width_mask(VmWidth width) noexcept -> std::uint64_t {
    const auto bits = vm_width_bits(width);
    if (bits == 0) return 0;
    if (bits == 64) return UINT64_MAX;
    return (UINT64_C(1) << bits) - 1U;
}

auto normalized(const VmValue& value, VmWidth width) noexcept -> VmValue {
    return VmValue::from_bits(width, value.bits());
}

auto read_as(
    const VmRegisterFile& registers,
    VmRegister index,
    VmWidth width) -> Result<VmValue, Diagnostic> {
    const auto value = registers.read(index);
    if (!value.has_value()) return propagate<VmValue>(value.error());
    return Result<VmValue, Diagnostic>::success(normalized(value.value(), width));
}

void set_zero_sign(VmFlags& flags, std::uint64_t value, VmWidth width) {
    const auto bits = vm_width_bits(width);
    const auto masked = value & width_mask(width);
    flags.zero = masked == 0;
    flags.sign = bits != 0 && (masked & (UINT64_C(1) << (bits - 1U))) != 0;
}

void set_subtract_flags(
    VmFlags& flags,
    std::uint64_t left,
    std::uint64_t right,
    std::uint64_t result,
    VmWidth width) {
    const auto mask = width_mask(width);
    const auto sign = UINT64_C(1) << (vm_width_bits(width) - 1U);
    left &= mask;
    right &= mask;
    result &= mask;
    set_zero_sign(flags, result, width);
    flags.carry = left < right;
    flags.overflow = ((left ^ right) & (left ^ result) & sign) != 0;
}

auto condition_matches(VmCondition condition, const VmFlags& flags) noexcept -> bool {
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

auto memory_range_valid(
    std::uint64_t offset,
    std::size_t width,
    std::size_t limit) noexcept -> bool {
    if (offset > limit) return false;
    return width <= limit - static_cast<std::size_t>(offset);
}

} // namespace

VmRegisterFile::VmRegisterFile(std::size_t count) : values_(count) {}

auto VmRegisterFile::read(VmRegister index) const -> Result<VmValue, Diagnostic> {
    if (index.index >= values_.size()) {
        return failure<VmValue>(
            "vm.register_out_of_range", "VM register read is out of range");
    }
    if (!values_[index.index].has_value()) {
        return failure<VmValue>(
            "vm.uninitialized_register", "VM register was read before initialization");
    }
    return Result<VmValue, Diagnostic>::success(*values_[index.index]);
}

auto VmRegisterFile::write(VmRegister index, VmValue value)
    -> Result<std::size_t, Diagnostic> {
    if (index.index >= values_.size()) {
        return failure<std::size_t>(
            "vm.register_out_of_range", "VM register write is out of range");
    }
    values_[index.index] = value;
    return Result<std::size_t, Diagnostic>::success(index.index);
}

VmFrameStack::VmFrameStack(std::size_t slotCount, std::size_t maxDepth)
    : slotCount_(slotCount), maxDepth_(maxDepth), frames_(1) {
    frames_.front().resize(slotCount_);
}

auto VmFrameStack::load(VmSlot slot) const -> Result<VmValue, Diagnostic> {
    if (slot.index >= slotCount_) {
        return failure<VmValue>("vm.slot_out_of_range", "VM slot read is out of range");
    }
    const auto& value = frames_.back()[slot.index];
    if (!value.has_value()) {
        return failure<VmValue>(
            "vm.uninitialized_slot", "VM slot was read before initialization");
    }
    return Result<VmValue, Diagnostic>::success(*value);
}

auto VmFrameStack::store(VmSlot slot, VmValue value)
    -> Result<std::size_t, Diagnostic> {
    if (slot.index >= slotCount_) {
        return failure<std::size_t>("vm.slot_out_of_range", "VM slot write is out of range");
    }
    frames_.back()[slot.index] = value;
    return Result<std::size_t, Diagnostic>::success(slot.index);
}

auto VmFrameStack::push_frame() -> Result<std::size_t, Diagnostic> {
    if (frames_.size() >= maxDepth_) {
        return failure<std::size_t>(
            "vm.frame_depth_exceeded", "VM frame-depth limit exceeded");
    }
    frames_.emplace_back(slotCount_);
    return Result<std::size_t, Diagnostic>::success(frames_.size());
}

auto VmFrameStack::pop_frame() -> Result<std::size_t, Diagnostic> {
    if (frames_.size() <= 1) {
        return failure<std::size_t>("vm.frame_underflow", "cannot pop the root VM frame");
    }
    frames_.pop_back();
    return Result<std::size_t, Diagnostic>::success(frames_.size());
}

LinearVmMemory::LinearVmMemory(std::size_t size) : bytes_(size) {}

auto LinearVmMemory::load(std::uint64_t offset, VmWidth width) const
    -> Result<VmValue, Diagnostic> {
    const auto count = vm_width_bytes(width);
    if (count == 0 || !memory_range_valid(offset, count, bytes_.size())) {
        return failure<VmValue>("vm.memory_out_of_range", "VM memory load is out of range");
    }
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < count; ++index) {
        value |= static_cast<std::uint64_t>(
            std::to_integer<unsigned int>(bytes_[static_cast<std::size_t>(offset) + index]))
            << (index * 8U);
    }
    return Result<VmValue, Diagnostic>::success(VmValue::from_bits(width, value));
}

auto LinearVmMemory::store(std::uint64_t offset, VmValue value)
    -> Result<std::size_t, Diagnostic> {
    const auto count = vm_width_bytes(value.width());
    if (count == 0 || !memory_range_valid(offset, count, bytes_.size())) {
        return failure<std::size_t>("vm.memory_out_of_range", "VM memory store is out of range");
    }
    for (std::size_t index = 0; index < count; ++index) {
        bytes_[static_cast<std::size_t>(offset) + index] =
            static_cast<std::byte>((value.bits() >> (index * 8U)) & 0xffU);
    }
    return Result<std::size_t, Diagnostic>::success(count);
}

auto RejectingVmNativeCallBridge::invoke(
    std::uint32_t,
    std::span<const VmValue>) -> Result<VmValue, Diagnostic> {
    return failure<VmValue>(
        "vm.native_call_rejected",
        "VM native calls require an explicit caller-supplied allowlist bridge");
}

auto execute_program(
    const VmProgram& program,
    VmMemory& memory,
    VmNativeCallBridge& nativeCalls,
    const VmExecutionInput& input,
    const VmLimits& limits) -> Result<VmExecutionResult, Diagnostic> {
    const auto validated = validate_program(program, limits);
    if (!validated.has_value()) return propagate<VmExecutionResult>(validated.error());
    if (limits.maxFrameDepth == 0) {
        return failure<VmExecutionResult>(
            "vm.frame_depth_exceeded", "VM frame-depth limit is zero");
    }
    if (memory.size() < program.localMemorySize) {
        return failure<VmExecutionResult>(
            "vm.memory_too_small", "provided VM memory is smaller than the program declaration");
    }
    if (input.arguments.size() > program.slotCount) {
        return failure<VmExecutionResult>(
            "vm.argument_limit", "VM input has more arguments than declared slots");
    }

    struct CallFrame {
        std::size_t returnPc{0};
        VmRegister destination;
    };
    std::vector<VmRegisterFile> registerFrames;
    registerFrames.emplace_back(program.registerCount);
    std::vector<VmFlags> flagFrames(1);
    std::vector<CallFrame> callFrames;
    VmFrameStack stack{program.slotCount, limits.maxFrameDepth};
    for (std::size_t index = 0; index < input.arguments.size(); ++index) {
        const auto stored = stack.store(
            VmSlot{static_cast<std::uint16_t>(index)}, input.arguments[index]);
        if (!stored.has_value()) return propagate<VmExecutionResult>(stored.error());
    }

    std::size_t pc = 0;
    std::uint64_t steps = 0;
    while (pc < program.instructions.size()) {
        if (steps >= limits.maxSteps) {
            return failure<VmExecutionResult>(
                "vm.step_limit", "VM execution step budget exhausted");
        }
        ++steps;
        const auto& instruction = program.instructions[pc];
        std::size_t nextPc = pc + 1;
        auto& registers = registerFrames.back();
        auto& flags = flagFrames.back();

        if (const auto* moveOp = std::get_if<VmMove>(&instruction)) {
            const auto source = read_as(registers, moveOp->source, moveOp->width);
            if (!source.has_value()) return propagate<VmExecutionResult>(source.error());
            const auto written = registers.write(moveOp->destination, source.value());
            if (!written.has_value()) return propagate<VmExecutionResult>(written.error());
        } else if (const auto* loadConstantOp = std::get_if<VmLoadConstant>(&instruction)) {
            const auto written = registers.write(loadConstantOp->destination, loadConstantOp->value);
            if (!written.has_value()) return propagate<VmExecutionResult>(written.error());
        } else if (const auto* loadSlotOp = std::get_if<VmLoadSlot>(&instruction)) {
            const auto loaded = stack.load(loadSlotOp->slot);
            if (!loaded.has_value()) return propagate<VmExecutionResult>(loaded.error());
            const auto written = registers.write(
                loadSlotOp->destination, normalized(loaded.value(), loadSlotOp->width));
            if (!written.has_value()) return propagate<VmExecutionResult>(written.error());
        } else if (const auto* storeSlotOp = std::get_if<VmStoreSlot>(&instruction)) {
            const auto source = read_as(registers, storeSlotOp->source, storeSlotOp->width);
            if (!source.has_value()) return propagate<VmExecutionResult>(source.error());
            const auto stored = stack.store(storeSlotOp->slot, source.value());
            if (!stored.has_value()) return propagate<VmExecutionResult>(stored.error());
        } else if (const auto* loadMemoryOp = std::get_if<VmLoadMemory>(&instruction)) {
            const auto address = registers.read(loadMemoryOp->address);
            if (!address.has_value()) return propagate<VmExecutionResult>(address.error());
            const auto count = vm_width_bytes(loadMemoryOp->width);
            if (!memory_range_valid(address.value().bits(), count, program.localMemorySize)) {
                return failure<VmExecutionResult>(
                    "vm.memory_out_of_range", "VM program load exceeds declared local memory");
            }
            const auto loaded = memory.load(address.value().bits(), loadMemoryOp->width);
            if (!loaded.has_value()) return propagate<VmExecutionResult>(loaded.error());
            const auto written = registers.write(loadMemoryOp->destination, loaded.value());
            if (!written.has_value()) return propagate<VmExecutionResult>(written.error());
        } else if (const auto* storeMemoryOp = std::get_if<VmStoreMemory>(&instruction)) {
            const auto address = registers.read(storeMemoryOp->address);
            if (!address.has_value()) return propagate<VmExecutionResult>(address.error());
            const auto source = read_as(registers, storeMemoryOp->source, storeMemoryOp->width);
            if (!source.has_value()) return propagate<VmExecutionResult>(source.error());
            const auto count = vm_width_bytes(storeMemoryOp->width);
            if (!memory_range_valid(address.value().bits(), count, program.localMemorySize)) {
                return failure<VmExecutionResult>(
                    "vm.memory_out_of_range", "VM program store exceeds declared local memory");
            }
            const auto stored = memory.store(address.value().bits(), source.value());
            if (!stored.has_value()) return propagate<VmExecutionResult>(stored.error());
        } else if (const auto* binaryOp = std::get_if<VmBinaryOperation>(&instruction)) {
            const auto leftValue = read_as(registers, binaryOp->left, binaryOp->width);
            if (!leftValue.has_value()) return propagate<VmExecutionResult>(leftValue.error());
            const auto rightValue = read_as(registers, binaryOp->right, binaryOp->width);
            if (!rightValue.has_value()) return propagate<VmExecutionResult>(rightValue.error());
            const auto left = leftValue.value().bits();
            const auto right = rightValue.value().bits();
            const auto mask = width_mask(binaryOp->width);
            std::uint64_t result = 0;
            switch (binaryOp->opcode) {
            case VmBinaryOpcode::Add: {
                result = (left + right) & mask;
                set_zero_sign(flags, result, binaryOp->width);
                flags.carry = vm_width_bits(binaryOp->width) == 64
                    ? result < left : left + right > mask;
                const auto sign = UINT64_C(1) << (vm_width_bits(binaryOp->width) - 1U);
                flags.overflow = (~(left ^ right) & (left ^ result) & sign) != 0;
                break;
            }
            case VmBinaryOpcode::Subtract:
                result = (left - right) & mask;
                set_subtract_flags(flags, left, right, result, binaryOp->width);
                break;
            case VmBinaryOpcode::Multiply:
                result = (left * right) & mask;
                set_zero_sign(flags, result, binaryOp->width);
                flags.carry = right != 0 && left > mask / right;
                flags.overflow = flags.carry;
                break;
            case VmBinaryOpcode::Divide:
                if (right == 0) {
                    return failure<VmExecutionResult>(
                        "vm.division_by_zero", "VM unsigned division by zero");
                }
                result = left / right;
                set_zero_sign(flags, result, binaryOp->width);
                flags.carry = false;
                flags.overflow = false;
                break;
            case VmBinaryOpcode::And:
                result = left & right;
                set_zero_sign(flags, result, binaryOp->width);
                flags.carry = false;
                flags.overflow = false;
                break;
            case VmBinaryOpcode::Or:
                result = left | right;
                set_zero_sign(flags, result, binaryOp->width);
                flags.carry = false;
                flags.overflow = false;
                break;
            case VmBinaryOpcode::Xor:
                result = left ^ right;
                set_zero_sign(flags, result, binaryOp->width);
                flags.carry = false;
                flags.overflow = false;
                break;
            case VmBinaryOpcode::ShiftLeft: {
                const auto widthBits = vm_width_bits(binaryOp->width);
                if (right >= widthBits) {
                    return failure<VmExecutionResult>(
                        "vm.invalid_shift", "VM shift count exceeds the value width");
                }
                result = (left << right) & mask;
                set_zero_sign(flags, result, binaryOp->width);
                flags.carry = right != 0
                    && ((left >> (widthBits - static_cast<std::uint32_t>(right))) & 1U) != 0;
                flags.overflow = false;
                break;
            }
            case VmBinaryOpcode::ShiftRight: {
                const auto widthBits = vm_width_bits(binaryOp->width);
                if (right >= widthBits) {
                    return failure<VmExecutionResult>(
                        "vm.invalid_shift", "VM shift count exceeds the value width");
                }
                result = left >> right;
                set_zero_sign(flags, result, binaryOp->width);
                flags.carry = right != 0 && ((left >> (right - 1U)) & 1U) != 0;
                flags.overflow = false;
                break;
            }
            }
            const auto written = registers.write(
                binaryOp->destination, VmValue::from_bits(binaryOp->width, result));
            if (!written.has_value()) return propagate<VmExecutionResult>(written.error());
        } else if (const auto* unaryOp = std::get_if<VmUnaryOperation>(&instruction)) {
            const auto source = read_as(registers, unaryOp->source, unaryOp->width);
            if (!source.has_value()) return propagate<VmExecutionResult>(source.error());
            const auto result = (~source.value().bits()) & width_mask(unaryOp->width);
            set_zero_sign(flags, result, unaryOp->width);
            flags.carry = false;
            flags.overflow = false;
            const auto written = registers.write(
                unaryOp->destination, VmValue::from_bits(unaryOp->width, result));
            if (!written.has_value()) return propagate<VmExecutionResult>(written.error());
        } else if (const auto* compareOp = std::get_if<VmCompare>(&instruction)) {
            const auto left = read_as(registers, compareOp->left, compareOp->width);
            if (!left.has_value()) return propagate<VmExecutionResult>(left.error());
            const auto right = read_as(registers, compareOp->right, compareOp->width);
            if (!right.has_value()) return propagate<VmExecutionResult>(right.error());
            set_subtract_flags(
                flags, left.value().bits(), right.value().bits(),
                left.value().bits() - right.value().bits(), compareOp->width);
        } else if (const auto* testOp = std::get_if<VmTest>(&instruction)) {
            const auto left = read_as(registers, testOp->left, testOp->width);
            if (!left.has_value()) return propagate<VmExecutionResult>(left.error());
            const auto right = read_as(registers, testOp->right, testOp->width);
            if (!right.has_value()) return propagate<VmExecutionResult>(right.error());
            set_zero_sign(flags, left.value().bits() & right.value().bits(), testOp->width);
            flags.carry = false;
            flags.overflow = false;
        } else if (const auto* jumpOp = std::get_if<VmJump>(&instruction)) {
            nextPc = jumpOp->target;
        } else if (const auto* conditionalJumpOp = std::get_if<VmConditionalJump>(&instruction)) {
            if (condition_matches(conditionalJumpOp->condition, flags)) {
                nextPc = conditionalJumpOp->target;
            }
        } else if (const auto* callOp = std::get_if<VmCall>(&instruction)) {
            std::vector<VmValue> arguments;
            arguments.reserve(callOp->arguments.size());
            for (const auto argument : callOp->arguments) {
                const auto value = registers.read(argument);
                if (!value.has_value()) return propagate<VmExecutionResult>(value.error());
                arguments.push_back(value.value());
            }
            const auto pushed = stack.push_frame();
            if (!pushed.has_value()) return propagate<VmExecutionResult>(pushed.error());
            for (std::size_t index = 0; index < arguments.size(); ++index) {
                const auto stored = stack.store(
                    VmSlot{static_cast<std::uint16_t>(index)}, arguments[index]);
                if (!stored.has_value()) return propagate<VmExecutionResult>(stored.error());
            }
            callFrames.push_back(CallFrame{nextPc, callOp->destination});
            registerFrames.emplace_back(program.registerCount);
            flagFrames.emplace_back();
            nextPc = callOp->target;
        } else if (const auto* nativeCallOp = std::get_if<VmNativeCall>(&instruction)) {
            std::vector<VmValue> arguments;
            arguments.reserve(nativeCallOp->arguments.size());
            for (const auto argument : nativeCallOp->arguments) {
                const auto value = registers.read(argument);
                if (!value.has_value()) return propagate<VmExecutionResult>(value.error());
                arguments.push_back(value.value());
            }
            const auto returned = nativeCalls.invoke(nativeCallOp->functionId, arguments);
            if (!returned.has_value()) return propagate<VmExecutionResult>(returned.error());
            const auto written = registers.write(
                nativeCallOp->destination,
                normalized(returned.value(), nativeCallOp->resultWidth));
            if (!written.has_value()) return propagate<VmExecutionResult>(written.error());
        } else if (const auto* returnOp = std::get_if<VmReturn>(&instruction)) {
            const auto returned = registers.read(returnOp->source);
            if (!returned.has_value()) return propagate<VmExecutionResult>(returned.error());
            if (!callFrames.empty()) {
                const auto frame = callFrames.back();
                callFrames.pop_back();
                registerFrames.pop_back();
                flagFrames.pop_back();
                const auto popped = stack.pop_frame();
                if (!popped.has_value()) return propagate<VmExecutionResult>(popped.error());
                const auto written = registerFrames.back().write(
                    frame.destination, returned.value());
                if (!written.has_value()) return propagate<VmExecutionResult>(written.error());
                nextPc = frame.returnPc;
                pc = nextPc;
                continue;
            }
            return Result<VmExecutionResult, Diagnostic>::success(VmExecutionResult{
                .returnValue = returned.value(), .steps = steps, .flags = flags});
        }
        pc = nextPc;
    }
    return failure<VmExecutionResult>(
        "vm.fell_off_program", "VM execution reached the end without returning");
}

} // namespace binobf::vm

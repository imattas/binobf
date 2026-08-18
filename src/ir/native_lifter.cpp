#include <binobf/ir/native_lifter.hpp>

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace binobf::ir {
namespace {

auto error(std::string code, std::string message) -> Diagnostic {
    return Diagnostic{DiagnosticSeverity::Error, std::move(code), std::move(message)};
}

auto warning(std::string code, std::string message) -> Diagnostic {
    return Diagnostic{DiagnosticSeverity::Warning, std::move(code), std::move(message)};
}

auto failed(std::string code, std::string message) -> Result<NativeLiftReport, Diagnostic> {
    return Result<NativeLiftReport, Diagnostic>::failure(
        error(std::move(code), std::move(message)));
}

class CapstoneHandle final {
public:
    CapstoneHandle() = default;
    CapstoneHandle(const CapstoneHandle&) = delete;
    auto operator=(const CapstoneHandle&) -> CapstoneHandle& = delete;
    ~CapstoneHandle() {
        if (handle_ != 0) static_cast<void>(cs_close(&handle_));
    }

    auto open() -> bool {
        return cs_open(CS_ARCH_X86, CS_MODE_64, &handle_) == CS_ERR_OK
            && cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK;
    }

    [[nodiscard]] auto get() const noexcept -> csh { return handle_; }

private:
    csh handle_{0};
};

class DecodedInstruction final {
public:
    DecodedInstruction() = default;
    DecodedInstruction(const DecodedInstruction&) = delete;
    auto operator=(const DecodedInstruction&) -> DecodedInstruction& = delete;
    ~DecodedInstruction() { cs_free(instruction_, count_); }

    auto decode(csh handle, const Instruction& source) -> bool {
        count_ = cs_disasm(
            handle,
            reinterpret_cast<const std::uint8_t*>(source.encoding.data()),
            source.encoding.size(),
            source.address.value,
            1,
            &instruction_);
        return count_ == 1 && instruction_ != nullptr && instruction_->detail != nullptr
            && instruction_->size == source.encoding.size();
    }

    [[nodiscard]] auto get() const noexcept -> const cs_insn& { return *instruction_; }

private:
    cs_insn* instruction_{nullptr};
    std::size_t count_{0};
};

auto is_supported_register(x86_reg reg) -> bool {
    switch (reg) {
    case X86_REG_EAX:
    case X86_REG_EBX:
    case X86_REG_ECX:
    case X86_REG_EDX:
    case X86_REG_ESI:
    case X86_REG_EDI:
    case X86_REG_EBP:
    case X86_REG_R8D:
    case X86_REG_R9D:
    case X86_REG_R10D:
    case X86_REG_R11D:
    case X86_REG_R12D:
    case X86_REG_R13D:
    case X86_REG_R14D:
    case X86_REG_R15D:
        return true;
    default:
        return false;
    }
}

auto argument_registers(NativeAbi abi) -> std::vector<x86_reg> {
    if (abi == NativeAbi::WindowsX64) {
        return {X86_REG_ECX, X86_REG_EDX, X86_REG_R8D, X86_REG_R9D};
    }
    return {X86_REG_EDI, X86_REG_ESI, X86_REG_EDX, X86_REG_ECX};
}

auto condition_for(unsigned int id) -> std::optional<IrCondition> {
    switch (id) {
    case X86_INS_JE: return IrCondition::Equal;
    case X86_INS_JNE: return IrCondition::NotEqual;
    case X86_INS_JB: return IrCondition::UnsignedBelow;
    case X86_INS_JAE: return IrCondition::UnsignedAboveOrEqual;
    case X86_INS_JL: return IrCondition::SignedLess;
    case X86_INS_JGE: return IrCondition::SignedGreaterOrEqual;
    default: return std::nullopt;
    }
}

auto binary_opcode(unsigned int id) -> std::optional<IrBinaryOpcode> {
    switch (id) {
    case X86_INS_ADD: return IrBinaryOpcode::Add;
    case X86_INS_SUB: return IrBinaryOpcode::Subtract;
    case X86_INS_IMUL: return IrBinaryOpcode::Multiply;
    case X86_INS_AND: return IrBinaryOpcode::And;
    case X86_INS_OR: return IrBinaryOpcode::Or;
    case X86_INS_XOR: return IrBinaryOpcode::Xor;
    case X86_INS_SHL: return IrBinaryOpcode::ShiftLeft;
    case X86_INS_SHR: return IrBinaryOpcode::ShiftRight;
    default: return std::nullopt;
    }
}

struct LiftState {
    NativeLiftReport report;
    std::map<unsigned int, IrVariable> variables;
    std::map<std::uint64_t, IrBlockId> blocksByAddress;
    bool complete{true};

    auto variable(x86_reg reg) -> IrVariable {
        const auto key = static_cast<unsigned int>(reg);
        const auto found = variables.find(key);
        if (found != variables.end()) return found->second;
        const auto index = static_cast<std::uint16_t>(report.function.variableWidths.size());
        const auto inserted = variables.emplace(key, IrVariable{index});
        report.function.variableWidths.push_back(IrWidth::U32);
        return inserted.first->second;
    }

    void fallback(const Instruction& source, std::string code, std::string reason, IrBlock& block) {
        complete = false;
        report.diagnostics.push_back(warning(std::move(code), reason));
        block.instructions.push_back(IrFallback{
            .sourceInstruction = source.id,
            .encoding = source.encoding,
            .reason = std::move(reason),
        });
    }
};

auto find_instruction(const BinaryImage& image, EntityId id) -> const Instruction* {
    const auto found = std::find_if(image.instructions.begin(), image.instructions.end(),
        [id](const auto& instruction) { return instruction.id == id; });
    return found == image.instructions.end() ? nullptr : &*found;
}

auto find_block(const BinaryImage& image, EntityId id) -> const BasicBlock* {
    const auto found = std::find_if(image.basicBlocks.begin(), image.basicBlocks.end(),
        [id](const auto& block) { return block.id == id; });
    return found == image.basicBlocks.end() ? nullptr : &*found;
}

auto operand_from(
    LiftState& state,
    const cs_x86_op& operand,
    std::string& failureCode,
    std::string& failureReason) -> std::optional<IrOperand> {
    if (operand.size != 4) {
        failureCode = "ir.unsupported_operand_width";
        failureReason = "only 32-bit native operands are supported by VM lowering";
        return std::nullopt;
    }
    if (operand.type == X86_OP_REG) {
        const auto reg = static_cast<x86_reg>(operand.reg);
        if (!is_supported_register(reg)) {
            failureCode = "ir.unsupported_register";
            failureReason = "native operand uses an unsupported register";
            return std::nullopt;
        }
        return IrOperand{IrVariableOperand{state.variable(reg)}};
    }
    if (operand.type == X86_OP_IMM) {
        return IrOperand{IrImmediateOperand{
            IrWidth::U32, static_cast<std::uint64_t>(operand.imm)}};
    }
    if (operand.type == X86_OP_MEM) {
        failureCode = "ir.unsupported_memory_operand";
        failureReason = "native memory operands are outside the Milestone 8 lowering subset";
        return std::nullopt;
    }
    failureCode = "ir.unsupported_operand";
    failureReason = "native operand type is unsupported";
    return std::nullopt;
}

auto target_block(const LiftState& state, std::uint64_t address) -> std::optional<IrBlockId> {
    const auto found = state.blocksByAddress.find(address);
    if (found == state.blocksByAddress.end()) return std::nullopt;
    return found->second;
}

auto has_relocation_reference(const Instruction& instruction) -> bool {
    return std::any_of(instruction.references.begin(), instruction.references.end(),
        [](const auto& reference) {
            return reference.kind == InstructionReferenceKind::Relocation
                || reference.relocation.has_value();
        });
}

void lift_decoded(
    LiftState& state,
    const Instruction& source,
    const cs_insn& decoded,
    IrBlock& output,
    bool& comparisonFlagsAvailable) {
    const auto& x86 = decoded.detail->x86;
    if (has_relocation_reference(source)) {
        state.fallback(source, "ir.relocation_backed_instruction",
            "relocation-backed native instructions are not lowerable", output);
        return;
    }
    for (std::uint8_t index = 0; index < x86.op_count; ++index) {
        if (x86.operands[index].type == X86_OP_MEM) {
            state.fallback(source, "ir.unsupported_memory_operand",
                "native memory operands are outside the Milestone 8 lowering subset", output);
            return;
        }
    }
    if (decoded.id == X86_INS_NOP) return;

    if (decoded.id == X86_INS_MOV) {
        if (x86.op_count != 2 || x86.operands[0].type != X86_OP_REG
            || x86.operands[0].size != 4
            || !is_supported_register(static_cast<x86_reg>(x86.operands[0].reg))) {
            state.fallback(source, "ir.unsupported_move",
                "native move is outside the supported register/immediate form", output);
            return;
        }
        std::string code;
        std::string reason;
        const auto operand = operand_from(state, x86.operands[1], code, reason);
        if (!operand.has_value()) {
            state.fallback(source, std::move(code), std::move(reason), output);
            return;
        }
        output.instructions.push_back(IrMove{
            IrWidth::U32,
            state.variable(static_cast<x86_reg>(x86.operands[0].reg)),
            *operand,
            source.id,
        });
        return;
    }

    if (const auto opcode = binary_opcode(decoded.id); opcode.has_value()) {
        if ((x86.op_count != 2 && decoded.id != X86_INS_IMUL)
            || x86.op_count < 2 || x86.op_count > 3
            || x86.operands[0].type != X86_OP_REG
            || x86.operands[0].size != 4
            || !is_supported_register(static_cast<x86_reg>(x86.operands[0].reg))) {
            state.fallback(source, "ir.unsupported_binary_operation",
                "native binary operation is outside the supported form", output);
            return;
        }
        const auto destination = state.variable(static_cast<x86_reg>(x86.operands[0].reg));
        std::size_t sourceIndex = 1;
        if (x86.op_count == 3) {
            std::string code;
            std::string reason;
            const auto initial = operand_from(state, x86.operands[1], code, reason);
            if (!initial.has_value()) {
                state.fallback(source, std::move(code), std::move(reason), output);
                return;
            }
            output.instructions.push_back(IrMove{
                IrWidth::U32, destination, *initial, source.id});
            sourceIndex = 2;
        }
        std::string code;
        std::string reason;
        const auto operand = operand_from(state, x86.operands[sourceIndex], code, reason);
        if (!operand.has_value()) {
            state.fallback(source, std::move(code), std::move(reason), output);
            return;
        }
        if ((decoded.id == X86_INS_SHL || decoded.id == X86_INS_SHR)
            && !std::holds_alternative<IrImmediateOperand>(*operand)) {
            state.fallback(source, "ir.unsupported_shift_count",
                "only immediate native shift counts are supported", output);
            return;
        }
        output.instructions.push_back(IrBinaryOperation{
            *opcode, IrWidth::U32, destination, *operand, source.id});
        if ((decoded.id == X86_INS_SHL || decoded.id == X86_INS_SHR)
            && std::get<IrImmediateOperand>(*operand).bits >= 32) {
            output.instructions.pop_back();
            state.fallback(source, "ir.unsupported_shift_count",
                "native shift counts of 32 or more use architecture-specific masking", output);
            comparisonFlagsAvailable = false;
            return;
        }
        comparisonFlagsAvailable = false;
        return;
    }

    if (decoded.id == X86_INS_NOT || decoded.id == X86_INS_INC || decoded.id == X86_INS_DEC) {
        if (x86.op_count != 1 || x86.operands[0].type != X86_OP_REG
            || x86.operands[0].size != 4
            || !is_supported_register(static_cast<x86_reg>(x86.operands[0].reg))) {
            state.fallback(source, "ir.unsupported_unary_operation",
                "native unary operation is outside the supported form", output);
            return;
        }
        const auto destination = state.variable(static_cast<x86_reg>(x86.operands[0].reg));
        if (decoded.id == X86_INS_NOT) {
            output.instructions.push_back(IrUnaryOperation{
                IrUnaryOpcode::Not, IrWidth::U32, destination, source.id});
        } else {
            output.instructions.push_back(IrBinaryOperation{
                decoded.id == X86_INS_INC ? IrBinaryOpcode::Add : IrBinaryOpcode::Subtract,
                IrWidth::U32,
                destination,
                IrImmediateOperand{IrWidth::U32, 1},
                source.id,
            });
        }
        comparisonFlagsAvailable = false;
        return;
    }

    if (decoded.id == X86_INS_CMP || decoded.id == X86_INS_TEST) {
        if (x86.op_count != 2 || x86.operands[0].type != X86_OP_REG
            || x86.operands[0].size != 4
            || !is_supported_register(static_cast<x86_reg>(x86.operands[0].reg))) {
            state.fallback(source, "ir.unsupported_comparison",
                "native comparison is outside the supported form", output);
            return;
        }
        std::string code;
        std::string reason;
        const auto right = operand_from(state, x86.operands[1], code, reason);
        if (!right.has_value()) {
            state.fallback(source, std::move(code), std::move(reason), output);
            return;
        }
        const auto left = state.variable(static_cast<x86_reg>(x86.operands[0].reg));
        if (decoded.id == X86_INS_CMP) {
            output.instructions.push_back(IrCompare{
                IrWidth::U32, left, *right, source.id});
        } else {
            output.instructions.push_back(IrTest{
                IrWidth::U32, left, *right, source.id});
        }
        comparisonFlagsAvailable = true;
        return;
    }

    if (decoded.id == X86_INS_JMP) {
        if (x86.op_count != 1 || x86.operands[0].type != X86_OP_IMM) {
            state.fallback(source, "ir.unsupported_branch",
                "indirect native branches are not lowerable", output);
            return;
        }
        const auto target = target_block(state, static_cast<std::uint64_t>(x86.operands[0].imm));
        if (!target.has_value()) {
            state.fallback(source, "ir.branch_target_missing",
                "native branch target is outside the selected function CFG", output);
            return;
        }
        output.instructions.push_back(IrJump{*target, source.id});
        return;
    }

    if (const auto condition = condition_for(decoded.id); condition.has_value()) {
        if (!comparisonFlagsAvailable) {
            state.fallback(source, "ir.unsupported_flag_dependency",
                "conditional lowering requires flags from a preceding compare or test", output);
            return;
        }
        if (x86.op_count != 1 || x86.operands[0].type != X86_OP_IMM) {
            state.fallback(source, "ir.unsupported_branch",
                "indirect native conditional branches are not lowerable", output);
            return;
        }
        const auto trueTarget = target_block(
            state, static_cast<std::uint64_t>(x86.operands[0].imm));
        const auto falseTarget = target_block(state, source.address.value + source.encoding.size());
        if (!trueTarget.has_value() || !falseTarget.has_value()) {
            state.fallback(source, "ir.branch_target_missing",
                "native conditional target is outside the selected function CFG", output);
            return;
        }
        output.instructions.push_back(IrConditionalJump{
            *condition, *trueTarget, *falseTarget, source.id});
        return;
    }

    if (decoded.id == X86_INS_RET) {
        output.instructions.push_back(IrReturn{
            IrWidth::U32, state.variable(X86_REG_EAX), source.id});
        return;
    }

    state.fallback(source, "ir.unsupported_instruction",
        "native instruction is outside the Milestone 8 lifting subset", output);
}

} // namespace

auto lift_function(
    const BinaryImage& image,
    EntityId functionId,
    const NativeFunctionSignature& signature,
    const IrLimits& limits) -> Result<NativeLiftReport, Diagnostic> {
    if (image.architecture != Architecture::X86_64) {
        return failed("ir.unsupported_architecture", "native VM lowering currently requires x86-64");
    }
    if (signature.arguments.size() > 4
        || signature.returnWidth != IrWidth::U32
        || std::any_of(signature.arguments.begin(), signature.arguments.end(),
            [](IrWidth width) { return width != IrWidth::U32; })) {
        return failed("ir.unsupported_signature",
            "Milestone 8 supports at most four 32-bit integer arguments and a 32-bit return");
    }
    const auto functionIt = std::find_if(image.functions.begin(), image.functions.end(),
        [functionId](const auto& function) { return function.id == functionId; });
    if (functionIt == image.functions.end()) {
        return failed("ir.function_not_found", "selected native function was not recovered");
    }
    const auto& function = *functionIt;
    if (!function.complete || !function.entryBlock.has_value()) {
        return failed("ir.incomplete_function", "selected native function is incomplete");
    }

    CapstoneHandle handle;
    if (!handle.open()) {
        return failed("ir.decoder_initialization_failed", "could not initialize x86-64 lifter");
    }

    LiftState state;
    state.report.function.sourceFunction = function.id;
    state.report.function.name = function.name;
    state.report.function.returnWidth = signature.returnWidth;

    const auto nativeArgumentRegisters = argument_registers(signature.abi);
    for (std::size_t index = 0; index < signature.arguments.size(); ++index) {
        const auto variable = state.variable(nativeArgumentRegisters[index]);
        state.report.function.arguments.push_back(IrArgumentBinding{
            static_cast<std::uint16_t>(index), variable, signature.arguments[index]});
    }

    for (std::size_t index = 0; index < function.basicBlocks.size(); ++index) {
        const auto* source = find_block(image, function.basicBlocks[index]);
        if (source == nullptr || source->hasUnresolvedSuccessor) {
            return failed("ir.incomplete_cfg", "selected function has an incomplete CFG");
        }
        const auto id = IrBlockId{static_cast<std::uint32_t>(index)};
        state.blocksByAddress.emplace(source->address.value, id);
        state.report.function.blocks.push_back(IrBlock{
            .id = id,
            .sourceBlock = source->id,
            .instructions = {},
        });
        if (source->id == *function.entryBlock) state.report.function.entry = id;
    }

    for (std::size_t blockIndex = 0; blockIndex < function.basicBlocks.size(); ++blockIndex) {
        const auto* sourceBlock = find_block(image, function.basicBlocks[blockIndex]);
        auto& output = state.report.function.blocks[blockIndex];
        bool comparisonFlagsAvailable = false;
        for (const auto instructionId : sourceBlock->instructions) {
            const auto* source = find_instruction(image, instructionId);
            if (source == nullptr || source->encoding.empty()) {
                return failed("ir.instruction_missing", "selected CFG references a missing instruction");
            }
            DecodedInstruction decoded;
            if (!decoded.decode(handle.get(), *source)) {
                state.fallback(*source, "ir.decode_failed",
                    "native instruction could not be decoded exactly", output);
                continue;
            }
            lift_decoded(state, *source, decoded.get(), output, comparisonFlagsAvailable);
        }
        if (output.instructions.empty()
            || (!std::holds_alternative<IrJump>(output.instructions.back())
                && !std::holds_alternative<IrConditionalJump>(output.instructions.back())
                && !std::holds_alternative<IrReturn>(output.instructions.back()))) {
            if (sourceBlock->edges.size() == 1 && sourceBlock->edges[0].targetBlock.has_value()) {
                const auto targetSource = *sourceBlock->edges[0].targetBlock;
                const auto found = std::find(
                    function.basicBlocks.begin(), function.basicBlocks.end(), targetSource);
                if (found != function.basicBlocks.end()) {
                    output.instructions.push_back(IrJump{
                        IrBlockId{static_cast<std::uint32_t>(
                            std::distance(function.basicBlocks.begin(), found))},
                        sourceBlock->instructions.empty()
                            ? sourceBlock->id : sourceBlock->instructions.back(),
                    });
                }
            }
        }
    }

    state.report.complete = state.complete;
    if (state.complete) {
        const auto validated = validate_function(state.report.function, limits);
        if (!validated.has_value()) {
            return Result<NativeLiftReport, Diagnostic>::failure(validated.error());
        }
    }
    return Result<NativeLiftReport, Diagnostic>::success(std::move(state.report));
}

} // namespace binobf::ir

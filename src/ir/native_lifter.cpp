#include <binobf/ir/native_lifter.hpp>

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
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

    auto open(Architecture architecture) -> bool {
        const auto mode = architecture == Architecture::X86 ? CS_MODE_32 : CS_MODE_64;
        return cs_open(CS_ARCH_X86, mode, &handle_) == CS_ERR_OK
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
    case X86_REG_XMM0:
    case X86_REG_XMM1:
    case X86_REG_XMM2:
    case X86_REG_XMM3:
    case X86_REG_XMM4:
    case X86_REG_XMM5:
    case X86_REG_XMM6:
    case X86_REG_XMM7:
    case X86_REG_ST0:
        return true;
    default:
        return false;
    }
}

auto is_supported_xmm_register(x86_reg reg) -> bool {
    switch (reg) {
    case X86_REG_XMM0:
    case X86_REG_XMM1:
    case X86_REG_XMM2:
    case X86_REG_XMM3:
    case X86_REG_XMM4:
    case X86_REG_XMM5:
    case X86_REG_XMM6:
    case X86_REG_XMM7:
        return true;
    default:
        return false;
    }
}

auto argument_registers(NativeAbi abi) -> std::vector<x86_reg> {
    switch (abi) {
    case NativeAbi::WindowsX64:
        return {X86_REG_ECX, X86_REG_EDX, X86_REG_R8D, X86_REG_R9D};
    case NativeAbi::SystemVAMD64:
        return {X86_REG_EDI, X86_REG_ESI, X86_REG_EDX, X86_REG_ECX};
    case NativeAbi::WindowsI386Fastcall:
        return {X86_REG_ECX, X86_REG_EDX};
    case NativeAbi::WindowsI386Thiscall:
        return {X86_REG_ECX};
    case NativeAbi::WindowsI386Cdecl:
    case NativeAbi::WindowsI386Stdcall:
    case NativeAbi::SystemVI386:
    case NativeAbi::WindowsARM64:
    case NativeAbi::AAPCS64:
        return {};
    }
    return {};
}

auto is_i386_abi(NativeAbi abi) noexcept -> bool {
    return abi == NativeAbi::WindowsI386Cdecl
        || abi == NativeAbi::WindowsI386Stdcall
        || abi == NativeAbi::WindowsI386Fastcall
        || abi == NativeAbi::WindowsI386Thiscall
        || abi == NativeAbi::SystemVI386;
}

auto is_arm64_abi(NativeAbi abi) noexcept -> bool {
    return abi == NativeAbi::WindowsARM64 || abi == NativeAbi::AAPCS64;
}

auto calling_convention(NativeAbi abi) noexcept -> IrCallingConvention {
    switch (abi) {
    case NativeAbi::WindowsX64: return IrCallingConvention::MicrosoftX64;
    case NativeAbi::SystemVAMD64: return IrCallingConvention::SystemV;
    case NativeAbi::WindowsI386Cdecl: return IrCallingConvention::MicrosoftI386Cdecl;
    case NativeAbi::WindowsI386Stdcall: return IrCallingConvention::MicrosoftI386Stdcall;
    case NativeAbi::WindowsI386Fastcall: return IrCallingConvention::MicrosoftI386Fastcall;
    case NativeAbi::WindowsI386Thiscall: return IrCallingConvention::MicrosoftI386Thiscall;
    case NativeAbi::SystemVI386: return IrCallingConvention::SystemVI386;
    case NativeAbi::WindowsARM64: return IrCallingConvention::MicrosoftARM64;
    case NativeAbi::AAPCS64: return IrCallingConvention::AAPCS64;
    }
    return IrCallingConvention::C;
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
    case X86_INS_ADDSS:
    case X86_INS_ADDSD: return IrBinaryOpcode::Add;
    case X86_INS_SUBSS:
    case X86_INS_SUBSD: return IrBinaryOpcode::Subtract;
    case X86_INS_MULSS:
    case X86_INS_MULSD: return IrBinaryOpcode::Multiply;
    case X86_INS_DIVSS:
    case X86_INS_DIVSD: return IrBinaryOpcode::Divide;
    default: return std::nullopt;
    }
}

auto floating_operation_type(unsigned int id) -> std::optional<IrType> {
    switch (id) {
    case X86_INS_MOVSS:
    case X86_INS_ADDSS:
    case X86_INS_SUBSS:
    case X86_INS_MULSS:
    case X86_INS_DIVSS:
        return IrType{IrTypeKind::FloatingPoint, 32U};
    case X86_INS_MOVSD:
    case X86_INS_ADDSD:
    case X86_INS_SUBSD:
    case X86_INS_MULSD:
    case X86_INS_DIVSD:
        return IrType{IrTypeKind::FloatingPoint, 64U};
    default:
        return std::nullopt;
    }
}

struct LiftState {
    NativeLiftReport report;
    const BinaryImage* image{nullptr};
    std::map<unsigned int, IrVariable> variables;
    std::map<std::int64_t, IrVariable> stackArguments;
    std::map<std::uint64_t, IrBlockId> blocksByAddress;
    std::map<std::string, IrFunctionSignature> externalDeclarations;
    std::map<std::string, std::uint16_t> symbolStorageIndices;
    std::vector<IrOperand> outgoingStackArguments;
    std::vector<const Instruction*> outgoingStackArgumentInstructions;
    Architecture architecture{Architecture::Unknown};
    IrType returnType{IrWidth::U32};
    bool framePointerEstablished{false};
    bool complete{true};

    auto fresh_variable(IrType type) -> IrVariable {
        const auto index = static_cast<std::uint16_t>(report.function.variableTypes.size());
        report.function.variableTypes.push_back(type);
        return IrVariable{index};
    }

    auto variable(x86_reg reg, IrType type = integer_type(IrWidth::U32)) -> IrVariable {
        const auto key = static_cast<unsigned int>(reg);
        const auto found = variables.find(key);
        if (found != variables.end()) {
            if (report.function.variableTypes[found->second.index] == type) {
                return found->second;
            }
            const auto replacement = fresh_variable(type);
            found->second = replacement;
            return replacement;
        }
        const auto created = fresh_variable(type);
        variables.emplace(key, created);
        return created;
    }

    void fallback(const Instruction& source, std::string code, std::string reason, IrBlock& block) {
        complete = false;
        report.diagnostics.push_back(warning(std::move(code), reason));
        block.instructions.push_back(IrFallback{
            .sourceInstruction = source.id,
            .encoding = source.encoding,
            .reason = std::move(reason),
            .effects = IrFallbackEffects{
                .reads = {},
                .writes = {},
                .clobberedRegisters = {"flags"},
                .readsMemory = true,
                .writesMemory = true,
                .changesControlFlow = true,
                .mayUnwind = true,
                .complete = true,
            },
            .unwindRegion = std::nullopt,
        });
    }

    void flush_unconsumed_stack_arguments(IrBlock& block) {
        for (const auto* instruction : outgoingStackArgumentInstructions) {
            fallback(
                *instruction,
                "ir.unconsumed_stack_argument",
                "i386 push was not consumed by an exact declared call",
                block);
        }
        outgoingStackArguments.clear();
        outgoingStackArgumentInstructions.clear();
    }
};

struct TypedOperand {
    IrOperand value;
    IrType type;
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
    std::string& failureReason,
    std::optional<IrType> preferredType = std::nullopt) -> std::optional<TypedOperand> {
    const bool scalarXmmRegister = operand.type == X86_OP_REG
        && operand.size == 16
        && preferredType.has_value()
        && preferredType->kind == IrTypeKind::FloatingPoint
        && (preferredType->bits == 32U || preferredType->bits == 64U)
        && is_supported_xmm_register(static_cast<x86_reg>(operand.reg));
    if (operand.size != 4 && operand.size != 8 && !scalarXmmRegister) {
        failureCode = "ir.unsupported_operand_width";
        failureReason = "native operand width is outside the supported scalar subset";
        return std::nullopt;
    }
    if (operand.type == X86_OP_REG) {
        const auto reg = static_cast<x86_reg>(operand.reg);
        if (!is_supported_register(reg)) {
            failureCode = "ir.unsupported_register";
            failureReason = "native operand uses an unsupported register";
            return std::nullopt;
        }
        const auto found = state.variables.find(static_cast<unsigned int>(reg));
        const auto type = preferredType.has_value()
            ? *preferredType
            : (found == state.variables.end()
                ? integer_type(operand.size == 8 ? IrWidth::U64 : IrWidth::U32)
                : state.report.function.variableTypes[found->second.index]);
        if (found != state.variables.end() && preferredType.has_value()
            && state.report.function.variableTypes[found->second.index] != *preferredType) {
            failureCode = "ir.type_mismatch";
            failureReason = "native register operand type does not match the instruction";
            return std::nullopt;
        }
        const auto variable = state.variable(reg, type);
        return TypedOperand{IrOperand{IrVariableOperand{variable}}, type};
    }
    if (operand.type == X86_OP_IMM) {
        const auto type = preferredType.value_or(
            integer_type(operand.size == 8 ? IrWidth::U64 : IrWidth::U32));
        return TypedOperand{
            IrOperand{IrImmediateOperand{type, static_cast<std::uint64_t>(operand.imm)}},
            type};
    }
    if (operand.type == X86_OP_MEM) {
        const auto& memory = operand.mem;
        const bool incomingStackAddress = memory.index == X86_REG_INVALID
            && memory.scale == 1
            && (memory.base == X86_REG_ESP
                || (memory.base == X86_REG_EBP && state.framePointerEstablished));
        if (incomingStackAddress) {
            const auto incomingOffset = memory.base == X86_REG_EBP
                ? memory.disp - 4
                : memory.disp;
            const auto found = state.stackArguments.find(incomingOffset);
            if (found != state.stackArguments.end()) {
                const auto type = state.report.function.variableTypes[found->second.index];
                if (preferredType.has_value() && type != *preferredType) {
                    failureCode = "ir.type_mismatch";
                    failureReason = "native stack argument type does not match the instruction";
                    return std::nullopt;
                }
                return TypedOperand{IrOperand{IrVariableOperand{found->second}}, type};
            }
        }
        failureCode = "ir.unsupported_memory_operand";
        failureReason = "native memory operand is not a declared stack argument";
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

auto referenced_symbol_name(
    const LiftState& state,
    const Instruction& instruction) -> std::optional<std::string> {
    if (state.image == nullptr) return std::nullopt;
    for (const auto& reference : instruction.references) {
        if (!reference.symbol.has_value()) continue;
        const auto symbol = std::find_if(
            state.image->symbols.begin(), state.image->symbols.end(),
            [&](const auto& candidate) { return candidate.id == *reference.symbol; });
        if (symbol != state.image->symbols.end() && !symbol->name.empty()) {
            return symbol->name;
        }
    }
    return std::nullopt;
}

auto register_from_binding_name(std::string_view name) -> std::optional<x86_reg> {
    if (name == "eax") return X86_REG_EAX;
    if (name == "ebx") return X86_REG_EBX;
    if (name == "ecx") return X86_REG_ECX;
    if (name == "edx") return X86_REG_EDX;
    if (name == "esi") return X86_REG_ESI;
    if (name == "edi") return X86_REG_EDI;
    if (name == "ebp") return X86_REG_EBP;
    if (name == "xmm0") return X86_REG_XMM0;
    if (name == "xmm1") return X86_REG_XMM1;
    if (name == "xmm2") return X86_REG_XMM2;
    if (name == "xmm3") return X86_REG_XMM3;
    if (name == "st0") return X86_REG_ST0;
    return std::nullopt;
}

auto operand_matches_type(
    const LiftState& state,
    const IrOperand& operand,
    const IrType& type) -> bool {
    if (const auto* variable = std::get_if<IrVariableOperand>(&operand)) {
        return variable->variable.index < state.report.function.variableTypes.size()
            && state.report.function.variableTypes[variable->variable.index] == type;
    }
    return std::get<IrImmediateOperand>(operand).type == type;
}

auto declared_call_arguments(
    const LiftState& state,
    const IrFunctionSignature& signature) -> std::optional<std::vector<IrOperand>> {
    if (signature.parameterTypes.empty()) {
        if (!state.outgoingStackArguments.empty() && !signature.variadic) return std::nullopt;
        std::vector<IrOperand> arguments;
        arguments.reserve(state.outgoingStackArguments.size());
        for (auto item = state.outgoingStackArguments.rbegin();
             item != state.outgoingStackArguments.rend(); ++item) {
            arguments.push_back(*item);
        }
        return arguments;
    }
    if (signature.parameterBindings.size() != signature.parameterTypes.size()) {
        return std::nullopt;
    }
    const auto stackBindingCount = static_cast<std::size_t>(std::count_if(
        signature.parameterBindings.begin(), signature.parameterBindings.end(),
        [](const auto& binding) { return binding.kind == IrStorageKind::Stack; }));
    if (state.outgoingStackArguments.size() < stackBindingCount
        || (!signature.variadic
            && state.outgoingStackArguments.size() != stackBindingCount)) {
        return std::nullopt;
    }

    std::vector<IrOperand> arguments;
    arguments.reserve(signature.parameterTypes.size()
        + state.outgoingStackArguments.size() - stackBindingCount);
    std::size_t stackIndex = 0;
    for (std::size_t index = 0; index < signature.parameterTypes.size(); ++index) {
        const auto& binding = signature.parameterBindings[index];
        IrOperand argument;
        if (binding.kind == IrStorageKind::Register) {
            const auto reg = register_from_binding_name(binding.name);
            if (!reg.has_value()) return std::nullopt;
            const auto found = state.variables.find(static_cast<unsigned int>(*reg));
            if (found == state.variables.end()) return std::nullopt;
            argument = IrVariableOperand{found->second};
        } else if (binding.kind == IrStorageKind::Stack) {
            argument = state.outgoingStackArguments[
                state.outgoingStackArguments.size() - 1U - stackIndex++];
        } else {
            return std::nullopt;
        }
        if (!operand_matches_type(state, argument, signature.parameterTypes[index])) {
            return std::nullopt;
        }
        arguments.push_back(argument);
    }
    if (signature.variadic) {
        const auto extraCount = state.outgoingStackArguments.size() - stackBindingCount;
        for (std::size_t index = 0; index < extraCount; ++index) {
            arguments.push_back(state.outgoingStackArguments[extraCount - 1U - index]);
        }
    }
    return arguments;
}

void lift_decoded(
    LiftState& state,
    const Instruction& source,
    const cs_insn& decoded,
    IrBlock& output,
    bool& comparisonFlagsAvailable) {
    const auto& x86 = decoded.detail->x86;
    if (has_relocation_reference(source)) {
        if (decoded.id == X86_INS_CALL) {
            const auto symbol = referenced_symbol_name(state, source);
            const auto declaration = symbol.has_value()
                ? state.externalDeclarations.find(*symbol)
                : state.externalDeclarations.end();
            const auto arguments = declaration != state.externalDeclarations.end()
                ? declared_call_arguments(state, declaration->second)
                : std::nullopt;
            if (symbol.has_value() && declaration != state.externalDeclarations.end()
                && arguments.has_value()) {
                std::optional<IrVariable> destination;
                const auto& returnType = declaration->second.returnType;
                if (returnType.kind != IrTypeKind::Void) {
                    if ((returnType.kind != IrTypeKind::Integer
                         && returnType.kind != IrTypeKind::Pointer)
                        || returnType.bits > 32U) {
                        state.fallback(
                            source,
                            "ir.unsupported_return_binding",
                            "declared external return requires an unsupported register binding",
                            output);
                        return;
                    }
                    destination = state.variable(X86_REG_EAX, returnType);
                }
                output.instructions.push_back(IrExternalCall{
                    .symbol = *symbol,
                    .signature = declaration->second,
                    .destination = destination,
                    .arguments = *arguments,
                    .sourceInstruction = source.id,
                    .unwindRegion = std::nullopt,
                });
                state.outgoingStackArguments.clear();
                state.outgoingStackArgumentInstructions.clear();
                comparisonFlagsAvailable = false;
                return;
            }
            state.fallback(
                source,
                symbol.has_value() ? "ir.undeclared_external_call"
                                   : "ir.external_symbol_missing",
                symbol.has_value()
                    ? "relocation-backed call has no exact external declaration"
                    : "relocation-backed call has no target symbol",
                output);
            return;
        }
        const auto symbol = referenced_symbol_name(state, source);
        const auto storage = symbol.has_value()
            ? state.symbolStorageIndices.find(*symbol)
            : state.symbolStorageIndices.end();
        if (symbol.has_value() && storage != state.symbolStorageIndices.end()
            && decoded.id == X86_INS_LEA
            && x86.op_count == 2
            && x86.operands[0].type == X86_OP_REG
            && x86.operands[1].type == X86_OP_MEM
            && is_supported_register(static_cast<x86_reg>(x86.operands[0].reg))) {
            const auto pointerType = IrType{
                IrTypeKind::Pointer,
                static_cast<std::uint16_t>(
                    state.architecture == Architecture::X86 ? 32U : 64U)};
            output.instructions.push_back(IrAddressOf{
                .destination = state.variable(
                    static_cast<x86_reg>(x86.operands[0].reg), pointerType),
                .storageIndex = storage->second,
                .sourceInstruction = source.id,
            });
            return;
        }
        if (symbol.has_value() && storage != state.symbolStorageIndices.end()
            && decoded.id == X86_INS_MOV
            && x86.op_count == 2
            && x86.operands[0].type == X86_OP_REG
            && x86.operands[1].type == X86_OP_MEM
            && is_supported_register(static_cast<x86_reg>(x86.operands[0].reg))) {
            const auto& storageLocation =
                state.report.function.storageLocations[storage->second];
            if (x86.operands[1].size * 8U != storageLocation.type.bits) {
                state.fallback(
                    source,
                    "ir.symbol_storage_type_mismatch",
                    "relocation-backed load width does not match its declaration",
                    output);
                return;
            }
            const auto addressSpace = static_cast<std::uint16_t>(
                storageLocation.kind == IrStorageKind::ThreadLocal ? 1U : 0U);
            const auto pointerType = IrType{
                IrTypeKind::Pointer,
                static_cast<std::uint16_t>(
                    state.architecture == Architecture::X86 ? 32U : 64U),
                1U,
                addressSpace,
            };
            const auto address = state.fresh_variable(pointerType);
            output.instructions.push_back(IrAddressOf{
                .destination = address,
                .storageIndex = storage->second,
                .sourceInstruction = source.id,
            });
            output.instructions.push_back(IrLoad{
                .type = storageLocation.type,
                .destination = state.variable(
                    static_cast<x86_reg>(x86.operands[0].reg), storageLocation.type),
                .address = IrAddress{
                    .base = address,
                    .index = std::nullopt,
                    .scale = 1,
                    .displacement = 0,
                    .addressSpace = addressSpace,
                    .alignment = storageLocation.alignment,
                },
                .byteOrder = storageLocation.type.byteOrder,
                .volatileAccess = false,
                .atomicOrdering = IrAtomicOrdering::None,
                .sourceInstruction = source.id,
                .unwindRegion = std::nullopt,
            });
            return;
        }
        state.fallback(source, "ir.relocation_backed_instruction",
            "relocation-backed native instructions are not lowerable", output);
        return;
    }
    if ((decoded.id == X86_INS_RET || decoded.id == X86_INS_JMP
         || condition_for(decoded.id).has_value())
        && !state.outgoingStackArguments.empty()) {
        state.flush_unconsumed_stack_arguments(output);
    }
    if (decoded.id == X86_INS_NOP) return;

    if (state.architecture == Architecture::X86) {
        const bool singleEbpOperand = x86.op_count == 1
            && x86.operands[0].type == X86_OP_REG
            && x86.operands[0].reg == X86_REG_EBP;
        if (decoded.id == X86_INS_PUSH && singleEbpOperand) return;
        if (decoded.id == X86_INS_POP && singleEbpOperand) return;
        if (decoded.id == X86_INS_LEAVE) {
            return;
        }
        if (decoded.id == X86_INS_MOV && x86.op_count == 2
            && x86.operands[0].type == X86_OP_REG
            && x86.operands[1].type == X86_OP_REG
            && ((x86.operands[0].reg == X86_REG_EBP
                 && x86.operands[1].reg == X86_REG_ESP)
                || (x86.operands[0].reg == X86_REG_ESP
                    && x86.operands[1].reg == X86_REG_EBP))) {
            if (x86.operands[0].reg == X86_REG_EBP) {
                state.framePointerEstablished = true;
            }
            return;
        }
    }

    if (state.architecture == Architecture::X86 && decoded.id == X86_INS_PUSH) {
        if (x86.op_count != 1) {
            state.fallback(source, "ir.unsupported_push", "i386 push operand is invalid", output);
            return;
        }
        std::string code;
        std::string reason;
        const auto operand = operand_from(state, x86.operands[0], code, reason);
        if (!operand.has_value()) {
            state.fallback(source, std::move(code), std::move(reason), output);
            return;
        }
        state.outgoingStackArguments.push_back(operand->value);
        state.outgoingStackArgumentInstructions.push_back(&source);
        return;
    }

    if (state.architecture == Architecture::X86
        && (decoded.id == X86_INS_ADD || decoded.id == X86_INS_SUB)
        && x86.op_count == 2
        && x86.operands[0].type == X86_OP_REG
        && x86.operands[0].reg == X86_REG_ESP
        && x86.operands[1].type == X86_OP_IMM) {
        return;
    }

    if (decoded.id == X86_INS_FLD) {
        if (x86.op_count != 1
            || state.returnType.kind != IrTypeKind::FloatingPoint
            || x86.operands[0].size * 8U != state.returnType.bits) {
            state.fallback(
                source,
                "ir.unsupported_x87_operation",
                "x87 load does not match the declared scalar return type",
                output);
            return;
        }
        std::string code;
        std::string reason;
        const auto operand = operand_from(
            state, x86.operands[0], code, reason, state.returnType);
        if (!operand.has_value()) {
            state.fallback(source, std::move(code), std::move(reason), output);
            return;
        }
        output.instructions.push_back(IrMove{
            state.returnType,
            state.variable(X86_REG_ST0, state.returnType),
            operand->value,
            source.id,
        });
        return;
    }

    if (decoded.id == X86_INS_MOV || decoded.id == X86_INS_MOVSS
        || decoded.id == X86_INS_MOVSD) {
        const auto moveType = floating_operation_type(decoded.id);
        const bool destinationWidthValid = moveType.has_value()
            ? x86.operands[0].size == 16
            : (x86.operands[0].size == 4 || x86.operands[0].size == 8);
        if (x86.op_count != 2 || x86.operands[0].type != X86_OP_REG
            || !destinationWidthValid
            || !is_supported_register(static_cast<x86_reg>(x86.operands[0].reg))) {
            state.fallback(source, "ir.unsupported_move",
                "native move is outside the supported register/immediate form", output);
            return;
        }
        std::string code;
        std::string reason;
        const auto operand = operand_from(
            state, x86.operands[1], code, reason, moveType);
        if (!operand.has_value()) {
            state.fallback(source, std::move(code), std::move(reason), output);
            return;
        }
        output.instructions.push_back(IrMove{
            operand->type,
            state.variable(static_cast<x86_reg>(x86.operands[0].reg), operand->type),
            operand->value,
            source.id,
        });
        return;
    }

    if (const auto opcode = binary_opcode(decoded.id); opcode.has_value()) {
        const auto operationType = floating_operation_type(decoded.id).value_or(
            integer_type(IrWidth::U32));
        const bool destinationWidthValid = operationType.kind == IrTypeKind::FloatingPoint
            ? x86.operands[0].size == 16
            : x86.operands[0].size == operationType.bits / 8U;
        if ((x86.op_count != 2 && decoded.id != X86_INS_IMUL)
            || x86.op_count < 2 || x86.op_count > 3
            || x86.operands[0].type != X86_OP_REG
            || !destinationWidthValid
            || !is_supported_register(static_cast<x86_reg>(x86.operands[0].reg))) {
            state.fallback(source, "ir.unsupported_binary_operation",
                "native binary operation is outside the supported form", output);
            return;
        }
        const auto destination = state.variable(
            static_cast<x86_reg>(x86.operands[0].reg), operationType);
        std::size_t sourceIndex = 1;
        if (x86.op_count == 3) {
            std::string code;
            std::string reason;
            const auto initial = operand_from(
                state, x86.operands[1], code, reason, operationType);
            if (!initial.has_value()) {
                state.fallback(source, std::move(code), std::move(reason), output);
                return;
            }
            output.instructions.push_back(IrMove{
                operationType, destination, initial->value, source.id});
            sourceIndex = 2;
        }
        std::string code;
        std::string reason;
        const auto operand = operand_from(
            state, x86.operands[sourceIndex], code, reason, operationType);
        if (!operand.has_value()) {
            state.fallback(source, std::move(code), std::move(reason), output);
            return;
        }
        if ((decoded.id == X86_INS_SHL || decoded.id == X86_INS_SHR)
            && !std::holds_alternative<IrImmediateOperand>(operand->value)) {
            state.fallback(source, "ir.unsupported_shift_count",
                "only immediate native shift counts are supported", output);
            return;
        }
        output.instructions.push_back(IrBinaryOperation{
            *opcode, operationType, destination, operand->value, source.id});
        if ((decoded.id == X86_INS_SHL || decoded.id == X86_INS_SHR)
            && std::get<IrImmediateOperand>(operand->value).bits >= 32) {
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
                IrWidth::U32, left, right->value, source.id});
        } else {
            output.instructions.push_back(IrTest{
                IrWidth::U32, left, right->value, source.id});
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
        if (state.returnType.kind == IrTypeKind::Void) {
            output.instructions.push_back(IrReturn{
                state.returnType, std::nullopt, source.id});
        } else if ((state.returnType.kind == IrTypeKind::Integer
                    || state.returnType.kind == IrTypeKind::Pointer)
                   && state.returnType.bits <= 32U) {
            output.instructions.push_back(IrReturn{
                state.returnType,
                state.variable(X86_REG_EAX, state.returnType),
                source.id});
        } else if (state.architecture == Architecture::X86
                   && state.returnType.kind == IrTypeKind::Integer
                   && state.returnType.bits == 64U) {
            output.instructions.push_back(IrReturn{
                state.returnType,
                state.variable(X86_REG_EAX, state.returnType),
                source.id});
        } else if (state.architecture == Architecture::X86
                   && state.returnType.kind == IrTypeKind::FloatingPoint
                   && (state.returnType.bits == 32U || state.returnType.bits == 64U)) {
            output.instructions.push_back(IrReturn{
                state.returnType,
                state.variable(X86_REG_ST0, state.returnType),
                source.id});
        } else {
            state.fallback(
                source,
                "ir.unsupported_return_binding",
                "native return value requires an unsupported register binding",
                output);
        }
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
    const NativeLiftOptions& options,
    const IrLimits& limits) -> Result<NativeLiftReport, Diagnostic> {
    if (image.architecture != Architecture::X86
        && image.architecture != Architecture::X86_64) {
        return failed("ir.unsupported_architecture", "native lifting requires an x86 architecture");
    }
    if ((image.architecture == Architecture::X86 && !is_i386_abi(signature.abi))
        || (image.architecture == Architecture::X86_64
            && (is_i386_abi(signature.abi) || is_arm64_abi(signature.abi)))) {
        return failed(
            "ir.abi_architecture_mismatch",
            "native ABI does not match the image architecture");
    }
    const auto maxArguments = image.architecture == Architecture::X86
        ? limits.maxArguments : std::size_t{4};
    if (signature.arguments.size() > maxArguments) {
        return failed("ir.unsupported_signature", "native signature has too many arguments");
    }
    const auto type_matches_architecture = [&](const IrType& type, bool allowVoid) {
        const auto checked = validate_type(type);
        if (!checked.has_value() || (!allowVoid && type.kind == IrTypeKind::Void)) return false;
        if (type.kind == IrTypeKind::Pointer) {
            const auto expected = image.architecture == Architecture::X86 ? 32U : 64U;
            return type.bits == expected;
        }
        return true;
    };
    if (!type_matches_architecture(signature.returnType, true)
        || std::any_of(
            signature.arguments.begin(), signature.arguments.end(),
            [&](const IrType& type) { return !type_matches_architecture(type, false); })) {
        return failed(
            "ir.unsupported_signature",
            "native signature contains an invalid type for the image architecture");
    }
    const bool variadicSupported = signature.abi == NativeAbi::WindowsI386Cdecl
        || signature.abi == NativeAbi::SystemVI386
        || signature.abi == NativeAbi::WindowsX64
        || signature.abi == NativeAbi::SystemVAMD64;
    if (signature.variadic && !variadicSupported) {
        return failed(
            "ir.unsupported_variadic_abi",
            "the selected native ABI does not permit variadic calls");
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
    if (!handle.open(image.architecture)) {
        return failed("ir.decoder_initialization_failed", "could not initialize x86 lifter");
    }

    LiftState state;
    state.image = &image;
    state.architecture = image.architecture;
    state.report.function.sourceFunction = function.id;
    state.report.function.name = function.name;
    state.returnType = signature.returnType;
    state.report.function.returnType = signature.returnType;
    for (const auto& declaration : options.externalDeclarations) {
        if (declaration.symbol.empty()
            || !state.externalDeclarations.emplace(
                    declaration.symbol, declaration.signature).second) {
            return failed(
                "ir.invalid_external_declaration",
                "native lift external declarations require unique non-empty symbols");
        }
    }
    if (options.symbolStorage.size() > limits.maxStorageLocations) {
        return failed(
            "ir.storage_limit",
            "native lift symbol-storage count exceeds the configured limit");
    }
    for (const auto& storage : options.symbolStorage) {
        const auto checkedType = validate_type(storage.type);
        const bool supportedKind = storage.kind == IrStorageKind::Global
            || storage.kind == IrStorageKind::ThreadLocal;
        const bool validAlignment = storage.alignment != 0U
            && (storage.alignment & (storage.alignment - 1U)) == 0U
            && storage.alignment <= limits.maxAlignment;
        const auto minimumSize = static_cast<std::uint64_t>(storage.type.bits)
            * static_cast<std::uint64_t>(storage.type.lanes) / 8U;
        if (storage.name.empty() || !checkedType.has_value()
            || storage.type.kind == IrTypeKind::Void || !supportedKind
            || storage.size < minimumSize || !validAlignment
            || state.symbolStorageIndices.contains(storage.name)) {
            return failed(
                "ir.invalid_symbol_storage",
                "native lift symbol storage must be unique, named, and valid");
        }
        const auto index = static_cast<std::uint16_t>(
            state.report.function.storageLocations.size());
        state.symbolStorageIndices.emplace(storage.name, index);
        state.report.function.storageLocations.push_back(storage);
    }

    const auto nativeArgumentRegisters = argument_registers(signature.abi);
    std::vector<IrStorageLocation> parameterBindings;
    parameterBindings.reserve(signature.arguments.size());
    std::size_t registerCursor = 0;
    std::uint64_t stackCursor = 4;
    for (std::size_t index = 0; index < signature.arguments.size(); ++index) {
        const auto type = signature.arguments[index];
        const auto typeBytes = static_cast<std::uint64_t>(type.bits)
            * static_cast<std::uint64_t>(type.lanes) / 8U;
        const bool registerEligible = typeBytes <= 4U
            && (type.kind == IrTypeKind::Integer || type.kind == IrTypeKind::Pointer);
        IrVariable variable;
        IrStorageLocation binding{};
        binding.type = type;
        binding.size = std::max<std::uint64_t>(typeBytes, 1U);
        binding.alignment = static_cast<std::uint32_t>(
            std::min<std::uint64_t>(std::max<std::uint64_t>(typeBytes, 1U), 4U));
        binding.index = static_cast<std::uint16_t>(index);
        if (registerEligible && registerCursor < nativeArgumentRegisters.size()) {
            const auto reg = nativeArgumentRegisters[registerCursor++];
            variable = state.variable(reg, type);
            binding.kind = IrStorageKind::Register;
            switch (reg) {
            case X86_REG_ECX: binding.name = "ecx"; break;
            case X86_REG_EDX: binding.name = "edx"; break;
            case X86_REG_EDI: binding.name = "edi"; break;
            case X86_REG_ESI: binding.name = "esi"; break;
            case X86_REG_R8D: binding.name = "r8d"; break;
            case X86_REG_R9D: binding.name = "r9d"; break;
            default: binding.name = "argument-register"; break;
            }
        } else {
            variable = state.fresh_variable(type);
            binding.kind = IrStorageKind::Stack;
            binding.name = "argument-" + std::to_string(index);
            binding.offset = static_cast<std::int64_t>(stackCursor);
            const auto slotBytes = std::max<std::uint64_t>(typeBytes, 4U);
            for (std::uint64_t part = 0; part < slotBytes; part += 4U) {
                state.stackArguments.emplace(
                    binding.offset + static_cast<std::int64_t>(part), variable);
            }
            stackCursor += (slotBytes + 3U) & ~UINT64_C(3);
        }
        parameterBindings.push_back(binding);
        state.report.function.storageLocations.push_back(binding);
        state.report.function.arguments.push_back(IrArgumentBinding{
            static_cast<std::uint16_t>(index), variable, type});
    }
    std::optional<IrStorageLocation> returnBinding;
    if (signature.returnType.kind != IrTypeKind::Void) {
        const auto returnBytes = static_cast<std::uint64_t>(signature.returnType.bits)
            * static_cast<std::uint64_t>(signature.returnType.lanes) / 8U;
        std::string returnRegister;
        if (signature.returnType.kind == IrTypeKind::FloatingPoint) {
            returnRegister = "st0";
        } else if (signature.returnType.kind == IrTypeKind::Vector) {
            returnRegister = "xmm0";
        } else if (returnBytes > 4U && image.architecture == Architecture::X86) {
            returnRegister = "edx:eax";
        } else {
            returnRegister = "eax";
        }
        returnBinding = IrStorageLocation{
            .kind = IrStorageKind::Register,
            .type = signature.returnType,
            .name = std::move(returnRegister),
            .offset = 0,
            .size = std::max<std::uint64_t>(returnBytes, 1U),
            .alignment = static_cast<std::uint32_t>(
                std::min<std::uint64_t>(std::max<std::uint64_t>(returnBytes, 1U), 4U)),
            .index = 0,
            .readonly = false,
        };
    }
    state.report.function.signature = IrFunctionSignature{
        .callingConvention = calling_convention(signature.abi),
        .parameterTypes = signature.arguments,
        .returnType = signature.returnType,
        .variadic = signature.variadic,
        .parameterBindings = std::move(parameterBindings),
        .returnBinding = std::move(returnBinding),
        .clobbers = {},
        .mayUnwind = false,
    };

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
        state.outgoingStackArguments.clear();
        state.outgoingStackArgumentInstructions.clear();
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
        if (!state.outgoingStackArguments.empty()) {
            state.flush_unconsumed_stack_arguments(output);
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

auto lift_function(
    const BinaryImage& image,
    EntityId function,
    const NativeFunctionSignature& signature,
    const IrLimits& limits) -> Result<NativeLiftReport, Diagnostic> {
    return lift_function(image, function, signature, NativeLiftOptions{}, limits);
}

} // namespace binobf::ir

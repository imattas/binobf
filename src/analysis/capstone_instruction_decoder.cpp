#include <binobf/analysis/instruction_decoder.hpp>

#include <capstone/arm64.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace binobf {
namespace {

auto failure(std::string code, std::string message) -> Result<Instruction, Diagnostic> {
    return Result<Instruction, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

class Handle final {
public:
    Handle() = default;
    Handle(const Handle&) = delete;
    auto operator=(const Handle&) -> Handle& = delete;
    ~Handle() {
        if (value_ != 0) {
            static_cast<void>(cs_close(&value_));
        }
    }

    auto open(Architecture architecture) -> cs_err {
        cs_arch capstoneArchitecture{};
        cs_mode mode{};
        switch (architecture) {
        case Architecture::X86:
            capstoneArchitecture = CS_ARCH_X86;
            mode = CS_MODE_32;
            break;
        case Architecture::X86_64:
            capstoneArchitecture = CS_ARCH_X86;
            mode = CS_MODE_64;
            break;
        case Architecture::ARM64:
            capstoneArchitecture = CS_ARCH_ARM64;
            mode = CS_MODE_ARM;
            break;
        case Architecture::Unknown:
            return CS_ERR_ARCH;
        }
        const auto opened = cs_open(capstoneArchitecture, mode, &value_);
        if (opened != CS_ERR_OK) return opened;
        return cs_option(value_, CS_OPT_DETAIL, CS_OPT_ON);
    }

    [[nodiscard]] auto value() const noexcept -> csh { return value_; }

private:
    csh value_{0};
};

class InstructionAllocation final {
public:
    InstructionAllocation() = default;
    InstructionAllocation(const InstructionAllocation&) = delete;
    auto operator=(const InstructionAllocation&) -> InstructionAllocation& = delete;
    ~InstructionAllocation() { cs_free(value_, count_); }

    auto decode(csh handle, const DecodeRequest& request) -> std::size_t {
        count_ = cs_disasm(
            handle,
            reinterpret_cast<const std::uint8_t*>(request.bytes.data()),
            request.bytes.size(),
            request.address.value,
            1,
            &value_);
        return count_;
    }

    [[nodiscard]] auto value() const noexcept -> const cs_insn& { return *value_; }

private:
    cs_insn* value_{nullptr};
    std::size_t count_{0};
};

auto has_group(csh handle, const cs_insn& instruction, std::uint8_t group) -> bool {
    return cs_insn_group(handle, &instruction, group);
}

auto immediate_target(Architecture architecture, const cs_insn& instruction)
    -> std::optional<std::uint64_t> {
    if (instruction.detail == nullptr) return std::nullopt;
    if (architecture == Architecture::X86 || architecture == Architecture::X86_64) {
        const auto& details = instruction.detail->x86;
        for (std::uint8_t index = 0; index < details.op_count; ++index) {
            if (details.operands[index].type == X86_OP_IMM) {
                return static_cast<std::uint64_t>(details.operands[index].imm);
            }
        }
    } else if (architecture == Architecture::ARM64) {
        const auto& details = instruction.detail->arm64;
        for (std::uint8_t index = 0; index < details.op_count; ++index) {
            if (details.operands[index].type == ARM64_OP_IMM) {
                return static_cast<std::uint64_t>(details.operands[index].imm);
            }
        }
    }
    return std::nullopt;
}

auto is_unconditional_direct_branch(Architecture architecture, unsigned int instructionId) -> bool {
    if (architecture == Architecture::X86 || architecture == Architecture::X86_64) {
        return instructionId == X86_INS_JMP;
    }
    return architecture == Architecture::ARM64 && instructionId == ARM64_INS_B;
}

auto normalize_registers(
    csh handle,
    const cs_regs registers,
    std::uint8_t count) -> std::vector<RegisterAccess> {
    std::vector<RegisterAccess> result;
    result.reserve(count);
    for (std::uint8_t index = 0; index < count; ++index) {
        const auto registerId = registers[index];
        const auto* name = cs_reg_name(handle, registerId);
        result.push_back(RegisterAccess{
            .id = registerId,
            .name = name == nullptr ? std::string{} : std::string{name},
        });
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return left.id < right.id;
    });
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}

class CapstoneInstructionDecoder final : public InstructionDecoder {
public:
    auto decode(const DecodeRequest& request) const
        -> Result<Instruction, Diagnostic> override {
        if (request.bytes.empty()) {
            return failure("analysis.empty_input", "instruction input is empty");
        }
        if (request.architecture == Architecture::Unknown) {
            return failure(
                "analysis.unsupported_architecture",
                "instruction architecture is unsupported");
        }
        if (!request.instructionId.valid() || !request.sectionId.valid()) {
            return failure("analysis.invalid_request", "instruction and section IDs must be valid");
        }

        Handle handle;
        const auto opened = handle.open(request.architecture);
        if (opened != CS_ERR_OK) {
            return failure(
                "analysis.decoder_initialization_failed",
                std::string{"could not initialize instruction decoder: "} + cs_strerror(opened));
        }
        InstructionAllocation allocation;
        if (allocation.decode(handle.value(), request) != 1) {
            return failure(
                "analysis.decode_failed",
                "instruction bytes do not contain a complete supported encoding");
        }
        const auto& decoded = allocation.value();
        const bool isCall = has_group(handle.value(), decoded, CS_GRP_CALL);
        const bool isJump = has_group(handle.value(), decoded, CS_GRP_JUMP);
        const bool isReturn = has_group(handle.value(), decoded, CS_GRP_RET)
            || has_group(handle.value(), decoded, CS_GRP_IRET);
        const bool isTrap = has_group(handle.value(), decoded, CS_GRP_INT);
        const auto target = (isCall || isJump)
            ? immediate_target(request.architecture, decoded) : std::nullopt;

        InstructionKind kind = InstructionKind::Normal;
        if (isReturn) {
            kind = InstructionKind::Return;
        } else if (isTrap) {
            kind = InstructionKind::Trap;
        } else if (isCall) {
            kind = target.has_value()
                ? InstructionKind::DirectCall : InstructionKind::IndirectCall;
        } else if (isJump) {
            if (!target.has_value()) {
                kind = InstructionKind::IndirectBranch;
            } else if (is_unconditional_direct_branch(request.architecture, decoded.id)) {
                kind = InstructionKind::DirectBranch;
            } else {
                kind = InstructionKind::ConditionalBranch;
            }
        }
        const bool hasFallthrough = kind == InstructionKind::Normal
            || kind == InstructionKind::ConditionalBranch
            || kind == InstructionKind::DirectCall
            || kind == InstructionKind::IndirectCall;

        cs_regs registersRead{};
        cs_regs registersWritten{};
        std::uint8_t registersReadCount = 0;
        std::uint8_t registersWrittenCount = 0;
        const auto access = cs_regs_access(
            handle.value(), &decoded,
            registersRead, &registersReadCount,
            registersWritten, &registersWrittenCount);
        if (access != CS_ERR_OK) {
            return failure(
                "analysis.register_access_failed",
                std::string{"could not derive register access: "} + cs_strerror(access));
        }

        std::vector<std::byte> encoding(decoded.size);
        std::transform(
            decoded.bytes, decoded.bytes + decoded.size, encoding.begin(),
            [](std::uint8_t value) { return static_cast<std::byte>(value); });
        std::optional<BinaryAddress> directTarget;
        if (target.has_value()) {
            directTarget = BinaryAddress{*target, request.address.kind};
        }
        std::vector<InstructionReference> references;
        if (directTarget.has_value()) {
            references.push_back(InstructionReference{
                .kind = isCall
                    ? InstructionReferenceKind::CallTarget
                    : InstructionReferenceKind::BranchTarget,
                .address = directTarget,
                .relocation = std::nullopt,
                .symbol = std::nullopt,
            });
        }
        return Result<Instruction, Diagnostic>::success(Instruction{
            .id = request.instructionId,
            .section = request.sectionId,
            .sectionOffset = request.sectionOffset,
            .address = request.address,
            .encoding = std::move(encoding),
            .mnemonic = decoded.mnemonic,
            .operands = decoded.op_str,
            .kind = kind,
            .directTarget = directTarget,
            .hasFallthrough = hasFallthrough,
            .registersRead = normalize_registers(
                handle.value(), registersRead, registersReadCount),
            .registersWritten = normalize_registers(
                handle.value(), registersWritten, registersWrittenCount),
            .references = std::move(references),
            .lineage = TransformationLineage{{TransformationRecord{
                .transform = TransformId{request.instructionId.value()},
                .source = request.sectionId,
                .passName = "machine-code-decode",
            }}},
        });
    }
};

} // namespace

auto make_instruction_decoder()
    -> Result<std::unique_ptr<InstructionDecoder>, Diagnostic> {
    return Result<std::unique_ptr<InstructionDecoder>, Diagnostic>::success(
        std::make_unique<CapstoneInstructionDecoder>());
}

} // namespace binobf

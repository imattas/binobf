#include <binobf/architecture/backend.hpp>

#include "x86_fixups.hpp"
#include "x86_abi.hpp"
#include "x86_templates.hpp"
#include "x86_unwind.hpp"

#include <capstone/arm64.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace binobf {
namespace {

constexpr std::array<std::string_view, 1> kDecodeEvidence{"instruction_decoder"};
constexpr std::array<std::string_view, 1> kAnalysisEvidence{"object_analyzer"};

auto failure(std::string code, std::string message) -> Result<Instruction, Diagnostic> {
    return Result<Instruction, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

auto backend_failure(std::string code, std::string message)
    -> Result<std::unique_ptr<ArchitectureBackend>, Diagnostic> {
    return Result<std::unique_ptr<ArchitectureBackend>, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

template <typename T>
auto service_failure(std::string code, std::string message) -> Result<T, Diagnostic> {
    return Result<T, Diagnostic>::failure(Diagnostic{
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
        const auto* registerName = cs_reg_name(handle, registerId);
        result.push_back(RegisterAccess{
            .id = registerId,
            .name = registerName == nullptr ? std::string{} : std::string{registerName},
        });
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return left.id < right.id;
    });
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}

auto analysis_support(Architecture architecture) -> SupportLevel {
    return architecture == Architecture::X86_64
        ? SupportLevel::Supported : SupportLevel::Experimental;
}

auto codegen_support(Architecture architecture) -> SupportLevel {
    return architecture == Architecture::X86_64
        ? SupportLevel::Restricted : SupportLevel::Planned;
}

class CapstoneArchitectureBackend final : public ArchitectureBackend {
public:
    CapstoneArchitectureBackend(
        Architecture architecture,
        std::unique_ptr<CodegenProvider> codegen)
        : architecture_(architecture),
          codegen_(std::move(codegen)),
          services_{
              BackendServiceRecord{
                  BackendService::Decode, SupportLevel::Supported, kDecodeEvidence},
              BackendServiceRecord{
                  BackendService::AnalyzeObject, analysis_support(architecture),
                  architecture == Architecture::X86_64
                      ? std::span<const std::string_view>{kAnalysisEvidence}
                      : std::span<const std::string_view>{}},
              BackendServiceRecord{
                  BackendService::EmitCode, codegen_support(architecture), {}},
              BackendServiceRecord{
                  BackendService::EncodeFixups, SupportLevel::Unsupported, {}},
              BackendServiceRecord{
                  BackendService::BuildAbiAdapter, SupportLevel::Unsupported, {}},
              BackendServiceRecord{
                  BackendService::BuildUnwind, SupportLevel::Unsupported, {}},
          } {}

    auto initialize() -> cs_err { return handle_.open(architecture_); }

    auto architecture() const noexcept -> Architecture override { return architecture_; }

    auto name() const noexcept -> std::string_view override {
        switch (architecture_) {
        case Architecture::X86: return "capstone-x86";
        case Architecture::X86_64: return "capstone-x86-64";
        case Architecture::ARM64: return "capstone-arm64";
        case Architecture::Unknown: return "capstone-unknown";
        }
        return "capstone-unknown";
    }

    auto services() const noexcept -> std::span<const BackendServiceRecord> override {
        return services_;
    }

    auto codegen() const noexcept -> const CodegenProvider* override {
        return codegen_.get();
    }

    auto emit_transform(const MachineTransformRequest& request) const
        -> Result<MachineTransformEmission, Diagnostic> override {
        if (request.architecture != architecture_) {
            return service_failure<MachineTransformEmission>(
                "architecture.request_mismatch",
                "transform request architecture does not match the fixed backend");
        }
        if (architecture_ != Architecture::X86) {
            return service_failure<MachineTransformEmission>(
                "architecture.service_unsupported",
                "the fixed backend does not implement the requested transform service");
        }
        auto emitted = detail::emit_x86_transform(request, *codegen_);
        if (!emitted.has_value()) {
            return service_failure<MachineTransformEmission>(
                emitted.error().code, emitted.error().message);
        }
        std::size_t offset = 0;
        std::size_t count = 0;
        InstructionKind lastKind = InstructionKind::Normal;
        bool decodedReadsFlags = false;
        bool decodedWritesFlags = false;
        bool decodedTouchesStack = false;
        bool decodedWritesRequestedRegister = false;
        bool decodedHasUnexpectedEquivalentEffect = false;
        const auto baseAddress = request.source.has_value()
            ? request.source->address.value : 0U;
        while (offset < emitted.value().emission.bytes.size()) {
            const auto instruction = decode(DecodeRequest{
                .architecture = Architecture::X86,
                .bytes = std::span<const std::byte>{emitted.value().emission.bytes}.subspan(offset),
                .address = BinaryAddress{baseAddress + offset, AddressKind::Virtual},
                .instructionId = EntityId{count + 1U},
                .sectionId = EntityId{1U},
                .sectionOffset = offset,
            });
            if (!instruction.has_value() || instruction.value().encoding.empty()) {
                return service_failure<MachineTransformEmission>(
                    "architecture.template_verification_failed",
                    "x86 template did not decode completely");
            }
            lastKind = instruction.value().kind;
            decodedReadsFlags = decodedReadsFlags || std::ranges::any_of(
                instruction.value().registersRead,
                [](const auto& value) { return value.name == "eflags"; });
            decodedWritesFlags = decodedWritesFlags || std::ranges::any_of(
                instruction.value().registersWritten,
                [](const auto& value) { return value.name == "eflags"; });
            decodedTouchesStack = decodedTouchesStack || std::ranges::any_of(
                instruction.value().registersRead,
                [](const auto& value) { return value.name == "esp"; })
                || std::ranges::any_of(
                    instruction.value().registersWritten,
                    [](const auto& value) { return value.name == "esp"; });
            decodedWritesRequestedRegister = decodedWritesRequestedRegister
                || std::ranges::any_of(
                    instruction.value().registersWritten,
                    [&](const auto& value) { return value.name == request.condition; });
            decodedHasUnexpectedEquivalentEffect = decodedHasUnexpectedEquivalentEffect
                || !instruction.value().registersRead.empty()
                || !instruction.value().registersWritten.empty();
            offset += instruction.value().encoding.size();
            ++count;
        }
        if (offset != emitted.value().emission.bytes.size()
            || count != emitted.value().instructionCount) {
            return service_failure<MachineTransformEmission>(
                "architecture.template_verification_failed",
                "x86 template instruction count or byte coverage changed during decode");
        }
        const auto expectedKind = emitted.value().controlFlow == MachineControlFlow::Conditional
            ? InstructionKind::ConditionalBranch
            : emitted.value().controlFlow == MachineControlFlow::Direct
                ? InstructionKind::DirectBranch : InstructionKind::Normal;
        if (lastKind != expectedKind
            || decodedReadsFlags != emitted.value().readsFlags
            || decodedWritesFlags != emitted.value().writesFlags
            || decodedTouchesStack
            || (request.kind == MachineTransformKind::ConstantMaterialization
                && !decodedWritesRequestedRegister)
            || (request.kind == MachineTransformKind::InstructionEquivalent
                && decodedHasUnexpectedEquivalentEffect)) {
            return service_failure<MachineTransformEmission>(
                "architecture.template_verification_failed",
                "decoded x86 control flow, flags, register, or stack effects do not match the template");
        }
        return emitted;
    }

    auto fixup_semantics(BinaryFormat format, std::uint64_t rawType) const
        -> Result<ObjectFixupSemantics, Diagnostic> override {
        if (architecture_ != Architecture::X86) {
            return service_failure<ObjectFixupSemantics>(
                "architecture.unsupported_fixup",
                "object fixup semantics are implemented only for x86");
        }
        return detail::x86_fixup_semantics(format, rawType);
    }

    auto encode_fixup(const ObjectFixupSemantics& semantics, std::int64_t value) const
        -> Result<ObjectFixupEncoding, Diagnostic> override {
        if (architecture_ != Architecture::X86) {
            return service_failure<ObjectFixupEncoding>(
                "architecture.unsupported_fixup",
                "object fixup encoding is implemented only for x86");
        }
        return detail::encode_x86_fixup(semantics, value);
    }

    auto build_abi_adapter(const AbiAdapterRequest& request) const
        -> Result<AbiAdapterPlan, Diagnostic> override {
        if (request.architecture != architecture_) {
            return service_failure<AbiAdapterPlan>(
                "architecture.request_mismatch",
                "ABI request architecture does not match the fixed backend");
        }
        if (architecture_ != Architecture::X86) {
            return service_failure<AbiAdapterPlan>(
                "architecture.service_unsupported",
                "the fixed backend does not implement ABI adapter generation");
        }
        return detail::build_x86_abi_adapter(request, *codegen_);
    }

    auto build_unwind(const UnwindRequest& request) const
        -> Result<UnwindPlan, Diagnostic> override {
        if (request.architecture != architecture_) {
            return service_failure<UnwindPlan>(
                "architecture.request_mismatch",
                "unwind request architecture does not match the fixed backend");
        }
        if (architecture_ != Architecture::X86) {
            return service_failure<UnwindPlan>(
                "architecture.service_unsupported",
                "the fixed backend does not implement unwind generation");
        }
        return detail::build_x86_unwind_plan(request);
    }

    auto decode(const DecodeRequest& request) const
        -> Result<Instruction, Diagnostic> override {
        if (request.architecture != architecture_) {
            return failure(
                "architecture.request_mismatch",
                "decode request architecture does not match the fixed backend");
        }
        if (request.bytes.empty()) {
            return failure("analysis.empty_input", "instruction input is empty");
        }
        if (!request.instructionId.valid() || !request.sectionId.valid()) {
            return failure("analysis.invalid_request", "instruction and section IDs must be valid");
        }

        InstructionAllocation allocation;
        if (allocation.decode(handle_.value(), request) != 1) {
            return failure(
                "analysis.decode_failed",
                "instruction bytes do not contain a complete supported encoding");
        }
        const auto& decoded = allocation.value();
        const bool isCall = has_group(handle_.value(), decoded, CS_GRP_CALL);
        const bool isJump = has_group(handle_.value(), decoded, CS_GRP_JUMP);
        const bool isReturn = has_group(handle_.value(), decoded, CS_GRP_RET)
            || has_group(handle_.value(), decoded, CS_GRP_IRET);
        const bool isTrap = has_group(handle_.value(), decoded, CS_GRP_INT);
        const auto target = (isCall || isJump)
            ? immediate_target(architecture_, decoded) : std::nullopt;

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
            } else if (is_unconditional_direct_branch(architecture_, decoded.id)) {
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
            handle_.value(), &decoded,
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
                handle_.value(), registersRead, registersReadCount),
            .registersWritten = normalize_registers(
                handle_.value(), registersWritten, registersWrittenCount),
            .references = std::move(references),
            .lineage = TransformationLineage{{TransformationRecord{
                .transform = TransformId{request.instructionId.value()},
                .source = request.sectionId,
                .passName = "machine-code-decode",
            }}},
        });
    }

private:
    Architecture architecture_;
    std::unique_ptr<CodegenProvider> codegen_;
    Handle handle_;
    std::array<BackendServiceRecord, 6> services_;
};

} // namespace

auto ArchitectureBackend::find_service(BackendService service) const noexcept
    -> const BackendServiceRecord* {
    const auto available = services();
    const auto found = std::ranges::find(available, service, &BackendServiceRecord::service);
    return found == available.end() ? nullptr : &*found;
}

auto make_architecture_backend(Architecture architecture)
    -> Result<std::unique_ptr<ArchitectureBackend>, Diagnostic> {
    if (architecture == Architecture::Unknown) {
        return backend_failure(
            "architecture.unsupported", "cannot create a backend for unknown architecture");
    }

    auto codegen = make_codegen_provider(architecture);
    if (!codegen.has_value()) {
        return backend_failure(codegen.error().code, codegen.error().message);
    }
    auto backend = std::make_unique<CapstoneArchitectureBackend>(
        architecture, std::move(codegen.value()));
    const auto opened = backend->initialize();
    if (opened != CS_ERR_OK) {
        return backend_failure(
            "analysis.decoder_initialization_failed",
            std::string{"could not initialize instruction decoder: "} + cs_strerror(opened));
    }
    std::unique_ptr<ArchitectureBackend> result = std::move(backend);
    return Result<std::unique_ptr<ArchitectureBackend>, Diagnostic>::success(
        std::move(result));
}

} // namespace binobf

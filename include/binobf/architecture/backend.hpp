#pragma once

#include <binobf/analysis/instruction_decoder.hpp>
#include <binobf/architecture/codegen.hpp>
#include <binobf/architecture/object_backend.hpp>
#include <binobf/capabilities/registry.hpp>

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

namespace binobf {

enum class BackendService : std::uint8_t {
    Decode,
    AnalyzeObject,
    EmitCode,
    EncodeFixups,
    BuildAbiAdapter,
    BuildUnwind,
};

struct BackendServiceRecord {
    BackendService service{BackendService::Decode};
    SupportLevel support{SupportLevel::Unsupported};
    std::span<const std::string_view> evidence;
};

class ArchitectureBackend : public InstructionDecoder {
public:
    [[nodiscard]] virtual auto architecture() const noexcept -> Architecture = 0;
    [[nodiscard]] virtual auto name() const noexcept -> std::string_view = 0;
    [[nodiscard]] virtual auto services() const noexcept
        -> std::span<const BackendServiceRecord> = 0;
    [[nodiscard]] virtual auto codegen() const noexcept -> const CodegenProvider* = 0;
    [[nodiscard]] virtual auto emit_transform(const MachineTransformRequest& request) const
        -> Result<MachineTransformEmission, Diagnostic> = 0;
    [[nodiscard]] virtual auto fixup_semantics(
        BinaryFormat format,
        std::uint64_t rawType) const -> Result<ObjectFixupSemantics, Diagnostic> = 0;
    [[nodiscard]] virtual auto encode_fixup(
        const ObjectFixupSemantics& semantics,
        std::int64_t value) const -> Result<ObjectFixupEncoding, Diagnostic> = 0;
    [[nodiscard]] virtual auto build_abi_adapter(const AbiAdapterRequest& request) const
        -> Result<AbiAdapterPlan, Diagnostic> = 0;
    [[nodiscard]] virtual auto build_unwind(const UnwindRequest& request) const
        -> Result<UnwindPlan, Diagnostic> = 0;
    [[nodiscard]] auto find_service(BackendService service) const noexcept
        -> const BackendServiceRecord*;
};

[[nodiscard]] auto make_architecture_backend(Architecture architecture)
    -> Result<std::unique_ptr<ArchitectureBackend>, Diagnostic>;

} // namespace binobf

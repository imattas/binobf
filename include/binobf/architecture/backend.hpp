#pragma once

#include <binobf/analysis/instruction_decoder.hpp>
#include <binobf/architecture/codegen.hpp>
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
    [[nodiscard]] auto find_service(BackendService service) const noexcept
        -> const BackendServiceRecord*;
};

[[nodiscard]] auto make_architecture_backend(Architecture architecture)
    -> Result<std::unique_ptr<ArchitectureBackend>, Diagnostic>;

} // namespace binobf

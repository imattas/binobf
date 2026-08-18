#pragma once

#include <binobf/core/types.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace binobf {

enum class DiagnosticSeverity : std::uint8_t {
    Info,
    Warning,
    Error,
};

struct DiagnosticLineageEntry {
    TransformId transform;
    EntityId source;
    std::string pass;

    auto operator==(const DiagnosticLineageEntry&) const -> bool = default;
};

struct Diagnostic {
    DiagnosticSeverity severity;
    std::string code;
    std::string message;
    std::optional<std::string> pass;
    std::optional<std::string> function;
    std::optional<BinaryAddress> originalAddress;
    std::optional<EntityId> transformedEntity;
    std::optional<std::string> explanation;
    std::optional<std::string> remediation;
    std::vector<DiagnosticLineageEntry> lineage;

    Diagnostic(DiagnosticSeverity severityValue, std::string codeValue, std::string messageValue)
        : severity(severityValue), code(std::move(codeValue)), message(std::move(messageValue)) {}
};

[[nodiscard]] auto to_string(DiagnosticSeverity severity) noexcept -> std::string_view;
[[nodiscard]] auto render_text(const Diagnostic& diagnostic) -> std::string;
[[nodiscard]] auto render_json(const Diagnostic& diagnostic) -> std::string;

} // namespace binobf

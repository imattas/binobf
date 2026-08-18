#pragma once

#include <binobf/capabilities/registry.hpp>

#include <cstddef>
#include <span>
#include <string_view>

namespace binobf {

struct AcceptanceEvidence {
    std::string_view id;
    std::string_view ctestName;
    bool releaseGate{true};
};

[[nodiscard]] auto builtin_acceptance_evidence()
    -> std::span<const AcceptanceEvidence>;
[[nodiscard]] auto validate_capability_evidence(
    const CapabilityRegistry& registry,
    std::span<const AcceptanceEvidence> evidence)
    -> Result<std::size_t, Diagnostic>;

} // namespace binobf

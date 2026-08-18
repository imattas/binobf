#pragma once

#include <binobf/capabilities/registry.hpp>

#include <string>

namespace binobf {

[[nodiscard]] auto render_format_capabilities_text(const CapabilityRegistry& registry)
    -> std::string;
[[nodiscard]] auto render_architecture_capabilities_text(
    const CapabilityRegistry& registry) -> std::string;
[[nodiscard]] auto render_pass_capabilities_text() -> std::string;
[[nodiscard]] auto render_feature_matrix_markdown(const CapabilityRegistry& registry)
    -> std::string;

} // namespace binobf

#pragma once

#include <binobf/transforms/pass.hpp>

#include <memory>
#include <span>
#include <string_view>

namespace binobf {

using PassFactory = std::unique_ptr<TransformPass> (*)();

struct PassRegistration {
    std::string_view name;
    PassFactory factory{nullptr};
};

[[nodiscard]] auto registered_passes() -> std::span<const PassRegistration>;
// Register extensions during single-threaded application startup, before
// retaining spans or beginning transformations.
[[nodiscard]] auto register_pass(PassRegistration registration)
    -> Result<bool, Diagnostic>;
[[nodiscard]] auto find_registered_pass(std::string_view name) noexcept
    -> const PassRegistration*;
[[nodiscard]] auto make_registered_pass(std::string_view name)
    -> std::unique_ptr<TransformPass>;

} // namespace binobf

#pragma once

#include <binobf/transforms/pass.hpp>

#include <memory>

namespace binobf {

[[nodiscard]] auto make_rename_private_symbols_pass()
    -> std::unique_ptr<TransformPass>;

[[nodiscard]] auto make_strip_debug_pass() -> std::unique_ptr<TransformPass>;
[[nodiscard]] auto make_metadata_cleanup_pass() -> std::unique_ptr<TransformPass>;
[[nodiscard]] auto make_strip_local_symbols_pass() -> std::unique_ptr<TransformPass>;

} // namespace binobf

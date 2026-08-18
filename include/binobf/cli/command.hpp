#pragma once

#include <iosfwd>
#include <span>
#include <string_view>

namespace binobf::cli {

[[nodiscard]] auto run_cli(
    std::span<const std::string_view> arguments,
    std::ostream& output,
    std::ostream& errors) -> int;

} // namespace binobf::cli

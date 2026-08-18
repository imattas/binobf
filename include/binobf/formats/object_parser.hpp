#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/model.hpp>
#include <binobf/core/result.hpp>

#include <cstddef>
#include <span>
#include <string_view>

namespace binobf {

[[nodiscard]] auto parse_object(
    std::span<const std::byte> bytes,
    std::string_view sourceName = {}) -> Result<BinaryImage, Diagnostic>;

} // namespace binobf

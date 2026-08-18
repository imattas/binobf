#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/result.hpp>
#include <binobf/core/types.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace binobf {

struct DetectionResult {
    BinaryFormat format{BinaryFormat::Unknown};
    BinaryType type{BinaryType::Unknown};
    Architecture architecture{Architecture::Unknown};
    std::uint64_t entryPoint{0};
};

[[nodiscard]] auto detect_binary(
    std::span<const std::byte> bytes,
    std::string_view sourceName = {}) -> Result<DetectionResult, Diagnostic>;

} // namespace binobf

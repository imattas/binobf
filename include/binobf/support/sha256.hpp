#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace binobf {

using Sha256Digest = std::array<std::byte, 32>;

class Sha256 {
public:
    Sha256() noexcept;

    [[nodiscard]] auto update(std::span<const std::byte> bytes) noexcept -> bool;
    [[nodiscard]] auto finish() const noexcept -> Sha256Digest;

private:
    std::array<std::uint32_t, 8> state_{};
    std::array<std::byte, 64> buffer_{};
    std::uint64_t byteCount_{0};
    std::size_t bufferSize_{0};

    void compress(std::span<const std::byte, 64> block) noexcept;
};

[[nodiscard]] auto sha256(std::span<const std::byte> bytes) noexcept
    -> std::optional<Sha256Digest>;
[[nodiscard]] auto sha256_hex(const Sha256Digest& digest) -> std::string;

} // namespace binobf

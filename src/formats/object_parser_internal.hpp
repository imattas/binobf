#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/model.hpp>
#include <binobf/core/result.hpp>
#include <binobf/formats/detector.hpp>

#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace binobf::formats::detail {

constexpr auto contains_range(
    std::size_t offset,
    std::size_t length,
    std::size_t size) noexcept -> bool {
    return offset <= size && length <= size - offset;
}

inline auto checked_add(std::size_t left, std::size_t right) noexcept
    -> std::optional<std::size_t> {
    if (right > std::numeric_limits<std::size_t>::max() - left) {
        return std::nullopt;
    }
    return left + right;
}

inline auto checked_multiply(std::size_t left, std::size_t right) noexcept
    -> std::optional<std::size_t> {
    if (left != 0 && right > std::numeric_limits<std::size_t>::max() / left) {
        return std::nullopt;
    }
    return left * right;
}

inline auto to_size(std::uint64_t value) noexcept -> std::optional<std::size_t> {
    if (value > std::numeric_limits<std::size_t>::max()) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(value);
}

class ByteReader {
public:
    explicit ByteReader(std::span<const std::byte> bytes) noexcept : bytes_(bytes) {}

    [[nodiscard]] auto u8(std::size_t offset) const noexcept -> std::optional<std::uint8_t> {
        if (!contains_range(offset, 1, bytes_.size())) {
            return std::nullopt;
        }
        return std::to_integer<std::uint8_t>(bytes_[offset]);
    }

    [[nodiscard]] auto u16(std::size_t offset) const noexcept -> std::optional<std::uint16_t> {
        if (!contains_range(offset, 2, bytes_.size())) {
            return std::nullopt;
        }
        return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes_[offset]))
            | static_cast<std::uint16_t>(
                static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes_[offset + 1]))
                << 8U);
    }

    [[nodiscard]] auto i16(std::size_t offset) const noexcept -> std::optional<std::int16_t> {
        const auto value = u16(offset);
        return value.has_value() ? std::optional{std::bit_cast<std::int16_t>(*value)} : std::nullopt;
    }

    [[nodiscard]] auto u32(std::size_t offset) const noexcept -> std::optional<std::uint32_t> {
        if (!contains_range(offset, 4, bytes_.size())) {
            return std::nullopt;
        }
        std::uint32_t value = 0;
        for (std::size_t index = 0; index < 4; ++index) {
            value |= static_cast<std::uint32_t>(
                std::to_integer<std::uint8_t>(bytes_[offset + index]))
                << static_cast<unsigned int>(index * 8U);
        }
        return value;
    }

    [[nodiscard]] auto i32(std::size_t offset) const noexcept -> std::optional<std::int32_t> {
        const auto value = u32(offset);
        return value.has_value() ? std::optional{std::bit_cast<std::int32_t>(*value)} : std::nullopt;
    }

    [[nodiscard]] auto u64(std::size_t offset) const noexcept -> std::optional<std::uint64_t> {
        if (!contains_range(offset, 8, bytes_.size())) {
            return std::nullopt;
        }
        std::uint64_t value = 0;
        for (std::size_t index = 0; index < 8; ++index) {
            value |= static_cast<std::uint64_t>(
                std::to_integer<std::uint8_t>(bytes_[offset + index]))
                << static_cast<unsigned int>(index * 8U);
        }
        return value;
    }

    [[nodiscard]] auto i64(std::size_t offset) const noexcept -> std::optional<std::int64_t> {
        const auto value = u64(offset);
        return value.has_value() ? std::optional{std::bit_cast<std::int64_t>(*value)} : std::nullopt;
    }

    [[nodiscard]] auto bytes(std::size_t offset, std::size_t length) const noexcept
        -> std::optional<std::span<const std::byte>> {
        if (!contains_range(offset, length, bytes_.size())) {
            return std::nullopt;
        }
        return bytes_.subspan(offset, length);
    }

    [[nodiscard]] auto size() const noexcept -> std::size_t { return bytes_.size(); }

private:
    std::span<const std::byte> bytes_;
};

inline auto read_string(std::span<const std::byte> table, std::uint64_t offset)
    -> std::optional<std::string> {
    const auto start = to_size(offset);
    if (!start.has_value() || *start >= table.size()) {
        return std::nullopt;
    }
    auto end = *start;
    while (end < table.size() && table[end] != std::byte{0}) {
        ++end;
    }
    if (end == table.size()) {
        return std::nullopt;
    }
    std::string value;
    value.reserve(end - *start);
    for (auto index = *start; index < end; ++index) {
        value.push_back(static_cast<char>(std::to_integer<unsigned char>(table[index])));
    }
    return value;
}

class EntityIdAllocator {
public:
    [[nodiscard]] auto allocate() noexcept -> EntityId {
        return EntityId{next_++};
    }

private:
    std::uint64_t next_{1};
};

inline auto failure(std::string code, std::string message)
    -> Result<BinaryImage, Diagnostic> {
    return Result<BinaryImage, Diagnostic>::failure(
        Diagnostic{DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

[[nodiscard]] auto parse_elf_object(
    std::span<const std::byte> bytes,
    const DetectionResult& detection) -> Result<BinaryImage, Diagnostic>;

[[nodiscard]] auto parse_coff_object(
    std::span<const std::byte> bytes,
    const DetectionResult& detection) -> Result<BinaryImage, Diagnostic>;

[[nodiscard]] auto parse_macho_object(
    std::span<const std::byte> bytes,
    const DetectionResult& detection) -> Result<BinaryImage, Diagnostic>;

} // namespace binobf::formats::detail

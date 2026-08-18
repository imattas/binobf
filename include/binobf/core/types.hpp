#pragma once

#include <compare>
#include <cstdint>
#include <string>
#include <string_view>

namespace binobf {

enum class BinaryFormat : std::uint8_t {
    PE,
    COFF,
    ELF,
    Archive,
    Unknown,
};

enum class BinaryType : std::uint8_t {
    Executable,
    SharedLibrary,
    KernelDriver,
    RelocatableObject,
    StaticLibrary,
    ImportLibrary,
    Unknown,
};

enum class Architecture : std::uint8_t {
    X86,
    X86_64,
    ARM64,
    Unknown,
};

enum class AddressKind : std::uint8_t {
    FileOffset,
    RelativeVirtual,
    Virtual,
};

class EntityId {
public:
    constexpr EntityId() noexcept = default;
    explicit constexpr EntityId(std::uint64_t value) noexcept : value_(value) {}

    [[nodiscard]] constexpr auto value() const noexcept -> std::uint64_t { return value_; }
    [[nodiscard]] constexpr auto valid() const noexcept -> bool { return value_ != 0; }

    auto operator<=>(const EntityId&) const = default;

private:
    std::uint64_t value_{0};
};

class TransformId {
public:
    constexpr TransformId() noexcept = default;
    explicit constexpr TransformId(std::uint64_t value) noexcept : value_(value) {}

    [[nodiscard]] constexpr auto value() const noexcept -> std::uint64_t { return value_; }
    [[nodiscard]] constexpr auto valid() const noexcept -> bool { return value_ != 0; }

    auto operator<=>(const TransformId&) const = default;

private:
    std::uint64_t value_{0};
};

struct BinaryAddress {
    std::uint64_t value{0};
    AddressKind kind{AddressKind::Virtual};

    auto operator<=>(const BinaryAddress&) const = default;
};

struct SourceLocation {
    std::string file;
    std::uint32_t line{0};
    std::uint32_t column{0};
};

[[nodiscard]] auto to_string(BinaryFormat format) noexcept -> std::string_view;
[[nodiscard]] auto to_string(BinaryType type) noexcept -> std::string_view;
[[nodiscard]] auto to_string(Architecture architecture) noexcept -> std::string_view;

} // namespace binobf

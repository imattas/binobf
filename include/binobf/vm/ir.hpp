#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/result.hpp>

#include <compare>
#include <cstddef>
#include <cstdint>
#include <variant>
#include <vector>

namespace binobf::vm {

struct VmVersion {
    std::uint16_t major{1};
    std::uint16_t minor{0};

    auto operator<=>(const VmVersion&) const = default;
};

inline constexpr VmVersion currentVmVersion{1, 1};

enum class VmWidth : std::uint8_t {
    U8,
    U16,
    U32,
    U64,
    Pointer,
};

[[nodiscard]] auto vm_width_bits(VmWidth width) noexcept -> std::uint32_t;
[[nodiscard]] auto vm_width_bytes(VmWidth width) noexcept -> std::size_t;

class VmValue {
public:
    [[nodiscard]] static auto from_bits(VmWidth width, std::uint64_t bits) noexcept
        -> VmValue;

    [[nodiscard]] auto width() const noexcept -> VmWidth { return width_; }
    [[nodiscard]] auto bits() const noexcept -> std::uint64_t { return bits_; }

    auto operator<=>(const VmValue&) const = default;

private:
    VmValue(VmWidth width, std::uint64_t bits) noexcept : width_(width), bits_(bits) {}

    VmWidth width_{VmWidth::U64};
    std::uint64_t bits_{0};
};

struct VmRegister {
    std::uint16_t index{0};
    auto operator<=>(const VmRegister&) const = default;
};

struct VmSlot {
    std::uint16_t index{0};
    auto operator<=>(const VmSlot&) const = default;
};

enum class VmBinaryOpcode : std::uint8_t {
    Add,
    Subtract,
    Multiply,
    Divide,
    And,
    Or,
    Xor,
    ShiftLeft,
    ShiftRight,
};

enum class VmUnaryOpcode : std::uint8_t {
    Not,
};

enum class VmCondition : std::uint8_t {
    Equal,
    NotEqual,
    UnsignedBelow,
    UnsignedAboveOrEqual,
    SignedLess,
    SignedGreaterOrEqual,
    Zero,
    Nonzero,
};

struct VmMove {
    VmWidth width{VmWidth::U64};
    VmRegister destination;
    VmRegister source;
    auto operator==(const VmMove&) const -> bool = default;
};

struct VmLoadConstant {
    VmRegister destination;
    VmValue value{VmValue::from_bits(VmWidth::U64, 0)};
    auto operator==(const VmLoadConstant&) const -> bool = default;
};

struct VmLoadSlot {
    VmWidth width{VmWidth::U64};
    VmRegister destination;
    VmSlot slot;
    auto operator==(const VmLoadSlot&) const -> bool = default;
};

struct VmStoreSlot {
    VmWidth width{VmWidth::U64};
    VmSlot slot;
    VmRegister source;
    auto operator==(const VmStoreSlot&) const -> bool = default;
};

struct VmLoadMemory {
    VmWidth width{VmWidth::U64};
    VmRegister destination;
    VmRegister address;
    auto operator==(const VmLoadMemory&) const -> bool = default;
};

struct VmStoreMemory {
    VmWidth width{VmWidth::U64};
    VmRegister address;
    VmRegister source;
    auto operator==(const VmStoreMemory&) const -> bool = default;
};

struct VmBinaryOperation {
    VmBinaryOpcode opcode{VmBinaryOpcode::Add};
    VmWidth width{VmWidth::U64};
    VmRegister destination;
    VmRegister left;
    VmRegister right;
    auto operator==(const VmBinaryOperation&) const -> bool = default;
};

struct VmUnaryOperation {
    VmUnaryOpcode opcode{VmUnaryOpcode::Not};
    VmWidth width{VmWidth::U64};
    VmRegister destination;
    VmRegister source;
    auto operator==(const VmUnaryOperation&) const -> bool = default;
};

struct VmCompare {
    VmWidth width{VmWidth::U64};
    VmRegister left;
    VmRegister right;
    auto operator==(const VmCompare&) const -> bool = default;
};

struct VmTest {
    VmWidth width{VmWidth::U64};
    VmRegister left;
    VmRegister right;
    auto operator==(const VmTest&) const -> bool = default;
};

struct VmJump {
    std::uint32_t target{0};
    auto operator==(const VmJump&) const -> bool = default;
};

struct VmConditionalJump {
    VmCondition condition{VmCondition::Equal};
    std::uint32_t target{0};
    auto operator==(const VmConditionalJump&) const -> bool = default;
};

struct VmNativeCall {
    VmWidth resultWidth{VmWidth::U64};
    VmRegister destination;
    std::uint32_t functionId{0};
    std::vector<VmRegister> arguments;
    auto operator==(const VmNativeCall&) const -> bool = default;
};

struct VmCall {
    VmRegister destination;
    std::uint32_t target{0};
    std::vector<VmRegister> arguments;
    auto operator==(const VmCall&) const -> bool = default;
};

struct VmReturn {
    VmRegister source;
    auto operator==(const VmReturn&) const -> bool = default;
};

using VmInstruction = std::variant<
    VmMove,
    VmLoadConstant,
    VmLoadSlot,
    VmStoreSlot,
    VmLoadMemory,
    VmStoreMemory,
    VmBinaryOperation,
    VmUnaryOperation,
    VmCompare,
    VmTest,
    VmJump,
    VmConditionalJump,
    VmCall,
    VmNativeCall,
    VmReturn>;

struct VmProgram {
    VmVersion version{currentVmVersion};
    std::uint16_t registerCount{0};
    std::uint16_t slotCount{0};
    std::uint32_t localMemorySize{0};
    std::vector<VmInstruction> instructions;

    auto operator==(const VmProgram&) const -> bool = default;
};

struct VmLimits {
    std::size_t maxBytecodeBytes{16U * 1024U * 1024U};
    std::size_t maxInstructions{1U << 20U};
    std::size_t maxRegisters{4096};
    std::size_t maxSlots{4096};
    std::size_t maxMemoryBytes{16U * 1024U * 1024U};
    std::size_t maxNativeArguments{64};
    std::size_t maxInternalArguments{64};
    std::size_t maxFrameDepth{64};
    std::uint64_t maxSteps{UINT64_C(10000000)};
};

[[nodiscard]] auto validate_program(
    const VmProgram& program,
    const VmLimits& limits = {}) -> Result<std::size_t, Diagnostic>;

} // namespace binobf::vm

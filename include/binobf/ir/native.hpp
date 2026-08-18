#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/result.hpp>
#include <binobf/core/types.hpp>

#include <compare>
#include <cstddef>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace binobf::ir {

enum class IrWidth : std::uint8_t {
    U8,
    U16,
    U32,
    U64,
};

[[nodiscard]] auto ir_width_bits(IrWidth width) noexcept -> std::uint32_t;

struct IrVariable {
    std::uint16_t index{0};
    auto operator<=>(const IrVariable&) const = default;
};

struct IrBlockId {
    std::uint32_t value{0};
    auto operator<=>(const IrBlockId&) const = default;
};

struct IrVariableOperand {
    IrVariable variable;
    auto operator==(const IrVariableOperand&) const -> bool = default;
};

struct IrImmediateOperand {
    IrWidth width{IrWidth::U32};
    std::uint64_t bits{0};
    auto operator==(const IrImmediateOperand&) const -> bool = default;
};

using IrOperand = std::variant<IrVariableOperand, IrImmediateOperand>;

enum class IrBinaryOpcode : std::uint8_t {
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

enum class IrUnaryOpcode : std::uint8_t {
    Not,
};

enum class IrCondition : std::uint8_t {
    Equal,
    NotEqual,
    UnsignedBelow,
    UnsignedAboveOrEqual,
    SignedLess,
    SignedGreaterOrEqual,
    Zero,
    Nonzero,
};

struct IrMove {
    IrWidth width{IrWidth::U32};
    IrVariable destination;
    IrOperand source;
    EntityId sourceInstruction;
    auto operator==(const IrMove&) const -> bool = default;
};

struct IrBinaryOperation {
    IrBinaryOpcode opcode{IrBinaryOpcode::Add};
    IrWidth width{IrWidth::U32};
    IrVariable destination;
    IrOperand source;
    EntityId sourceInstruction;
    auto operator==(const IrBinaryOperation&) const -> bool = default;
};

struct IrUnaryOperation {
    IrUnaryOpcode opcode{IrUnaryOpcode::Not};
    IrWidth width{IrWidth::U32};
    IrVariable destination;
    EntityId sourceInstruction;
    auto operator==(const IrUnaryOperation&) const -> bool = default;
};

struct IrCompare {
    IrWidth width{IrWidth::U32};
    IrVariable left;
    IrOperand right;
    EntityId sourceInstruction;
    auto operator==(const IrCompare&) const -> bool = default;
};

struct IrTest {
    IrWidth width{IrWidth::U32};
    IrVariable left;
    IrOperand right;
    EntityId sourceInstruction;
    auto operator==(const IrTest&) const -> bool = default;
};

struct IrJump {
    IrBlockId target;
    EntityId sourceInstruction;
    auto operator==(const IrJump&) const -> bool = default;
};

struct IrConditionalJump {
    IrCondition condition{IrCondition::Equal};
    IrBlockId trueTarget;
    IrBlockId falseTarget;
    EntityId sourceInstruction;
    auto operator==(const IrConditionalJump&) const -> bool = default;
};

struct IrReturn {
    IrWidth width{IrWidth::U32};
    IrVariable value;
    EntityId sourceInstruction;
    auto operator==(const IrReturn&) const -> bool = default;
};

struct IrInternalCall {
    EntityId targetFunction;
    IrWidth resultWidth{IrWidth::U32};
    IrVariable destination;
    std::vector<IrOperand> arguments;
    EntityId sourceInstruction;
    auto operator==(const IrInternalCall&) const -> bool = default;
};

struct IrFallback {
    EntityId sourceInstruction;
    std::vector<std::byte> encoding;
    std::string reason;
    auto operator==(const IrFallback&) const -> bool = default;
};

using IrInstruction = std::variant<
    IrMove,
    IrBinaryOperation,
    IrUnaryOperation,
    IrCompare,
    IrTest,
    IrJump,
    IrConditionalJump,
    IrInternalCall,
    IrReturn,
    IrFallback>;

struct IrArgumentBinding {
    std::uint16_t argumentIndex{0};
    IrVariable destination;
    IrWidth width{IrWidth::U32};
    auto operator==(const IrArgumentBinding&) const -> bool = default;
};

struct IrBlock {
    IrBlockId id;
    EntityId sourceBlock;
    std::vector<IrInstruction> instructions;
    auto operator==(const IrBlock&) const -> bool = default;
};

struct IrFunction {
    EntityId sourceFunction;
    std::string name;
    std::vector<IrArgumentBinding> arguments;
    IrWidth returnWidth{IrWidth::U32};
    std::vector<IrWidth> variableWidths;
    IrBlockId entry;
    std::vector<IrBlock> blocks;
    auto operator==(const IrFunction&) const -> bool = default;
};

struct IrModule {
    EntityId entryFunction;
    std::vector<IrFunction> functions;
    auto operator==(const IrModule&) const -> bool = default;
};

struct IrLimits {
    std::size_t maxBlocks{65536};
    std::size_t maxInstructions{1U << 20U};
    std::size_t maxVariables{4096};
    std::size_t maxArguments{64};
    std::size_t maxFallbackBytes{64};
    std::size_t maxFunctions{1024};
    std::size_t maxCallDepth{64};
};

[[nodiscard]] auto function_contains_fallback(const IrFunction& function) noexcept -> bool;

[[nodiscard]] auto validate_function(
    const IrFunction& function,
    const IrLimits& limits = {}) -> Result<std::size_t, Diagnostic>;

[[nodiscard]] auto validate_module(
    const IrModule& module,
    const IrLimits& limits = {}) -> Result<std::size_t, Diagnostic>;

} // namespace binobf::ir

#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/result.hpp>
#include <binobf/core/types.hpp>

#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
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

enum class IrTypeKind : std::uint8_t {
    Void,
    Integer,
    Pointer,
    FloatingPoint,
    Vector,
};

enum class IrByteOrder : std::uint8_t {
    Little,
    Big,
};

struct IrType {
    IrTypeKind kind{IrTypeKind::Void};
    std::uint16_t bits{0};
    std::uint16_t lanes{1};
    std::uint16_t addressSpace{0};
    IrByteOrder byteOrder{IrByteOrder::Little};

    constexpr IrType() noexcept = default;
    constexpr IrType(
        IrTypeKind kindValue,
        std::uint16_t bitsValue,
        std::uint16_t lanesValue = 1U,
        std::uint16_t addressSpaceValue = 0U,
        IrByteOrder byteOrderValue = IrByteOrder::Little) noexcept
        : kind(kindValue),
          bits(bitsValue),
          lanes(lanesValue),
          addressSpace(addressSpaceValue),
          byteOrder(byteOrderValue) {}
    constexpr IrType(IrWidth width) noexcept
        : kind(IrTypeKind::Integer),
          bits(width == IrWidth::U8 ? 8U
               : width == IrWidth::U16 ? 16U
               : width == IrWidth::U32 ? 32U
                                       : 64U) {}

    auto operator<=>(const IrType&) const = default;
};

[[nodiscard]] auto integer_type(IrWidth width) noexcept -> IrType;
[[nodiscard]] auto integer_width(const IrType& type) -> Result<IrWidth, Diagnostic>;
[[nodiscard]] auto validate_type(const IrType& type) -> Result<std::size_t, Diagnostic>;

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
    IrType type{IrWidth::U32};
    std::uint64_t bits{0};
    auto operator==(const IrImmediateOperand&) const -> bool = default;
};

using IrOperand = std::variant<IrVariableOperand, IrImmediateOperand>;

struct IrIntegerConstant {
    IrType type{IrWidth::U32};
    std::uint64_t bits{0};
    auto operator==(const IrIntegerConstant&) const -> bool = default;
};

struct IrFloatingConstant {
    IrType type{IrTypeKind::FloatingPoint, 32U};
    std::uint64_t rawBits{0};
    auto operator==(const IrFloatingConstant&) const -> bool = default;
};

struct IrNullPointerConstant {
    IrType type{IrTypeKind::Pointer, 64U};
    auto operator==(const IrNullPointerConstant&) const -> bool = default;
};

struct IrSymbolAddressConstant {
    IrType type{IrTypeKind::Pointer, 64U};
    std::string symbol;
    std::int64_t addend{0};
    auto operator==(const IrSymbolAddressConstant&) const -> bool = default;
};

struct IrZeroVectorConstant {
    IrType type{IrTypeKind::Vector, 32U, 2U};
    auto operator==(const IrZeroVectorConstant&) const -> bool = default;
};

using IrValue = std::variant<
    IrVariableOperand,
    IrIntegerConstant,
    IrFloatingConstant,
    IrNullPointerConstant,
    IrSymbolAddressConstant,
    IrZeroVectorConstant>;

enum class IrStorageKind : std::uint8_t {
    Register,
    Argument,
    Stack,
    Local,
    Global,
    ThreadLocal,
};

struct IrStorageLocation {
    IrStorageKind kind{IrStorageKind::Local};
    IrType type{IrWidth::U32};
    std::string name;
    std::int64_t offset{0};
    std::uint64_t size{0};
    std::uint32_t alignment{1};
    std::uint16_t index{0};
    bool readonly{false};
    auto operator==(const IrStorageLocation&) const -> bool = default;
};

struct IrAddress {
    IrVariable base;
    std::optional<IrVariable> index;
    std::uint8_t scale{1};
    std::int64_t displacement{0};
    std::uint16_t addressSpace{0};
    std::uint32_t alignment{1};
    auto operator==(const IrAddress&) const -> bool = default;
};

enum class IrAtomicOrdering : std::uint8_t {
    None,
    Relaxed,
    Acquire,
    Release,
    AcquireRelease,
    SequentiallyConsistent,
};

enum class IrCastKind : std::uint8_t {
    ZeroExtend,
    SignExtend,
    Truncate,
    Bitcast,
    IntegerToPointer,
    PointerToInteger,
    FloatingExtend,
    FloatingTruncate,
};

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

enum class IrCallingConvention : std::uint8_t {
    C,
    SystemV,
    MicrosoftX64,
    AArch64,
    Fast,
};

struct IrCallClobbers {
    std::vector<std::string> registers;
    bool flags{false};
    bool memory{false};
    auto operator==(const IrCallClobbers&) const -> bool = default;
};

struct IrFunctionSignature {
    IrCallingConvention callingConvention{IrCallingConvention::C};
    std::vector<IrType> parameterTypes;
    IrType returnType{IrTypeKind::Void, 0U};
    bool variadic{false};
    std::vector<IrStorageLocation> parameterBindings;
    std::optional<IrStorageLocation> returnBinding;
    IrCallClobbers clobbers;
    bool mayUnwind{false};
    auto operator==(const IrFunctionSignature&) const -> bool = default;
};

struct IrExternalDeclaration {
    std::string symbol;
    IrFunctionSignature signature;
    auto operator==(const IrExternalDeclaration&) const -> bool = default;
};

struct IrMove {
    IrType type{IrWidth::U32};
    IrVariable destination;
    IrOperand source;
    EntityId sourceInstruction;
    auto operator==(const IrMove&) const -> bool = default;
};

struct IrBinaryOperation {
    IrBinaryOpcode opcode{IrBinaryOpcode::Add};
    IrType type{IrWidth::U32};
    IrVariable destination;
    IrOperand source;
    EntityId sourceInstruction;
    auto operator==(const IrBinaryOperation&) const -> bool = default;
};

struct IrUnaryOperation {
    IrUnaryOpcode opcode{IrUnaryOpcode::Not};
    IrType type{IrWidth::U32};
    IrVariable destination;
    EntityId sourceInstruction;
    auto operator==(const IrUnaryOperation&) const -> bool = default;
};

struct IrCompare {
    IrType type{IrWidth::U32};
    IrVariable left;
    IrOperand right;
    EntityId sourceInstruction;
    auto operator==(const IrCompare&) const -> bool = default;
};

struct IrTest {
    IrType type{IrWidth::U32};
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

struct IrSwitchCase {
    std::uint64_t value{0};
    IrBlockId target;
    auto operator==(const IrSwitchCase&) const -> bool = default;
};

struct IrSwitch {
    IrVariable selector;
    std::vector<IrSwitchCase> cases;
    IrBlockId defaultTarget;
    EntityId sourceInstruction;
    auto operator==(const IrSwitch&) const -> bool = default;
};

struct IrIndirectJump {
    IrVariable target;
    std::vector<IrBlockId> targets;
    EntityId sourceInstruction;
    auto operator==(const IrIndirectJump&) const -> bool = default;
};

struct IrReturn {
    IrType type{IrWidth::U32};
    IrVariable value;
    EntityId sourceInstruction;
    auto operator==(const IrReturn&) const -> bool = default;
};

struct IrInternalCall {
    EntityId targetFunction;
    IrType resultType{IrWidth::U32};
    IrVariable destination;
    std::vector<IrOperand> arguments;
    EntityId sourceInstruction;
    std::optional<std::uint32_t> unwindRegion;
    auto operator==(const IrInternalCall&) const -> bool = default;
};

struct IrExternalCall {
    std::string symbol;
    IrFunctionSignature signature;
    std::optional<IrVariable> destination;
    std::vector<IrOperand> arguments;
    EntityId sourceInstruction;
    std::optional<std::uint32_t> unwindRegion;
    auto operator==(const IrExternalCall&) const -> bool = default;
};

using IrCallTarget = std::variant<EntityId, std::string>;

struct IrTailCall {
    IrCallTarget target;
    IrFunctionSignature signature;
    std::vector<IrOperand> arguments;
    EntityId sourceInstruction;
    std::optional<std::uint32_t> unwindRegion;
    auto operator==(const IrTailCall&) const -> bool = default;
};

struct IrFallbackEffects {
    std::vector<IrVariable> reads;
    std::vector<IrVariable> writes;
    std::vector<std::string> clobberedRegisters;
    bool readsMemory{false};
    bool writesMemory{false};
    bool changesControlFlow{false};
    bool mayUnwind{false};
    bool complete{false};
    auto operator==(const IrFallbackEffects&) const -> bool = default;
};

struct IrFallback {
    EntityId sourceInstruction;
    std::vector<std::byte> encoding;
    std::string reason;
    IrFallbackEffects effects;
    std::optional<std::uint32_t> unwindRegion;
    auto operator==(const IrFallback&) const -> bool = default;
};

struct IrLoad {
    IrType type{IrWidth::U32};
    IrVariable destination;
    IrAddress address;
    IrByteOrder byteOrder{IrByteOrder::Little};
    bool volatileAccess{false};
    IrAtomicOrdering atomicOrdering{IrAtomicOrdering::None};
    EntityId sourceInstruction;
    std::optional<std::uint32_t> unwindRegion;
    auto operator==(const IrLoad&) const -> bool = default;
};

struct IrStore {
    IrType type{IrWidth::U32};
    IrAddress address;
    IrValue value;
    IrByteOrder byteOrder{IrByteOrder::Little};
    bool volatileAccess{false};
    IrAtomicOrdering atomicOrdering{IrAtomicOrdering::None};
    EntityId sourceInstruction;
    std::optional<std::uint32_t> unwindRegion;
    auto operator==(const IrStore&) const -> bool = default;
};

struct IrAddressOf {
    IrVariable destination;
    std::uint16_t storageIndex{0};
    EntityId sourceInstruction;
    auto operator==(const IrAddressOf&) const -> bool = default;
};

struct IrPointerOffset {
    IrVariable destination;
    IrVariable pointer;
    IrValue offset;
    EntityId sourceInstruction;
    auto operator==(const IrPointerOffset&) const -> bool = default;
};

struct IrCast {
    IrCastKind kind{IrCastKind::Bitcast};
    IrType sourceType{IrWidth::U32};
    IrType destinationType{IrWidth::U32};
    IrVariable destination;
    IrValue source;
    EntityId sourceInstruction;
    auto operator==(const IrCast&) const -> bool = default;
};

using IrInstruction = std::variant<
    IrMove,
    IrBinaryOperation,
    IrUnaryOperation,
    IrCompare,
    IrTest,
    IrJump,
    IrConditionalJump,
    IrSwitch,
    IrIndirectJump,
    IrInternalCall,
    IrExternalCall,
    IrTailCall,
    IrLoad,
    IrStore,
    IrAddressOf,
    IrPointerOffset,
    IrCast,
    IrReturn,
    IrFallback>;

struct IrArgumentBinding {
    std::uint16_t argumentIndex{0};
    IrVariable destination;
    IrType type{IrWidth::U32};
    auto operator==(const IrArgumentBinding&) const -> bool = default;
};

struct IrBlock {
    IrBlockId id;
    EntityId sourceBlock;
    std::vector<IrInstruction> instructions;
    auto operator==(const IrBlock&) const -> bool = default;
};

enum class IrUnwindRegionKind : std::uint8_t {
    Cleanup,
    Catch,
};

struct IrUnwindRegion {
    std::uint32_t id{0};
    IrUnwindRegionKind kind{IrUnwindRegionKind::Cleanup};
    std::optional<std::uint32_t> parent;
    IrBlockId landingBlock;
    std::vector<IrBlockId> protectedBlocks;
    std::vector<std::string> actions;
    auto operator==(const IrUnwindRegion&) const -> bool = default;
};

struct IrFunction {
    EntityId sourceFunction;
    std::string name;
    std::vector<IrArgumentBinding> arguments;
    IrType returnType{IrWidth::U32};
    std::vector<IrType> variableTypes;
    std::vector<IrStorageLocation> storageLocations;
    IrFunctionSignature signature;
    IrBlockId entry;
    std::vector<IrBlock> blocks;
    std::vector<IrUnwindRegion> unwindRegions;
    auto operator==(const IrFunction&) const -> bool = default;
};

struct IrModule {
    EntityId entryFunction;
    std::vector<IrExternalDeclaration> declarations;
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
    std::size_t maxStorageLocations{4096};
    std::size_t maxMemoryOperations{1U << 20U};
    std::uint64_t maxAggregateStorageBytes{1ULL << 32U};
    std::uint32_t maxAlignment{1U << 20U};
    std::size_t maxCalls{1U << 20U};
    std::size_t maxSwitchCases{65536};
    std::size_t maxIndirectTargets{65536};
    std::size_t maxExternalDeclarations{65536};
    std::size_t maxUnwindRegions{65536};
    std::size_t maxUnwindActions{1U << 20U};
};

[[nodiscard]] auto function_contains_fallback(const IrFunction& function) noexcept -> bool;

[[nodiscard]] auto fallback_blocks_rewrite(
    const IrFunction& function,
    const std::vector<IrBlockId>& blocks) noexcept -> bool;

[[nodiscard]] auto validate_function(
    const IrFunction& function,
    const IrLimits& limits = {}) -> Result<std::size_t, Diagnostic>;

[[nodiscard]] auto validate_module(
    const IrModule& module,
    const IrLimits& limits = {}) -> Result<std::size_t, Diagnostic>;

} // namespace binobf::ir

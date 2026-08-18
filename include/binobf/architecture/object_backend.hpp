#pragma once

#include <binobf/architecture/codegen.hpp>
#include <binobf/core/model.hpp>
#include <binobf/ir/native_lifter.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace binobf {

enum class MachineTransformKind : std::uint8_t {
    InstructionEquivalent,
    ConstantMaterialization,
    ConditionalInversion,
    DirectJump,
    DeadCodeFill,
    AbiCallAdapter,
};

enum class MachineControlFlow : std::uint8_t {
    Fallthrough,
    Conditional,
    Direct,
    Call,
    Return,
};

enum class UnwindDisposition : std::uint8_t {
    NotRequired,
    Preserve,
    Emit,
};

enum class UnwindEncoding : std::uint8_t {
    None,
    WindowsI386,
    DwarfCfi32,
};

enum class UnwindActionKind : std::uint8_t {
    DefineCanonicalFrameAddress,
    SaveRegister,
    RestoreRegister,
};

struct MachineTransformRequest {
    Architecture architecture{Architecture::Unknown};
    BinaryFormat format{BinaryFormat::Unknown};
    MachineTransformKind kind{MachineTransformKind::InstructionEquivalent};
    std::optional<Instruction> source;
    std::optional<std::uint64_t> targetAddress;
    std::optional<std::uint64_t> constantBits;
    std::string condition;
    std::size_t exactSize{0};
    MachineCodeLimits limits{};
};

struct MachineTransformEmission {
    MachineEmission emission;
    std::size_t instructionCount{0};
    MachineControlFlow controlFlow{MachineControlFlow::Fallthrough};
    std::int64_t stackDelta{0};
    bool readsFlags{false};
    bool writesFlags{false};
};

struct ObjectFixupSemantics {
    MachineFixupKind kind{MachineFixupKind::Absolute32};
    std::uint64_t rawType{0};
    std::uint8_t bitWidth{0};
    bool isSigned{false};
    bool pcRelative{false};
    bool implicitAddend{false};
    std::int8_t pcBias{0};

    auto operator==(const ObjectFixupSemantics&) const -> bool = default;
};

struct ObjectFixupEncoding {
    ObjectFixupSemantics semantics;
    std::vector<std::byte> fieldBytes;

    auto operator==(const ObjectFixupEncoding&) const -> bool = default;
};

struct UnwindAction {
    UnwindActionKind kind{UnwindActionKind::DefineCanonicalFrameAddress};
    std::string registerName;
    std::int64_t offset{0};

    auto operator==(const UnwindAction&) const -> bool = default;
};

struct UnwindRequest {
    Architecture architecture{Architecture::Unknown};
    BinaryFormat format{BinaryFormat::Unknown};
    BinaryAddress codeStart{};
    std::uint64_t codeSize{0};
    std::vector<UnwindAction> actions;
    std::optional<std::string> handlerSymbol;
    MachineCodeLimits limits{};
    bool handlerOwned{false};
};

struct UnwindPlan {
    UnwindDisposition disposition{UnwindDisposition::NotRequired};
    UnwindEncoding encoding{UnwindEncoding::None};
    BinaryAddress codeStart{};
    std::uint64_t codeSize{0};
    std::vector<UnwindAction> actions;
    std::vector<std::byte> encoded;
    std::vector<MachineFixup> fixups;
};

struct AbiArgumentMove {
    ir::IrStorageLocation source;
    ir::IrStorageLocation destination;

    auto operator==(const AbiArgumentMove&) const -> bool = default;
};

struct AbiAdapterRequest {
    Architecture architecture{Architecture::Unknown};
    BinaryFormat format{BinaryFormat::Unknown};
    ir::NativeAbi sourceAbi{ir::NativeAbi::WindowsX64};
    ir::NativeAbi destinationAbi{ir::NativeAbi::WindowsX64};
    ir::IrFunctionSignature signature;
    std::string symbol;
    bool tailCall{false};
    std::uint32_t stackAlignment{1};
    MachineCodeLimits limits{};
};

struct AbiAdapterPlan {
    MachineEmission emission;
    std::vector<AbiArgumentMove> argumentMoves;
    std::uint64_t stackArgumentBytes{0};
    std::int64_t stackDelta{0};
    bool callerCleansStack{false};
    ir::IrCallClobbers clobbers;
    UnwindRequest unwind;
};

} // namespace binobf

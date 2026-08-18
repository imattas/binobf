#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/model.hpp>
#include <binobf/core/result.hpp>
#include <binobf/ir/native.hpp>

#include <vector>

namespace binobf::ir {

enum class NativeAbi : std::uint8_t {
    WindowsX64,
    SystemVAMD64,
    WindowsI386Cdecl,
    WindowsI386Stdcall,
    WindowsI386Fastcall,
    WindowsI386Thiscall,
    SystemVI386,
};

struct NativeFunctionSignature {
    NativeAbi abi{NativeAbi::WindowsX64};
    std::vector<IrType> arguments;
    IrType returnType{IrWidth::U32};
    bool variadic{false};
};

struct NativeLiftReport {
    IrFunction function;
    bool complete{false};
    std::vector<Diagnostic> diagnostics;
};

struct NativeLiftOptions {
    std::vector<IrExternalDeclaration> externalDeclarations;
    std::vector<IrStorageLocation> symbolStorage;
};

[[nodiscard]] auto lift_function(
    const BinaryImage& image,
    EntityId function,
    const NativeFunctionSignature& signature,
    const NativeLiftOptions& options = {},
    const IrLimits& limits = {}) -> Result<NativeLiftReport, Diagnostic>;

[[nodiscard]] auto lift_function(
    const BinaryImage& image,
    EntityId function,
    const NativeFunctionSignature& signature,
    const IrLimits& limits) -> Result<NativeLiftReport, Diagnostic>;

} // namespace binobf::ir

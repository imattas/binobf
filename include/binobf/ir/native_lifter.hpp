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
};

struct NativeFunctionSignature {
    NativeAbi abi{NativeAbi::WindowsX64};
    std::vector<IrWidth> arguments;
    IrWidth returnWidth{IrWidth::U32};
};

struct NativeLiftReport {
    IrFunction function;
    bool complete{false};
    std::vector<Diagnostic> diagnostics;
};

[[nodiscard]] auto lift_function(
    const BinaryImage& image,
    EntityId function,
    const NativeFunctionSignature& signature,
    const IrLimits& limits = {}) -> Result<NativeLiftReport, Diagnostic>;

} // namespace binobf::ir

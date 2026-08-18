#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/model.hpp>
#include <binobf/core/result.hpp>
#include <binobf/ir/native_lifter.hpp>
#include <binobf/ir/vm_lowering.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace binobf::vm {

inline constexpr std::string_view embeddedRuntimeSymbol = "binobf_vm_execute_embedded_u32";

struct VmProtectionOptions {
    std::string function;
    ir::NativeAbi abi{ir::NativeAbi::WindowsX64};
    std::size_t argumentCount{0};
    std::uint64_t seed{0};
};

struct VmProtectionReport {
    std::string functionName;
    std::string sectionName;
    std::string runtimeSymbol;
    ir::NativeAbi abi{ir::NativeAbi::WindowsX64};
    std::size_t argumentCount{0};
    std::uint64_t seed{0};
    std::uint64_t originalAddress{0};
    std::uint64_t protectedAddress{0};
    std::uint64_t wrapperOffset{0};
    std::uint64_t wrapperSize{0};
    std::uint64_t bytecodeOffset{0};
    std::uint64_t bytecodeSize{0};
    std::uint64_t runtimeRelocationOffset{0};
    std::vector<ir::VmLoweringLineage> instructionLineage;
};

struct VmProtectionResult {
    BinaryImage image;
    std::vector<std::byte> bytecode;
    VmProtectionReport report;
};

[[nodiscard]] auto protect_function(const BinaryImage& image, const VmProtectionOptions& options)
    -> Result<VmProtectionResult, Diagnostic>;

} // namespace binobf::vm

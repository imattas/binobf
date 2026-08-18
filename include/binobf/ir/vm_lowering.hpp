#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/result.hpp>
#include <binobf/ir/native.hpp>
#include <binobf/vm/ir.hpp>

#include <cstdint>
#include <vector>

namespace binobf::ir {

struct VmLoweringLineage {
    std::uint32_t vmInstruction{0};
    EntityId source;
    auto operator==(const VmLoweringLineage&) const -> bool = default;
};

struct VmLoweringReport {
    vm::VmProgram program;
    std::vector<VmLoweringLineage> lineage;
};

[[nodiscard]] auto lower_to_vm(
    const IrFunction& function,
    const IrLimits& irLimits = {},
    const vm::VmLimits& vmLimits = {}) -> Result<VmLoweringReport, Diagnostic>;

[[nodiscard]] auto lower_module_to_vm(
    const IrModule& module,
    const IrLimits& irLimits = {},
    const vm::VmLimits& vmLimits = {}) -> Result<VmLoweringReport, Diagnostic>;

} // namespace binobf::ir

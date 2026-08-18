#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/result.hpp>
#include <binobf/ir/native.hpp>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace binobf::ir {

struct DispatcherCase {
    IrBlockId block;
    std::uint32_t value{0};
    auto operator==(const DispatcherCase&) const -> bool = default;
};

struct FlatteningStatistics {
    std::size_t originalBlocks{0};
    std::size_t dispatcherBlocks{0};
    std::size_t transitionBlocks{0};
    std::size_t bogusBlocks{0};
    auto operator==(const FlatteningStatistics&) const -> bool = default;
};

struct FlatteningReport {
    IrFunction function;
    IrVariable dispatcherState;
    IrBlockId dispatcherEntry;
    IrBlockId bogusBlock;
    std::vector<DispatcherCase> cases;
    FlatteningStatistics statistics;
    auto operator==(const FlatteningReport&) const -> bool = default;
};

[[nodiscard]] auto flatten_control_flow(
    const IrFunction& function,
    std::uint64_t seed,
    const IrLimits& limits = {}) -> Result<FlatteningReport, Diagnostic>;

} // namespace binobf::ir

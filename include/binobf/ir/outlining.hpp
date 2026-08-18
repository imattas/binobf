#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/result.hpp>
#include <binobf/ir/native.hpp>

#include <cstddef>
#include <cstdint>

namespace binobf::ir {

struct InternalizationStatistics {
    std::size_t movedBlocks{0};
    std::size_t liveInVariables{0};
    auto operator==(const InternalizationStatistics&) const -> bool = default;
};

struct InternalizationReport {
    IrModule module;
    EntityId helperFunction;
    InternalizationStatistics statistics;
    auto operator==(const InternalizationReport&) const -> bool = default;
};

[[nodiscard]] auto split_function(
    const IrFunction& function,
    std::uint64_t seed,
    const IrLimits& limits = {}) -> Result<InternalizationReport, Diagnostic>;

[[nodiscard]] auto outline_block(
    const IrFunction& function,
    IrBlockId block,
    std::uint64_t seed,
    const IrLimits& limits = {}) -> Result<InternalizationReport, Diagnostic>;

} // namespace binobf::ir

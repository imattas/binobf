#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/model.hpp>
#include <binobf/core/result.hpp>

#include <vector>

namespace binobf {

struct AnalysisReport {
    BinaryImage image;
    std::vector<Diagnostic> diagnostics;
};

[[nodiscard]] auto analyze_object(const BinaryImage& input)
    -> Result<AnalysisReport, Diagnostic>;

} // namespace binobf

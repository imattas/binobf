#pragma once

#include <binobf/transforms/pass.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

namespace binobf {

enum class PassStatus : std::uint8_t {
    Applied,
    Unchanged,
    Unsupported,
};

struct PassReport {
    std::string name;
    PassStatus status{PassStatus::Unchanged};
    PassStatistics statistics;
    std::vector<Diagnostic> diagnostics;
};

struct TransformationOutcome {
    BinaryImage image;
    std::vector<PassReport> reports;
    bool changed{false};
};

class PassManager {
public:
    [[nodiscard]] auto add(std::unique_ptr<TransformPass> pass)
        -> Result<std::size_t, Diagnostic>;

    [[nodiscard]] auto run(TransformContext& context, const BinaryImage& input) const
        -> Result<TransformationOutcome, Diagnostic>;

    [[nodiscard]] auto size() const noexcept -> std::size_t { return passes_.size(); }

private:
    std::vector<std::unique_ptr<TransformPass>> passes_;
};

} // namespace binobf

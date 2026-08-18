#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/model.hpp>
#include <binobf/core/result.hpp>
#include <binobf/transforms/selection.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <optional>
#include <utility>
#include <vector>

namespace binobf {

enum class PassRisk : std::uint8_t {
    Low,
    Medium,
    High,
};

struct PassRequirements {
    bool requiresCfg{false};
    bool requiresFullRelocations{false};
    bool requiresLiftedIr{false};
    bool changesCodeSize{false};
    bool supportedPostLink{false};
    PassRisk risk{PassRisk::Low};
    std::vector<BinaryFormat> formats;
    std::vector<Architecture> architectures;
};

struct PassStatistics {
    std::size_t examined{0};
    std::size_t changed{0};
    std::size_t skipped{0};
};

struct TransformResult {
    bool changed{false};
    PassStatistics statistics;
    std::vector<Diagnostic> diagnostics;
};

class TransformContext {
public:
    explicit TransformContext(std::uint64_t seed = 0, bool dryRun = false) noexcept
        : seed_(seed), dryRun_(dryRun) {}

    [[nodiscard]] auto seed() const noexcept -> std::uint64_t { return seed_; }
    [[nodiscard]] auto dry_run() const noexcept -> bool { return dryRun_; }
    [[nodiscard]] auto allocate_transform_id() noexcept -> TransformId {
        return TransformId{nextTransformId_++};
    }

    void preserve_symbol(std::string name);
    [[nodiscard]] auto is_symbol_preserved(std::string_view name) const -> bool;
    [[nodiscard]] auto set_function_selection(FunctionSelectionPolicy policy)
        -> Result<std::size_t, Diagnostic>;
    [[nodiscard]] auto has_function_selection() const noexcept -> bool {
        return functionSelector_.has_value();
    }
    [[nodiscard]] auto is_function_selected(
        const BinaryImage& image, const Function& function) const -> bool;
    [[nodiscard]] auto is_symbol_selected(
        const BinaryImage& image, const Symbol& symbol) const -> bool;
    void record_symbol_rename(std::string_view oldName, std::string_view newName);

private:
    std::uint64_t seed_{0};
    bool dryRun_{false};
    std::uint64_t nextTransformId_{1};
    std::vector<std::string> preservedSymbols_;
    std::optional<FunctionSelector> functionSelector_;
    std::vector<std::pair<std::string, std::string>> symbolAliases_;
};

class TransformPass {
public:
    virtual ~TransformPass() = default;

    [[nodiscard]] virtual auto name() const noexcept -> std::string_view = 0;
    [[nodiscard]] virtual auto dependencies() const -> std::vector<std::string> = 0;
    [[nodiscard]] virtual auto requirements() const -> PassRequirements = 0;
    [[nodiscard]] virtual auto supports(
        const TransformContext& context,
        const BinaryImage& image) const -> bool = 0;
    [[nodiscard]] virtual auto run(
        TransformContext& context,
        BinaryImage& image) const -> Result<TransformResult, Diagnostic> = 0;
};

} // namespace binobf

#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/model.hpp>
#include <binobf/core/result.hpp>

#include <cstdint>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

namespace binobf {

struct FunctionSelectionPolicy {
    std::vector<std::string> includeNames;
    std::vector<std::string> excludeNames;
    std::vector<std::string> includeRegex;
    std::vector<std::string> excludeRegex;
    std::vector<std::string> sections;
    std::vector<SymbolVisibility> visibilities;
    std::optional<std::uint8_t> percentage;
    std::uint64_t seed{0};

    auto operator==(const FunctionSelectionPolicy&) const -> bool = default;
};

class FunctionSelector {
public:
    [[nodiscard]] static auto compile(FunctionSelectionPolicy policy)
        -> Result<FunctionSelector, Diagnostic>;

    [[nodiscard]] auto matches(
        const BinaryImage& image,
        const Function& function,
        std::string_view originalName) const -> bool;
    [[nodiscard]] auto matches(
        const BinaryImage& image,
        const Symbol& symbol,
        std::string_view originalName) const -> bool;
    [[nodiscard]] auto policy() const noexcept -> const FunctionSelectionPolicy& {
        return policy_;
    }

private:
    FunctionSelectionPolicy policy_;
    std::vector<std::regex> includeRegex_;
    std::vector<std::regex> excludeRegex_;
};

} // namespace binobf

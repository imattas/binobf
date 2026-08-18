#include <binobf/transforms/selection.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <regex>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace binobf {
namespace {

auto selection_error(std::string message) -> Diagnostic {
    return Diagnostic{
        DiagnosticSeverity::Error, "selection.regex", std::move(message)};
}

auto section_name(const BinaryImage& image, EntityId id) -> std::string_view {
    const auto found = std::find_if(
        image.sections.begin(), image.sections.end(), [id](const auto& section) {
            return section.id == id;
        });
    return found == image.sections.end() ? std::string_view{} : found->name;
}

auto find_symbol(const BinaryImage& image, const Function& function) -> const Symbol* {
    if (!function.symbol.has_value()) return nullptr;
    const auto found = std::find_if(
        image.symbols.begin(), image.symbols.end(), [&function](const auto& symbol) {
            return symbol.id == *function.symbol;
        });
    return found == image.symbols.end() ? nullptr : &*found;
}

auto contains(std::span<const std::string> values, std::string_view value) -> bool {
    return std::find(values.begin(), values.end(), value) != values.end();
}

auto regex_matches(std::span<const std::regex> patterns, std::string_view value) -> bool {
    return std::any_of(patterns.begin(), patterns.end(), [value](const auto& pattern) {
        return std::regex_match(value.begin(), value.end(), pattern);
    });
}

auto stable_hash(std::uint64_t seed,
                 std::string_view name,
                 std::string_view section,
                 SymbolVisibility visibility) noexcept -> std::uint64_t {
    constexpr std::uint64_t offset = UINT64_C(14695981039346656037);
    constexpr std::uint64_t prime = UINT64_C(1099511628211);
    std::uint64_t hash = offset;
    const auto add = [&hash](std::uint8_t value) {
        hash ^= value;
        hash *= prime;
    };
    for (std::size_t index = 0; index < sizeof(seed); ++index) {
        add(static_cast<std::uint8_t>((seed >> (index * 8U)) & 0xffU));
    }
    for (const auto value : name) add(static_cast<std::uint8_t>(value));
    add(0xffU);
    for (const auto value : section) add(static_cast<std::uint8_t>(value));
    add(0xfeU);
    add(static_cast<std::uint8_t>(visibility));
    return hash;
}

auto matches_policy(const FunctionSelectionPolicy& policy,
                    std::span<const std::regex> includeRegex,
                    std::span<const std::regex> excludeRegex,
                    std::string_view name,
                    std::string_view section,
                    SymbolVisibility visibility) -> bool {
    if (contains(policy.excludeNames, name) || regex_matches(excludeRegex, name)) {
        return false;
    }
    const bool hasAllowlist = !policy.includeNames.empty() || !includeRegex.empty();
    if (hasAllowlist
        && !contains(policy.includeNames, name)
        && !regex_matches(includeRegex, name)) {
        return false;
    }
    if (!policy.sections.empty() && !contains(policy.sections, section)) return false;
    if (!policy.visibilities.empty()
        && std::find(policy.visibilities.begin(), policy.visibilities.end(), visibility)
            == policy.visibilities.end()) {
        return false;
    }
    if (policy.percentage.has_value()) {
        const auto threshold = static_cast<std::uint64_t>(*policy.percentage) * 100U;
        if (stable_hash(policy.seed, name, section, visibility) % 10000U >= threshold) {
            return false;
        }
    }
    return true;
}

} // namespace

auto FunctionSelector::compile(FunctionSelectionPolicy policy)
    -> Result<FunctionSelector, Diagnostic> {
    if (policy.percentage.has_value() && *policy.percentage > 100U) {
        return Result<FunctionSelector, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "selection.percentage",
            "selection percentage must be between 0 and 100"});
    }
    FunctionSelector result;
    result.policy_ = std::move(policy);
    try {
        const auto flags = std::regex_constants::ECMAScript | std::regex_constants::optimize;
        result.includeRegex_.reserve(result.policy_.includeRegex.size());
        for (const auto& pattern : result.policy_.includeRegex) {
            result.includeRegex_.emplace_back(pattern, flags);
        }
        result.excludeRegex_.reserve(result.policy_.excludeRegex.size());
        for (const auto& pattern : result.policy_.excludeRegex) {
            result.excludeRegex_.emplace_back(pattern, flags);
        }
    } catch (const std::regex_error&) {
        return Result<FunctionSelector, Diagnostic>::failure(
            selection_error("selection contains an invalid ECMAScript regular expression"));
    }
    return Result<FunctionSelector, Diagnostic>::success(std::move(result));
}

auto FunctionSelector::matches(const BinaryImage& image,
                               const Function& function,
                               std::string_view originalName) const -> bool {
    const auto* symbol = find_symbol(image, function);
    const auto visibility = symbol == nullptr ? SymbolVisibility::Unknown : symbol->visibility;
    return matches_policy(
        policy_, includeRegex_, excludeRegex_, originalName,
        section_name(image, function.section), visibility);
}

auto FunctionSelector::matches(const BinaryImage& image,
                               const Symbol& symbol,
                               std::string_view originalName) const -> bool {
    if (!symbol.section.has_value() || symbol.kind != SymbolKind::Function || !symbol.defined) {
        return false;
    }
    return matches_policy(
        policy_, includeRegex_, excludeRegex_, originalName,
        section_name(image, *symbol.section), symbol.visibility);
}

} // namespace binobf

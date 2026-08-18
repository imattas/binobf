#include <binobf/transforms/pass_manager.hpp>

#include <binobf/formats/object_writer.hpp>
#include <binobf/verify/structural_verifier.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <span>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace binobf {
namespace {

auto error(std::string code, std::string message) -> Diagnostic {
    return Diagnostic{DiagnosticSeverity::Error, std::move(code), std::move(message)};
}

auto ordered_passes(const std::vector<std::unique_ptr<TransformPass>>& passes)
    -> Result<std::vector<std::size_t>, Diagnostic> {
    std::unordered_map<std::string, std::size_t> indices;
    for (std::size_t index = 0; index < passes.size(); ++index) {
        indices.emplace(std::string{passes[index]->name()}, index);
    }
    std::vector<std::vector<std::size_t>> dependents(passes.size());
    std::vector<std::size_t> indegree(passes.size());
    for (std::size_t index = 0; index < passes.size(); ++index) {
        std::unordered_set<std::string> uniqueDependencies;
        for (const auto& dependency : passes[index]->dependencies()) {
            if (!uniqueDependencies.insert(dependency).second) {
                return Result<std::vector<std::size_t>, Diagnostic>::failure(error(
                    "pass.duplicate_dependency",
                    "pass " + std::string{passes[index]->name()}
                        + " repeats dependency " + dependency));
            }
            const auto found = indices.find(dependency);
            if (found == indices.end()) {
                return Result<std::vector<std::size_t>, Diagnostic>::failure(error(
                    "pass.missing_dependency",
                    "pass " + std::string{passes[index]->name()}
                        + " requires missing pass " + dependency));
            }
            dependents[found->second].push_back(index);
            ++indegree[index];
        }
    }
    std::vector<std::size_t> order;
    order.reserve(passes.size());
    while (order.size() != passes.size()) {
        std::size_t next = passes.size();
        for (std::size_t index = 0; index < passes.size(); ++index) {
            if (indegree[index] == 0
                && std::find(order.begin(), order.end(), index) == order.end()) {
                next = index;
                break;
            }
        }
        if (next == passes.size()) {
            return Result<std::vector<std::size_t>, Diagnostic>::failure(error(
                "pass.dependency_cycle", "pass dependencies contain a cycle"));
        }
        order.push_back(next);
        for (const auto dependent : dependents[next]) {
            --indegree[dependent];
        }
    }
    return Result<std::vector<std::size_t>, Diagnostic>::success(std::move(order));
}

auto verification_error(
    std::string_view passName,
    const Diagnostic& cause) -> Diagnostic {
    auto diagnostic = error(
        "pass.verification_failed",
        "pass " + std::string{passName} + " failed verification: "
        + cause.code + ": " + cause.message);
    diagnostic.pass = std::string{passName};
    diagnostic.explanation = "the candidate output did not satisfy the structural commit gate";
    diagnostic.remediation = "inspect the cause and preserve every affected format relationship";
    return diagnostic;
}

auto unsupported_diagnostic(std::string_view passName) -> Diagnostic {
    auto diagnostic = Diagnostic{
        DiagnosticSeverity::Info,
        "pass.unsupported",
        "pass requirements are not satisfied by this input",
    };
    diagnostic.pass = std::string{passName};
    diagnostic.explanation =
        "the input format, architecture, analysis, or relocation coverage is outside the pass contract";
    diagnostic.remediation = "select a supported input or a pass with compatible requirements";
    return diagnostic;
}

} // namespace

void TransformContext::preserve_symbol(std::string name) {
    if (std::find(preservedSymbols_.begin(), preservedSymbols_.end(), name)
        == preservedSymbols_.end()) {
        preservedSymbols_.push_back(std::move(name));
    }
}

auto TransformContext::is_symbol_preserved(std::string_view name) const -> bool {
    return std::find(preservedSymbols_.begin(), preservedSymbols_.end(), name)
        != preservedSymbols_.end();
}

auto TransformContext::set_function_selection(FunctionSelectionPolicy policy)
    -> Result<std::size_t, Diagnostic> {
    auto selector = FunctionSelector::compile(std::move(policy));
    if (!selector.has_value()) {
        return Result<std::size_t, Diagnostic>::failure(std::move(selector).error());
    }
    functionSelector_ = std::move(selector).value();
    return Result<std::size_t, Diagnostic>::success(1);
}

namespace {

auto original_name(
    std::span<const std::pair<std::string, std::string>> aliases,
    std::string_view name) -> std::string {
    for (auto item = aliases.rbegin(); item != aliases.rend(); ++item) {
        if (item->first == name) return item->second;
    }
    return std::string{name};
}

} // namespace

auto TransformContext::is_function_selected(
    const BinaryImage& image, const Function& function) const -> bool {
    if (!functionSelector_.has_value()) return true;
    return functionSelector_->matches(
        image, function, original_name(symbolAliases_, function.name));
}

auto TransformContext::is_symbol_selected(
    const BinaryImage& image, const Symbol& symbol) const -> bool {
    if (!functionSelector_.has_value()) return true;
    return functionSelector_->matches(
        image, symbol, original_name(symbolAliases_, symbol.name));
}

void TransformContext::record_symbol_rename(
    std::string_view oldName, std::string_view newName) {
    symbolAliases_.emplace_back(
        std::string{newName}, original_name(symbolAliases_, oldName));
}

auto PassManager::add(std::unique_ptr<TransformPass> pass)
    -> Result<std::size_t, Diagnostic> {
    if (!pass || pass->name().empty()) {
        return Result<std::size_t, Diagnostic>::failure(
            error("pass.invalid", "pass must have a nonempty name"));
    }
    const auto duplicate = std::find_if(
        passes_.begin(), passes_.end(), [&pass](const auto& existing) {
            return existing->name() == pass->name();
        });
    if (duplicate != passes_.end()) {
        return Result<std::size_t, Diagnostic>::failure(error(
            "pass.duplicate", "duplicate pass name: " + std::string{pass->name()}));
    }
    const auto index = passes_.size();
    passes_.push_back(std::move(pass));
    return Result<std::size_t, Diagnostic>::success(index);
}

auto PassManager::run(TransformContext& context, const BinaryImage& input) const
    -> Result<TransformationOutcome, Diagnostic> {
    const auto order = ordered_passes(passes_);
    if (!order.has_value()) {
        return Result<TransformationOutcome, Diagnostic>::failure(order.error());
    }
    BinaryImage working = input;
    std::vector<PassReport> reports;
    reports.reserve(passes_.size());
    bool anyChanged = false;
    for (const auto index : order.value()) {
        const auto& pass = *passes_[index];
        if (!pass.supports(context, working)) {
            reports.push_back(PassReport{
                .name = std::string{pass.name()},
                .status = PassStatus::Unsupported,
                .statistics = {},
                .diagnostics = {unsupported_diagnostic(pass.name())},
            });
            continue;
        }
        const auto before = write_object(working);
        if (!before.has_value()) {
            return Result<TransformationOutcome, Diagnostic>::failure(
                verification_error(pass.name(), before.error()));
        }
        BinaryImage candidate = working;
        auto passResult = pass.run(context, candidate);
        if (!passResult.has_value()) {
            auto diagnostic = passResult.error();
            if (!diagnostic.pass.has_value()) diagnostic.pass = std::string{pass.name()};
            return Result<TransformationOutcome, Diagnostic>::failure(std::move(diagnostic));
        }
        const auto after = write_object(candidate);
        if (!after.has_value()) {
            return Result<TransformationOutcome, Diagnostic>::failure(
                verification_error(pass.name(), after.error()));
        }
        const bool actuallyChanged = before.value() != after.value();
        if (actuallyChanged != passResult.value().changed) {
            auto diagnostic = error(
                "pass.contract_violation",
                "pass " + std::string{pass.name()}
                    + " reported an incorrect changed state");
            diagnostic.pass = std::string{pass.name()};
            diagnostic.explanation =
                "the pass report disagrees with serialized candidate bytes";
            diagnostic.remediation =
                "make the pass changed flag match its actual serialized output";
            return Result<TransformationOutcome, Diagnostic>::failure(std::move(diagnostic));
        }
        const auto verified = verify_object(after.value(), std::string{pass.name()} + ".verify.o");
        if (!verified.has_value()) {
            return Result<TransformationOutcome, Diagnostic>::failure(
                verification_error(pass.name(), verified.error()));
        }
        const auto status = actuallyChanged ? PassStatus::Applied : PassStatus::Unchanged;
        reports.push_back(PassReport{
            .name = std::string{pass.name()},
            .status = status,
            .statistics = passResult.value().statistics,
            .diagnostics = std::move(passResult.value().diagnostics),
        });
        if (actuallyChanged) {
            anyChanged = true;
            working = std::move(candidate);
        }
    }
    return Result<TransformationOutcome, Diagnostic>::success(TransformationOutcome{
        .image = context.dry_run() ? input : std::move(working),
        .reports = std::move(reports),
        .changed = anyChanged,
    });
}

} // namespace binobf

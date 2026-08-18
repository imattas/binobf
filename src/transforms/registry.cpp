#include <binobf/transforms/registry.hpp>

#include <binobf/transforms/baseline.hpp>
#include <binobf/transforms/instruction.hpp>

#include <algorithm>
#include <array>
#include <vector>

namespace binobf {
namespace {

constexpr std::array kBuiltinPasses{
    PassRegistration{"block-reordering", &make_block_reordering_pass},
    PassRegistration{"block-splitting", &make_block_splitting_pass},
    PassRegistration{"branch-inversion", &make_branch_inversion_pass},
    PassRegistration{"cleanup-metadata", &make_metadata_cleanup_pass},
    PassRegistration{"constant-rewriting", &make_constant_rewriting_pass},
    PassRegistration{"dead-code-insertion", &make_dead_code_insertion_pass},
    PassRegistration{"function-reordering", &make_function_reordering_pass},
    PassRegistration{"instruction-substitution", &make_instruction_substitution_pass},
    PassRegistration{"rename-private-symbols", &make_rename_private_symbols_pass},
    PassRegistration{"strip-debug", &make_strip_debug_pass},
    PassRegistration{"strip-local-symbols", &make_strip_local_symbols_pass},
};

} // namespace

auto pass_registry() -> std::vector<PassRegistration>& {
    static auto passes = [] {
        return std::vector<PassRegistration>{
            kBuiltinPasses.begin(), kBuiltinPasses.end()};
    }();
    return passes;
}

auto registered_passes() -> std::span<const PassRegistration> {
    const auto& passes = pass_registry();
    return passes;
}

auto register_pass(PassRegistration registration) -> Result<bool, Diagnostic> {
    if (registration.name.empty() || registration.factory == nullptr) {
        return Result<bool, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "pass.registration_invalid",
            "registered passes require a non-empty name and factory"});
    }
    const auto candidate = registration.factory();
    if (!candidate || candidate->name() != registration.name) {
        return Result<bool, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "pass.registration_invalid",
            "pass factory name must match its registration name"});
    }
    auto& passes = pass_registry();
    const auto position = std::ranges::lower_bound(
        passes, registration.name, {}, &PassRegistration::name);
    if (position != passes.end() && position->name == registration.name) {
        return Result<bool, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "pass.registration_duplicate",
            "a pass with this name is already registered: "
                + std::string{registration.name}});
    }
    passes.insert(position, registration);
    return Result<bool, Diagnostic>::success(true);
}

auto find_registered_pass(std::string_view name) noexcept
    -> const PassRegistration* {
    const auto passes = registered_passes();
    const auto found = std::ranges::lower_bound(passes, name, {}, &PassRegistration::name);
    if (found == passes.end() || found->name != name) {
        return nullptr;
    }
    return &*found;
}

auto make_registered_pass(std::string_view name) -> std::unique_ptr<TransformPass> {
    const auto* registration = find_registered_pass(name);
    if (registration == nullptr || registration->factory == nullptr) {
        return nullptr;
    }
    return registration->factory();
}

} // namespace binobf

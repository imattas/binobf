#include <binobf/transforms/registry.hpp>

#include <binobf/transforms/baseline.hpp>
#include <binobf/transforms/instruction.hpp>

#include <algorithm>
#include <array>

namespace binobf {
namespace {

constexpr std::array kPasses{
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

auto registered_passes() -> std::span<const PassRegistration> {
    return kPasses;
}

auto find_registered_pass(std::string_view name) noexcept
    -> const PassRegistration* {
    const auto found = std::ranges::lower_bound(kPasses, name, {}, &PassRegistration::name);
    if (found == kPasses.end() || found->name != name) {
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

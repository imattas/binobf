#include <binobf/transforms/registry.hpp>

#include "../test_support.hpp"

#include <array>
#include <string_view>

using namespace std::string_view_literals;

TEST_CASE(pass_registry_has_unique_names_and_factories_for_every_builtin) {
    constexpr std::array expected{
        "strip-debug"sv, "cleanup-metadata"sv, "strip-local-symbols"sv,
        "rename-private-symbols"sv, "instruction-substitution"sv,
        "constant-rewriting"sv, "branch-inversion"sv, "dead-code-insertion"sv,
        "block-splitting"sv, "block-reordering"sv, "function-reordering"sv,
    };
    const auto registrations = binobf::registered_passes();
    REQUIRE_EQ(registrations.size(), expected.size());
    for (const auto name : expected) {
        const auto* registration = binobf::find_registered_pass(name);
        REQUIRE(registration != nullptr);
        REQUIRE(registration->factory != nullptr);
        const auto pass = binobf::make_registered_pass(name);
        REQUIRE(pass != nullptr);
        REQUIRE_EQ(pass->name(), name);
    }
    REQUIRE(binobf::find_registered_pass("not-a-pass") == nullptr);
    REQUIRE(binobf::make_registered_pass("not-a-pass") == nullptr);
}

TEST_CASE(pass_registry_is_sorted_and_contains_unique_names) {
    const auto registrations = binobf::registered_passes();
    for (std::size_t index = 1; index < registrations.size(); ++index) {
        REQUIRE(registrations[index - 1].name < registrations[index].name);
    }
}

int main() {
    return binobf::test::run_all();
}

#include <binobf/transforms/registry.hpp>

#include "../test_support.hpp"

#include <array>
#include <memory>
#include <string_view>

using namespace std::string_view_literals;

class ExtensionPass final : public binobf::TransformPass {
  public:
    auto name() const noexcept -> std::string_view override { return "test-extension"; }
    auto dependencies() const -> std::vector<std::string> override { return {}; }
    auto requirements() const -> binobf::PassRequirements override { return {}; }
    auto supports(const binobf::TransformContext&, const binobf::BinaryImage&) const
        -> bool override { return true; }
    auto run(binobf::TransformContext&, binobf::BinaryImage&) const
        -> binobf::Result<binobf::TransformResult, binobf::Diagnostic> override {
        return binobf::Result<binobf::TransformResult, binobf::Diagnostic>::success({});
    }
};

auto make_extension_pass() -> std::unique_ptr<binobf::TransformPass> {
    return std::make_unique<ExtensionPass>();
}

const auto extensionRegistration = binobf::register_pass(
    binobf::PassRegistration{"test-extension", &make_extension_pass});

TEST_CASE(pass_registry_has_unique_names_and_factories_for_every_builtin) {
    constexpr std::array expected{
        "strip-debug"sv, "cleanup-metadata"sv, "strip-local-symbols"sv,
        "rename-private-symbols"sv, "instruction-substitution"sv,
        "constant-rewriting"sv, "branch-inversion"sv, "dead-code-insertion"sv,
        "block-splitting"sv, "block-reordering"sv, "function-reordering"sv,
        "test-extension"sv,
    };
    REQUIRE(extensionRegistration.has_value());
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

TEST_CASE(pass_registry_rejects_invalid_and_duplicate_extensions) {
    const auto duplicate = binobf::register_pass(
        binobf::PassRegistration{"test-extension", &make_extension_pass});
    REQUIRE(!duplicate.has_value());
    REQUIRE_EQ(duplicate.error().code, std::string{"pass.registration_duplicate"});

    const auto invalid = binobf::register_pass(binobf::PassRegistration{"", nullptr});
    REQUIRE(!invalid.has_value());
    REQUIRE_EQ(invalid.error().code, std::string{"pass.registration_invalid"});
}

int main() {
    return binobf::test::run_all();
}

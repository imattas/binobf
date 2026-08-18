#include <binobf/architecture/codegen.hpp>

#include "../test_support.hpp"

#include <array>

TEST_CASE(codegen_provider_is_fixed_to_each_supported_architecture) {
    for (const auto architecture : std::array{
             binobf::Architecture::X86,
             binobf::Architecture::X86_64,
             binobf::Architecture::ARM64}) {
        auto provider = binobf::make_codegen_provider(architecture);
        REQUIRE(provider.has_value());
        REQUIRE_EQ(provider.value()->architecture(), architecture);
        REQUIRE_EQ(provider.value()->provider_version(), "LLVM 22.1.8");
    }
    const auto unknown = binobf::make_codegen_provider(binobf::Architecture::Unknown);
    REQUIRE(!unknown.has_value());
    REQUIRE_EQ(unknown.error().code, "codegen.unsupported_architecture");
}

TEST_CASE(codegen_request_defaults_are_bounded_and_provider_neutral) {
    const binobf::MachineAssemblyRequest request{};
    REQUIRE(request.limits.maxAssemblyBytes > 0U);
    REQUIRE(request.limits.maxAssemblyBytes <= (1U << 20U));
    REQUIRE(request.limits.maxEmittedBytes <= (16U << 20U));
    REQUIRE_EQ(request.sectionName, ".text");
}

int main() {
    return binobf::test::run_all();
}

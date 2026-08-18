#include <binobf/capabilities/registry.hpp>

#include "../test_support.hpp"

#include <array>

TEST_CASE(builtin_capability_registry_contains_each_public_matrix_axis) {
    const auto& registry = binobf::builtin_capability_registry();
    REQUIRE_EQ(registry.records().size(), 48U);

    const auto* peDetection = registry.find(binobf::CapabilityKey{
        .capability = binobf::Capability::Detection,
        .format = binobf::BinaryFormat::PE,
    });
    REQUIRE(peDetection != nullptr);
    REQUIRE_EQ(peDetection->support, binobf::SupportLevel::Supported);

    const auto* x86Analysis = registry.find(binobf::CapabilityKey{
        .capability = binobf::Capability::ObjectAnalysis,
        .architecture = binobf::Architecture::X86,
    });
    REQUIRE(x86Analysis != nullptr);
    REQUIRE_EQ(x86Analysis->support, binobf::SupportLevel::Experimental);

    const auto* peObjectParsing = registry.find(binobf::CapabilityKey{
        .capability = binobf::Capability::RelocatableObjectParsing,
        .format = binobf::BinaryFormat::PE,
    });
    REQUIRE(peObjectParsing != nullptr);
    REQUIRE_EQ(peObjectParsing->support, binobf::SupportLevel::NotApplicable);
}

TEST_CASE(capability_registry_rejects_duplicate_keys_and_unknown_lookups) {
    const binobf::CapabilityRecord duplicate{
        .key = {.capability = binobf::Capability::Detection,
                .format = binobf::BinaryFormat::PE},
        .support = binobf::SupportLevel::Supported,
        .qualifier = {},
        .evidence = {"format-detection"},
    };
    const std::array records{duplicate, duplicate};
    const auto registry = binobf::CapabilityRegistry::create(records);
    REQUIRE(!registry.has_value());
    REQUIRE_EQ(registry.error().code, "capability.duplicate_key");

    const auto& builtin = binobf::builtin_capability_registry();
    REQUIRE(builtin.find(binobf::CapabilityKey{
                .capability = binobf::Capability::Detection,
                .format = binobf::BinaryFormat::Unknown,
            }) == nullptr);
}

int main() {
    return binobf::test::run_all();
}

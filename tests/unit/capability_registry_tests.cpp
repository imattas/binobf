#include <binobf/capabilities/registry.hpp>
#include <binobf/capabilities/evidence.hpp>

#include "../test_support.hpp"

#include <array>

TEST_CASE(builtin_capability_registry_contains_each_public_matrix_axis) {
    const auto& registry = binobf::builtin_capability_registry();
    REQUIRE_EQ(registry.records().size(), 57U);

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
    REQUIRE_EQ(x86Analysis->support, binobf::SupportLevel::Supported);

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

TEST_CASE(supported_capabilities_require_known_release_evidence) {
    const auto validated = binobf::validate_capability_evidence(
        binobf::builtin_capability_registry(),
        binobf::builtin_acceptance_evidence());
    REQUIRE(validated.has_value());
    REQUIRE(validated.value() > 0U);
}

TEST_CASE(unknown_and_duplicate_evidence_ids_are_rejected) {
    const std::array duplicateEvidence{
        binobf::AcceptanceEvidence{"format-detection", "format_detector", true},
        binobf::AcceptanceEvidence{"format-detection", "core_types", true},
    };
    const auto duplicate = binobf::validate_capability_evidence(
        binobf::builtin_capability_registry(), duplicateEvidence);
    REQUIRE(!duplicate.has_value());
    REQUIRE_EQ(duplicate.error().code, "capability.duplicate_evidence");

    const std::array unknownRecords{
        binobf::CapabilityRecord{
            .key = {.capability = binobf::Capability::Detection,
                    .format = binobf::BinaryFormat::PE},
            .support = binobf::SupportLevel::Supported,
            .qualifier = {},
            .evidence = {"does-not-exist"},
        },
    };
    const auto unknownRegistry = binobf::CapabilityRegistry::create(unknownRecords);
    REQUIRE(unknownRegistry.has_value());
    const auto unknown = binobf::validate_capability_evidence(
        unknownRegistry.value(), binobf::builtin_acceptance_evidence());
    REQUIRE(!unknown.has_value());
    REQUIRE_EQ(unknown.error().code, "capability.unknown_evidence");

    const std::array missingRecords{
        binobf::CapabilityRecord{
            .key = {.capability = binobf::Capability::Detection,
                    .format = binobf::BinaryFormat::PE},
            .support = binobf::SupportLevel::Supported,
            .qualifier = {},
            .evidence = {},
        },
    };
    const auto missingRegistry = binobf::CapabilityRegistry::create(missingRecords);
    REQUIRE(missingRegistry.has_value());
    const auto missing = binobf::validate_capability_evidence(
        missingRegistry.value(), binobf::builtin_acceptance_evidence());
    REQUIRE(!missing.has_value());
    REQUIRE_EQ(missing.error().code, "capability.missing_evidence");
}

int main() {
    return binobf::test::run_all();
}

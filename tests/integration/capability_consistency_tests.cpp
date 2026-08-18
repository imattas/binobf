#include <binobf/architecture/backend.hpp>
#include <binobf/capabilities/evidence.hpp>
#include <binobf/capabilities/render.hpp>
#include <binobf/capabilities/registry.hpp>
#include <binobf/transforms/registry.hpp>

#include "../test_support.hpp"

#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

namespace {

std::filesystem::path readmePath;

} // namespace

TEST_CASE(architecture_backend_services_match_public_capabilities) {
    const auto& capabilities = binobf::builtin_capability_registry();
    for (const auto architecture : std::array{
             binobf::Architecture::X86,
             binobf::Architecture::X86_64,
             binobf::Architecture::ARM64}) {
        auto backend = binobf::make_architecture_backend(architecture);
        REQUIRE(backend.has_value());

        for (const auto pair : std::array{
                 std::pair{binobf::BackendService::Decode,
                           binobf::Capability::InstructionDecoding},
                 std::pair{binobf::BackendService::AnalyzeObject,
                           binobf::Capability::ObjectAnalysis},
                 std::pair{binobf::BackendService::EmitCode,
                           binobf::Capability::CodeGeneration}}) {
            const auto* service = backend.value()->find_service(pair.first);
            const auto* capability = capabilities.find(binobf::CapabilityKey{
                .capability = pair.second,
                .architecture = architecture,
            });
            REQUIRE(service != nullptr);
            REQUIRE(capability != nullptr);
            REQUIRE_EQ(service->support, capability->support);
        }
    }
}

TEST_CASE(registered_passes_have_truthful_complete_requirements) {
    for (const auto& registration : binobf::registered_passes()) {
        REQUIRE(registration.factory != nullptr);
        const auto pass = registration.factory();
        REQUIRE(pass != nullptr);
        REQUIRE_EQ(pass->name(), registration.name);
        REQUIRE(!pass->requirements().formats.empty());
        REQUIRE(!pass->requirements().architectures.empty());
    }
}

TEST_CASE(capability_evidence_and_readme_render_are_release_consistent) {
    const auto& capabilities = binobf::builtin_capability_registry();
    const auto validated = binobf::validate_capability_evidence(
        capabilities, binobf::builtin_acceptance_evidence());
    REQUIRE(validated.has_value());

    std::ifstream input(readmePath, std::ios::binary);
    REQUIRE(input.good());
    const std::string contents(std::istreambuf_iterator<char>{input},
                               std::istreambuf_iterator<char>{});
    REQUIRE(!input.bad());
    constexpr std::string_view startMarker = "<!-- binobf:feature-matrix:start -->\n";
    constexpr std::string_view endMarker = "<!-- binobf:feature-matrix:end -->";
    const auto start = contents.find(startMarker);
    REQUIRE(start != std::string::npos);
    const auto bodyStart = start + startMarker.size();
    const auto end = contents.find(endMarker, bodyStart);
    REQUIRE(end != std::string::npos);
    REQUIRE_EQ(contents.substr(bodyStart, end - bodyStart),
               binobf::render_feature_matrix_markdown(capabilities));
    REQUIRE(binobf::render_format_capabilities_text(capabilities).find("missing")
            == std::string::npos);
    REQUIRE(binobf::render_architecture_capabilities_text(capabilities).find("missing")
            == std::string::npos);
}

auto main(int argc, char** argv) -> int {
    if (argc != 2) {
        return 2;
    }
    readmePath = argv[1];
    return binobf::test::run_all();
}

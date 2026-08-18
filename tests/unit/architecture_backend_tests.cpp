#include <binobf/architecture/backend.hpp>

#include "../test_support.hpp"

#include <array>

TEST_CASE(backends_have_fixed_supported_architecture_and_decode_service) {
    for (const auto architecture : std::array{
             binobf::Architecture::X86,
             binobf::Architecture::X86_64,
             binobf::Architecture::ARM64}) {
        auto backend = binobf::make_architecture_backend(architecture);
        REQUIRE(backend.has_value());
        REQUIRE_EQ(backend.value()->architecture(), architecture);
        const auto* decode = backend.value()->find_service(binobf::BackendService::Decode);
        REQUIRE(decode != nullptr);
        REQUIRE_EQ(decode->support, binobf::SupportLevel::Supported);
        REQUIRE(!decode->evidence.empty());
        REQUIRE(!backend.value()->name().empty());
    }
}

TEST_CASE(backend_rejects_unknown_architecture_and_mismatched_decode_request) {
    const auto unknown = binobf::make_architecture_backend(binobf::Architecture::Unknown);
    REQUIRE(!unknown.has_value());
    REQUIRE_EQ(unknown.error().code, "architecture.unsupported");

    auto backend = binobf::make_architecture_backend(binobf::Architecture::X86_64);
    REQUIRE(backend.has_value());
    const std::array bytes{std::byte{0xC3}};
    const auto decoded = backend.value()->decode(binobf::DecodeRequest{
        .architecture = binobf::Architecture::X86,
        .bytes = bytes,
        .address = {0x1000, binobf::AddressKind::Virtual},
        .instructionId = binobf::EntityId{1},
        .sectionId = binobf::EntityId{2},
    });
    REQUIRE(!decoded.has_value());
    REQUIRE_EQ(decoded.error().code, "architecture.request_mismatch");
}

TEST_CASE(backend_service_levels_mirror_the_current_architecture_matrix) {
    auto x86 = binobf::make_architecture_backend(binobf::Architecture::X86);
    auto x64 = binobf::make_architecture_backend(binobf::Architecture::X86_64);
    auto arm64 = binobf::make_architecture_backend(binobf::Architecture::ARM64);
    REQUIRE(x86.has_value());
    REQUIRE(x64.has_value());
    REQUIRE(arm64.has_value());
    REQUIRE_EQ(x86.value()->find_service(binobf::BackendService::AnalyzeObject)->support,
               binobf::SupportLevel::Experimental);
    REQUIRE_EQ(x64.value()->find_service(binobf::BackendService::AnalyzeObject)->support,
               binobf::SupportLevel::Supported);
    REQUIRE_EQ(arm64.value()->find_service(binobf::BackendService::AnalyzeObject)->support,
               binobf::SupportLevel::Experimental);
    REQUIRE_EQ(x86.value()->find_service(binobf::BackendService::EmitCode)->support,
               binobf::SupportLevel::Planned);
    REQUIRE_EQ(x64.value()->find_service(binobf::BackendService::EmitCode)->support,
               binobf::SupportLevel::Restricted);
    REQUIRE_EQ(arm64.value()->find_service(binobf::BackendService::EmitCode)->support,
               binobf::SupportLevel::Planned);
}

int main() {
    return binobf::test::run_all();
}

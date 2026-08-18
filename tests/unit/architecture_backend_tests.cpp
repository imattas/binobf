#include <binobf/architecture/backend.hpp>

#include "../test_support.hpp"

#include <algorithm>
#include <array>
#include <span>
#include <string>

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
               binobf::SupportLevel::Supported);
    REQUIRE_EQ(x64.value()->find_service(binobf::BackendService::AnalyzeObject)->support,
               binobf::SupportLevel::Supported);
    REQUIRE_EQ(arm64.value()->find_service(binobf::BackendService::AnalyzeObject)->support,
               binobf::SupportLevel::Supported);
    REQUIRE_EQ(x86.value()->find_service(binobf::BackendService::EmitCode)->support,
               binobf::SupportLevel::Supported);
    REQUIRE_EQ(x64.value()->find_service(binobf::BackendService::EmitCode)->support,
               binobf::SupportLevel::Restricted);
    REQUIRE_EQ(arm64.value()->find_service(binobf::BackendService::EmitCode)->support,
               binobf::SupportLevel::Supported);
    for (const auto service : {
             binobf::BackendService::EncodeFixups,
             binobf::BackendService::BuildAbiAdapter,
             binobf::BackendService::BuildUnwind}) {
        const auto* record = x86.value()->find_service(service);
        REQUIRE(record != nullptr);
        REQUIRE_EQ(record->support, binobf::SupportLevel::Supported);
        REQUIRE(!record->evidence.empty());
    }
}

TEST_CASE(backends_own_fixed_codegen_providers_and_verify_deterministic_emission) {
    using namespace binobf;
    struct Golden {
        Architecture architecture;
        BinaryFormat format;
        std::string triple;
        MachineSyntax syntax;
        std::string assembly;
    };
    const std::array goldens{
        Golden{Architecture::X86, BinaryFormat::COFF, "i686-pc-windows-msvc",
               MachineSyntax::Intel, "nop\nret\n"},
        Golden{Architecture::X86_64, BinaryFormat::ELF, "x86_64-unknown-linux-gnu",
               MachineSyntax::Intel, "nop\nret\n"},
        Golden{Architecture::ARM64, BinaryFormat::ELF, "aarch64-unknown-linux-gnu",
               MachineSyntax::GNU, "nop\nret\n"},
    };
    for (const auto& golden : goldens) {
        auto backend = make_architecture_backend(golden.architecture);
        REQUIRE(backend.has_value());
        REQUIRE(backend.value()->codegen() != nullptr);
        REQUIRE_EQ(backend.value()->codegen()->architecture(), golden.architecture);
        REQUIRE_EQ(backend.value()->codegen()->provider_version(), "LLVM 22.1.8");

        MachineAssemblyRequest request{};
        request.architecture = golden.architecture;
        request.format = golden.format;
        request.triple = golden.triple;
        request.assembly = golden.assembly;
        request.syntax = golden.syntax;
        request.expectedInstructionCount = 2U;
        const auto first = backend.value()->codegen()->emit(request);
        const auto second = backend.value()->codegen()->emit(request);
        REQUIRE(first.has_value());
        REQUIRE(second.has_value());
        REQUIRE_EQ(first.value().bytes, second.value().bytes);
        REQUIRE_EQ(first.value().fixups, second.value().fixups);

        std::size_t offset = 0U;
        std::size_t instructionCount = 0U;
        while (offset < first.value().bytes.size()) {
            const auto remaining = std::span<const std::byte>{first.value().bytes}.subspan(offset);
            const auto decoded = backend.value()->decode(DecodeRequest{
                .architecture = golden.architecture,
                .bytes = remaining,
                .address = {0x1000U + offset, AddressKind::Virtual},
                .instructionId = EntityId{instructionCount + 1U},
                .sectionId = EntityId{1U},
                .sectionOffset = offset,
            });
            REQUIRE(decoded.has_value());
            REQUIRE(!decoded.value().encoding.empty());
            offset += decoded.value().encoding.size();
            ++instructionCount;
        }
        REQUIRE_EQ(instructionCount, std::size_t{2});
    }
}

TEST_CASE(arm64_decoder_distinguishes_conditional_b_and_exposes_nzcv_reads) {
    auto backend = binobf::make_architecture_backend(binobf::Architecture::ARM64);
    REQUIRE(backend.has_value());
    const std::array encoded{
        std::byte{0x01}, std::byte{0x08}, std::byte{0x00}, std::byte{0x54}};
    const auto decoded = backend.value()->decode(binobf::DecodeRequest{
        .architecture = binobf::Architecture::ARM64,
        .bytes = encoded,
        .address = {0x1000, binobf::AddressKind::Virtual},
        .instructionId = binobf::EntityId{1},
        .sectionId = binobf::EntityId{2},
    });
    REQUIRE(decoded.has_value());
    REQUIRE_EQ(decoded.value().kind, binobf::InstructionKind::ConditionalBranch);
    REQUIRE_EQ(decoded.value().directTarget->value, UINT64_C(0x1100));
    REQUIRE(std::ranges::find(decoded.value().registersRead, "nzcv",
                              &binobf::RegisterAccess::name)
            != decoded.value().registersRead.end());
}

int main() {
    return binobf::test::run_all();
}

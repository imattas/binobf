#include <binobf/architecture/codegen.hpp>
#include <binobf/architecture/backend.hpp>

#include "../test_support.hpp"

#include <array>
#include <cstddef>
#include <span>
#include <string>
#include <vector>

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

TEST_CASE(codegen_provider_rejects_empty_and_mismatched_requests) {
    auto provider = binobf::make_codegen_provider(binobf::Architecture::X86_64);
    REQUIRE(provider.has_value());
    binobf::MachineAssemblyRequest emptyRequest{};
    emptyRequest.architecture = binobf::Architecture::X86_64;
    emptyRequest.format = binobf::BinaryFormat::COFF;
    emptyRequest.triple = "x86_64-pc-windows-msvc";
    const auto empty = provider.value()->emit(emptyRequest);
    REQUIRE(!empty.has_value());
    REQUIRE_EQ(empty.error().code, "codegen.empty_input");
    binobf::MachineAssemblyRequest mismatchedRequest{};
    mismatchedRequest.architecture = binobf::Architecture::ARM64;
    mismatchedRequest.format = binobf::BinaryFormat::COFF;
    mismatchedRequest.triple = "aarch64-pc-windows-msvc";
    mismatchedRequest.assembly = "ret";
    const auto mismatch = provider.value()->emit(mismatchedRequest);
    REQUIRE(!mismatch.has_value());
    REQUIRE_EQ(mismatch.error().code, "codegen.request_mismatch");
}

TEST_CASE(codegen_provider_validates_format_triple_and_resource_limits) {
    auto provider = binobf::make_codegen_provider(binobf::Architecture::X86_64);
    REQUIRE(provider.has_value());

    binobf::MachineAssemblyRequest request{};
    request.architecture = binobf::Architecture::X86_64;
    request.format = binobf::BinaryFormat::COFF;
    request.triple = "x86_64-pc-windows-msvc";
    request.assembly = "nop";
    const auto validEmission = provider.value()->emit(request);
    REQUIRE(validEmission.has_value());
    REQUIRE_EQ(validEmission.value().bytes, std::vector<std::byte>{std::byte{0x90}});

    request.format = binobf::BinaryFormat::PE;
    const auto unsupportedFormat = provider.value()->emit(request);
    REQUIRE(!unsupportedFormat.has_value());
    REQUIRE_EQ(unsupportedFormat.error().code, "codegen.unsupported_format");

    request.format = binobf::BinaryFormat::COFF;
    request.triple = "aarch64-pc-windows-msvc";
    const auto unsupportedTriple = provider.value()->emit(request);
    REQUIRE(!unsupportedTriple.has_value());
    REQUIRE_EQ(unsupportedTriple.error().code, "codegen.unsupported_triple");

    request.triple = "x86_64-pc-windows-msvc";
    request.limits.maxAssemblyBytes = (1U << 20U) + 1U;
    const auto excessiveLimit = provider.value()->emit(request);
    REQUIRE(!excessiveLimit.has_value());
    REQUIRE_EQ(excessiveLimit.error().code, "codegen.resource_limit");
}

TEST_CASE(codegen_provider_rejects_directives_malformed_input_and_decode_mismatches) {
    auto provider = binobf::make_codegen_provider(binobf::Architecture::X86_64);
    REQUIRE(provider.has_value());
    binobf::MachineAssemblyRequest request{};
    request.architecture = binobf::Architecture::X86_64;
    request.format = binobf::BinaryFormat::ELF;
    request.triple = "x86_64-unknown-linux-gnu";

    request.assembly = ".section .unbounded\nnop\n";
    const auto section = provider.value()->emit(request);
    REQUIRE(!section.has_value());
    REQUIRE_EQ(section.error().code, "codegen.directive_rejected");

    request.assembly = "#INCLUDE \"outside.s\"\n";
    const auto include = provider.value()->emit(request);
    REQUIRE(!include.has_value());
    REQUIRE_EQ(include.error().code, "codegen.directive_rejected");

    request.assembly = "definitely_not_an_instruction eax, ebx\n";
    const auto malformed = provider.value()->emit(request);
    REQUIRE(!malformed.has_value());
    REQUIRE_EQ(malformed.error().code, "codegen.assembly_failed");

    request.assembly = "nop\nret\n";
    request.expectedInstructionCount = 1U;
    const auto countMismatch = provider.value()->emit(request);
    REQUIRE(!countMismatch.has_value());
    REQUIRE_EQ(countMismatch.error().code, "codegen.verification_failed");
}

TEST_CASE(codegen_provider_emits_deterministic_verified_machine_code) {
    struct Golden {
        binobf::Architecture architecture;
        binobf::BinaryFormat format;
        std::string triple;
        binobf::MachineSyntax syntax;
        std::string assembly;
        std::vector<std::byte> bytes;
    };
    const std::array<Golden, 3> goldens{
        Golden{
            binobf::Architecture::X86,
            binobf::BinaryFormat::COFF,
            "i686-pc-windows-msvc",
            binobf::MachineSyntax::Intel,
            "nop\nret\n",
            {std::byte{0x90}, std::byte{0xc3}},
        },
        Golden{
            binobf::Architecture::X86_64,
            binobf::BinaryFormat::ELF,
            "x86_64-unknown-linux-gnu",
            binobf::MachineSyntax::Intel,
            "nop\nret\n",
            {std::byte{0x90}, std::byte{0xc3}},
        },
        Golden{
            binobf::Architecture::ARM64,
            binobf::BinaryFormat::ELF,
            "aarch64-unknown-linux-gnu",
            binobf::MachineSyntax::GNU,
            "nop\nret\n",
            {
                std::byte{0x1f}, std::byte{0x20}, std::byte{0x03}, std::byte{0xd5},
                std::byte{0xc0}, std::byte{0x03}, std::byte{0x5f}, std::byte{0xd6},
            },
        },
    };

    for (const auto& golden : goldens) {
        auto provider = binobf::make_codegen_provider(golden.architecture);
        REQUIRE(provider.has_value());
        binobf::MachineAssemblyRequest request{};
        request.architecture = golden.architecture;
        request.format = golden.format;
        request.triple = golden.triple;
        request.syntax = golden.syntax;
        request.assembly = golden.assembly;
        request.expectedInstructionCount = 2U;

        const auto first = provider.value()->emit(request);
        REQUIRE(first.has_value());
        REQUIRE_EQ(first.value().bytes, golden.bytes);
        REQUIRE(first.value().fixups.empty());
        REQUIRE_EQ(first.value().provider, "LLVM 22.1.8");

        const auto repeated = provider.value()->emit(request);
        REQUIRE(repeated.has_value());
        REQUIRE_EQ(repeated.value().bytes, first.value().bytes);
        REQUIRE_EQ(repeated.value().fixups, first.value().fixups);

        auto backend = binobf::make_architecture_backend(golden.architecture);
        REQUIRE(backend.has_value());
        std::size_t offset = 0U;
        std::uint64_t instructionId = 1U;
        while (offset < first.value().bytes.size()) {
            const auto remaining = std::span<const std::byte>{first.value().bytes}.subspan(offset);
            const auto decoded = backend.value()->decode(binobf::DecodeRequest{
                .architecture = golden.architecture,
                .bytes = remaining,
                .address = {offset, binobf::AddressKind::Virtual},
                .instructionId = binobf::EntityId{instructionId},
                .sectionId = binobf::EntityId{1U},
                .sectionOffset = offset,
            });
            REQUIRE(decoded.has_value());
            REQUIRE(!decoded.value().encoding.empty());
            offset += decoded.value().encoding.size();
            ++instructionId;
        }
        REQUIRE_EQ(offset, first.value().bytes.size());
        REQUIRE_EQ(instructionId, 3U);
    }
}

int main() {
    return binobf::test::run_all();
}

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
    const auto validShell = provider.value()->emit(request);
    REQUIRE(!validShell.has_value());
    REQUIRE_EQ(validShell.error().code, "codegen.not_implemented");

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

int main() {
    return binobf::test::run_all();
}

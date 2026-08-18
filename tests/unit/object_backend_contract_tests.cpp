#include <binobf/architecture/backend.hpp>
#include <binobf/architecture/object_backend.hpp>

#include "../test_support.hpp"

#include <algorithm>
#include <array>
#include <cstddef>

TEST_CASE(x86_backend_emits_an_exact_bounded_dead_code_fill) {
    auto backend = binobf::make_architecture_backend(binobf::Architecture::X86);
    REQUIRE(backend.has_value());

    binobf::MachineTransformRequest request{};
    request.architecture = binobf::Architecture::X86;
    request.format = binobf::BinaryFormat::COFF;
    request.kind = binobf::MachineTransformKind::DeadCodeFill;
    request.exactSize = 3;
    const auto emitted = backend.value()->emit_transform(request);

    REQUIRE(emitted.has_value());
    REQUIRE_EQ(emitted.value().emission.bytes.size(), std::size_t{3});
    REQUIRE_EQ(emitted.value().instructionCount, std::size_t{3});
    REQUIRE_EQ(emitted.value().controlFlow, binobf::MachineControlFlow::Fallthrough);
    REQUIRE_EQ(emitted.value().stackDelta, std::int64_t{0});
}

TEST_CASE(fixed_backend_rejects_a_transform_for_another_architecture) {
    auto backend = binobf::make_architecture_backend(binobf::Architecture::X86);
    REQUIRE(backend.has_value());

    binobf::MachineTransformRequest request{};
    request.architecture = binobf::Architecture::ARM64;
    request.format = binobf::BinaryFormat::COFF;
    request.kind = binobf::MachineTransformKind::DeadCodeFill;
    request.exactSize = 1;
    const auto emitted = backend.value()->emit_transform(request);

    REQUIRE(!emitted.has_value());
    REQUIRE_EQ(emitted.error().code, "architecture.request_mismatch");
}

TEST_CASE(unimplemented_callable_services_fail_with_stable_diagnostics) {
    auto backend = binobf::make_architecture_backend(binobf::Architecture::X86);
    REQUIRE(backend.has_value());

    const auto fixup = backend.value()->fixup_semantics(binobf::BinaryFormat::COFF, 0xffffU);
    REQUIRE(!fixup.has_value());
    REQUIRE_EQ(fixup.error().code, "architecture.service_unsupported");

    binobf::AbiAdapterRequest abi{};
    abi.architecture = binobf::Architecture::X86;
    abi.format = binobf::BinaryFormat::COFF;
    abi.symbol = "external";
    const auto adapter = backend.value()->build_abi_adapter(abi);
    REQUIRE(!adapter.has_value());
    REQUIRE_EQ(adapter.error().code, "architecture.service_unsupported");

    binobf::UnwindRequest unwind{};
    unwind.architecture = binobf::Architecture::X86;
    unwind.format = binobf::BinaryFormat::COFF;
    unwind.codeSize = 1;
    const auto plan = backend.value()->build_unwind(unwind);
    REQUIRE(!plan.has_value());
    REQUIRE_EQ(plan.error().code, "architecture.service_unsupported");
}

TEST_CASE(fixup_encoding_rejects_a_zero_width_before_dispatch) {
    auto backend = binobf::make_architecture_backend(binobf::Architecture::X86);
    REQUIRE(backend.has_value());

    binobf::ObjectFixupSemantics semantics{};
    semantics.bitWidth = 0;
    const auto encoded = backend.value()->encode_fixup(semantics, 0);

    REQUIRE(!encoded.has_value());
    REQUIRE_EQ(encoded.error().code, "architecture.invalid_fixup");
}

TEST_CASE(backend_service_records_are_unique_sorted_and_evidence_bound) {
    for (const auto architecture : std::array{
             binobf::Architecture::X86,
             binobf::Architecture::X86_64,
             binobf::Architecture::ARM64}) {
        auto backend = binobf::make_architecture_backend(architecture);
        REQUIRE(backend.has_value());
        const auto services = backend.value()->services();
        REQUIRE(std::ranges::is_sorted(services, {}, &binobf::BackendServiceRecord::service));
        REQUIRE(std::adjacent_find(
                    services.begin(), services.end(),
                    [](const auto& left, const auto& right) {
                        return left.service == right.service;
                    }) == services.end());
        for (const auto& service : services) {
            if (service.support == binobf::SupportLevel::Supported) {
                REQUIRE(!service.evidence.empty());
            }
        }
    }
}

int main() {
    return binobf::test::run_all();
}

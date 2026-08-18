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

TEST_CASE(codegen_provider_normalizes_external_call_fixups) {
    struct CallCase {
        binobf::Architecture architecture;
        binobf::BinaryFormat format;
        std::string triple;
        binobf::MachineSyntax syntax;
        std::string assembly;
        std::uint64_t offset;
        std::uint8_t bitWidth;
        std::int64_t addend;
        binobf::MachineFixupKind kind;
    };
    const std::array<CallCase, 6> cases{
        CallCase{binobf::Architecture::X86, binobf::BinaryFormat::COFF,
                 "i686-pc-windows-msvc", binobf::MachineSyntax::Intel,
                 "call external_symbol\n", 1U, 32U, -4,
                 binobf::MachineFixupKind::PcRelative32},
        CallCase{binobf::Architecture::X86_64, binobf::BinaryFormat::COFF,
                 "x86_64-pc-windows-msvc", binobf::MachineSyntax::Intel,
                 "call external_symbol\n", 1U, 32U, -4,
                 binobf::MachineFixupKind::PcRelative32},
        CallCase{binobf::Architecture::X86, binobf::BinaryFormat::ELF,
                 "i686-unknown-linux-gnu", binobf::MachineSyntax::Intel,
                 "call external_symbol\n", 1U, 32U, -4,
                 binobf::MachineFixupKind::PcRelative32},
        CallCase{binobf::Architecture::X86_64, binobf::BinaryFormat::ELF,
                 "x86_64-unknown-linux-gnu", binobf::MachineSyntax::Intel,
                 "call external_symbol\n", 1U, 32U, -4,
                 binobf::MachineFixupKind::PltRelative32},
        CallCase{binobf::Architecture::ARM64, binobf::BinaryFormat::COFF,
                 "aarch64-pc-windows-msvc", binobf::MachineSyntax::GNU,
                 "bl external_symbol\n", 0U, 26U, 0,
                 binobf::MachineFixupKind::AArch64Call26},
        CallCase{binobf::Architecture::ARM64, binobf::BinaryFormat::ELF,
                 "aarch64-unknown-linux-gnu", binobf::MachineSyntax::GNU,
                 "bl external_symbol\n", 0U, 26U, 0,
                 binobf::MachineFixupKind::AArch64Call26},
    };

    for (const auto& item : cases) {
        auto provider = binobf::make_codegen_provider(item.architecture);
        REQUIRE(provider.has_value());
        binobf::MachineAssemblyRequest request{};
        request.architecture = item.architecture;
        request.format = item.format;
        request.triple = item.triple;
        request.syntax = item.syntax;
        request.assembly = item.assembly;
        request.expectedInstructionCount = 1U;
        const auto emission = provider.value()->emit(request);
        REQUIRE(emission.has_value());
        REQUIRE_EQ(emission.value().fixups.size(), 1U);
        const auto& fixup = emission.value().fixups.front();
        REQUIRE_EQ(fixup.offset, item.offset);
        REQUIRE_EQ(fixup.bitWidth, item.bitWidth);
        REQUIRE(fixup.isSigned);
        REQUIRE(fixup.pcRelative);
        REQUIRE_EQ(fixup.addend, item.addend);
        REQUIRE_EQ(fixup.symbol, "external_symbol");
        if (fixup.kind != item.kind) {
            binobf::test::fail(
                "fixup.kind == item.kind",
                __FILE__,
                __LINE__,
                std::string{binobf::to_string(item.architecture)} + "/" +
                    std::string{binobf::to_string(item.format)} +
                    " actual=" +
                    std::to_string(static_cast<unsigned int>(fixup.kind)) +
                    " expected=" +
                    std::to_string(static_cast<unsigned int>(item.kind)));
        }
        if (item.architecture == binobf::Architecture::X86) {
            auto backend = binobf::make_architecture_backend(binobf::Architecture::X86);
            REQUIRE(backend.has_value());
            const auto rawType = item.format == binobf::BinaryFormat::COFF
                ? UINT64_C(0x14)
                : UINT64_C(2);
            const auto semantics = backend.value()->fixup_semantics(item.format, rawType);
            REQUIRE(semantics.has_value());
            const auto encoded = backend.value()->encode_fixup(
                semantics.value(), fixup.addend);
            REQUIRE(encoded.has_value());
            const auto begin = emission.value().bytes.begin()
                + static_cast<std::ptrdiff_t>(fixup.offset);
            const std::vector<std::byte> field(
                begin, begin + static_cast<std::ptrdiff_t>(encoded.value().fieldBytes.size()));
            REQUIRE_EQ(field, encoded.value().fieldBytes);
        }
        const auto repeated = provider.value()->emit(request);
        REQUIRE(repeated.has_value());
        REQUIRE_EQ(repeated.value().fixups, emission.value().fixups);
    }
}

TEST_CASE(codegen_provider_normalizes_absolute_got_plt_and_page_fixups) {
    auto x64 = binobf::make_codegen_provider(binobf::Architecture::X86_64);
    REQUIRE(x64.has_value());
    binobf::MachineAssemblyRequest request{};
    request.architecture = binobf::Architecture::X86_64;
    request.format = binobf::BinaryFormat::ELF;
    request.triple = "x86_64-unknown-linux-gnu";
    request.syntax = binobf::MachineSyntax::Intel;

    request.assembly = ".quad external_symbol\n";
    const auto absolute = x64.value()->emit(request);
    REQUIRE(absolute.has_value());
    REQUIRE_EQ(absolute.value().fixups.size(), 1U);
    REQUIRE_EQ(absolute.value().fixups.front().offset, 0U);
    REQUIRE_EQ(absolute.value().fixups.front().bitWidth, 64U);
    REQUIRE(!absolute.value().fixups.front().isSigned);
    REQUIRE(!absolute.value().fixups.front().pcRelative);
    REQUIRE_EQ(absolute.value().fixups.front().addend, 0);
    REQUIRE_EQ(absolute.value().fixups.front().symbol, "external_symbol");
    REQUIRE_EQ(absolute.value().fixups.front().kind,
               binobf::MachineFixupKind::Absolute64);
    const auto absoluteRepeated = x64.value()->emit(request);
    REQUIRE(absoluteRepeated.has_value());
    REQUIRE_EQ(absoluteRepeated.value().fixups, absolute.value().fixups);

    request.assembly = "mov rax, qword ptr [rip + external_symbol@GOTPCREL]\n";
    request.expectedInstructionCount = 1U;
    const auto got = x64.value()->emit(request);
    REQUIRE(got.has_value());
    REQUIRE_EQ(got.value().fixups.size(), 1U);
    REQUIRE_EQ(got.value().fixups.front().offset, 3U);
    REQUIRE_EQ(got.value().fixups.front().bitWidth, 32U);
    REQUIRE(got.value().fixups.front().isSigned);
    REQUIRE(got.value().fixups.front().pcRelative);
    REQUIRE_EQ(got.value().fixups.front().addend, -4);
    REQUIRE_EQ(got.value().fixups.front().kind,
               binobf::MachineFixupKind::GotRelative32);
    const auto gotRepeated = x64.value()->emit(request);
    REQUIRE(gotRepeated.has_value());
    REQUIRE_EQ(gotRepeated.value().fixups, got.value().fixups);

    request.assembly = "call external_symbol@PLT\n";
    const auto plt = x64.value()->emit(request);
    REQUIRE(plt.has_value());
    REQUIRE_EQ(plt.value().fixups.size(), 1U);
    REQUIRE_EQ(plt.value().fixups.front().offset, 1U);
    REQUIRE_EQ(plt.value().fixups.front().addend, -4);
    REQUIRE_EQ(plt.value().fixups.front().kind,
               binobf::MachineFixupKind::PltRelative32);
    const auto pltRepeated = x64.value()->emit(request);
    REQUIRE(pltRepeated.has_value());
    REQUIRE_EQ(pltRepeated.value().fixups, plt.value().fixups);

    auto arm64 = binobf::make_codegen_provider(binobf::Architecture::ARM64);
    REQUIRE(arm64.has_value());
    request = {};
    request.architecture = binobf::Architecture::ARM64;
    request.format = binobf::BinaryFormat::ELF;
    request.triple = "aarch64-unknown-linux-gnu";
    request.syntax = binobf::MachineSyntax::GNU;
    request.assembly =
        "adrp x0, external_symbol\n"
        "add x0, x0, :lo12:external_symbol\n";
    request.expectedInstructionCount = 2U;
    const auto page = arm64.value()->emit(request);
    REQUIRE(page.has_value());
    REQUIRE_EQ(page.value().fixups.size(), 2U);
    REQUIRE_EQ(page.value().fixups[0].offset, 0U);
    REQUIRE_EQ(page.value().fixups[0].bitWidth, 21U);
    REQUIRE(page.value().fixups[0].isSigned);
    REQUIRE(page.value().fixups[0].pcRelative);
    REQUIRE_EQ(page.value().fixups[0].kind,
               binobf::MachineFixupKind::AArch64Page21);
    REQUIRE_EQ(page.value().fixups[1].offset, 4U);
    REQUIRE_EQ(page.value().fixups[1].bitWidth, 12U);
    REQUIRE(!page.value().fixups[1].isSigned);
    REQUIRE(!page.value().fixups[1].pcRelative);
    REQUIRE_EQ(page.value().fixups[1].kind,
               binobf::MachineFixupKind::AArch64PageOffset12);
    REQUIRE_EQ(page.value().fixups[0].symbol, "external_symbol");
    REQUIRE_EQ(page.value().fixups[1].symbol, "external_symbol");
    const auto pageRepeated = arm64.value()->emit(request);
    REQUIRE(pageRepeated.has_value());
    REQUIRE_EQ(pageRepeated.value().fixups, page.value().fixups);
}

TEST_CASE(codegen_provider_rejects_unsupported_and_excessive_fixups) {
    auto provider = binobf::make_codegen_provider(binobf::Architecture::X86_64);
    REQUIRE(provider.has_value());
    binobf::MachineAssemblyRequest request{};
    request.architecture = binobf::Architecture::X86_64;
    request.format = binobf::BinaryFormat::ELF;
    request.triple = "x86_64-unknown-linux-gnu";
    request.syntax = binobf::MachineSyntax::Intel;
    request.assembly = ".long external_symbol@SIZE\n";
    const auto unsupported = provider.value()->emit(request);
    REQUIRE(!unsupported.has_value());
    REQUIRE_EQ(unsupported.error().code, "codegen.unsupported_fixup");

    request.assembly = ".quad first_symbol\n.quad second_symbol\n";
    request.limits.maxFixups = 1U;
    const auto excessive = provider.value()->emit(request);
    REQUIRE(!excessive.has_value());
    REQUIRE_EQ(excessive.error().code, "codegen.resource_limit");
}

TEST_CASE(codegen_provider_rejects_unaligned_arm64_machine_code_bases) {
    auto provider = binobf::make_codegen_provider(binobf::Architecture::ARM64);
    REQUIRE(provider.has_value());
    binobf::MachineAssemblyRequest request{};
    request.architecture = binobf::Architecture::ARM64;
    request.format = binobf::BinaryFormat::ELF;
    request.triple = "aarch64-unknown-linux-gnu";
    request.syntax = binobf::MachineSyntax::GNU;
    request.baseAddress = {2U, binobf::AddressKind::Virtual};
    request.assembly = "nop\n";
    const auto result = provider.value()->emit(request);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "codegen.invalid_alignment");
}

TEST_CASE(codegen_provider_enforces_unique_symbols_before_and_after_assembly) {
    auto provider = binobf::make_codegen_provider(binobf::Architecture::X86_64);
    REQUIRE(provider.has_value());
    binobf::MachineAssemblyRequest request{};
    request.architecture = binobf::Architecture::X86_64;
    request.format = binobf::BinaryFormat::ELF;
    request.triple = "x86_64-unknown-linux-gnu";
    request.syntax = binobf::MachineSyntax::Intel;
    request.limits.maxSymbols = 1U;

    request.assembly = ".globl one\none :\nnop\n";
    const auto oneSymbol = provider.value()->emit(request);
    REQUIRE(oneSymbol.has_value());

    request.assembly = ".globl one, two\none :\nnop\ntwo :\nret\n";
    const auto spacedLabels = provider.value()->emit(request);
    REQUIRE(!spacedLabels.has_value());
    REQUIRE_EQ(spacedLabels.error().code, "codegen.resource_limit");

    request.assembly = "call external_one\ncall external_two\n";
    const auto implicitExternals = provider.value()->emit(request);
    REQUIRE(!implicitExternals.has_value());
    REQUIRE_EQ(implicitExternals.error().code, "codegen.resource_limit");
}

TEST_CASE(codegen_provider_preserves_i386_got_relocation_semantics_and_addends) {
    auto provider = binobf::make_codegen_provider(binobf::Architecture::X86);
    REQUIRE(provider.has_value());
    binobf::MachineAssemblyRequest request{};
    request.architecture = binobf::Architecture::X86;
    request.format = binobf::BinaryFormat::ELF;
    request.triple = "i686-unknown-linux-gnu";
    request.syntax = binobf::MachineSyntax::Intel;

    request.assembly = "mov eax, dword ptr [external_symbol@GOT + 7]\n";
    const auto got = provider.value()->emit(request);
    if (!got.has_value()) {
        binobf::test::fail(got.error().message, __FILE__, __LINE__);
    }
    REQUIRE_EQ(got.value().fixups.size(), 1U);
    REQUIRE_EQ(got.value().fixups.front().kind,
               binobf::MachineFixupKind::GotRelative32);
    REQUIRE(!got.value().fixups.front().pcRelative);
    REQUIRE_EQ(got.value().fixups.front().addend, 7);
    auto backend = binobf::make_architecture_backend(binobf::Architecture::X86);
    REQUIRE(backend.has_value());
    const auto gotSemantics = backend.value()->fixup_semantics(
        binobf::BinaryFormat::ELF, 3U);
    REQUIRE(gotSemantics.has_value());
    const auto gotField = backend.value()->encode_fixup(
        gotSemantics.value(), got.value().fixups.front().addend);
    REQUIRE(gotField.has_value());
    const auto gotOffset = static_cast<std::size_t>(got.value().fixups.front().offset);
    REQUIRE_EQ(std::vector<std::byte>(
                   got.value().bytes.begin() + static_cast<std::ptrdiff_t>(gotOffset),
                   got.value().bytes.begin() + static_cast<std::ptrdiff_t>(gotOffset + 4U)),
               gotField.value().fieldBytes);

    request.assembly = "lea eax, [_GLOBAL_OFFSET_TABLE_ + 11]\n";
    const auto gotPc = provider.value()->emit(request);
    if (!gotPc.has_value()) {
        binobf::test::fail(gotPc.error().message, __FILE__, __LINE__);
    }
    REQUIRE_EQ(gotPc.value().fixups.size(), 1U);
    REQUIRE_EQ(gotPc.value().fixups.front().kind,
               binobf::MachineFixupKind::GotPcRelative32);
    REQUIRE(gotPc.value().fixups.front().pcRelative);
    REQUIRE_EQ(gotPc.value().fixups.front().addend, 13);
    const auto gotPcSemantics = backend.value()->fixup_semantics(
        binobf::BinaryFormat::ELF, 10U);
    REQUIRE(gotPcSemantics.has_value());
    const auto gotPcField = backend.value()->encode_fixup(
        gotPcSemantics.value(), gotPc.value().fixups.front().addend);
    REQUIRE(gotPcField.has_value());
    const auto gotPcOffset = static_cast<std::size_t>(gotPc.value().fixups.front().offset);
    REQUIRE_EQ(std::vector<std::byte>(
                   gotPc.value().bytes.begin() + static_cast<std::ptrdiff_t>(gotPcOffset),
                   gotPc.value().bytes.begin()
                       + static_cast<std::ptrdiff_t>(gotPcOffset + 4U)),
               gotPcField.value().fieldBytes);
}

int main() {
    return binobf::test::run_all();
}

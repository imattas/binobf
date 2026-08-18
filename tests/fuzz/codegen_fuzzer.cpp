#include <binobf/architecture/codegen.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

namespace {

struct Target {
    binobf::Architecture architecture;
    binobf::BinaryFormat format;
    std::string_view triple;
    binobf::MachineSyntax syntax;
};

constexpr std::array kTargets{
    Target{binobf::Architecture::X86, binobf::BinaryFormat::COFF,
           "i686-pc-windows-msvc", binobf::MachineSyntax::Intel},
    Target{binobf::Architecture::X86, binobf::BinaryFormat::ELF,
           "i686-unknown-linux-gnu", binobf::MachineSyntax::Intel},
    Target{binobf::Architecture::X86_64, binobf::BinaryFormat::COFF,
           "x86_64-pc-windows-msvc", binobf::MachineSyntax::Intel},
    Target{binobf::Architecture::X86_64, binobf::BinaryFormat::ELF,
           "x86_64-unknown-linux-gnu", binobf::MachineSyntax::Intel},
    Target{binobf::Architecture::ARM64, binobf::BinaryFormat::COFF,
           "aarch64-pc-windows-msvc", binobf::MachineSyntax::GNU},
    Target{binobf::Architecture::ARM64, binobf::BinaryFormat::ELF,
           "aarch64-unknown-linux-gnu", binobf::MachineSyntax::GNU},
};

[[noreturn]] void determinism_failure() {
    std::abort();
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0U) return 0;
    const auto& target = kTargets[data[0] % kTargets.size()];
    constexpr std::array x86Tokens{
        std::string_view{"nop\n"},
        std::string_view{"ret\n"},
        std::string_view{"int3\n"},
        std::string_view{".byte 0x90\n"},
        std::string_view{".p2align 1\n"},
    };
    constexpr std::array armTokens{
        std::string_view{"nop\n"},
        std::string_view{"ret\n"},
        std::string_view{"brk #0\n"},
        std::string_view{".long 0xd503201f\n"},
        std::string_view{".p2align 2\n"},
    };
    std::string assembly{".text\n"};
    assembly.reserve(65536U);
    for (std::size_t index = 1U; index < size && assembly.size() < 65500U; ++index) {
        const auto token = target.architecture == binobf::Architecture::ARM64
            ? armTokens[data[index] % armTokens.size()]
            : x86Tokens[data[index] % x86Tokens.size()];
        if (token.size() > 65536U - assembly.size()) break;
        assembly.append(token);
    }
    if (assembly == ".text\n") assembly.append("nop\n");

    auto provider = binobf::make_codegen_provider(target.architecture);
    if (!provider.has_value()) determinism_failure();
    binobf::MachineAssemblyRequest request{};
    request.architecture = target.architecture;
    request.format = target.format;
    request.triple = target.triple;
    request.assembly = std::move(assembly);
    request.syntax = target.syntax;
    request.limits.maxAssemblyBytes = 65536U;
    request.limits.maxLines = 4096U;
    request.limits.maxSymbols = 1024U;
    request.limits.maxEmittedBytes = 262144U;
    request.limits.maxFixups = 4096U;
    request.limits.maxInstructions = 8192U;

    const auto first = provider.value()->emit(request);
    const auto second = provider.value()->emit(request);
    if (first.has_value() != second.has_value()) determinism_failure();
    if (first.has_value()) {
        if (first.value().bytes != second.value().bytes ||
            first.value().fixups != second.value().fixups ||
            first.value().alignment != second.value().alignment ||
            first.value().provider != second.value().provider) {
            determinism_failure();
        }
    } else if (first.error().code != second.error().code ||
               first.error().message != second.error().message) {
        determinism_failure();
    }
    return 0;
}

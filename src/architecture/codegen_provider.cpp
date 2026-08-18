#include <binobf/architecture/codegen.hpp>

#include "llvm_mc_assembler.hpp"

#include <llvm/Support/TargetSelect.h>

#include <algorithm>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

namespace binobf {
namespace {

[[nodiscard]] auto failure(std::string code, std::string message)
    -> Result<MachineEmission, Diagnostic> {
    return Result<MachineEmission, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error,
        std::move(code),
        std::move(message),
    });
}

void initialize_llvm_mc_targets() {
    static std::once_flag initialized;
    std::call_once(initialized, [] {
        LLVMInitializeX86TargetInfo();
        LLVMInitializeX86TargetMC();
        LLVMInitializeX86AsmParser();
        LLVMInitializeAArch64TargetInfo();
        LLVMInitializeAArch64TargetMC();
        LLVMInitializeAArch64AsmParser();
    });
}

[[nodiscard]] auto triple_matches_architecture(
    std::string_view triple,
    Architecture architecture) noexcept -> bool {
    const auto separator = triple.find('-');
    const auto machine = triple.substr(0, separator);
    switch (architecture) {
    case Architecture::X86:
        return machine == "i386" || machine == "i486" || machine == "i586" ||
               machine == "i686" || machine == "x86";
    case Architecture::X86_64:
        return machine == "x86_64" || machine == "amd64";
    case Architecture::ARM64:
        return machine == "aarch64" || machine == "arm64";
    case Architecture::Unknown:
        return false;
    }
    return false;
}

[[nodiscard]] auto triple_matches_format(
    std::string_view triple,
    BinaryFormat format) noexcept -> bool {
    switch (format) {
    case BinaryFormat::COFF:
        return triple.find("windows") != std::string_view::npos ||
               triple.find("win32") != std::string_view::npos;
    case BinaryFormat::ELF:
        return triple.find("linux") != std::string_view::npos ||
               triple.find("elf") != std::string_view::npos ||
               triple.find("none") != std::string_view::npos;
    case BinaryFormat::PE:
    case BinaryFormat::Archive:
    case BinaryFormat::Unknown:
        return false;
    }
    return false;
}

[[nodiscard]] auto limits_are_valid(const MachineCodeLimits& limits) noexcept -> bool {
    constexpr MachineCodeLimits ceilings{};
    return limits.maxAssemblyBytes > 0U &&
           limits.maxAssemblyBytes <= ceilings.maxAssemblyBytes &&
           limits.maxLines > 0U && limits.maxLines <= ceilings.maxLines &&
           limits.maxSymbols > 0U && limits.maxSymbols <= ceilings.maxSymbols &&
           limits.maxEmittedBytes > 0U &&
           limits.maxEmittedBytes <= ceilings.maxEmittedBytes &&
           limits.maxFixups > 0U && limits.maxFixups <= ceilings.maxFixups &&
           limits.maxInstructions > 0U &&
           limits.maxInstructions <= ceilings.maxInstructions;
}

class LlvmMcCodegenProvider final : public CodegenProvider {
public:
    explicit LlvmMcCodegenProvider(Architecture architecture) noexcept
        : architecture_(architecture) {
        initialize_llvm_mc_targets();
    }

    auto architecture() const noexcept -> Architecture override {
        return architecture_;
    }

    auto provider_version() const noexcept -> std::string_view override {
        return "LLVM 22.1.8";
    }

    auto emit(const MachineAssemblyRequest& request) const
        -> Result<MachineEmission, Diagnostic> override {
        if (request.architecture != architecture_) {
            return failure(
                "codegen.request_mismatch",
                "the assembly request architecture does not match its fixed provider");
        }
        if (request.assembly.empty()) {
            return failure("codegen.empty_input", "assembly input must not be empty");
        }
        if (request.format != BinaryFormat::COFF && request.format != BinaryFormat::ELF) {
            return failure(
                "codegen.unsupported_format",
                "LLVM MC emission supports only COFF and ELF object formats");
        }
        if (request.triple.empty() ||
            !triple_matches_architecture(request.triple, architecture_) ||
            !triple_matches_format(request.triple, request.format)) {
            return failure(
                "codegen.unsupported_triple",
                "the target triple does not match the requested architecture and object format");
        }
        if (architecture_ == Architecture::ARM64
            && (request.baseAddress.value & 3U) != 0U) {
            return failure(
                "codegen.invalid_alignment",
                "AArch64 machine-code base addresses must be four-byte aligned");
        }
        if (!limits_are_valid(request.limits) ||
            request.assembly.size() > request.limits.maxAssemblyBytes ||
            (request.expectedInstructionCount.has_value() &&
             request.expectedInstructionCount.value() > request.limits.maxInstructions)) {
            return failure(
                "codegen.resource_limit",
                "the request exceeds the configured machine-code resource limits");
        }
        const auto lineCount = static_cast<std::size_t>(
                                   std::count(
                                       request.assembly.begin(),
                                       request.assembly.end(),
                                       '\n')) +
                               1U;
        if (lineCount > request.limits.maxLines) {
            return failure(
                "codegen.resource_limit",
                "the assembly input exceeds the configured line limit");
        }
        return detail::assemble_with_llvm_mc(request);
    }

private:
    Architecture architecture_;
};

} // namespace

auto make_codegen_provider(Architecture architecture)
    -> Result<std::unique_ptr<CodegenProvider>, Diagnostic> {
    if (architecture == Architecture::Unknown) {
        return Result<std::unique_ptr<CodegenProvider>, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "codegen.unsupported_architecture",
            "cannot create a code-generation provider for an unknown architecture",
        });
    }
    std::unique_ptr<CodegenProvider> provider =
        std::make_unique<LlvmMcCodegenProvider>(architecture);
    return Result<std::unique_ptr<CodegenProvider>, Diagnostic>::success(
        std::move(provider));
}

} // namespace binobf

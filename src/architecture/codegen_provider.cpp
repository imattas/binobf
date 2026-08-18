#include <binobf/architecture/codegen.hpp>

#include <memory>
#include <string>
#include <utility>

namespace binobf {
namespace {

class ContractCodegenProvider final : public CodegenProvider {
public:
    explicit ContractCodegenProvider(Architecture architecture) noexcept
        : architecture_(architecture) {}

    auto architecture() const noexcept -> Architecture override {
        return architecture_;
    }

    auto provider_version() const noexcept -> std::string_view override {
        return "LLVM 22.1.8";
    }

    auto emit(const MachineAssemblyRequest&) const
        -> Result<MachineEmission, Diagnostic> override {
        return Result<MachineEmission, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "codegen.not_implemented",
            "machine-code emission is not available until the private provider is initialized",
        });
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
        std::make_unique<ContractCodegenProvider>(architecture);
    return Result<std::unique_ptr<CodegenProvider>, Diagnostic>::success(
        std::move(provider));
}

} // namespace binobf

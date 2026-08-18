#include <binobf/analysis/instruction_decoder.hpp>

#include <binobf/architecture/backend.hpp>

#include <memory>
#include <string>
#include <utility>

namespace binobf {
namespace {

auto failure(std::string code, std::string message) -> Result<Instruction, Diagnostic> {
    return Result<Instruction, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

class DispatchingInstructionDecoder final : public InstructionDecoder {
public:
    auto decode(const DecodeRequest& request) const
        -> Result<Instruction, Diagnostic> override {
        if (request.bytes.empty()) {
            return failure("analysis.empty_input", "instruction input is empty");
        }
        if (request.architecture == Architecture::Unknown) {
            return failure(
                "analysis.unsupported_architecture",
                "instruction architecture is unsupported");
        }
        auto backend = make_architecture_backend(request.architecture);
        if (!backend.has_value()) {
            return Result<Instruction, Diagnostic>::failure(
                std::move(backend).error());
        }
        return backend.value()->decode(request);
    }
};

} // namespace

auto make_instruction_decoder()
    -> Result<std::unique_ptr<InstructionDecoder>, Diagnostic> {
    return Result<std::unique_ptr<InstructionDecoder>, Diagnostic>::success(
        std::make_unique<DispatchingInstructionDecoder>());
}

} // namespace binobf

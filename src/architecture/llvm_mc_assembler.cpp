#include "llvm_mc_assembler.hpp"

#include <binobf/architecture/backend.hpp>

#include <llvm/ADT/SmallString.h>
#include <llvm/MC/MCAsmBackend.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCCodeEmitter.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCObjectWriter.h>
#include <llvm/MC/MCParser/MCAsmParser.h>
#include <llvm/MC/MCParser/MCTargetAsmParser.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCStreamer.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/TargetParser/Triple.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace binobf::detail {
namespace {

constexpr std::array<std::string_view, 10> kAllowedDirectives{
    ".text",
    ".intel_syntax",
    ".att_syntax",
    ".p2align",
    ".balign",
    ".byte",
    ".short",
    ".long",
    ".quad",
    ".globl",
};

[[nodiscard]] auto failure(std::string code, std::string message)
    -> Result<MachineEmission, Diagnostic> {
    return Result<MachineEmission, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error,
        std::move(code),
        std::move(message),
    });
}

[[nodiscard]] auto trim(std::string_view text) noexcept -> std::string_view {
    while (!text.empty() &&
           std::isspace(static_cast<unsigned char>(text.front())) != 0) {
        text.remove_prefix(1U);
    }
    while (!text.empty() &&
           std::isspace(static_cast<unsigned char>(text.back())) != 0) {
        text.remove_suffix(1U);
    }
    return text;
}

[[nodiscard]] auto lowercase(std::string_view text) -> std::string {
    std::string result;
    result.reserve(text.size());
    for (const char character : text) {
        result.push_back(static_cast<char>(
            std::tolower(static_cast<unsigned char>(character))));
    }
    return result;
}

[[nodiscard]] auto screen_statement(
    std::string_view statement,
    std::size_t& symbolCount,
    const MachineCodeLimits& limits) -> Result<bool, Diagnostic> {
    statement = trim(statement);
    const auto loweredStatement = lowercase(statement);
    const bool isInclude = loweredStatement == "#include" ||
        loweredStatement.starts_with("#include ") ||
        loweredStatement.starts_with("#include\t");
    if (statement.empty() || statement.starts_with("//") ||
        (statement.starts_with('#') && !isInclude)) {
        return Result<bool, Diagnostic>::success(true);
    }
    if (isInclude) {
        return Result<bool, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "codegen.directive_rejected",
            "source inclusion is not permitted in machine assembly requests",
        });
    }

    const auto colon = statement.find(':');
    const auto whitespace = statement.find_first_of(" \t");
    if (colon != std::string_view::npos &&
        (whitespace == std::string_view::npos || colon < whitespace)) {
        ++symbolCount;
        if (symbolCount > limits.maxSymbols) {
            return Result<bool, Diagnostic>::failure(Diagnostic{
                DiagnosticSeverity::Error,
                "codegen.resource_limit",
                "the assembly input exceeds the configured symbol limit",
            });
        }
        statement = trim(statement.substr(colon + 1U));
        if (statement.empty()) {
            return Result<bool, Diagnostic>::success(true);
        }
    }

    if (!statement.starts_with('.')) {
        return Result<bool, Diagnostic>::success(true);
    }
    const auto tokenEnd = statement.find_first_of(" \t,");
    const auto token = lowercase(statement.substr(0U, tokenEnd));
    const auto allowed = std::find(
        kAllowedDirectives.begin(), kAllowedDirectives.end(), token);
    if (allowed == kAllowedDirectives.end()) {
        return Result<bool, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "codegen.directive_rejected",
            "assembly directive '" + token + "' is outside the bounded allowlist",
        });
    }
    if (token == ".globl") {
        ++symbolCount;
        if (symbolCount > limits.maxSymbols) {
            return Result<bool, Diagnostic>::failure(Diagnostic{
                DiagnosticSeverity::Error,
                "codegen.resource_limit",
                "the assembly input exceeds the configured symbol limit",
            });
        }
    }
    return Result<bool, Diagnostic>::success(true);
}

[[nodiscard]] auto screen_directives(const MachineAssemblyRequest& request)
    -> Result<bool, Diagnostic> {
    std::size_t lineCount = 0U;
    std::size_t symbolCount = 0U;
    std::size_t lineStart = 0U;
    while (lineStart <= request.assembly.size()) {
        const auto lineEnd = request.assembly.find('\n', lineStart);
        const auto length = lineEnd == std::string::npos
            ? request.assembly.size() - lineStart
            : lineEnd - lineStart;
        const auto line = std::string_view{request.assembly}.substr(lineStart, length);
        ++lineCount;
        if (lineCount > request.limits.maxLines) {
            return Result<bool, Diagnostic>::failure(Diagnostic{
                DiagnosticSeverity::Error,
                "codegen.resource_limit",
                "the assembly input exceeds the configured line limit",
            });
        }

        std::size_t statementStart = 0U;
        while (statementStart <= line.size()) {
            const auto statementEnd = line.find(';', statementStart);
            const auto statementLength = statementEnd == std::string_view::npos
                ? line.size() - statementStart
                : statementEnd - statementStart;
            auto screened = screen_statement(
                line.substr(statementStart, statementLength),
                symbolCount,
                request.limits);
            if (!screened.has_value()) {
                return screened;
            }
            if (statementEnd == std::string_view::npos) {
                break;
            }
            statementStart = statementEnd + 1U;
        }

        if (lineEnd == std::string::npos) {
            break;
        }
        lineStart = lineEnd + 1U;
    }
    return Result<bool, Diagnostic>::success(true);
}

struct AssemblyDiagnostic {
    bool hasError{false};
    int line{0};
    int column{0};
    std::string message;
};

void capture_diagnostic(const llvm::SMDiagnostic& diagnostic, void* context) {
    auto& captured = *static_cast<AssemblyDiagnostic*>(context);
    if (captured.hasError || diagnostic.getKind() != llvm::SourceMgr::DK_Error) {
        return;
    }
    captured.hasError = true;
    captured.line = diagnostic.getLineNo();
    captured.column = diagnostic.getColumnNo();
    constexpr std::size_t kMaximumMessageBytes = 512U;
    captured.message = diagnostic.getMessage().take_front(kMaximumMessageBytes).str();
}

[[nodiscard]] auto diagnostic_message(const AssemblyDiagnostic& diagnostic)
    -> std::string {
    std::string message = "LLVM MC rejected the assembly";
    if (diagnostic.line > 0) {
        message += " at line " + std::to_string(diagnostic.line);
        if (diagnostic.column >= 0) {
            message += ", column " + std::to_string(diagnostic.column + 1);
        }
    }
    if (!diagnostic.message.empty()) {
        message += ": " + diagnostic.message;
    }
    return message;
}

[[nodiscard]] auto prepared_assembly(const MachineAssemblyRequest& request)
    -> std::string {
    std::string result;
    constexpr std::string_view kIntelSyntax = ".intel_syntax noprefix\n";
    constexpr std::string_view kAttSyntax = ".att_syntax\n";
    if (request.architecture != Architecture::ARM64) {
        const auto prefix = request.syntax == MachineSyntax::Intel
            ? kIntelSyntax
            : kAttSyntax;
        result.reserve(prefix.size() + request.assembly.size());
        result.append(prefix);
    } else {
        result.reserve(request.assembly.size());
    }
    result.append(request.assembly);
    return result;
}

[[nodiscard]] auto build_object(const MachineAssemblyRequest& request)
    -> Result<std::vector<std::byte>, Diagnostic> {
    auto screened = screen_directives(request);
    if (!screened.has_value()) {
        return Result<std::vector<std::byte>, Diagnostic>::failure(
            std::move(screened).error());
    }
    if (request.architecture == Architecture::ARM64 &&
        request.syntax != MachineSyntax::GNU) {
        return Result<std::vector<std::byte>, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "codegen.unsupported_syntax",
            "AArch64 assembly requires GNU syntax",
        });
    }

    const llvm::Triple triple{llvm::Triple::normalize(request.triple)};
    std::string targetError;
    const auto* target = llvm::TargetRegistry::lookupTarget(triple, targetError);
    if (target == nullptr) {
        return Result<std::vector<std::byte>, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "codegen.unsupported_triple",
            "LLVM target lookup failed: " + targetError,
        });
    }

    llvm::MCTargetOptions options{};
    auto registerInfo = std::unique_ptr<llvm::MCRegisterInfo>{
        target->createMCRegInfo(triple)};
    if (!registerInfo) {
        return Result<std::vector<std::byte>, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "codegen.provider_failed",
            "LLVM could not create target register information",
        });
    }
    auto assemblyInfo = std::unique_ptr<llvm::MCAsmInfo>{
        target->createMCAsmInfo(*registerInfo, triple, options)};
    auto subtargetInfo = std::unique_ptr<llvm::MCSubtargetInfo>{
        target->createMCSubtargetInfo(triple, request.cpu, request.features)};
    auto instructionInfo = std::unique_ptr<llvm::MCInstrInfo>{
        target->createMCInstrInfo()};
    if (!assemblyInfo || !subtargetInfo || !instructionInfo) {
        return Result<std::vector<std::byte>, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "codegen.provider_failed",
            "LLVM could not create target MC metadata",
        });
    }

    const auto assembly = prepared_assembly(request);
    llvm::SourceMgr sourceManager;
    AssemblyDiagnostic assemblyDiagnostic{};
    sourceManager.setDiagHandler(capture_diagnostic, &assemblyDiagnostic);
    sourceManager.AddNewSourceBuffer(
        llvm::MemoryBuffer::getMemBufferCopy(assembly, "<binobf-assembly>"),
        llvm::SMLoc{});

    llvm::MCContext context{
        triple,
        assemblyInfo.get(),
        registerInfo.get(),
        subtargetInfo.get(),
        &sourceManager,
        &options,
    };
    const bool positionIndependent =
        request.relocationModel != RelocationModel::Static;
    const bool largeCodeModel = request.codeModel == CodeModel::Large;
    auto objectFileInfo = std::unique_ptr<llvm::MCObjectFileInfo>{
        target->createMCObjectFileInfo(context, positionIndependent, largeCodeModel)};
    if (!objectFileInfo) {
        return Result<std::vector<std::byte>, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "codegen.provider_failed",
            "LLVM could not create object-file metadata",
        });
    }
    context.setObjectFileInfo(objectFileInfo.get());

    llvm::SmallString<0> objectStorage;
    llvm::raw_svector_ostream objectStream{objectStorage};
    auto codeEmitter = std::unique_ptr<llvm::MCCodeEmitter>{
        target->createMCCodeEmitter(*instructionInfo, context)};
    auto assemblyBackend = std::unique_ptr<llvm::MCAsmBackend>{
        target->createMCAsmBackend(*subtargetInfo, *registerInfo, options)};
    if (!codeEmitter || !assemblyBackend) {
        return Result<std::vector<std::byte>, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "codegen.provider_failed",
            "LLVM could not create the target object emitter",
        });
    }
    auto objectWriter = assemblyBackend->createObjectWriter(objectStream);
    auto streamer = std::unique_ptr<llvm::MCStreamer>{
        target->createMCObjectStreamer(
            triple,
            context,
            std::move(assemblyBackend),
            std::move(objectWriter),
            std::move(codeEmitter),
            *subtargetInfo)};
    if (!streamer) {
        return Result<std::vector<std::byte>, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "codegen.provider_failed",
            "LLVM could not create the target object streamer",
        });
    }

    auto parser = std::unique_ptr<llvm::MCAsmParser>{
        llvm::createMCAsmParser(
            sourceManager, context, *streamer, *assemblyInfo)};
    auto targetParser = std::unique_ptr<llvm::MCTargetAsmParser>{
        target->createMCAsmParser(
            *subtargetInfo, *parser, *instructionInfo, options)};
    if (!parser || !targetParser) {
        return Result<std::vector<std::byte>, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "codegen.provider_failed",
            "LLVM target does not provide an assembly parser",
        });
    }
    parser->setTargetParser(*targetParser);
    if (parser->Run(false) != 0 || assemblyDiagnostic.hasError) {
        return Result<std::vector<std::byte>, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "codegen.assembly_failed",
            diagnostic_message(assemblyDiagnostic),
        });
    }

    const auto objectBytes = std::as_bytes(
        std::span<const char>{objectStorage.data(), objectStorage.size()});
    return Result<std::vector<std::byte>, Diagnostic>::success(
        std::vector<std::byte>{objectBytes.begin(), objectBytes.end()});
}

[[nodiscard]] auto extract_text_section(
    const MachineAssemblyRequest& request,
    const std::vector<std::byte>& objectBytes)
    -> Result<MachineEmission, Diagnostic> {
    const auto objectChars = std::span<const char>{
        reinterpret_cast<const char*>(objectBytes.data()), objectBytes.size()};
    const llvm::MemoryBufferRef buffer{
        llvm::StringRef{objectChars.data(), objectChars.size()},
        "<binobf-object>"};
    auto objectOrError = llvm::object::ObjectFile::createObjectFile(buffer);
    if (!objectOrError) {
        return failure(
            "codegen.object_failed",
            "LLVM could not read its emitted object: " +
                llvm::toString(objectOrError.takeError()));
    }
    auto object = std::move(*objectOrError);

    MachineEmission emission{};
    std::size_t matchingSections = 0U;
    for (const auto& section : object->sections()) {
        auto nameOrError = section.getName();
        if (!nameOrError) {
            return failure(
                "codegen.object_failed",
                "LLVM could not read an emitted section name: " +
                    llvm::toString(nameOrError.takeError()));
        }
        const auto name = *nameOrError;
        if (name == request.sectionName) {
            ++matchingSections;
            auto contentsOrError = section.getContents();
            if (!contentsOrError) {
                return failure(
                    "codegen.object_failed",
                    "LLVM could not read the emitted text section: " +
                        llvm::toString(contentsOrError.takeError()));
            }
            const auto contents = *contentsOrError;
            if (contents.size() > request.limits.maxEmittedBytes) {
                return failure(
                    "codegen.resource_limit",
                    "the emitted text section exceeds the configured byte limit");
            }
            const auto bytes = std::as_bytes(
                std::span<const char>{contents.data(), contents.size()});
            emission.bytes.assign(bytes.begin(), bytes.end());
            emission.alignment = section.getAlignment().value();
        } else if (section.isText() && !section.isVirtual()) {
            auto contentsOrError = section.getContents();
            if (!contentsOrError) {
                return failure(
                    "codegen.object_failed",
                    "LLVM could not inspect an additional executable section: " +
                        llvm::toString(contentsOrError.takeError()));
            }
            if (!contentsOrError->empty()) {
                return failure(
                    "codegen.unexpected_section",
                    "the assembly defined executable content outside the requested section");
            }
        }
    }
    if (matchingSections != 1U) {
        return failure(
            "codegen.section_mismatch",
            "the emitted object must contain exactly one requested text section");
    }
    emission.provider = "LLVM 22.1.8";
    return Result<MachineEmission, Diagnostic>::success(std::move(emission));
}

[[nodiscard]] auto verify_emission(
    const MachineAssemblyRequest& request,
    MachineEmission emission) -> Result<MachineEmission, Diagnostic> {
    auto backend = make_architecture_backend(request.architecture);
    if (!backend.has_value()) {
        return failure(
            "codegen.verification_failed",
            "a fixed decoder is unavailable for emitted machine code");
    }
    std::size_t offset = 0U;
    std::size_t instructionCount = 0U;
    while (offset < emission.bytes.size()) {
        if (instructionCount >= request.limits.maxInstructions ||
            request.baseAddress.value >
                std::numeric_limits<std::uint64_t>::max() - offset) {
            return failure(
                "codegen.verification_failed",
                "emitted instruction verification exceeded its bounded address space");
        }
        const auto decoded = backend.value()->decode(DecodeRequest{
            .architecture = request.architecture,
            .bytes = std::span<const std::byte>{emission.bytes}.subspan(offset),
            .address = {
                request.baseAddress.value + offset,
                request.baseAddress.kind,
            },
            .instructionId = EntityId{instructionCount + 1U},
            .sectionId = EntityId{1U},
            .sectionOffset = offset,
        });
        if (!decoded.has_value() || decoded.value().encoding.empty() ||
            decoded.value().encoding.size() > emission.bytes.size() - offset) {
            return failure(
                "codegen.verification_failed",
                "the fixed decoder did not consume the complete emitted text section");
        }
        offset += decoded.value().encoding.size();
        ++instructionCount;
    }
    if (request.expectedInstructionCount.has_value() &&
        instructionCount != request.expectedInstructionCount.value()) {
        return failure(
            "codegen.verification_failed",
            "the emitted instruction count does not match the request contract");
    }
    return Result<MachineEmission, Diagnostic>::success(std::move(emission));
}

} // namespace

auto assemble_with_llvm_mc(const MachineAssemblyRequest& request)
    -> Result<MachineEmission, Diagnostic> {
    auto object = build_object(request);
    if (!object.has_value()) {
        return Result<MachineEmission, Diagnostic>::failure(
            std::move(object).error());
    }
    auto emission = extract_text_section(request, object.value());
    if (!emission.has_value()) {
        return emission;
    }
    return verify_emission(request, std::move(emission).value());
}

} // namespace binobf::detail

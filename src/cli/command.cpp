#include <binobf/cli/command.hpp>

#include <binobf/analysis/object_analyzer.hpp>
#include <binobf/capabilities/render.hpp>
#include <binobf/capabilities/registry.hpp>
#include <binobf/config/config.hpp>
#include <binobf/core/diagnostic.hpp>
#include <binobf/core/types.hpp>
#include <binobf/evidence/manifest.hpp>
#include <binobf/evidence/lineage.hpp>
#include <binobf/formats/archive.hpp>
#include <binobf/formats/archive_writer.hpp>
#include <binobf/formats/detector.hpp>
#include <binobf/formats/linked_image.hpp>
#include <binobf/formats/linked_writer.hpp>
#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/ir/control_flow.hpp>
#include <binobf/ir/native_lifter.hpp>
#include <binobf/ir/outlining.hpp>
#include <binobf/ir/vm_lowering.hpp>
#include <binobf/support/artifact_transaction.hpp>
#include <binobf/support/sha256.hpp>
#include <binobf/transforms/pass_manager.hpp>
#include <binobf/transforms/registry.hpp>
#include <binobf/verify/structural_verifier.hpp>
#include <binobf/vm/bytecode.hpp>
#include <binobf/vm/protection.hpp>

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <future>
#include <iomanip>
#include <memory>
#include <numeric>
#include <ostream>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

namespace binobf::cli {
namespace {

constexpr std::uintmax_t maximumInspectionSize = UINTMAX_C(512) * 1024U * 1024U;

enum class DiagnosticFormat : std::uint8_t {
    Text,
    Json,
};

thread_local std::optional<DiagnosticFormat> transformDiagnosticFormat;

struct TransformDiagnosticScope {
    std::optional<DiagnosticFormat> previous;

    explicit TransformDiagnosticScope(DiagnosticFormat format)
        : previous(transformDiagnosticFormat) {
        transformDiagnosticFormat = format;
    }

    ~TransformDiagnosticScope() {
        transformDiagnosticFormat = previous;
    }
};

void print_usage(std::ostream& stream) {
    stream
        << "Usage:\n"
        << "  binobf inspect <path> [--diagnostics=text|json]\n"
        << "  binobf analyze <binary> [--diagnostics=text|json]\n"
        << "  binobf verify <binary> [--diagnostics=text|json]\n"
        << "  binobf config <path>\n"
        << "  binobf lineage <sidecar> --protected-address=<integer>\n"
        << "  binobf transform [<binary>] [--config=<path>] [-o <output>]"
           " [--passes=<list|minimal|balanced|none>] [--seed=N] [--dry-run]"
           " [--allow-signature-invalidation] [--manifest=<path>|--no-manifest]\n"
        << "      [--lineage=<path>] [--jobs=N] [--diagnostics=text|json]\n"
        << "  binobf passes\n"
        << "  binobf vm lower <object> --function=<name>"
           " --abi=windows-x64|sysv-amd64 --args=N -o <program.bvm> [--seed=N]"
           " [--cfg=flatten|--outline-block=N|--split-function]\n"
        << "  binobf vm protect <object> --function=<name>"
           " --abi=windows-x64|sysv-amd64 --args=N -o <object> [--seed=N]\n"
        << "  binobf vm disassemble <program.bvm>\n"
        << "  binobf formats\n"
        << "  binobf architectures\n"
        << "  binobf version\n"
        << "  binobf help\n";
}

void print_diagnostic(
    std::ostream& stream,
    const Diagnostic& diagnostic,
    DiagnosticFormat format) {
    const auto effectiveFormat = transformDiagnosticFormat.has_value()
        && format == DiagnosticFormat::Text ? *transformDiagnosticFormat : format;
    stream << (effectiveFormat == DiagnosticFormat::Json
        ? render_json(diagnostic)
        : render_text(diagnostic)) << '\n';
}

auto parse_diagnostic_format(
    std::span<const std::string_view> arguments,
    std::ostream& errors) -> Result<DiagnosticFormat, int> {
    if (arguments.size() == 2) {
        return Result<DiagnosticFormat, int>::success(DiagnosticFormat::Text);
    }
    if (arguments.size() != 3) {
        print_usage(errors);
        return Result<DiagnosticFormat, int>::failure(2);
    }
    if (arguments[2] == "--diagnostics=text") {
        return Result<DiagnosticFormat, int>::success(DiagnosticFormat::Text);
    }
    if (arguments[2] == "--diagnostics=json") {
        return Result<DiagnosticFormat, int>::success(DiagnosticFormat::Json);
    }
    errors << "unknown inspect option: " << arguments[2] << '\n';
    print_usage(errors);
    return Result<DiagnosticFormat, int>::failure(2);
}

auto read_input(const std::filesystem::path& path)
    -> Result<std::vector<std::byte>, Diagnostic> {
    std::error_code fileSizeError;
    const auto fileSize = std::filesystem::file_size(path, fileSizeError);
    if (fileSizeError) {
        return Result<std::vector<std::byte>, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "io.open_failed",
            "could not open input file: " + path.string(),
        });
    }
    if (fileSize > maximumInspectionSize) {
        return Result<std::vector<std::byte>, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "io.input_too_large",
            "input exceeds the 512 MiB inspection limit",
        });
    }

    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return Result<std::vector<std::byte>, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "io.open_failed",
            "could not open input file: " + path.string(),
        });
    }

    std::vector<std::byte> bytes(static_cast<std::size_t>(fileSize));
    if (!bytes.empty()) {
        stream.read(
            reinterpret_cast<char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
        if (!stream || static_cast<std::size_t>(stream.gcount()) != bytes.size()) {
            return Result<std::vector<std::byte>, Diagnostic>::failure(Diagnostic{
                DiagnosticSeverity::Error,
                "io.read_failed",
                "input changed or could not be read completely",
            });
        }
    }
    return Result<std::vector<std::byte>, Diagnostic>::success(std::move(bytes));
}

auto inspect(
    std::span<const std::string_view> arguments,
    std::ostream& output,
    std::ostream& errors) -> int {
    const auto diagnosticFormat = parse_diagnostic_format(arguments, errors);
    if (!diagnosticFormat.has_value()) {
        return diagnosticFormat.error();
    }

    const std::filesystem::path path{std::string{arguments[1]}};
    auto input = read_input(path);
    if (!input.has_value()) {
        print_diagnostic(errors, input.error(), diagnosticFormat.value());
        return 3;
    }

    const auto detection = detect_binary(input.value(), path.filename().string());
    if (!detection.has_value()) {
        print_diagnostic(errors, detection.error(), diagnosticFormat.value());
        return 3;
    }

    const auto& result = detection.value();
    output << "path: " << path.string() << '\n'
           << "format: " << to_string(result.format) << '\n'
           << "type: " << to_string(result.type) << '\n'
           << "architecture: " << to_string(result.architecture) << '\n'
           << "entry-point: 0x" << std::hex << result.entryPoint << std::dec << '\n'
           << "file-size: " << input.value().size() << '\n'
           << "inspection: supported\n";
    return 0;
}

auto is_linked_type(BinaryType type) noexcept -> bool {
    return type == BinaryType::Executable
        || type == BinaryType::SharedLibrary
        || type == BinaryType::KernelDriver;
}

auto is_archive_format(BinaryFormat format) noexcept -> bool {
    return format == BinaryFormat::Archive;
}

auto analyze(
    std::span<const std::string_view> arguments,
    std::ostream& output,
    std::ostream& errors) -> int {
    const auto diagnosticFormat = parse_diagnostic_format(arguments, errors);
    if (!diagnosticFormat.has_value()) {
        return diagnosticFormat.error();
    }

    const std::filesystem::path path{std::string{arguments[1]}};
    auto input = read_input(path);
    if (!input.has_value()) {
        print_diagnostic(errors, input.error(), diagnosticFormat.value());
        return 3;
    }
    const auto detection = detect_binary(input.value(), path.filename().string());
    if (!detection.has_value()) {
        print_diagnostic(errors, detection.error(), diagnosticFormat.value());
        return 3;
    }
    if (is_linked_type(detection.value().type)) {
        const auto parsed = parse_linked_image(input.value(), path.filename().string());
        if (!parsed.has_value()) {
            print_diagnostic(errors, parsed.error(), diagnosticFormat.value());
            return 3;
        }
        const auto& linked = parsed.value();
        const auto& image = linked.image;
        output << "path: " << path.string() << '\n'
               << "format: " << to_string(image.format) << '\n'
               << "type: " << to_string(image.type) << '\n'
               << "architecture: " << to_string(image.architecture) << '\n'
               << "sections: " << image.sections.size() << '\n'
               << "segments: " << image.segments.size() << '\n'
               << "symbols: " << image.symbols.size() << '\n'
               << "imports: " << image.imports.size() << '\n'
               << "exports: " << image.exports.size() << '\n'
               << "relocations: " << image.relocations.size() << '\n'
               << "functions: " << image.functions.size() << '\n'
               << "unwind-records: " << image.unwindInfo.size() << '\n'
               << "resources: " << image.resources.size() << '\n'
               << "debug-records: " << image.debugInfo.size() << '\n'
               << "directories: " << linked.directories.size() << '\n'
               << "signed: " << (linked.signedImage ? "true" : "false") << '\n';
        for (const auto& section : image.sections) {
            output << "section[" << section.formatIndex << "]: " << section.name
                   << " size=" << section.logicalSize << '\n';
        }
        return 0;
    }
    if (is_archive_format(detection.value().format)) {
        const auto parsed = parse_archive(input.value(), path.filename().string());
        if (!parsed.has_value()) {
            print_diagnostic(errors, parsed.error(), diagnosticFormat.value());
            return 3;
        }
        const auto& archive = parsed.value();
        const auto objectMembers = std::count_if(
            archive.members.begin(), archive.members.end(), [](const ArchiveMember& member) {
                return member.kind == ArchiveMemberKind::Object;
            });
        const auto importMembers = std::count_if(
            archive.members.begin(), archive.members.end(), [](const ArchiveMember& member) {
                return member.kind == ArchiveMemberKind::ImportObject;
            });
        output << "path: " << path.string() << '\n'
               << "format: archive\n"
               << "type: " << to_string(archive.type) << '\n'
               << "architecture: " << to_string(archive.architecture) << '\n'
               << "members: " << archive.members.size() << '\n'
               << "object-members: " << objectMembers << '\n'
               << "import-members: " << importMembers << '\n'
               << "archive-symbols: " << archive.symbols.size() << '\n';
        for (const auto& member : archive.members) {
            output << "member[" << member.id.value() << "]: " << member.name
                   << " size=" << member.contents.size()
                   << " format=" << to_string(member.format) << '\n';
        }
        return 0;
    }
    auto parsed = parse_object(input.value(), path.filename().string());
    if (!parsed.has_value()) {
        print_diagnostic(errors, parsed.error(), diagnosticFormat.value());
        return 3;
    }

    auto analyzed = analyze_object(parsed.value());
    if (!analyzed.has_value()) {
        print_diagnostic(errors, analyzed.error(), diagnosticFormat.value());
        return 3;
    }
    const auto& image = analyzed.value().image;
    const auto edgeCount = std::accumulate(
        image.basicBlocks.begin(), image.basicBlocks.end(), std::size_t{0},
        [](std::size_t total, const auto& block) { return total + block.edges.size(); });
    const auto incompleteFunctions = static_cast<std::size_t>(std::count_if(
        image.functions.begin(), image.functions.end(), [](const auto& function) {
            return !function.complete;
        }));
    output << "path: " << path.string() << '\n'
           << "format: " << to_string(image.format) << '\n'
           << "type: " << to_string(image.type) << '\n'
           << "architecture: " << to_string(image.architecture) << '\n'
           << "sections: " << image.sections.size() << '\n'
           << "symbols: " << image.symbols.size() << '\n'
           << "relocations: " << image.relocations.size() << '\n'
           << "functions: " << image.functions.size() << '\n'
           << "instructions: " << image.instructions.size() << '\n'
           << "basic-blocks: " << image.basicBlocks.size() << '\n'
           << "cfg-edges: " << edgeCount << '\n'
           << "incomplete-functions: " << incompleteFunctions << '\n';
    for (const auto& section : image.sections) {
        output << "section[" << section.formatIndex << "]: " << section.name
               << " size=" << section.logicalSize << '\n';
    }
    for (const auto& function : image.functions) {
        output << "function[" << function.name << "]: address=0x"
               << std::hex << function.address.value << std::dec
               << " size=" << function.size
               << " instructions=" << function.instructions.size()
               << " blocks=" << function.basicBlocks.size()
               << " complete=" << (function.complete ? "true" : "false") << '\n';
    }
    for (const auto& diagnostic : analyzed.value().diagnostics) {
        output << "analysis-diagnostic[" << diagnostic.code << "]: "
               << diagnostic.message << '\n';
    }
    return 0;
}

auto verify(
    std::span<const std::string_view> arguments,
    std::ostream& output,
    std::ostream& errors) -> int {
    const auto diagnosticFormat = parse_diagnostic_format(arguments, errors);
    if (!diagnosticFormat.has_value()) {
        return diagnosticFormat.error();
    }

    const std::filesystem::path path{std::string{arguments[1]}};
    auto input = read_input(path);
    if (!input.has_value()) {
        print_diagnostic(errors, input.error(), diagnosticFormat.value());
        return 3;
    }
    const auto detection = detect_binary(input.value(), path.filename().string());
    if (!detection.has_value()) {
        print_diagnostic(errors, detection.error(), diagnosticFormat.value());
        return 3;
    }
    if (is_archive_format(detection.value().format)) {
        auto verified = verify_archive(input.value(), path.filename().string());
        if (!verified.has_value()) {
            print_diagnostic(errors, verified.error(), diagnosticFormat.value());
            return 3;
        }
        const auto& report = verified.value();
        output << "path: " << path.string() << '\n'
               << "format: archive\n"
               << "type: " << to_string(report.image.type) << '\n'
               << "architecture: " << to_string(report.image.architecture) << '\n'
               << "members: " << report.image.members.size() << '\n'
               << "archive-symbols: " << report.image.symbols.size() << '\n';
        for (const auto& check : report.checks) {
            output << check.name << ": " << verification_status_name(check.status)
                   << " examined=" << check.examined << '\n';
        }
        output << "verification: passed\n";
        return 0;
    }
    auto verified = is_linked_type(detection.value().type)
        ? verify_linked_image(input.value(), path.filename().string())
        : verify_object(input.value(), path.filename().string());
    if (!verified.has_value()) {
        print_diagnostic(errors, verified.error(), diagnosticFormat.value());
        return 3;
    }

    const auto& report = verified.value();
    output << "path: " << path.string() << '\n'
           << "format: " << to_string(report.image.format) << '\n'
           << "type: " << to_string(report.image.type) << '\n'
           << "architecture: " << to_string(report.image.architecture) << '\n'
           << "sections: " << report.image.sections.size() << '\n'
           << "symbols: " << report.image.symbols.size() << '\n'
           << "relocations: " << report.image.relocations.size() << '\n';
    for (const auto& check : report.checks) {
        output << check.name << ": " << verification_status_name(check.status)
               << " examined=" << check.examined << '\n';
    }
    output << "verification: passed\n";
    return 0;
}

auto paths_conflict(
    const std::filesystem::path& input,
    const std::filesystem::path& output) -> bool {
    std::error_code inputError;
    std::error_code outputError;
    const auto absoluteInput = std::filesystem::absolute(input, inputError).lexically_normal();
    const auto absoluteOutput = std::filesystem::absolute(output, outputError).lexically_normal();
    if (inputError || outputError) {
        return input == output;
    }
#ifdef _WIN32
    auto inputText = absoluteInput.string();
    auto outputText = absoluteOutput.string();
    std::transform(inputText.begin(), inputText.end(), inputText.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    std::transform(outputText.begin(), outputText.end(), outputText.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    return inputText == outputText;
#else
    return absoluteInput == absoluteOutput;
#endif
}

auto write_output_transactionally(
    const std::filesystem::path& output,
    const std::vector<std::byte>& bytes) -> std::optional<Diagnostic> {
    const std::array artifacts{ArtifactPayload{output, bytes}};
    const auto committed = commit_artifacts(artifacts);
    if (!committed.has_value()) return committed.error();
    return std::nullopt;
}

struct TransformOptions {
    std::filesystem::path input;
    std::optional<std::filesystem::path> output;
    std::vector<std::string> passes;
    std::vector<std::string> preservedSymbols;
    std::optional<config::SelectionConfig> selection;
    std::string passDescription;
    std::uint64_t seed{0};
    std::size_t jobs{1};
    DiagnosticFormat diagnostics{DiagnosticFormat::Text};
    bool dryRun{false};
    bool allowSignatureInvalidation{false};
    config::ManifestConfig manifest;
    std::optional<std::filesystem::path> lineagePath;
    std::string canonicalConfig;
};

auto split_passes(std::string_view value) -> std::optional<std::vector<std::string>> {
    if (value == "none") return std::vector<std::string>{};
    if (value == "minimal") {
        return std::vector<std::string>{
            "strip-debug", "cleanup-metadata", "strip-local-symbols",
            "rename-private-symbols"};
    }
    if (value == "balanced") {
        return std::vector<std::string>{
            "strip-debug", "cleanup-metadata", "strip-local-symbols",
            "rename-private-symbols",
            "instruction-substitution", "constant-rewriting",
            "branch-inversion", "dead-code-insertion", "block-splitting",
            "block-reordering", "function-reordering"};
    }
    std::vector<std::string> names;
    while (!value.empty()) {
        const auto separator = value.find(',');
        const auto name = value.substr(0, separator);
        if (name.empty()) return std::nullopt;
        if (find_registered_pass(name) == nullptr) {
            return std::nullopt;
        }
        if (std::find(names.begin(), names.end(), name) != names.end()) return std::nullopt;
        names.emplace_back(name);
        if (separator == std::string_view::npos) break;
        value.remove_prefix(separator + 1);
    }
    return names;
}

auto parse_transform_options(
    std::span<const std::string_view> arguments,
    std::ostream& errors) -> Result<TransformOptions, int> {
    std::optional<std::filesystem::path> configPath;
    std::optional<std::filesystem::path> cliInput;
    std::optional<std::filesystem::path> cliOutput;
    std::optional<std::vector<std::string>> cliPasses;
    std::optional<std::string> cliPassDescription;
    std::optional<std::uint64_t> cliSeed;
    std::optional<std::size_t> cliJobs;
    std::optional<DiagnosticFormat> cliDiagnostics;
    std::vector<std::string> cliPreservedSymbols;
    std::optional<bool> cliManifestEnabled;
    std::optional<std::filesystem::path> cliManifestPath;
    std::optional<std::filesystem::path> cliLineagePath;
    bool cliDryRun = false;
    bool cliAllowSignatureInvalidation = false;
    bool sawPreservedSymbol = false;

    for (std::size_t index = 1; index < arguments.size(); ++index) {
        const auto argument = arguments[index];
        if (argument == "-o") {
            if (cliOutput.has_value() || index + 1 >= arguments.size()) {
                errors << "transform requires exactly one path after -o\n";
                return Result<TransformOptions, int>::failure(2);
            }
            cliOutput = std::filesystem::path{std::string{arguments[++index]}};
        } else if (argument == "--config") {
            if (configPath.has_value() || index + 1 >= arguments.size()) {
                errors << "transform requires exactly one path after --config\n";
                return Result<TransformOptions, int>::failure(2);
            }
            configPath = std::filesystem::path{std::string{arguments[++index]}};
        } else if (argument.starts_with("--config=")) {
            if (configPath.has_value() || argument.size() == 9) {
                errors << "transform accepts one non-empty --config option\n";
                return Result<TransformOptions, int>::failure(2);
            }
            configPath = std::filesystem::path{std::string{argument.substr(9)}};
        } else if (argument.starts_with("--passes=")) {
            if (cliPasses.has_value()) {
                errors << "transform accepts one --passes option\n";
                return Result<TransformOptions, int>::failure(2);
            }
            cliPassDescription = std::string{argument.substr(9)};
            const auto parsed = split_passes(argument.substr(9));
            if (!parsed.has_value()) {
                errors << "unknown or duplicate transformation pass list\n";
                return Result<TransformOptions, int>::failure(2);
            }
            cliPasses = *parsed;
        } else if (argument.starts_with("--seed=")) {
            if (cliSeed.has_value()) {
                errors << "transform accepts one --seed option\n";
                return Result<TransformOptions, int>::failure(2);
            }
            const auto value = argument.substr(7);
            std::uint64_t seed = 0;
            const auto parsed = std::from_chars(
                value.data(), value.data() + value.size(), seed, 10);
            if (value.empty() || parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
                errors << "transform seed must be an unsigned decimal integer\n";
                return Result<TransformOptions, int>::failure(2);
            }
            cliSeed = seed;
        } else if (argument.starts_with("--jobs=")) {
            if (cliJobs.has_value()) {
                errors << "transform accepts one --jobs option\n";
                return Result<TransformOptions, int>::failure(2);
            }
            const auto value = argument.substr(7);
            std::size_t jobs = 0;
            const auto parsed = std::from_chars(
                value.data(), value.data() + value.size(), jobs, 10);
            if (value.empty() || parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()
                || jobs == 0U || jobs > 64U) {
                errors << "transform jobs must be an integer from 1 through 64\n";
                return Result<TransformOptions, int>::failure(2);
            }
            cliJobs = jobs;
        } else if (argument == "--diagnostics=text" || argument == "--diagnostics=json") {
            if (cliDiagnostics.has_value()) {
                errors << "transform accepts one --diagnostics option\n";
                return Result<TransformOptions, int>::failure(2);
            }
            cliDiagnostics = argument.ends_with("=json")
                ? DiagnosticFormat::Json : DiagnosticFormat::Text;
        } else if (argument == "--dry-run") {
            if (cliDryRun) {
                errors << "transform accepts --dry-run once\n";
                return Result<TransformOptions, int>::failure(2);
            }
            cliDryRun = true;
        } else if (argument == "--allow-signature-invalidation") {
            if (cliAllowSignatureInvalidation) {
                errors << "signature invalidation intent was specified more than once\n";
                return Result<TransformOptions, int>::failure(2);
            }
            cliAllowSignatureInvalidation = true;
        } else if (argument == "--no-manifest") {
            if (cliManifestEnabled.has_value()) {
                errors << "transform accepts one manifest policy option\n";
                return Result<TransformOptions, int>::failure(2);
            }
            cliManifestEnabled = false;
        } else if (argument.starts_with("--manifest=")) {
            if (cliManifestEnabled.has_value() || argument.size() == 11) {
                errors << "transform accepts one non-empty --manifest option\n";
                return Result<TransformOptions, int>::failure(2);
            }
            cliManifestEnabled = true;
            cliManifestPath = std::filesystem::path{std::string{argument.substr(11)}};
        } else if (argument.starts_with("--lineage=")) {
            if (cliLineagePath.has_value() || argument.size() == 10) {
                errors << "transform accepts one non-empty --lineage option\n";
                return Result<TransformOptions, int>::failure(2);
            }
            cliLineagePath = std::filesystem::path{std::string{argument.substr(10)}};
        } else if (argument.starts_with("--preserve-symbol=")) {
            const auto name = argument.substr(18);
            if (name.empty()) {
                errors << "preserved symbol name cannot be empty\n";
                return Result<TransformOptions, int>::failure(2);
            }
            sawPreservedSymbol = true;
            cliPreservedSymbols.emplace_back(name);
        } else if (!argument.starts_with('-')) {
            if (cliInput.has_value()) {
                errors << "transform accepts at most one input binary\n";
                return Result<TransformOptions, int>::failure(2);
            }
            cliInput = std::filesystem::path{std::string{argument}};
        } else {
            errors << "unknown transform option: " << argument << '\n';
            return Result<TransformOptions, int>::failure(2);
        }
    }

    TransformOptions options;
    options.manifest.enabled = true;
    options.diagnostics = cliDiagnostics.value_or(DiagnosticFormat::Text);
    if (configPath.has_value()) {
        const auto bytes = read_input(*configPath);
        if (!bytes.has_value()) {
            print_diagnostic(errors, bytes.error(), DiagnosticFormat::Text);
            return Result<TransformOptions, int>::failure(3);
        }
        const auto parsed = config::parse_transform_config(bytes.value(), *configPath);
        if (!parsed.has_value()) {
            print_diagnostic(errors, parsed.error(), DiagnosticFormat::Text);
            return Result<TransformOptions, int>::failure(3);
        }
        const auto& configured = parsed.value().config;
        if (configured.input.has_value()) options.input = *configured.input;
        options.output = configured.output;
        if (configured.passes.has_value()) options.passes = *configured.passes;
        if (configured.passDescription.has_value()) {
            options.passDescription = *configured.passDescription;
        }
        if (configured.seed.has_value()) options.seed = *configured.seed;
        if (configured.jobs.has_value()) options.jobs = *configured.jobs;
        if (configured.dryRun.has_value()) options.dryRun = *configured.dryRun;
        if (configured.allowSignatureInvalidation.has_value()) {
            options.allowSignatureInvalidation = *configured.allowSignatureInvalidation;
        }
        options.preservedSymbols = configured.preservedSymbols;
        options.selection = configured.selection;
        if (configured.manifest.enabled.has_value()) {
            options.manifest.enabled = configured.manifest.enabled;
        }
        if (configured.manifest.path.has_value()) {
            options.manifest.path = configured.manifest.path;
        }
        options.lineagePath = configured.lineagePath;
    }

    if (cliInput.has_value()) options.input = *cliInput;
    if (cliOutput.has_value()) options.output = *cliOutput;
    if (cliPasses.has_value()) {
        options.passes = *cliPasses;
        options.passDescription = *cliPassDescription;
    }
    if (cliSeed.has_value()) options.seed = *cliSeed;
    if (cliJobs.has_value()) options.jobs = *cliJobs;
    if (cliDryRun) options.dryRun = true;
    if (cliAllowSignatureInvalidation) options.allowSignatureInvalidation = true;
    if (cliManifestEnabled.has_value()) {
        options.manifest.enabled = cliManifestEnabled;
        options.manifest.path = cliManifestPath;
    }
    if (cliLineagePath.has_value()) options.lineagePath = cliLineagePath;
    if (sawPreservedSymbol) {
        for (const auto& symbol : cliPreservedSymbols) {
            if (std::find(options.preservedSymbols.begin(), options.preservedSymbols.end(), symbol)
                != options.preservedSymbols.end()) {
                errors << "preserved symbol was specified more than once: " << symbol << '\n';
                return Result<TransformOptions, int>::failure(2);
            }
            options.preservedSymbols.push_back(symbol);
        }
    }

    if (options.input.empty()) {
        errors << "transform requires an input binary or config.input\n";
        return Result<TransformOptions, int>::failure(2);
    }
    if (options.passDescription.empty()) {
        errors << "transform requires --passes=<list|minimal|balanced|none>\n";
        return Result<TransformOptions, int>::failure(2);
    }
    if (!options.dryRun && !options.output.has_value()) {
        errors << "transform requires -o <output> unless --dry-run is used\n";
        return Result<TransformOptions, int>::failure(2);
    }
    if (!options.dryRun && options.manifest.enabled.value_or(true) &&
        !options.manifest.path.has_value()) {
        auto path = *options.output;
        path += ".manifest.json";
        options.manifest.path = std::move(path);
    }

    config::TransformConfig effective;
    effective.input = options.input;
    effective.output = options.output;
    effective.seed = options.seed;
    effective.jobs = options.jobs;
    effective.passes = options.passes;
    effective.passDescription = options.passDescription;
    effective.dryRun = options.dryRun;
    effective.allowSignatureInvalidation = options.allowSignatureInvalidation;
    effective.preservedSymbols = options.preservedSymbols;
    effective.selection = options.selection;
    effective.manifest = options.manifest;
    effective.lineagePath = options.lineagePath;
    options.canonicalConfig = config::canonicalize_transform_config(effective);
    return Result<TransformOptions, int>::success(std::move(options));
}

auto configure_function_selection(
    TransformContext& context,
    const std::optional<config::SelectionConfig>& configured,
    std::uint64_t fallbackSeed) -> std::optional<Diagnostic> {
    if (!configured.has_value()) return std::nullopt;
    FunctionSelectionPolicy policy;
    policy.includeNames = configured->includeNames;
    policy.excludeNames = configured->excludeNames;
    policy.includeRegex = configured->includeRegex;
    policy.excludeRegex = configured->excludeRegex;
    policy.sections = configured->sections;
    policy.percentage = configured->percentage;
    policy.seed = configured->seed.value_or(fallbackSeed);
    for (const auto visibility : configured->visibilities) {
        switch (visibility) {
        case config::SelectionVisibility::Local:
            policy.visibilities.push_back(SymbolVisibility::Local);
            break;
        case config::SelectionVisibility::Hidden:
            policy.visibilities.push_back(SymbolVisibility::Hidden);
            break;
        case config::SelectionVisibility::External:
            policy.visibilities.push_back(SymbolVisibility::External);
            break;
        }
    }
    auto selected = context.set_function_selection(std::move(policy));
    if (!selected.has_value()) return std::move(selected).error();
    return std::nullopt;
}

auto configure_pass_manager(PassManager& manager, const std::vector<std::string>& passes)
    -> std::optional<Diagnostic>;
auto archive_member_seed(std::uint64_t seed, const ArchiveMember& member) noexcept
    -> std::uint64_t;

struct ArchiveMemberResult {
    std::vector<std::byte> contents;
    std::vector<PassReport> reports;
    bool changed{false};
};

auto transform_archive_member(const ArchiveMember& member, const TransformOptions& options)
    -> Result<ArchiveMemberResult, Diagnostic> {
    const auto object = parse_object(member.contents, member.name);
    if (!object.has_value()) {
        return Result<ArchiveMemberResult, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "archive.member_invalid",
            "object member failed to parse: " + member.name + ": " + object.error().code,
        });
    }
    PassManager manager;
    if (const auto managerError = configure_pass_manager(manager, options.passes)) {
        return Result<ArchiveMemberResult, Diagnostic>::failure(*managerError);
    }
    const auto seed = archive_member_seed(options.seed, member);
    TransformContext context{seed, options.dryRun};
    for (const auto& symbol : options.preservedSymbols) context.preserve_symbol(symbol);
    if (const auto selectionError = configure_function_selection(context, options.selection, seed)) {
        return Result<ArchiveMemberResult, Diagnostic>::failure(*selectionError);
    }
    const auto transformed = manager.run(context, object.value());
    if (!transformed.has_value()) {
        return Result<ArchiveMemberResult, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "archive.member_transform_failed",
            "object member transformation failed: " + member.name + ": "
                + transformed.error().code + ": " + transformed.error().message,
        });
    }
    const auto written = write_object(transformed.value().image);
    if (!written.has_value()) {
        return Result<ArchiveMemberResult, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "archive.member_write_failed",
            "object member emission failed: " + member.name + ": " + written.error().code,
        });
    }
    const auto verified = verify_object(written.value(), member.name);
    if (!verified.has_value() || verified.value().image.format != member.format
        || verified.value().image.architecture != member.architecture) {
        return Result<ArchiveMemberResult, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "archive.member_output_invalid",
            "emitted object member failed structural verification: " + member.name,
        });
    }
    return Result<ArchiveMemberResult, Diagnostic>::success(ArchiveMemberResult{
        .contents = written.value(),
        .reports = transformed.value().reports,
        .changed = transformed.value().changed,
    });
}

auto pass_status(PassStatus status) noexcept -> std::string_view {
    switch (status) {
    case PassStatus::Applied: return "applied";
    case PassStatus::Unchanged: return "unchanged";
    case PassStatus::Unsupported: return "unsupported";
    }
    return "unknown";
}

auto sha256_of(std::span<const std::byte> bytes)
    -> Result<std::string, Diagnostic> {
    const auto digest = sha256(bytes);
    if (!digest.has_value()) {
        return Result<std::string, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "manifest.hash_limit",
            "artifact is too large for SHA-256 length encoding",
        });
    }
    return Result<std::string, Diagnostic>::success(sha256_hex(*digest));
}

auto text_bytes(std::string_view text) -> std::vector<std::byte> {
    const auto bytes = std::as_bytes(std::span{text.data(), text.size()});
    return std::vector<std::byte>{bytes.begin(), bytes.end()};
}

auto make_transform_artifacts(
    const TransformOptions& options,
    std::span<const std::byte> inputBytes,
    const std::vector<std::byte>& outputBytes,
    std::string_view format,
    std::string_view architecture,
    std::vector<evidence::ManifestPassReport> reports,
    std::optional<std::string> lineageJson)
    -> Result<std::vector<ArtifactPayload>, Diagnostic> {
    std::vector<ArtifactPayload> artifacts;
    artifacts.push_back(ArtifactPayload{*options.output, outputBytes});
    if (!options.manifest.enabled.value_or(true) && !options.lineagePath.has_value()) {
        return Result<std::vector<ArtifactPayload>, Diagnostic>::success(
            std::move(artifacts));
    }
    if (options.manifest.enabled.value_or(true) && !options.manifest.path.has_value()) {
        return Result<std::vector<ArtifactPayload>, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "manifest.path_missing",
            "manifest output is enabled but no destination was resolved",
        });
    }

    const auto inputHash = sha256_of(inputBytes);
    if (!inputHash.has_value()) {
        return Result<std::vector<ArtifactPayload>, Diagnostic>::failure(inputHash.error());
    }
    const auto outputHash = sha256_of(outputBytes);
    if (!outputHash.has_value()) {
        return Result<std::vector<ArtifactPayload>, Diagnostic>::failure(outputHash.error());
    }
    const auto canonicalBytes = std::as_bytes(std::span{
        options.canonicalConfig.data(), options.canonicalConfig.size()});
    const auto configHash = sha256_of(canonicalBytes);
    if (!configHash.has_value()) {
        return Result<std::vector<ArtifactPayload>, Diagnostic>::failure(configHash.error());
    }

    if (options.manifest.enabled.value_or(true)) {
        const evidence::BuildManifest manifest{
            .schemaVersion = 1,
            .toolVersion = std::string{evidence::tool_version()},
            .inputName = options.input.filename().generic_string(),
            .outputName = options.output->filename().generic_string(),
            .inputSha256 = inputHash.value(),
            .outputSha256 = outputHash.value(),
            .configSha256 = configHash.value(),
            .seed = options.seed,
            .passes = options.passes,
            .format = std::string{format},
            .architecture = std::string{architecture},
            .inputSize = static_cast<std::uint64_t>(inputBytes.size()),
            .outputSize = static_cast<std::uint64_t>(outputBytes.size()),
            .reports = std::move(reports),
            .verification = "reparsed",
        };
        artifacts.push_back(ArtifactPayload{
            *options.manifest.path,
            text_bytes(evidence::serialize_manifest(manifest)),
        });
    }
    if (options.lineagePath.has_value()) {
        if (!lineageJson.has_value()) {
            return Result<std::vector<ArtifactPayload>, Diagnostic>::failure(Diagnostic{
                DiagnosticSeverity::Error,
                "lineage.unavailable",
                "lineage output was requested but no verified mapping was produced",
            });
        }
        artifacts.push_back(ArtifactPayload{
            *options.lineagePath, text_bytes(*lineageJson)});
    }
    return Result<std::vector<ArtifactPayload>, Diagnostic>::success(std::move(artifacts));
}

auto commit_transform_outputs(
    const TransformOptions& options,
    std::span<const std::byte> inputBytes,
    const std::vector<std::byte>& outputBytes,
    std::string_view format,
    std::string_view architecture,
    std::vector<evidence::ManifestPassReport> reports,
    std::optional<std::string> lineageJson = std::nullopt) -> std::optional<Diagnostic> {
    auto artifacts = make_transform_artifacts(
        options, inputBytes, outputBytes, format, architecture,
        std::move(reports), std::move(lineageJson));
    if (!artifacts.has_value()) return std::move(artifacts).error();
    const auto committed = commit_artifacts(artifacts.value());
    if (!committed.has_value()) return committed.error();
    return std::nullopt;
}

auto configure_pass_manager(PassManager& manager, const std::vector<std::string>& passes)
    -> std::optional<Diagnostic> {
    for (const auto& name : passes) {
        const auto added = manager.add(make_registered_pass(name));
        if (!added.has_value()) return added.error();
    }
    return std::nullopt;
}

auto archive_member_seed(std::uint64_t seed, const ArchiveMember& member) noexcept
    -> std::uint64_t {
    auto hash = UINT64_C(14695981039346656037) ^ seed;
    const auto add = [&](std::uint8_t value) {
        hash ^= value;
        hash *= UINT64_C(1099511628211);
    };
    for (const auto character : member.name) add(static_cast<std::uint8_t>(character));
    add(static_cast<std::uint8_t>(member.format));
    add(static_cast<std::uint8_t>(member.architecture));
    for (const auto byte : member.contents) add(std::to_integer<std::uint8_t>(byte));
    return hash;
}

struct ArchivePassAggregate {
    std::string name;
    PassStatus status{PassStatus::Unsupported};
    PassStatistics statistics;
};

auto uses_medium_risk_pass(const std::vector<std::string>& passes) -> bool {
    return std::any_of(passes.begin(), passes.end(), [](const auto& name) {
        return name == "instruction-substitution"
            || name == "constant-rewriting"
            || name == "branch-inversion"
            || name == "dead-code-insertion"
            || name == "block-splitting"
            || name == "block-reordering"
            || name == "function-reordering";
    });
}

auto transform(
    std::span<const std::string_view> arguments,
    std::ostream& output,
    std::ostream& errors) -> int {
    const auto parsedOptions = parse_transform_options(arguments, errors);
    if (!parsedOptions.has_value()) {
        if (parsedOptions.error() == 2) print_usage(errors);
        return parsedOptions.error();
    }
    const auto* options = &parsedOptions.value();
    const TransformDiagnosticScope diagnosticScope{options->diagnostics};
    if (options->output.has_value() && paths_conflict(options->input, *options->output)) {
        print_diagnostic(errors, Diagnostic{
            DiagnosticSeverity::Error,
            "io.output_conflict",
            "input and output paths must be different",
        }, DiagnosticFormat::Text);
        return 3;
    }
    auto input = read_input(options->input);
    if (!input.has_value()) {
        print_diagnostic(errors, input.error(), DiagnosticFormat::Text);
        return 3;
    }
    const auto detection = detect_binary(input.value(), options->input.filename().string());
    if (!detection.has_value()) {
        print_diagnostic(errors, detection.error(), DiagnosticFormat::Text);
        return 3;
    }
    if (options->lineagePath.has_value() &&
        (is_archive_format(detection.value().format) ||
         is_linked_type(detection.value().type))) {
        print_diagnostic(errors, Diagnostic{
            DiagnosticSeverity::Error,
            "lineage.object_only",
            "lineage sidecars currently require one relocatable object namespace",
        }, DiagnosticFormat::Text);
        return 3;
    }
    if (is_archive_format(detection.value().format)) {
        if (options->allowSignatureInvalidation) {
            print_diagnostic(errors, Diagnostic{
                DiagnosticSeverity::Error,
                "archive.signature_option_not_applicable",
                "signature invalidation is not applicable to archives",
            }, DiagnosticFormat::Text);
            return 3;
        }
        auto parsed = parse_archive(input.value(), options->input.filename().string());
        if (!parsed.has_value()) {
            print_diagnostic(errors, parsed.error(), DiagnosticFormat::Text);
            return 3;
        }
        if (uses_medium_risk_pass(options->passes)) {
            errors << "[warning] medium-risk machine-code transformations enabled; "
                      "unsupported archive members will be skipped\n";
        }
        std::vector<ArchivePassAggregate> aggregates;
        aggregates.reserve(options->passes.size());
        for (const auto& name : options->passes) {
            aggregates.push_back(ArchivePassAggregate{
                .name = name,
                .status = PassStatus::Unsupported,
                .statistics = {},
            });
        }
        std::size_t objectMembers = 0;
        std::size_t transformedMembers = 0;
        std::size_t preservedMembers = 0;
        std::vector<std::pair<std::size_t, std::future<Result<ArchiveMemberResult, Diagnostic>>>> pending;
        const auto flush_pending = [&]() -> std::optional<Diagnostic> {
            for (auto& [memberIndex, future] : pending) {
                auto result = future.get();
                if (!result.has_value()) return std::move(result).error();
                if (result.value().changed) ++transformedMembers;
                parsed.value().members[memberIndex].contents = std::move(result.value().contents);
                for (const auto& report : result.value().reports) {
                    const auto aggregate = std::find_if(
                        aggregates.begin(), aggregates.end(),
                        [&](const ArchivePassAggregate& candidate) {
                            return candidate.name == report.name;
                        });
                    if (aggregate == aggregates.end()) continue;
                    if (report.status == PassStatus::Applied) {
                        aggregate->status = PassStatus::Applied;
                    } else if (report.status == PassStatus::Unchanged
                        && aggregate->status == PassStatus::Unsupported) {
                        aggregate->status = PassStatus::Unchanged;
                    }
                    aggregate->statistics.examined += report.statistics.examined;
                    aggregate->statistics.changed += report.statistics.changed;
                    aggregate->statistics.skipped += report.statistics.skipped;
                }
            }
            pending.clear();
            return std::nullopt;
        };
        for (std::size_t memberIndex = 0; memberIndex < parsed.value().members.size(); ++memberIndex) {
            auto& member = parsed.value().members[memberIndex];
            if (parsed.value().type == BinaryType::ImportLibrary
                && (member.kind == ArchiveMemberKind::Object
                    || member.kind == ArchiveMemberKind::ImportObject)) {
                ++preservedMembers;
                for (auto& aggregate : aggregates) ++aggregate.statistics.skipped;
                continue;
            }
            if (member.kind != ArchiveMemberKind::Object) {
                if (member.kind == ArchiveMemberKind::ImportObject
                    || member.kind == ArchiveMemberKind::Opaque) {
                    ++preservedMembers;
                    for (auto& aggregate : aggregates) ++aggregate.statistics.skipped;
                }
                continue;
            }
            ++objectMembers;
            if (pending.size() == options->jobs) {
                if (const auto error = flush_pending()) {
                    print_diagnostic(errors, *error, DiagnosticFormat::Text);
                    return 3;
                }
            }
            pending.emplace_back(
                memberIndex,
                std::async(std::launch::async, [member, options]() {
                    return transform_archive_member(member, *options);
                }));
        }
        if (const auto error = flush_pending()) {
            print_diagnostic(errors, *error, DiagnosticFormat::Text);
            return 3;
        }
        const auto written = write_archive(parsed.value());
        if (!written.has_value()) {
            print_diagnostic(errors, written.error(), DiagnosticFormat::Text);
            return 3;
        }
        const auto verificationName = options->output.has_value()
            ? options->output->filename().string() : std::string{"dry-run.a"};
        const auto verified = verify_archive(written.value(), verificationName);
        if (!verified.has_value()) {
            print_diagnostic(errors, verified.error(), DiagnosticFormat::Text);
            return 3;
        }
        std::vector<evidence::ManifestPassReport> manifestReports;
        manifestReports.reserve(aggregates.size());
        for (const auto& aggregate : aggregates) {
            manifestReports.push_back(evidence::ManifestPassReport{
                .name = aggregate.name,
                .status = std::string{pass_status(aggregate.status)},
                .examined = aggregate.statistics.examined,
                .changed = aggregate.statistics.changed,
                .skipped = aggregate.statistics.skipped,
            });
        }
        if (!options->dryRun) {
            if (const auto writeError = commit_transform_outputs(
                    *options,
                    input.value(),
                    written.value(),
                    "archive",
                    to_string(verified.value().image.architecture),
                    std::move(manifestReports))) {
                print_diagnostic(errors, *writeError, DiagnosticFormat::Text);
                return 3;
            }
        }
        output << "input: " << options->input.string() << '\n'
               << "output: "
               << (options->dryRun ? "not-written" : options->output->string()) << '\n'
               << "format: archive\n"
               << "type: " << to_string(verified.value().image.type) << '\n'
               << "passes: " << options->passDescription << '\n'
               << "seed: " << options->seed << '\n'
               << "dry-run: " << (options->dryRun ? "true" : "false") << '\n'
               << "object-members: " << objectMembers << '\n'
               << "transformed-members: " << transformedMembers << '\n'
               << "preserved-members: " << preservedMembers << '\n';
        if (!options->dryRun && options->manifest.enabled.value_or(true)) {
            output << "manifest: " << options->manifest.path->string() << '\n';
        }
        for (const auto& aggregate : aggregates) {
            output << aggregate.name << ": " << pass_status(aggregate.status)
                   << " examined=" << aggregate.statistics.examined
                   << " changed=" << aggregate.statistics.changed
                   << " skipped=" << aggregate.statistics.skipped << '\n';
        }
        output << "archive-symbols: " << verified.value().image.symbols.size() << '\n'
               << "verification: reparsed\n";
        return 0;
    }
    if (is_linked_type(detection.value().type)) {
        if (!options->preservedSymbols.empty()) {
            print_diagnostic(errors, Diagnostic{
                DiagnosticSeverity::Error,
                "linked.symbol_preservation_unsupported",
                "linked debug rewriting does not alter symbols or accept symbol allowlists",
            }, DiagnosticFormat::Text);
            return 3;
        }
        const auto unsupportedCodePass = std::find_if(
            options->passes.begin(), options->passes.end(), [](const auto& name) {
                return name == "instruction-substitution"
                    || name == "constant-rewriting"
                    || name == "branch-inversion"
                    || name == "dead-code-insertion"
                    || name == "block-splitting"
                    || name == "block-reordering"
                    || name == "function-reordering";
            });
        if (unsupportedCodePass != options->passes.end()) {
            print_diagnostic(errors, Diagnostic{
                DiagnosticSeverity::Error,
                "linked.pass_unsupported",
                "post-link code transformation is not enabled: " + *unsupportedCodePass,
            }, DiagnosticFormat::Text);
            return 3;
        }
        const auto parsed = parse_linked_image(
            input.value(), options->input.filename().string());
        if (!parsed.has_value()) {
            print_diagnostic(errors, parsed.error(), DiagnosticFormat::Text);
            return 3;
        }
        const bool stripDebug = std::find(
            options->passes.begin(), options->passes.end(), "strip-debug")
            != options->passes.end();
        const auto rewritten = rewrite_linked_image(parsed.value(), LinkedRewriteOptions{
            .stripDebug = stripDebug,
            .allowSignatureInvalidation = options->allowSignatureInvalidation,
        });
        if (!rewritten.has_value()) {
            print_diagnostic(errors, rewritten.error(), DiagnosticFormat::Text);
            return 3;
        }
        for (const auto& diagnostic : rewritten.value().diagnostics) {
            print_diagnostic(errors, diagnostic, DiagnosticFormat::Text);
        }
        std::vector<evidence::ManifestPassReport> manifestReports;
        manifestReports.reserve(options->passes.size());
        for (const auto& pass : options->passes) {
            if (pass == "strip-debug") {
                const auto removed = rewritten.value().stats.debugRecordsRemoved
                    + rewritten.value().stats.debugSectionsRemoved;
                manifestReports.push_back(evidence::ManifestPassReport{
                    .name = pass,
                    .status = removed == 0 ? "unchanged" : "applied",
                    .examined = parsed.value().image.debugInfo.size(),
                    .changed = removed,
                    .skipped = 0,
                });
            } else {
                manifestReports.push_back(evidence::ManifestPassReport{
                    .name = pass,
                    .status = "unsupported",
                    .examined = 0,
                    .changed = 0,
                    .skipped = 0,
                });
            }
        }
        if (!options->dryRun) {
            if (const auto writeError = commit_transform_outputs(
                    *options,
                    input.value(),
                    rewritten.value().bytes,
                    to_string(rewritten.value().image.image.format),
                    to_string(rewritten.value().image.image.architecture),
                    std::move(manifestReports))) {
                print_diagnostic(errors, *writeError, DiagnosticFormat::Text);
                return 3;
            }
        }
        output << "input: " << options->input.string() << '\n'
               << "output: "
               << (options->dryRun ? "not-written" : options->output->string()) << '\n'
               << "format: " << to_string(rewritten.value().image.image.format) << '\n'
               << "passes: " << options->passDescription << '\n'
               << "seed: " << options->seed << '\n'
               << "dry-run: " << (options->dryRun ? "true" : "false") << '\n';
        if (!options->dryRun && options->manifest.enabled.value_or(true)) {
            output << "manifest: " << options->manifest.path->string() << '\n';
        }
        for (const auto& pass : options->passes) {
            if (pass == "strip-debug") {
                const auto removed = rewritten.value().stats.debugRecordsRemoved
                    + rewritten.value().stats.debugSectionsRemoved;
                output << "strip-debug: " << (removed == 0 ? "unchanged" : "applied")
                       << " examined=" << parsed.value().image.debugInfo.size()
                       << " changed=" << removed << " skipped=0\n";
            } else {
                output << pass << ": unsupported examined=0 changed=0 skipped=0\n";
            }
        }
        output << "signature-removed: "
               << (rewritten.value().stats.signatureRemoved ? "true" : "false") << '\n'
               << "bytes-changed: " << rewritten.value().stats.bytesChanged << '\n'
               << "verification: reparsed\n";
        return 0;
    }
    if (options->allowSignatureInvalidation) {
        print_diagnostic(errors, Diagnostic{
            DiagnosticSeverity::Error,
            "object.signature_option_not_applicable",
            "signature invalidation is only applicable to linked PE images",
        }, DiagnosticFormat::Text);
        return 3;
    }
    auto parsed = parse_object(input.value(), options->input.filename().string());
    if (!parsed.has_value()) {
        print_diagnostic(errors, parsed.error(), DiagnosticFormat::Text);
        return 3;
    }
    const bool usesMediumRisk = uses_medium_risk_pass(options->passes);
    if (usesMediumRisk) {
        errors << "[warning] medium-risk machine-code transformations enabled; "
                  "unsupported functions will be skipped\n";
    }
    PassManager manager;
    if (const auto managerError = configure_pass_manager(manager, options->passes)) {
        print_diagnostic(errors, *managerError, DiagnosticFormat::Text);
        return 3;
    }
    TransformContext context{options->seed, options->dryRun};
    for (const auto& symbol : options->preservedSymbols) context.preserve_symbol(symbol);
    if (const auto selectionError = configure_function_selection(
            context, options->selection, options->seed)) {
        print_diagnostic(errors, *selectionError, DiagnosticFormat::Text);
        return 3;
    }
    const auto transformed = manager.run(context, parsed.value());
    if (!transformed.has_value()) {
        print_diagnostic(errors, transformed.error(), DiagnosticFormat::Text);
        return 3;
    }
    const auto written = write_object(transformed.value().image);
    if (!written.has_value()) {
        print_diagnostic(errors, written.error(), DiagnosticFormat::Text);
        return 3;
    }
    const auto verificationName = options->output.has_value()
        ? options->output->filename().string() : std::string{"dry-run.o"};
    const auto verified = verify_object(written.value(), verificationName);
    if (!verified.has_value()
        || verified.value().image.format != parsed.value().format
        || verified.value().image.architecture != parsed.value().architecture) {
        print_diagnostic(errors, Diagnostic{
            DiagnosticSeverity::Error,
            "object.output_invalid",
            "emitted object failed structural round-trip verification",
        }, DiagnosticFormat::Text);
        return 3;
    }
    std::vector<evidence::ManifestPassReport> manifestReports;
    manifestReports.reserve(transformed.value().reports.size());
    for (const auto& report : transformed.value().reports) {
        manifestReports.push_back(evidence::ManifestPassReport{
            .name = report.name,
            .status = std::string{pass_status(report.status)},
            .examined = report.statistics.examined,
            .changed = report.statistics.changed,
            .skipped = report.statistics.skipped,
        });
    }
    std::optional<std::string> lineageJson;
    if (options->lineagePath.has_value() && !options->dryRun) {
        const auto originalAnalysis = analyze_object(parsed.value());
        if (!originalAnalysis.has_value()) {
            print_diagnostic(errors, originalAnalysis.error(), DiagnosticFormat::Text);
            return 3;
        }
        const auto protectedAnalysis = analyze_object(verified.value().image);
        if (!protectedAnalysis.has_value()) {
            print_diagnostic(errors, protectedAnalysis.error(), DiagnosticFormat::Text);
            return 3;
        }
        const auto inputHash = sha256_of(input.value());
        const auto outputHash = sha256_of(written.value());
        if (!inputHash.has_value() || !outputHash.has_value()) {
            print_diagnostic(
                errors,
                inputHash.has_value() ? outputHash.error() : inputHash.error(),
                DiagnosticFormat::Text);
            return 3;
        }
        const auto lineage = evidence::make_object_lineage(
            originalAnalysis.value().image,
            protectedAnalysis.value().image,
            transformed.value().image,
            inputHash.value(),
            outputHash.value());
        if (!lineage.has_value()) {
            print_diagnostic(errors, lineage.error(), DiagnosticFormat::Text);
            return 3;
        }
        lineageJson = evidence::serialize_lineage(lineage.value());
    }
    if (!options->dryRun) {
        if (const auto writeError = commit_transform_outputs(
                *options,
                input.value(),
                written.value(),
                to_string(verified.value().image.format),
                to_string(verified.value().image.architecture),
                std::move(manifestReports),
                std::move(lineageJson))) {
            print_diagnostic(errors, *writeError, DiagnosticFormat::Text);
            return 3;
        }
    }
    output << "input: " << options->input.string() << '\n'
           << "output: " << (options->dryRun ? "not-written" : options->output->string()) << '\n'
           << "format: " << to_string(verified.value().image.format) << '\n'
           << "passes: " << options->passDescription << '\n'
           << "seed: " << options->seed << '\n'
           << "dry-run: " << (options->dryRun ? "true" : "false") << '\n';
    if (!options->dryRun && options->manifest.enabled.value_or(true)) {
        output << "manifest: " << options->manifest.path->string() << '\n';
    }
    if (options->lineagePath.has_value()) {
        output << "lineage: "
               << (options->dryRun ? std::string{"not-written"}
                                   : options->lineagePath->string())
               << '\n';
    }
    for (const auto& report : transformed.value().reports) {
        output << report.name << ": " << pass_status(report.status)
               << " examined=" << report.statistics.examined
               << " changed=" << report.statistics.changed
               << " skipped=" << report.statistics.skipped << '\n';
    }
    output
           << "verification: reparsed\n";
    return 0;
}

void print_formats(std::ostream& output) {
    output << render_format_capabilities_text(builtin_capability_registry());
}

void print_architectures(std::ostream& output) {
    output << render_architecture_capabilities_text(builtin_capability_registry());
}

void print_passes(std::ostream& output) {
    output << render_pass_capabilities_text();
}

struct VmLowerOptions {
    enum class AdvancedCfg : std::uint8_t {
        None,
        Flatten,
        Outline,
        Split,
    };

    std::filesystem::path input;
    std::filesystem::path output;
    std::string function;
    ir::NativeAbi abi{ir::NativeAbi::WindowsX64};
    std::string abiName;
    std::size_t argumentCount{0};
    std::uint64_t seed{0};
    bool hasOutput{false};
    bool hasFunction{false};
    bool hasAbi{false};
    bool hasArgumentCount{false};
    bool hasSeed{false};
    AdvancedCfg advancedCfg{AdvancedCfg::None};
    std::optional<ir::IrBlockId> outlineBlock;
};

auto parse_vm_lower_options(
    std::span<const std::string_view> arguments,
    std::ostream& errors) -> std::optional<VmLowerOptions> {
    if (arguments.size() < 4 || arguments[1] != "lower") {
        print_usage(errors);
        return std::nullopt;
    }
    VmLowerOptions options;
    options.input = std::filesystem::path{std::string{arguments[2]}};
    for (std::size_t index = 3; index < arguments.size(); ++index) {
        const auto argument = arguments[index];
        if (argument == "-o") {
            if (options.hasOutput || index + 1 >= arguments.size()) {
                errors << "vm lower requires one output path after -o\n";
                return std::nullopt;
            }
            options.output = std::filesystem::path{std::string{arguments[++index]}};
            options.hasOutput = true;
        } else if (argument.starts_with("--function=")) {
            if (options.hasFunction || argument.size() == std::string_view{"--function="}.size()) {
                errors << "vm lower requires one non-empty function name\n";
                return std::nullopt;
            }
            options.function = std::string{argument.substr(std::string_view{"--function="}.size())};
            options.hasFunction = true;
        } else if (argument.starts_with("--abi=")) {
            if (options.hasAbi) {
                errors << "vm lower ABI was specified more than once\n";
                return std::nullopt;
            }
            const auto value = argument.substr(std::string_view{"--abi="}.size());
            if (value == "windows-x64") {
                options.abi = ir::NativeAbi::WindowsX64;
            } else if (value == "sysv-amd64") {
                options.abi = ir::NativeAbi::SystemVAMD64;
            } else {
                errors << "vm lower ABI must be windows-x64 or sysv-amd64\n";
                return std::nullopt;
            }
            options.abiName = std::string{value};
            options.hasAbi = true;
        } else if (argument.starts_with("--args=")) {
            if (options.hasArgumentCount) {
                errors << "vm lower argument count was specified more than once\n";
                return std::nullopt;
            }
            const auto value = argument.substr(std::string_view{"--args="}.size());
            std::size_t parsedValue = 0;
            const auto parsed = std::from_chars(
                value.data(), value.data() + value.size(), parsedValue, 10);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()
                || parsedValue > 4) {
                errors << "vm lower argument count must be an integer from 0 through 4\n";
                return std::nullopt;
            }
            options.argumentCount = parsedValue;
            options.hasArgumentCount = true;
        } else if (argument.starts_with("--seed=")) {
            if (options.hasSeed) {
                errors << "vm lower seed was specified more than once\n";
                return std::nullopt;
            }
            const auto value = argument.substr(std::string_view{"--seed="}.size());
            const auto parsed = std::from_chars(
                value.data(), value.data() + value.size(), options.seed, 10);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
                errors << "vm lower seed must be an unsigned decimal integer\n";
                return std::nullopt;
            }
            options.hasSeed = true;
        } else if (argument == "--cfg=flatten") {
            if (options.advancedCfg != VmLowerOptions::AdvancedCfg::None) {
                errors << "vm lower accepts only one advanced CFG transformation\n";
                return std::nullopt;
            }
            options.advancedCfg = VmLowerOptions::AdvancedCfg::Flatten;
        } else if (argument == "--split-function") {
            if (options.advancedCfg != VmLowerOptions::AdvancedCfg::None) {
                errors << "vm lower accepts only one advanced CFG transformation\n";
                return std::nullopt;
            }
            options.advancedCfg = VmLowerOptions::AdvancedCfg::Split;
        } else if (argument.starts_with("--outline-block=")) {
            if (options.advancedCfg != VmLowerOptions::AdvancedCfg::None) {
                errors << "vm lower accepts only one advanced CFG transformation\n";
                return std::nullopt;
            }
            const auto value = argument.substr(std::string_view{"--outline-block="}.size());
            std::uint32_t parsedValue = 0;
            const auto parsed = std::from_chars(
                value.data(), value.data() + value.size(), parsedValue, 10);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
                errors << "vm lower outline block must be an unsigned decimal IR block ID\n";
                return std::nullopt;
            }
            options.advancedCfg = VmLowerOptions::AdvancedCfg::Outline;
            options.outlineBlock = ir::IrBlockId{parsedValue};
        } else {
            errors << "unknown vm lower option: " << argument << '\n';
            return std::nullopt;
        }
    }
    if (!options.hasOutput || !options.hasFunction || !options.hasAbi
        || !options.hasArgumentCount) {
        errors << "vm lower requires --function, --abi, --args, and -o\n";
        return std::nullopt;
    }
    return options;
}

auto vm_lower(
    std::span<const std::string_view> arguments,
    std::ostream& output,
    std::ostream& errors) -> int {
    const auto options = parse_vm_lower_options(arguments, errors);
    if (!options.has_value()) {
        print_usage(errors);
        return 2;
    }
    if (paths_conflict(options->input, options->output)) {
        print_diagnostic(errors, Diagnostic{
            DiagnosticSeverity::Error,
            "io.output_matches_input",
            "refusing to replace the input object with VM bytecode",
        }, DiagnosticFormat::Text);
        return 3;
    }
    const auto input = read_input(options->input);
    if (!input.has_value()) {
        print_diagnostic(errors, input.error(), DiagnosticFormat::Text);
        return 3;
    }
    BinaryImage parsedImage;
    std::string selectedFunctionName = options->function;
    const auto detection = detect_binary(input.value(), options->input.filename().string());
    if (!detection.has_value()) {
        print_diagnostic(errors, detection.error(), DiagnosticFormat::Text);
        return 3;
    }
    if (is_archive_format(detection.value().format)) {
        const auto separator = options->function.find("::");
        if (separator == std::string::npos || separator == 0U
            || separator + 2U >= options->function.size()) {
            print_diagnostic(errors, Diagnostic{
                DiagnosticSeverity::Error,
                "ir.archive_function_identity",
                "archive VM lowering requires --function=member::function",
            }, DiagnosticFormat::Text);
            return 3;
        }
        const auto memberName = std::string_view{options->function}.substr(0, separator);
        selectedFunctionName = options->function.substr(separator + 2U);
        const auto archive = parse_archive(input.value(), options->input.filename().string());
        if (!archive.has_value()) {
            print_diagnostic(errors, archive.error(), DiagnosticFormat::Text);
            return 3;
        }
        const auto member = std::find_if(
            archive.value().members.begin(), archive.value().members.end(),
            [&](const auto& candidate) {
                return candidate.kind == ArchiveMemberKind::Object
                    && candidate.name == memberName;
            });
        if (member == archive.value().members.end()) {
            print_diagnostic(errors, Diagnostic{
                DiagnosticSeverity::Error,
                "ir.archive_member_not_found",
                "selected archive member was not found: " + std::string{memberName},
            }, DiagnosticFormat::Text);
            return 3;
        }
        const auto parsed = parse_object(member->contents, member->name);
        if (!parsed.has_value()) {
            print_diagnostic(errors, parsed.error(), DiagnosticFormat::Text);
            return 3;
        }
        parsedImage = parsed.value();
    } else if (is_linked_type(detection.value().type)) {
        const auto linked = parse_linked_image(
            input.value(), options->input.filename().string());
        if (!linked.has_value()) {
            print_diagnostic(errors, linked.error(), DiagnosticFormat::Text);
            return 3;
        }
        parsedImage = linked.value().image;
    } else {
        const auto parsed = parse_object(input.value(), options->input.filename().string());
        if (!parsed.has_value()) {
            print_diagnostic(errors, parsed.error(), DiagnosticFormat::Text);
            return 3;
        }
        parsedImage = parsed.value();
    }
    const auto analyzed = analyze_object(parsedImage);
    if (!analyzed.has_value()) {
        print_diagnostic(errors, analyzed.error(), DiagnosticFormat::Text);
        return 3;
    }
    const auto function = std::find_if(
        analyzed.value().image.functions.begin(),
        analyzed.value().image.functions.end(),
        [&](const auto& candidate) { return candidate.name == selectedFunctionName; });
    if (function == analyzed.value().image.functions.end()) {
        print_diagnostic(errors, Diagnostic{
            DiagnosticSeverity::Error,
            "ir.function_not_found",
            "selected function was not recovered: " + selectedFunctionName,
        }, DiagnosticFormat::Text);
        return 3;
    }
    ir::NativeFunctionSignature signature;
    signature.abi = options->abi;
    signature.arguments.assign(options->argumentCount, ir::IrType{ir::IrWidth::U32});
    signature.returnType = ir::IrType{ir::IrWidth::U32};
    const auto lifted = ir::lift_function(
        analyzed.value().image, function->id, signature);
    if (!lifted.has_value()) {
        print_diagnostic(errors, lifted.error(), DiagnosticFormat::Text);
        return 3;
    }
    if (!lifted.value().complete) {
        for (const auto& diagnostic : lifted.value().diagnostics) {
            print_diagnostic(errors, diagnostic, DiagnosticFormat::Text);
        }
        return 3;
    }
    std::string_view cfgName = "none";
    if (options->advancedCfg != VmLowerOptions::AdvancedCfg::None) {
        switch (options->advancedCfg) {
        case VmLowerOptions::AdvancedCfg::Flatten: cfgName = "flatten"; break;
        case VmLowerOptions::AdvancedCfg::Outline: cfgName = "outline"; break;
        case VmLowerOptions::AdvancedCfg::Split: cfgName = "split"; break;
        case VmLowerOptions::AdvancedCfg::None: break;
        }
        errors << "warning: high-risk control-flow transformation enabled: "
               << cfgName << '\n';
    }
    const auto lowered = [&]() -> Result<ir::VmLoweringReport, Diagnostic> {
        switch (options->advancedCfg) {
        case VmLowerOptions::AdvancedCfg::None:
            return ir::lower_to_vm(lifted.value().function);
        case VmLowerOptions::AdvancedCfg::Flatten: {
            const auto transformed = ir::flatten_control_flow(
                lifted.value().function, options->seed);
            if (!transformed.has_value()) {
                return Result<ir::VmLoweringReport, Diagnostic>::failure(
                    transformed.error());
            }
            return ir::lower_to_vm(transformed.value().function);
        }
        case VmLowerOptions::AdvancedCfg::Outline: {
            const auto transformed = ir::outline_block(
                lifted.value().function, *options->outlineBlock, options->seed);
            if (!transformed.has_value()) {
                return Result<ir::VmLoweringReport, Diagnostic>::failure(
                    transformed.error());
            }
            return ir::lower_module_to_vm(transformed.value().module);
        }
        case VmLowerOptions::AdvancedCfg::Split: {
            const auto transformed = ir::split_function(
                lifted.value().function, options->seed);
            if (!transformed.has_value()) {
                return Result<ir::VmLoweringReport, Diagnostic>::failure(
                    transformed.error());
            }
            return ir::lower_module_to_vm(transformed.value().module);
        }
        }
        return Result<ir::VmLoweringReport, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "ir.invalid_cfg_transform",
            "advanced CFG transformation selection is invalid"});
    }();
    if (!lowered.has_value()) {
        print_diagnostic(errors, lowered.error(), DiagnosticFormat::Text);
        return 3;
    }
    const auto assembled = vm::assemble_program(
        lowered.value().program, vm::VmAssemblyOptions{options->seed});
    if (!assembled.has_value()) {
        print_diagnostic(errors, assembled.error(), DiagnosticFormat::Text);
        return 3;
    }
    if (const auto writeError = write_output_transactionally(options->output, assembled.value())) {
        print_diagnostic(errors, *writeError, DiagnosticFormat::Text);
        return 3;
    }
    output << "function: " << options->function << '\n'
           << "abi: " << options->abiName << '\n'
           << "arguments: " << options->argumentCount << " x u32\n"
           << "seed: " << options->seed << '\n'
           << "cfg-transform: " << cfgName << '\n'
           << "bytecode: " << options->output.string() << '\n';
    return 0;
}

struct VmProtectOptions {
    std::filesystem::path input;
    std::filesystem::path output;
    std::string function;
    ir::NativeAbi abi{ir::NativeAbi::WindowsX64};
    std::string abiName;
    std::size_t argumentCount{0};
    std::uint64_t seed{0};
    bool hasOutput{false};
    bool hasFunction{false};
    bool hasAbi{false};
    bool hasArgumentCount{false};
    bool hasSeed{false};
};

auto parse_vm_protect_options(
    std::span<const std::string_view> arguments,
    std::ostream& errors) -> std::optional<VmProtectOptions> {
    if (arguments.size() < 4 || arguments[1] != "protect") {
        print_usage(errors);
        return std::nullopt;
    }
    VmProtectOptions options;
    options.input = std::filesystem::path{std::string{arguments[2]}};
    for (std::size_t index = 3; index < arguments.size(); ++index) {
        const auto argument = arguments[index];
        if (argument == "-o") {
            if (options.hasOutput || index + 1 >= arguments.size()) {
                errors << "vm protect requires one output path after -o\n";
                return std::nullopt;
            }
            options.output = std::filesystem::path{std::string{arguments[++index]}};
            options.hasOutput = true;
        } else if (argument.starts_with("--function=")) {
            if (options.hasFunction
                || argument.size() == std::string_view{"--function="}.size()) {
                errors << "vm protect requires one non-empty function name\n";
                return std::nullopt;
            }
            options.function = std::string{
                argument.substr(std::string_view{"--function="}.size())};
            options.hasFunction = true;
        } else if (argument.starts_with("--abi=")) {
            if (options.hasAbi) {
                errors << "vm protect ABI was specified more than once\n";
                return std::nullopt;
            }
            const auto value = argument.substr(std::string_view{"--abi="}.size());
            if (value == "windows-x64") {
                options.abi = ir::NativeAbi::WindowsX64;
            } else if (value == "sysv-amd64") {
                options.abi = ir::NativeAbi::SystemVAMD64;
            } else {
                errors << "vm protect ABI must be windows-x64 or sysv-amd64\n";
                return std::nullopt;
            }
            options.abiName = std::string{value};
            options.hasAbi = true;
        } else if (argument.starts_with("--args=")) {
            if (options.hasArgumentCount) {
                errors << "vm protect argument count was specified more than once\n";
                return std::nullopt;
            }
            const auto value = argument.substr(std::string_view{"--args="}.size());
            std::size_t parsedValue = 0;
            const auto parsed = std::from_chars(
                value.data(), value.data() + value.size(), parsedValue, 10);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()
                || parsedValue > 8) {
                errors << "vm protect argument count must be an integer from 0 through 8\n";
                return std::nullopt;
            }
            options.argumentCount = parsedValue;
            options.hasArgumentCount = true;
        } else if (argument.starts_with("--seed=")) {
            if (options.hasSeed) {
                errors << "vm protect seed was specified more than once\n";
                return std::nullopt;
            }
            const auto value = argument.substr(std::string_view{"--seed="}.size());
            const auto parsed = std::from_chars(
                value.data(), value.data() + value.size(), options.seed, 10);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
                errors << "vm protect seed must be an unsigned decimal integer\n";
                return std::nullopt;
            }
            options.hasSeed = true;
        } else {
            errors << "unknown vm protect option: " << argument << '\n';
            return std::nullopt;
        }
    }
    if (!options.hasOutput || !options.hasFunction || !options.hasAbi
        || !options.hasArgumentCount) {
        errors << "vm protect requires --function, --abi, --args, and -o\n";
        return std::nullopt;
    }
    return options;
}

auto vm_protect(
    std::span<const std::string_view> arguments,
    std::ostream& output,
    std::ostream& errors) -> int {
    const auto options = parse_vm_protect_options(arguments, errors);
    if (!options.has_value()) {
        print_usage(errors);
        return 2;
    }
    if (paths_conflict(options->input, options->output)) {
        print_diagnostic(errors, Diagnostic{
            DiagnosticSeverity::Error,
            "io.output_matches_input",
            "refusing to replace the input object during VM protection",
        }, DiagnosticFormat::Text);
        return 3;
    }
    const auto input = read_input(options->input);
    if (!input.has_value()) {
        print_diagnostic(errors, input.error(), DiagnosticFormat::Text);
        return 3;
    }
    const auto protectionOptions = vm::VmProtectionOptions{
        .function = options->function,
        .abi = options->abi,
        .argumentCount = options->argumentCount,
        .seed = options->seed,
    };
    std::optional<vm::VmProtectionReport> report;
    std::string protectedMember;
    std::vector<std::byte> writtenBytes;
    if (const auto detection = detect_binary(input.value(), options->input.filename().string());
        detection.has_value() && is_archive_format(detection.value().format)) {
        const auto separator = options->function.find("::");
        const auto memberSelector = separator == std::string::npos
            ? std::string_view{}
            : std::string_view{options->function}.substr(0, separator);
        const auto selectedFunction = separator == std::string::npos
            ? std::string_view{options->function}
            : std::string_view{options->function}.substr(separator + 2U);
        if (selectedFunction.empty() || (separator != std::string::npos && memberSelector.empty())) {
            print_diagnostic(errors, Diagnostic{
                DiagnosticSeverity::Error,
                "vm.protection_function",
                "archive VM protection requires member::function with non-empty names",
            }, DiagnosticFormat::Text);
            return 3;
        }
        auto archive = parse_archive(input.value(), options->input.filename().string());
        if (!archive.has_value()) {
            print_diagnostic(errors, archive.error(), DiagnosticFormat::Text);
            return 3;
        }
        std::optional<Diagnostic> firstFailure;
        for (auto& member : archive.value().members) {
            if (member.kind != ArchiveMemberKind::Object) continue;
            if (!memberSelector.empty() && member.name != memberSelector) continue;
            const auto parsed = parse_object(member.contents, member.name);
            if (!parsed.has_value()) {
                print_diagnostic(errors, parsed.error(), DiagnosticFormat::Text);
                return 3;
            }
            auto memberProtectionOptions = protectionOptions;
            memberProtectionOptions.function = std::string{selectedFunction};
            const auto protectedResult = vm::protect_function(
                parsed.value(), memberProtectionOptions);
            if (!protectedResult.has_value()) {
                if (!firstFailure.has_value() || protectedResult.error().code != "vm.protection_function_not_found") {
                    firstFailure = protectedResult.error();
                }
                if (protectedResult.error().code != "vm.protection_function_not_found") break;
                continue;
            }
            const auto memberBytes = write_object(protectedResult.value().image);
            if (!memberBytes.has_value()) {
                print_diagnostic(errors, memberBytes.error(), DiagnosticFormat::Text);
                return 3;
            }
            member.contents = memberBytes.value();
            report = protectedResult.value().report;
            protectedMember = member.name;
            break;
        }
        if (!report.has_value()) {
            print_diagnostic(errors, firstFailure.value_or(Diagnostic{
                DiagnosticSeverity::Error, "vm.protection_function_not_found",
                "selected function was not found in any archive object"}), DiagnosticFormat::Text);
            return 3;
        }
        const auto archiveBytes = write_archive(archive.value());
        if (!archiveBytes.has_value()) {
            print_diagnostic(errors, archiveBytes.error(), DiagnosticFormat::Text);
            return 3;
        }
        const auto verified = verify_archive(archiveBytes.value(), options->output.filename().string());
        if (!verified.has_value()) {
            print_diagnostic(errors, verified.error(), DiagnosticFormat::Text);
            return 3;
        }
        writtenBytes = archiveBytes.value();
    } else {
        const auto parsed = parse_object(input.value(), options->input.filename().string());
        if (!parsed.has_value()) {
            print_diagnostic(errors, parsed.error(), DiagnosticFormat::Text);
            return 3;
        }
        const auto protectedResult = vm::protect_function(parsed.value(), protectionOptions);
        if (!protectedResult.has_value()) {
            print_diagnostic(errors, protectedResult.error(), DiagnosticFormat::Text);
            return 3;
        }
        const auto written = write_object(protectedResult.value().image);
        if (!written.has_value()) {
            print_diagnostic(errors, written.error(), DiagnosticFormat::Text);
            return 3;
        }
        const auto verified = verify_object(written.value(), options->output.filename().string());
        if (!verified.has_value()) {
            print_diagnostic(errors, verified.error(), DiagnosticFormat::Text);
            return 3;
        }
        report = protectedResult.value().report;
        writtenBytes = written.value();
    }
    if (const auto writeError = write_output_transactionally(options->output, writtenBytes)) {
        print_diagnostic(errors, *writeError, DiagnosticFormat::Text);
        return 3;
    }
    output << "function: " << report->functionName << '\n'
           << "abi: " << options->abiName << '\n'
           << "arguments: " << report->argumentCount << " x u32\n"
           << "seed: " << report->seed << '\n'
           << "section: " << report->sectionName << '\n'
           << "original-address: " << report->originalAddress << '\n'
           << "protected-address: " << report->protectedAddress << '\n'
           << "wrapper-offset: " << report->wrapperOffset << '\n'
           << "wrapper-size: " << report->wrapperSize << '\n'
           << "bytecode-offset: " << report->bytecodeOffset << '\n'
           << "bytecode-size: " << report->bytecodeSize << '\n'
           << "runtime-symbol: " << report->runtimeSymbol << '\n'
           << "runtime-relocation-offset: " << report->runtimeRelocationOffset << '\n'
           << (protectedMember.empty() ? "" : "protected-member: " + protectedMember + '\n')
           << "protected-object: " << options->output.string() << '\n'
           << "verification: reparsed\n";
    return 0;
}

auto vm_command(
    std::span<const std::string_view> arguments,
    std::ostream& output,
    std::ostream& errors) -> int {
    if (arguments.size() >= 2 && arguments[1] == "lower") {
        return vm_lower(arguments, output, errors);
    }
    if (arguments.size() >= 2 && arguments[1] == "protect") {
        return vm_protect(arguments, output, errors);
    }
    if (arguments.size() != 3 || arguments[1] != "disassemble") {
        print_usage(errors);
        return 2;
    }
    const std::filesystem::path path{std::string{arguments[2]}};
    const auto input = read_input(path);
    if (!input.has_value()) {
        print_diagnostic(errors, input.error(), DiagnosticFormat::Text);
        return 3;
    }
    const auto disassembled = vm::disassemble_bytecode(input.value());
    if (!disassembled.has_value()) {
        print_diagnostic(errors, disassembled.error(), DiagnosticFormat::Text);
        return 3;
    }
    output << disassembled.value();
    return 0;
}

auto config_command(
    std::span<const std::string_view> arguments,
    std::ostream& output,
    std::ostream& errors) -> int {
    if (arguments.size() != 2) {
        print_usage(errors);
        return 2;
    }
    const std::filesystem::path path{std::string{arguments[1]}};
    const auto bytes = read_input(path);
    if (!bytes.has_value()) {
        print_diagnostic(errors, bytes.error(), DiagnosticFormat::Text);
        return 3;
    }
    const auto parsed = config::parse_transform_config(bytes.value(), path);
    if (!parsed.has_value()) {
        print_diagnostic(errors, parsed.error(), DiagnosticFormat::Text);
        return 3;
    }
    output << parsed.value().canonicalJson << '\n';
    return 0;
}

auto lineage_command(
    std::span<const std::string_view> arguments,
    std::ostream& output,
    std::ostream& errors) -> int {
    constexpr std::string_view prefix{"--protected-address="};
    if (arguments.size() != 3 || !arguments[2].starts_with(prefix)) {
        print_usage(errors);
        return 2;
    }
    auto value = arguments[2].substr(prefix.size());
    int base = 10;
    if (value.starts_with("0x") || value.starts_with("0X")) {
        value.remove_prefix(2);
        base = 16;
    }
    std::uint64_t address = 0;
    const auto parsedAddress = std::from_chars(
        value.data(), value.data() + value.size(), address, base);
    if (value.empty() || parsedAddress.ec != std::errc{} ||
        parsedAddress.ptr != value.data() + value.size()) {
        errors << "protected address must be an unsigned decimal or hexadecimal integer\n";
        return 2;
    }

    const std::filesystem::path path{std::string{arguments[1]}};
    const auto bytes = read_input(path);
    if (!bytes.has_value()) {
        print_diagnostic(errors, bytes.error(), DiagnosticFormat::Text);
        return 3;
    }
    const auto document = evidence::parse_lineage(bytes.value());
    if (!document.has_value()) {
        print_diagnostic(errors, document.error(), DiagnosticFormat::Text);
        return 3;
    }
    const auto query = evidence::query_lineage(document.value(), address);
    if (!query.has_value()) {
        print_diagnostic(errors, query.error(), DiagnosticFormat::Text);
        return 3;
    }
    output << "protected-function: " << query.value().protectedEntity.name << '\n'
           << "protected-section: " << query.value().protectedEntity.section << '\n'
           << "protected-address: " << query.value().protectedEntity.address << '\n'
           << "original-function: " << query.value().originalEntity.name << '\n'
           << "original-section: " << query.value().originalEntity.section << '\n'
           << "original-address: " << query.value().originalEntity.address << '\n'
           << "address-kind: " << query.value().originalEntity.addressKind << '\n';
    if (query.value().transforms.empty()) {
        output << "transforms: none\n";
    } else {
        for (const auto& transform : query.value().transforms) {
            output << "transform: " << transform.id << ':' << transform.pass
                   << " source=" << transform.sourceEntity << '\n';
        }
    }
    return 0;
}

} // namespace

auto run_cli(
    std::span<const std::string_view> arguments,
    std::ostream& output,
    std::ostream& errors) -> int {
    if (arguments.empty()) {
        print_usage(errors);
        return 2;
    }

    const auto command = arguments.front();
    if (command == "help" || command == "--help" || command == "-h") {
        print_usage(output);
        return 0;
    }
    if (command == "version" || command == "--version") {
        if (arguments.size() != 1) {
            print_usage(errors);
            return 2;
        }
        output << "binobf " << evidence::tool_version() << '\n';
        return 0;
    }
    if (command == "formats") {
        if (arguments.size() != 1) {
            print_usage(errors);
            return 2;
        }
        print_formats(output);
        return 0;
    }
    if (command == "architectures") {
        if (arguments.size() != 1) {
            print_usage(errors);
            return 2;
        }
        print_architectures(output);
        return 0;
    }
    if (command == "passes") {
        if (arguments.size() != 1) {
            print_usage(errors);
            return 2;
        }
        print_passes(output);
        return 0;
    }
    if (command == "config") {
        return config_command(arguments, output, errors);
    }
    if (command == "lineage") {
        return lineage_command(arguments, output, errors);
    }
    if (command == "vm") {
        return vm_command(arguments, output, errors);
    }
    if (command == "inspect") {
        if (arguments.size() < 2) {
            print_usage(errors);
            return 2;
        }
        return inspect(arguments, output, errors);
    }
    if (command == "analyze") {
        if (arguments.size() < 2) {
            print_usage(errors);
            return 2;
        }
        return analyze(arguments, output, errors);
    }
    if (command == "verify") {
        if (arguments.size() < 2) {
            print_usage(errors);
            return 2;
        }
        return verify(arguments, output, errors);
    }
    if (command == "transform") {
        if (arguments.size() < 2) {
            print_usage(errors);
            return 2;
        }
        return transform(arguments, output, errors);
    }

    errors << "unknown command: " << command << '\n';
    print_usage(errors);
    return 2;
}

} // namespace binobf::cli

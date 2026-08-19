#include "../test_support.hpp"

#include <binobf/cli/command.hpp>
#include <binobf/capabilities/render.hpp>
#include <binobf/formats/archive.hpp>
#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/evidence/manifest.hpp>
#include <binobf/support/sha256.hpp>
#include <binobf/vm/bytecode.hpp>

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

using namespace std::string_view_literals;

namespace {

class TemporaryFile {
public:
    TemporaryFile(std::string_view name, const std::vector<std::byte>& contents)
        : path_(std::filesystem::temp_directory_path() / std::string{name}) {
        std::ofstream stream(path_, std::ios::binary | std::ios::trunc);
        if (!stream) {
            throw std::runtime_error("could not create CLI test fixture");
        }
        stream.write(
            reinterpret_cast<const char*>(contents.data()),
            static_cast<std::streamsize>(contents.size()));
        if (!stream) {
            throw std::runtime_error("could not write CLI test fixture");
        }
    }

    TemporaryFile(const TemporaryFile&) = delete;
    auto operator=(const TemporaryFile&) -> TemporaryFile& = delete;

    ~TemporaryFile() {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
    }

    [[nodiscard]] auto path() const -> const std::filesystem::path& { return path_; }

private:
    std::filesystem::path path_;
};

class TemporaryOutput {
public:
    explicit TemporaryOutput(std::string_view name)
        : path_(std::filesystem::temp_directory_path() / std::string{name}) {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
        auto temporary = path_;
        temporary += ".binobf.tmp";
        std::filesystem::remove(temporary, ignored);
    }

    TemporaryOutput(const TemporaryOutput&) = delete;
    auto operator=(const TemporaryOutput&) -> TemporaryOutput& = delete;

    ~TemporaryOutput() {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
        auto temporary = path_;
        temporary += ".binobf.tmp";
        std::filesystem::remove(temporary, ignored);
        auto manifest = manifest_path();
        std::filesystem::remove(manifest, ignored);
        manifest += ".binobf.tmp";
        std::filesystem::remove(manifest, ignored);
    }

    [[nodiscard]] auto path() const -> const std::filesystem::path& { return path_; }
    [[nodiscard]] auto manifest_path() const -> std::filesystem::path {
        auto result = path_;
        result += ".manifest.json";
        return result;
    }

private:
    std::filesystem::path path_;
};

void put_u16(std::vector<std::byte>& bytes, std::size_t offset, std::uint16_t value) {
    bytes.at(offset) = static_cast<std::byte>(value & 0xffU);
    bytes.at(offset + 1) = static_cast<std::byte>((value >> 8U) & 0xffU);
}

void put_u32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        bytes.at(offset + index) = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

auto make_elf64_object() -> std::vector<std::byte> {
    std::vector<std::byte> bytes(64);
    bytes[0] = std::byte{0x7f};
    bytes[1] = std::byte{'E'};
    bytes[2] = std::byte{'L'};
    bytes[3] = std::byte{'F'};
    bytes[4] = std::byte{2};
    bytes[5] = std::byte{1};
    bytes[6] = std::byte{1};
    put_u16(bytes, 16, 1);
    put_u16(bytes, 18, 62);
    put_u32(bytes, 20, 1);
    put_u16(bytes, 52, 64);
    return bytes;
}

auto make_coff_object() -> std::vector<std::byte> {
    std::vector<std::byte> bytes(64);
    put_u16(bytes, 0, 0x8664);
    put_u16(bytes, 2, 1);
    put_u16(bytes, 16, 0);
    constexpr std::string_view name = ".text";
    for (std::size_t index = 0; index < name.size(); ++index) {
        bytes[20 + index] = static_cast<std::byte>(name[index]);
    }
    put_u32(bytes, 20 + 16, 4);
    put_u32(bytes, 20 + 20, 60);
    put_u32(bytes, 20 + 36, 0x60500020U);
    bytes[60] = std::byte{0x90};
    bytes[61] = std::byte{0x90};
    bytes[62] = std::byte{0x90};
    bytes[63] = std::byte{0x90};
    return bytes;
}

auto make_coff_function_object() -> std::vector<std::byte> {
    binobf::BinaryImage image;
    image.format = binobf::BinaryFormat::COFF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86_64;
    image.sections.push_back(binobf::Section{
        .id = binobf::EntityId{1}, .formatIndex = 1,
        .formatFlags = 0x60500020, .name = ".text", .kind = binobf::SectionKind::Code,
        .address = {}, .logicalSize = 3, .alignment = 16,
        .readable = true, .executable = true,
        .contents = {std::byte{0x90}, std::byte{0x90}, std::byte{0xc3}}, .lineage = {}});
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{2}, .formatIndex = 0, .formatTableIndex = 0,
        .formatType = 0x20, .formatStorage = 2, .formatSectionIndex = 1,
        .auxiliaryData = {}, .name = "cli_function", .section = binobf::EntityId{1},
        .address = {}, .size = 3, .kind = binobf::SymbolKind::Function,
        .visibility = binobf::SymbolVisibility::External, .defined = true,
        .definition = binobf::SymbolDefinitionKind::SectionRelative,
        .commonAlignment = 0, .tlsModel = binobf::TlsModel::None, .lineage = {}});
    const auto written = binobf::write_object(image);
    if (!written.has_value()) throw std::runtime_error(written.error().message);
    return written.value();
}

auto make_coff_selection_object() -> std::vector<std::byte> {
    binobf::BinaryImage image;
    image.format = binobf::BinaryFormat::COFF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86_64;
    image.sections.push_back(binobf::Section{
        .id = binobf::EntityId{1}, .formatIndex = 1,
        .formatFlags = 0x60500020, .name = ".text", .kind = binobf::SectionKind::Code,
        .address = {}, .logicalSize = 8, .alignment = 16,
        .readable = true, .executable = true,
        .contents = {
            std::byte{0x0f}, std::byte{0x1f}, std::byte{0x00}, std::byte{0xc3},
            std::byte{0x0f}, std::byte{0x1f}, std::byte{0x00}, std::byte{0xc3}},
        .lineage = {}});
    for (const auto& [id, name, offset] :
         std::array<std::tuple<std::uint64_t, std::string, std::uint64_t>, 2>{
             std::tuple{UINT64_C(2), std::string{"selected_cli"}, UINT64_C(0)},
             std::tuple{UINT64_C(3), std::string{"excluded_cli"}, UINT64_C(4)}}) {
        image.symbols.push_back(binobf::Symbol{
            .id = binobf::EntityId{id},
            .formatIndex = static_cast<std::uint32_t>(image.symbols.size()),
            .formatTableIndex = 0, .formatType = 0x20, .formatStorage = 2,
            .formatSectionIndex = 1, .auxiliaryData = {}, .name = name,
            .section = binobf::EntityId{1},
            .address = binobf::BinaryAddress{offset, binobf::AddressKind::RelativeVirtual},
            .size = 4, .kind = binobf::SymbolKind::Function,
            .visibility = binobf::SymbolVisibility::External,
            .defined = true,
            .definition = binobf::SymbolDefinitionKind::SectionRelative,
            .commonAlignment = 0, .tlsModel = binobf::TlsModel::None, .lineage = {}});
    }
    const auto written = binobf::write_object(image);
    if (!written.has_value()) throw std::runtime_error(written.error().message);
    return written.value();
}

auto make_coff_vm_protection_object() -> std::vector<std::byte> {
    binobf::BinaryImage image;
    image.format = binobf::BinaryFormat::COFF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86_64;
    image.sections.push_back(binobf::Section{
        .id = binobf::EntityId{1}, .formatIndex = 1,
        .formatFlags = 0x60500020, .name = ".text", .kind = binobf::SectionKind::Code,
        .address = {}, .logicalSize = 5, .alignment = 16,
        .readable = true, .executable = true,
        .contents = {std::byte{0x89}, std::byte{0xc8}, std::byte{0x01},
                     std::byte{0xd0}, std::byte{0xc3}},
        .lineage = {}});
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{2}, .formatIndex = 0, .formatTableIndex = 0,
        .formatType = 0x20, .formatStorage = 2, .formatSectionIndex = 1,
        .auxiliaryData = {}, .name = "cli_vm_add", .section = binobf::EntityId{1},
        .address = {}, .size = 5, .kind = binobf::SymbolKind::Function,
        .visibility = binobf::SymbolVisibility::External,
        .defined = true,
        .definition = binobf::SymbolDefinitionKind::SectionRelative,
        .commonAlignment = 0, .tlsModel = binobf::TlsModel::None, .lineage = {}});
    const auto written = binobf::write_object(image);
    if (!written.has_value()) throw std::runtime_error(written.error().message);
    return written.value();
}

void append_text(std::vector<std::byte>& bytes, std::string_view value) {
    for (const auto character : value) bytes.push_back(static_cast<std::byte>(character));
}

void append_archive_field(
    std::vector<std::byte>& bytes, std::string value, std::size_t width) {
    value.resize(width, ' ');
    append_text(bytes, std::string_view{value}.substr(0, width));
}

void append_archive_member(
    std::vector<std::byte>& bytes,
    std::string name,
    const std::vector<std::byte>& contents) {
    append_archive_field(bytes, std::move(name), 16);
    append_archive_field(bytes, "0", 12);
    append_archive_field(bytes, "0", 6);
    append_archive_field(bytes, "0", 6);
    append_archive_field(bytes, "644", 8);
    append_archive_field(bytes, std::to_string(contents.size()), 10);
    append_text(bytes, "`\n");
    bytes.insert(bytes.end(), contents.begin(), contents.end());
    if ((contents.size() & 1U) != 0) bytes.push_back(std::byte{'\n'});
}

auto make_archive() -> std::vector<std::byte> {
    std::vector<std::byte> bytes;
    append_text(bytes, "!<arch>\n");
    append_archive_member(bytes, "function.obj/", make_coff_function_object());
    append_archive_member(bytes, "note.txt/", {std::byte{'o'}, std::byte{'k'}});
    return bytes;
}

auto make_vm_archive() -> std::vector<std::byte> {
    std::vector<std::byte> bytes;
    append_text(bytes, "!<arch>\n");
    append_archive_member(bytes, "vm-function.obj/", make_coff_vm_protection_object());
    append_archive_member(bytes, "note.txt/", {std::byte{'o'}, std::byte{'k'}});
    return bytes;
}

auto make_parallel_archive() -> std::vector<std::byte> {
    std::vector<std::byte> bytes;
    append_text(bytes, "!<arch>\n");
    append_archive_member(bytes, "first.obj/", make_coff_object());
    append_archive_member(bytes, "second.obj/", make_coff_object());
    append_archive_member(bytes, "note.txt/", {std::byte{'o'}, std::byte{'k'}});
    return bytes;
}

auto read_all(const std::filesystem::path& path) -> std::vector<std::byte> {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) {
        throw std::runtime_error("could not open CLI test fixture");
    }
    const auto end = stream.tellg();
    if (end < 0) {
        throw std::runtime_error("could not size CLI test fixture");
    }
    std::vector<std::byte> bytes(static_cast<std::size_t>(end));
    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return bytes;
}

auto text_bytes(std::string_view text) -> std::vector<std::byte> {
    std::vector<std::byte> bytes;
    bytes.reserve(text.size());
    append_text(bytes, text);
    return bytes;
}

auto digest_hex(const std::vector<std::byte>& bytes) -> std::string {
    const auto digest = binobf::sha256(bytes);
    if (!digest.has_value()) throw std::runtime_error("test SHA-256 input was too large");
    return binobf::sha256_hex(*digest);
}

} // namespace

TEST_CASE(inspect_reports_a_valid_elf_object_through_the_library_dispatcher) {
    const TemporaryFile fixture{"binobf-cli-valid.o", make_elf64_object()};
    const auto pathText = fixture.path().string();
    const std::array<std::string_view, 2> arguments{"inspect"sv, pathText};
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
    REQUIRE_CONTAINS(output.str(), "format: ELF");
    REQUIRE_CONTAINS(output.str(), "type: relocatable-object");
    REQUIRE_CONTAINS(output.str(), "architecture: x86-64");
    REQUIRE_CONTAINS(output.str(), "file-size: 64");
    REQUIRE_CONTAINS(output.str(), "inspection: supported");
    REQUIRE(errors.str().empty());
}

TEST_CASE(inspect_never_modifies_the_input) {
    const TemporaryFile fixture{"binobf-cli-read-only.o", make_elf64_object()};
    const auto before = read_all(fixture.path());
    const auto pathText = fixture.path().string();
    const std::array<std::string_view, 2> arguments{"inspect"sv, pathText};
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
    REQUIRE_EQ(read_all(fixture.path()), before);
}

TEST_CASE(inspect_renders_machine_readable_failures_when_requested) {
    const TemporaryFile fixture{
        "binobf-cli-unknown.bin",
        {std::byte{'n'}, std::byte{'o'}, std::byte{'p'}, std::byte{'e'}},
    };
    const auto pathText = fixture.path().string();
    const std::array<std::string_view, 3> arguments{
        "inspect"sv, pathText, "--diagnostics=json"sv,
    };
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 3);
    REQUIRE(output.str().empty());
    REQUIRE_CONTAINS(errors.str(), "\"severity\":\"error\"");
    REQUIRE_CONTAINS(errors.str(), "\"code\":\"format.unknown\"");
}

TEST_CASE(usage_errors_and_io_errors_have_distinct_exit_codes) {
    std::ostringstream output;
    std::ostringstream errors;
    const std::array<std::string_view, 0> noArguments{};
    REQUIRE_EQ(binobf::cli::run_cli(noArguments, output, errors), 2);
    REQUIRE_CONTAINS(errors.str(), "Usage:");

    output.str({});
    errors.str({});
    const std::array missingPath{"inspect"sv};
    REQUIRE_EQ(binobf::cli::run_cli(missingPath, output, errors), 2);

    output.str({});
    errors.str({});
    const std::array nonexistent{"inspect"sv, "Z:/binobf/does-not-exist.o"sv};
    REQUIRE_EQ(binobf::cli::run_cli(nonexistent, output, errors), 3);
    REQUIRE_CONTAINS(errors.str(), "io.open_failed");
}

TEST_CASE(version_command_reports_build_version) {
    std::ostringstream output;
    std::ostringstream errors;
    const std::array arguments{"--version"sv};
    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
    REQUIRE_EQ(output.str(), "binobf " + std::string{binobf::evidence::tool_version()} + "\n");
    REQUIRE(errors.str().empty());
}

TEST_CASE(capability_commands_are_accurate_and_do_not_overclaim) {
    std::ostringstream output;
    std::ostringstream errors;
    const std::array formats{"formats"sv};
    REQUIRE_EQ(binobf::cli::run_cli(formats, output, errors), 0);
    REQUIRE_EQ(
        output.str(),
        "PE detection=supported parsing=n/a emission=supported linked-parsing=supported verification=supported baseline-transformation=supported strip-debug machine-code-transformation=planned vm-lowering=n/a vm-protection=n/a\n"
        "COFF detection=supported parsing=supported emission=supported linked-parsing=n/a verification=supported baseline-transformation=supported machine-code-transformation=supported vm-lowering=restricted vm-protection=restricted\n"
        "ELF detection=supported parsing=supported emission=supported linked-parsing=supported verification=supported baseline-transformation=supported including linked machine-code-transformation=supported vm-lowering=restricted vm-protection=restricted\n"
        "Mach-O detection=supported parsing=supported emission=supported linked-parsing=n/a verification=supported baseline-transformation=planned machine-code-transformation=restricted x86-64 object backend vm-lowering=restricted vm-protection=restricted\n"
        "archive detection=supported parsing=supported members emission=supported linked-parsing=n/a verification=supported baseline-transformation=supported per object member machine-code-transformation=supported per object member vm-lowering=unsupported vm-protection=restricted per x86-64 object member\n");
    REQUIRE(errors.str().empty());

    output.str({});
    errors.str({});
    const std::array architectures{"architectures"sv};
    REQUIRE_EQ(binobf::cli::run_cli(architectures, output, errors), 0);
    REQUIRE_EQ(
        output.str(),
        "x86 detection=supported decoder=supported object-analysis=supported codegen=supported\n"
        "x86-64 detection=supported decoder=supported object-analysis=supported codegen=supported\n"
        "arm64 detection=supported decoder=supported object-analysis=supported codegen=supported\n");
    REQUIRE(errors.str().empty());
}

TEST_CASE(analyze_reports_normalized_object_counts_without_modifying_input) {
    const TemporaryFile fixture{"binobf-cli-analyze.obj", make_coff_object()};
    const auto before = read_all(fixture.path());
    const auto pathText = fixture.path().string();
    const std::array<std::string_view, 2> arguments{"analyze"sv, pathText};
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
    REQUIRE_CONTAINS(output.str(), "format: COFF");
    REQUIRE_CONTAINS(output.str(), "sections: 1");
    REQUIRE_CONTAINS(output.str(), "symbols: 0");
    REQUIRE_CONTAINS(output.str(), "relocations: 0");
    REQUIRE_CONTAINS(output.str(), "functions: 0");
    REQUIRE_CONTAINS(output.str(), "instructions: 0");
    REQUIRE_CONTAINS(output.str(), "basic-blocks: 0");
    REQUIRE_CONTAINS(output.str(), "section[1]: .text");
    REQUIRE(errors.str().empty());
    REQUIRE_EQ(read_all(fixture.path()), before);
}

TEST_CASE(analyze_reports_function_cfg_and_completeness_summaries) {
    const TemporaryFile fixture{"binobf-cli-function.obj", make_coff_function_object()};
    const auto pathText = fixture.path().string();
    const std::array<std::string_view, 2> arguments{"analyze"sv, pathText};
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
    REQUIRE_CONTAINS(output.str(), "functions: 1");
    REQUIRE_CONTAINS(output.str(), "instructions: 3");
    REQUIRE_CONTAINS(output.str(), "basic-blocks: 1");
    REQUIRE_CONTAINS(output.str(), "incomplete-functions: 0");
    REQUIRE_CONTAINS(output.str(), "function[cli_function]");
    REQUIRE_CONTAINS(output.str(), "complete=true");
    REQUIRE(errors.str().empty());
}

TEST_CASE(analyze_dispatches_archives_and_reports_malformed_objects_as_json) {
    const TemporaryFile archive{"binobf-cli-analyze.a", make_archive()};
    const auto archivePath = archive.path().string();
    const std::array<std::string_view, 2> archiveArguments{"analyze"sv, archivePath};
    std::ostringstream output;
    std::ostringstream errors;
    REQUIRE_EQ(binobf::cli::run_cli(archiveArguments, output, errors), 0);
    REQUIRE_CONTAINS(output.str(), "format: archive");
    REQUIRE_CONTAINS(output.str(), "object-members: 1");
    REQUIRE_CONTAINS(output.str(), "member[");
    REQUIRE(errors.str().empty());

    auto malformedBytes = make_coff_object();
    put_u32(malformedBytes, 20 + 20, 0xfffffff0U);
    const TemporaryFile malformed{"binobf-cli-malformed.obj", malformedBytes};
    const auto malformedPath = malformed.path().string();
    const std::array<std::string_view, 3> malformedArguments{
        "analyze"sv, malformedPath, "--diagnostics=json"sv,
    };
    output.str({});
    errors.str({});
    REQUIRE_EQ(binobf::cli::run_cli(malformedArguments, output, errors), 3);
    REQUIRE_CONTAINS(errors.str(), "\"code\":\"coff.truncated\"");
}

TEST_CASE(verify_and_transform_dispatch_archives_transactionally) {
    const TemporaryFile input{"binobf-cli-transform-input.a", make_archive()};
    const TemporaryOutput transformed{"binobf-cli-transform-output.a"};
    const auto inputPath = input.path().string();
    const auto outputPath = transformed.path().string();
    std::ostringstream output;
    std::ostringstream errors;
    const std::array<std::string_view, 2> verifyArguments{"verify"sv, inputPath};
    REQUIRE_EQ(binobf::cli::run_cli(verifyArguments, output, errors), 0);
    REQUIRE_CONTAINS(output.str(), "member-layouts: passed examined=2");
    REQUIRE_CONTAINS(output.str(), "object-members: passed examined=1");
    REQUIRE_CONTAINS(output.str(), "verification: passed");
    REQUIRE(errors.str().empty());

    output.str({});
    errors.str({});
    const std::array<std::string_view, 7> transformArguments{
        "transform"sv, inputPath, "-o"sv, outputPath,
        "--passes=none"sv, "--seed=52"sv,
        "--jobs=2"sv,
    };
    REQUIRE_EQ(binobf::cli::run_cli(transformArguments, output, errors), 0);
    REQUIRE_EQ(read_all(transformed.path()), read_all(input.path()));
    const auto parsed = binobf::parse_archive(read_all(transformed.path()), "output.a");
    REQUIRE(parsed.has_value());
    REQUIRE_EQ(parsed.value().members.size(), std::size_t{2});
    REQUIRE_CONTAINS(output.str(), "format: archive");
    REQUIRE_CONTAINS(output.str(), "object-members: 1");
    REQUIRE_CONTAINS(output.str(), "preserved-members: 1");
    REQUIRE_CONTAINS(output.str(), "verification: reparsed");
    REQUIRE(errors.str().empty());
}

TEST_CASE(transform_rejects_out_of_range_archive_jobs) {
    const TemporaryFile input{"binobf-cli-jobs-input.a", make_archive()};
    const auto inputPath = input.path().string();
    std::ostringstream output;
    std::ostringstream errors;
    const std::array<std::string_view, 3> arguments{
        "transform"sv, inputPath, "--jobs=0"sv,
    };

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 2);
    REQUIRE(output.str().empty());
    REQUIRE_CONTAINS(errors.str(), "transform jobs must be an integer from 1 through 64");
}

TEST_CASE(transform_archive_jobs_preserve_deterministic_output) {
    const TemporaryFile input{"binobf-cli-parallel-input.a", make_parallel_archive()};
    const TemporaryOutput serial{"binobf-cli-parallel-serial.a"};
    const TemporaryOutput parallel{"binobf-cli-parallel-parallel.a"};
    const auto inputPath = input.path().string();
    const auto serialPath = serial.path().string();
    const auto parallelPath = parallel.path().string();
    const std::array<std::string_view, 7> serialArguments{
        "transform"sv, inputPath, "-o"sv, serialPath,
        "--passes=none"sv, "--seed=52"sv, "--jobs=1"sv,
    };
    const std::array<std::string_view, 7> parallelArguments{
        "transform"sv, inputPath, "-o"sv, parallelPath,
        "--passes=none"sv, "--seed=52"sv, "--jobs=2"sv,
    };
    std::ostringstream serialOutput;
    std::ostringstream serialErrors;
    std::ostringstream parallelOutput;
    std::ostringstream parallelErrors;

    REQUIRE_EQ(binobf::cli::run_cli(serialArguments, serialOutput, serialErrors), 0);
    REQUIRE_EQ(binobf::cli::run_cli(parallelArguments, parallelOutput, parallelErrors), 0);
    REQUIRE_EQ(read_all(serial.path()), read_all(parallel.path()));
    REQUIRE_CONTAINS(parallelOutput.str(), "object-members: 2");
    REQUIRE(serialErrors.str().empty());
    REQUIRE(parallelErrors.str().empty());
}

TEST_CASE(verify_reports_each_structural_check_without_overclaiming) {
    const TemporaryFile fixture{"binobf-cli-verify.obj", make_coff_object()};
    const auto pathText = fixture.path().string();
    const std::array<std::string_view, 2> arguments{"verify"sv, pathText};
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
    REQUIRE_CONTAINS(output.str(), "verification: passed");
    REQUIRE_CONTAINS(output.str(), "headers: passed examined=1");
    REQUIRE_CONTAINS(output.str(), "section-ranges: passed examined=1");
    REQUIRE_CONTAINS(output.str(), "imports-exports: not-applicable");
    REQUIRE_CONTAINS(output.str(), "branch-destinations: not-applicable");
    REQUIRE_CONTAINS(output.str(), "unwind-semantics: unsupported");
    REQUIRE(errors.str().empty());
}

TEST_CASE(verify_rejects_malformed_objects_and_supports_json_diagnostics) {
    auto malformedBytes = make_coff_object();
    put_u32(malformedBytes, 20 + 20, 0xfffffff0U);
    const TemporaryFile malformed{"binobf-cli-verify-malformed.obj", malformedBytes};
    const auto pathText = malformed.path().string();
    const std::array<std::string_view, 3> arguments{
        "verify"sv, pathText, "--diagnostics=json"sv,
    };
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 3);
    REQUIRE(output.str().empty());
    REQUIRE_CONTAINS(errors.str(), "\"severity\":\"error\"");
    REQUIRE_CONTAINS(errors.str(), "\"code\":\"coff.truncated\"");
}

TEST_CASE(verify_requires_exactly_one_input_path) {
    const std::array arguments{"verify"sv};
    std::ostringstream output;
    std::ostringstream errors;
    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 2);
    REQUIRE_CONTAINS(errors.str(), "Usage:");
}

TEST_CASE(transform_with_no_passes_round_trips_without_modifying_input) {
    const TemporaryFile input{"binobf-cli-transform-input.obj", make_coff_object()};
    const TemporaryOutput output{"binobf-cli-transform-output.obj"};
    const auto before = read_all(input.path());
    const auto inputPath = input.path().string();
    const auto outputPath = output.path().string();
    const std::array<std::string_view, 5> arguments{
        "transform"sv, inputPath, "-o"sv, outputPath, "--passes=none"sv,
    };
    std::ostringstream stdoutStream;
    std::ostringstream stderrStream;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, stdoutStream, stderrStream), 0);
    REQUIRE_EQ(read_all(input.path()), before);
    REQUIRE(std::filesystem::exists(output.path()));
    REQUIRE(read_all(output.path()) != before);
    const auto inputImage = binobf::parse_object(before, "input.obj");
    const auto outputImage = binobf::parse_object(read_all(output.path()), "output.obj");
    REQUIRE(inputImage.has_value());
    REQUIRE(outputImage.has_value());
    REQUIRE_EQ(outputImage.value().format, inputImage.value().format);
    REQUIRE_EQ(outputImage.value().architecture, inputImage.value().architecture);
    REQUIRE_EQ(outputImage.value().sections.size(), inputImage.value().sections.size());
    REQUIRE_EQ(outputImage.value().symbols.size(), inputImage.value().symbols.size());
    REQUIRE_EQ(outputImage.value().relocations.size(), inputImage.value().relocations.size());
    REQUIRE_CONTAINS(stdoutStream.str(), "passes: none");
    REQUIRE(std::filesystem::exists(output.manifest_path()));
    const auto manifest = read_all(output.manifest_path());
    const auto manifestText = std::string{
        reinterpret_cast<const char*>(manifest.data()), manifest.size()};
    REQUIRE_CONTAINS(manifestText, digest_hex(before));
    REQUIRE_CONTAINS(manifestText, digest_hex(read_all(output.path())));
    REQUIRE_CONTAINS(manifestText, "\"verification\":\"reparsed\"");
    REQUIRE(stderrStream.str().empty());
}

TEST_CASE(transform_rejects_unknown_pass_sets_without_creating_output) {
    const TemporaryFile input{"binobf-cli-transform-invalid.obj", make_coff_object()};
    const TemporaryOutput output{"binobf-cli-transform-invalid-output.obj"};
    const auto inputPath = input.path().string();
    const auto outputPath = output.path().string();
    const std::array<std::string_view, 5> arguments{
        "transform"sv, inputPath, "-o"sv, outputPath, "--passes=unknown"sv,
    };
    std::ostringstream stdoutStream;
    std::ostringstream stderrStream;
    REQUIRE_EQ(binobf::cli::run_cli(arguments, stdoutStream, stderrStream), 2);
    REQUIRE(!std::filesystem::exists(output.path()));
}

TEST_CASE(transform_reports_runtime_diagnostics_as_json) {
    auto malformedBytes = make_coff_object();
    put_u32(malformedBytes, 20 + 20, 0xfffffff0U);
    const TemporaryFile input{"binobf-cli-transform-malformed.obj", malformedBytes};
    const TemporaryOutput output{"binobf-cli-transform-malformed-output.obj"};
    const auto inputPath = input.path().string();
    const auto outputPath = output.path().string();
    const auto arguments = std::array<std::string_view, 6>{
        "transform"sv, inputPath, "-o"sv, outputPath,
        "--passes=none"sv, "--diagnostics=json"sv,
    };
    std::ostringstream stdoutStream;
    std::ostringstream stderrStream;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, stdoutStream, stderrStream), 3);
    REQUIRE(stdoutStream.str().empty());
    REQUIRE_CONTAINS(stderrStream.str(), "\"severity\":\"error\"");
    REQUIRE_CONTAINS(stderrStream.str(), "\"code\":\"coff.truncated\"");
    REQUIRE(!std::filesystem::exists(output.path()));
}

TEST_CASE(passes_command_reports_baseline_capabilities) {
    const std::array arguments{"passes"sv};
    std::ostringstream output;
    std::ostringstream errors;
    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
    REQUIRE_EQ(output.str(), binobf::render_pass_capabilities_text());
    REQUIRE(errors.str().empty());
}

TEST_CASE(transform_accepts_balanced_profile_and_warns_about_medium_risk_passes) {
    const TemporaryFile input{"binobf-cli-transform-balanced.obj", make_coff_object()};
    const TemporaryOutput output{"binobf-cli-transform-balanced-output.obj"};
    const auto inputPath = input.path().string();
    const auto outputPath = output.path().string();
    const std::array<std::string_view, 6> arguments{
        "transform"sv, inputPath, "-o"sv, outputPath,
        "--passes=balanced"sv, "--seed=44"sv,
    };
    std::ostringstream stdoutStream;
    std::ostringstream stderrStream;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, stdoutStream, stderrStream), 0);
    REQUIRE(std::filesystem::exists(output.path()));
    REQUIRE_CONTAINS(stdoutStream.str(), "instruction-substitution:");
    REQUIRE_CONTAINS(stdoutStream.str(), "function-reordering:");
    REQUIRE_CONTAINS(stderrStream.str(), "medium-risk");
}

TEST_CASE(transform_minimal_profile_reports_seed_and_pass_statistics) {
    const TemporaryFile input{"binobf-cli-transform-minimal.obj", make_coff_object()};
    const TemporaryOutput output{"binobf-cli-transform-minimal-output.obj"};
    const auto inputPath = input.path().string();
    const auto outputPath = output.path().string();
    const std::array<std::string_view, 6> arguments{
        "transform"sv, inputPath, "-o"sv, outputPath,
        "--passes=minimal"sv, "--seed=1234"sv,
    };
    std::ostringstream stdoutStream;
    std::ostringstream stderrStream;
    REQUIRE_EQ(binobf::cli::run_cli(arguments, stdoutStream, stderrStream), 0);
    REQUIRE(std::filesystem::exists(output.path()));
    REQUIRE_CONTAINS(stdoutStream.str(), "seed: 1234");
    REQUIRE_CONTAINS(stdoutStream.str(), "strip-debug:");
    REQUIRE_CONTAINS(stdoutStream.str(), "cleanup-metadata:");
    REQUIRE_CONTAINS(stdoutStream.str(), "strip-local-symbols:");
    REQUIRE_CONTAINS(stdoutStream.str(), "rename-private-symbols:");
    REQUIRE_CONTAINS(stdoutStream.str(), "verification: reparsed");
    REQUIRE(stderrStream.str().empty());
}

TEST_CASE(transform_dry_run_never_creates_an_output) {
    const TemporaryFile input{"binobf-cli-transform-dry.obj", make_coff_object()};
    const auto inputPath = input.path().string();
    const std::array<std::string_view, 5> arguments{
        "transform"sv, inputPath, "--passes=minimal"sv, "--seed=9"sv, "--dry-run"sv,
    };
    std::ostringstream stdoutStream;
    std::ostringstream stderrStream;
    REQUIRE_EQ(binobf::cli::run_cli(arguments, stdoutStream, stderrStream), 0);
    REQUIRE_CONTAINS(stdoutStream.str(), "dry-run: true");
    REQUIRE_CONTAINS(stdoutStream.str(), "output: not-written");
    REQUIRE(stderrStream.str().empty());
}

TEST_CASE(config_command_prints_canonical_effective_json_without_writing_artifacts) {
    const TemporaryFile configuration{
        "binobf-cli-canonical.toml",
        text_bytes("version=1\nseed=77\nprofile=\"minimal\"\n")};
    const auto configPath = configuration.path().string();
    const std::array<std::string_view, 2> arguments{"config"sv, configPath};
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
    REQUIRE_CONTAINS(output.str(), "\"pass_description\":\"minimal\"");
    REQUIRE_CONTAINS(output.str(), "\"seed\":77");
    REQUIRE_CONTAINS(output.str(), "\"version\":1");
    REQUIRE(errors.str().empty());
}

TEST_CASE(transform_loads_relative_inputs_outputs_and_defaults_from_config) {
    const TemporaryFile input{"binobf-cli-config-input.obj", make_coff_object()};
    const TemporaryOutput transformed{"binobf-cli-config-output.obj"};
    const auto configText = std::string{"version=1\ninput=\""}
        + input.path().filename().generic_string() + "\"\noutput=\""
        + transformed.path().filename().generic_string()
        + "\"\npasses=[\"strip-debug\"]\nseed=777\n";
    const TemporaryFile configuration{
        "binobf-cli-transform.toml", text_bytes(configText)};
    const auto option = std::string{"--config="} + configuration.path().string();
    const std::array<std::string_view, 2> arguments{"transform"sv, option};
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
    REQUIRE(std::filesystem::exists(transformed.path()));
    REQUIRE_CONTAINS(output.str(), "seed: 777");
    REQUIRE_CONTAINS(output.str(), "passes: strip-debug");
    REQUIRE(errors.str().empty());
}

TEST_CASE(transform_config_selects_only_allowlisted_functions) {
    const TemporaryFile input{
        "binobf-cli-selection-input.obj", make_coff_selection_object()};
    const TemporaryOutput transformed{"binobf-cli-selection-output.obj"};
    const auto configText = std::string{"version=1\ninput=\""}
        + input.path().filename().generic_string() + "\"\noutput=\""
        + transformed.path().filename().generic_string()
        + "\"\npasses=[\"instruction-substitution\"]\n"
          "[selection]\ninclude=[\"selected_cli\"]\n"
          "[manifest]\nenabled=false\n";
    const TemporaryFile configuration{
        "binobf-cli-selection.toml", text_bytes(configText)};
    const auto option = std::string{"--config="} + configuration.path().string();
    const std::array<std::string_view, 2> arguments{"transform"sv, option};
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
    const auto parsed = binobf::parse_object(read_all(transformed.path()), "selected.obj");
    REQUIRE(parsed.has_value());
    const auto& code = parsed.value().sections.front().contents;
    const std::array expected{
        std::byte{0x0f}, std::byte{0x1f}, std::byte{0x00}, std::byte{0xc3}};
    REQUIRE(!std::equal(code.begin(), code.begin() + 4, expected.begin()));
    REQUIRE(std::equal(code.begin() + 4, code.end(), expected.begin()));
    REQUIRE_CONTAINS(output.str(), "instruction-substitution: applied");
    REQUIRE_CONTAINS(errors.str(), "medium-risk");
}

TEST_CASE(explicit_transform_arguments_override_config_values) {
    const TemporaryFile input{"binobf-cli-override-input.obj", make_coff_object()};
    const TemporaryOutput configuredOutput{"binobf-cli-configured-output.obj"};
    const TemporaryOutput cliOutput{"binobf-cli-explicit-output.obj"};
    const auto configText = std::string{"version=1\ninput=\""}
        + input.path().filename().generic_string() + "\"\noutput=\""
        + configuredOutput.path().filename().generic_string()
        + "\"\nprofile=\"balanced\"\nseed=1\n";
    const TemporaryFile configuration{
        "binobf-cli-override.toml", text_bytes(configText)};
    const auto configOption = std::string{"--config="} + configuration.path().string();
    const auto outputPath = cliOutput.path().string();
    const std::array<std::string_view, 6> arguments{
        "transform"sv, configOption, "-o"sv, outputPath,
        "--passes=none"sv, "--seed=99"sv};
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
    REQUIRE(std::filesystem::exists(cliOutput.path()));
    REQUIRE(!std::filesystem::exists(configuredOutput.path()));
    REQUIRE_CONTAINS(output.str(), "seed: 99");
    REQUIRE_CONTAINS(output.str(), "passes: none");
    REQUIRE(errors.str().empty());
}

TEST_CASE(transform_reports_invalid_config_as_a_data_error) {
    const TemporaryFile configuration{
        "binobf-cli-invalid.toml", text_bytes("version=2\n")};
    const auto option = std::string{"--config="} + configuration.path().string();
    const std::array<std::string_view, 2> arguments{"transform"sv, option};
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 3);
    REQUIRE(output.str().empty());
    REQUIRE_CONTAINS(errors.str(), "config.version");
}

TEST_CASE(transform_can_disable_the_default_manifest_explicitly) {
    const TemporaryFile input{"binobf-cli-no-manifest-input.obj", make_coff_object()};
    const TemporaryOutput transformed{"binobf-cli-no-manifest-output.obj"};
    const auto inputPath = input.path().string();
    const auto outputPath = transformed.path().string();
    const std::array<std::string_view, 6> arguments{
        "transform"sv, inputPath, "-o"sv, outputPath,
        "--passes=none"sv, "--no-manifest"sv};
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
    REQUIRE(std::filesystem::exists(transformed.path()));
    REQUIRE(!std::filesystem::exists(transformed.manifest_path()));
    REQUIRE(errors.str().empty());
}

TEST_CASE(transform_writes_a_custom_manifest_and_is_byte_deterministic_on_repeat) {
    const TemporaryFile input{"binobf-cli-custom-manifest-input.obj", make_coff_object()};
    const TemporaryOutput transformed{"binobf-cli-custom-manifest-output.obj"};
    const TemporaryOutput manifest{"binobf-cli-custom-manifest.json"};
    const auto inputPath = input.path().string();
    const auto outputPath = transformed.path().string();
    const auto manifestOption = std::string{"--manifest="} + manifest.path().string();
    const std::array<std::string_view, 6> arguments{
        "transform"sv, inputPath, "-o"sv, outputPath,
        "--passes=none"sv, manifestOption};
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
    const auto firstBinary = read_all(transformed.path());
    const auto firstManifest = read_all(manifest.path());
    REQUIRE(!std::filesystem::exists(transformed.manifest_path()));
    std::error_code ignored;
    std::filesystem::remove(transformed.path(), ignored);
    std::filesystem::remove(manifest.path(), ignored);
    output.str({});
    errors.str({});

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
    REQUIRE_EQ(read_all(transformed.path()), firstBinary);
    REQUIRE_EQ(read_all(manifest.path()), firstManifest);
    REQUIRE(errors.str().empty());
}

TEST_CASE(preexisting_manifest_prevents_the_binary_from_being_committed) {
    const TemporaryFile input{"binobf-cli-atomic-input.obj", make_coff_object()};
    const TemporaryOutput transformed{"binobf-cli-atomic-output.obj"};
    {
        std::ofstream existing(transformed.manifest_path());
        existing << "owned";
    }
    const auto inputPath = input.path().string();
    const auto outputPath = transformed.path().string();
    const std::array<std::string_view, 5> arguments{
        "transform"sv, inputPath, "-o"sv, outputPath, "--passes=none"sv};
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 3);
    REQUIRE(!std::filesystem::exists(transformed.path()));
    REQUIRE_CONTAINS(errors.str(), "io.output_exists");
}

TEST_CASE(object_transform_persists_lineage_and_queries_protected_addresses) {
    const TemporaryFile input{
        "binobf-cli-lineage-input.obj", make_coff_function_object()};
    const TemporaryOutput transformed{"binobf-cli-lineage-output.obj"};
    const TemporaryOutput lineage{"binobf-cli-lineage-output.json"};
    const auto inputPath = input.path().string();
    const auto outputPath = transformed.path().string();
    const auto lineageOption = std::string{"--lineage="} + lineage.path().string();
    const std::array<std::string_view, 6> transformArguments{
        "transform"sv, inputPath, "-o"sv, outputPath,
        "--passes=none"sv, lineageOption};
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(transformArguments, output, errors), 0);
    REQUIRE(std::filesystem::exists(transformed.path()));
    REQUIRE(std::filesystem::exists(transformed.manifest_path()));
    REQUIRE(std::filesystem::exists(lineage.path()));
    REQUIRE_CONTAINS(output.str(), "lineage:");
    REQUIRE(errors.str().empty());

    output.str({});
    errors.str({});
    const auto lineagePath = lineage.path().string();
    const std::array<std::string_view, 3> queryArguments{
        "lineage"sv, lineagePath, "--protected-address=1"sv};
    REQUIRE_EQ(binobf::cli::run_cli(queryArguments, output, errors), 0);
    REQUIRE_CONTAINS(output.str(), "protected-function: cli_function");
    REQUIRE_CONTAINS(output.str(), "original-function: cli_function");
    REQUIRE_CONTAINS(output.str(), "original-address: 0");
    REQUIRE(errors.str().empty());
}

TEST_CASE(lineage_output_is_rejected_for_ambiguous_archive_namespaces) {
    const TemporaryFile input{"binobf-cli-lineage-archive.a", make_archive()};
    const TemporaryOutput transformed{"binobf-cli-lineage-archive-output.a"};
    const TemporaryOutput lineage{"binobf-cli-lineage-archive.json"};
    const auto inputPath = input.path().string();
    const auto outputPath = transformed.path().string();
    const auto lineageOption = std::string{"--lineage="} + lineage.path().string();
    const std::array<std::string_view, 6> arguments{
        "transform"sv, inputPath, "-o"sv, outputPath,
        "--passes=none"sv, lineageOption};
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 3);
    REQUIRE(!std::filesystem::exists(transformed.path()));
    REQUIRE(!std::filesystem::exists(lineage.path()));
    REQUIRE_CONTAINS(errors.str(), "lineage.object_only");
}

TEST_CASE(vm_disassemble_command_decodes_versioned_bytecode_without_modifying_it) {
    using namespace binobf::vm;
    const VmProgram program{
        .version = currentVmVersion, .registerCount = 1, .slotCount = 0,
        .localMemorySize = 0,
        .instructions = {
            VmLoadConstant{VmRegister{0}, VmValue::from_bits(VmWidth::U32, 42)},
            VmReturn{VmRegister{0}},
        }};
    const auto assembled = assemble_program(program, VmAssemblyOptions{88});
    REQUIRE(assembled.has_value());
    const TemporaryFile input{"binobf-cli-program.bvm", assembled.value()};
    const auto before = read_all(input.path());
    const auto inputPath = input.path().string();
    const std::array<std::string_view, 3> arguments{
        "vm"sv, "disassemble"sv, inputPath};
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
    REQUIRE_CONTAINS(output.str(), "0000 LOAD_CONST v0, u32 0x2a");
    REQUIRE_CONTAINS(output.str(), "0001 RET v0");
    REQUIRE_EQ(read_all(input.path()), before);
    REQUIRE(errors.str().empty());
}

TEST_CASE(vm_disassemble_command_rejects_malformed_bytecode) {
    const TemporaryFile input{"binobf-cli-malformed.bvm", {std::byte{'B'}}};
    const auto inputPath = input.path().string();
    const std::array<std::string_view, 3> arguments{
        "vm"sv, "disassemble"sv, inputPath};
    std::ostringstream output;
    std::ostringstream errors;
    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 3);
    REQUIRE_CONTAINS(errors.str(), "vm.truncated_bytecode");
}

TEST_CASE(vm_protect_command_writes_a_deterministic_relocatable_object) {
    const TemporaryFile input{
        "binobf-cli-vm-protect-input.obj", make_coff_vm_protection_object()};
    const TemporaryOutput protectedOutput{"binobf-cli-vm-protect-output.obj"};
    const auto inputPath = input.path().string();
    const auto outputPath = protectedOutput.path().string();
    const std::array<std::string_view, 9> arguments{
        "vm"sv, "protect"sv, inputPath, "--function=cli_vm_add"sv,
        "--abi=windows-x64"sv, "--args=2"sv, "-o"sv, outputPath,
        "--seed=16016"sv};
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
    REQUIRE(std::filesystem::exists(protectedOutput.path()));
    const auto first = read_all(protectedOutput.path());
    REQUIRE_CONTAINS(output.str(), "function: cli_vm_add");
    REQUIRE_CONTAINS(output.str(), "runtime-symbol: binobf_vm_execute_embedded_u32");
    REQUIRE_CONTAINS(output.str(), "protected-object:");
    REQUIRE_CONTAINS(output.str(), "verification: reparsed");
    REQUIRE(errors.str().empty());
    const auto parsed = binobf::parse_object(first, "protected.obj");
    REQUIRE(parsed.has_value());
    REQUIRE(std::any_of(parsed.value().symbols.begin(), parsed.value().symbols.end(),
        [](const auto& symbol) {
            return symbol.name == "cli_vm_add" && symbol.address.value != 0;
        }));

    std::error_code ignored;
    std::filesystem::remove(protectedOutput.path(), ignored);
    output.str({});
    errors.str({});
    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
    REQUIRE_EQ(read_all(protectedOutput.path()), first);
    REQUIRE(errors.str().empty());
}

TEST_CASE(vm_protect_command_rejects_abi_mismatch_and_output_conflicts) {
    const TemporaryFile input{
        "binobf-cli-vm-protect-invalid.obj", make_coff_vm_protection_object()};
    const TemporaryOutput protectedOutput{"binobf-cli-vm-protect-invalid-output.obj"};
    const auto inputPath = input.path().string();
    const auto outputPath = protectedOutput.path().string();
    const std::array<std::string_view, 8> mismatch{
        "vm"sv, "protect"sv, inputPath, "--function=cli_vm_add"sv,
        "--abi=sysv-amd64"sv, "--args=2"sv, "-o"sv, outputPath};
    std::ostringstream output;
    std::ostringstream errors;
    REQUIRE_EQ(binobf::cli::run_cli(mismatch, output, errors), 3);
    REQUIRE(!std::filesystem::exists(protectedOutput.path()));
    REQUIRE_CONTAINS(errors.str(), "vm.protection_abi_format");

    output.str({});
    errors.str({});
    const std::array<std::string_view, 8> conflict{
        "vm"sv, "protect"sv, inputPath, "--function=cli_vm_add"sv,
        "--abi=windows-x64"sv, "--args=2"sv, "-o"sv, inputPath};
    REQUIRE_EQ(binobf::cli::run_cli(conflict, output, errors), 3);
    REQUIRE_CONTAINS(errors.str(), "io.output_matches_input");
}

TEST_CASE(vm_protect_command_updates_the_matching_archive_member) {
    const TemporaryFile input{"binobf-cli-vm-protect-input.lib", make_vm_archive()};
    const TemporaryOutput protectedOutput{"binobf-cli-vm-protect-output.lib"};
    const auto inputPath = input.path().string();
    const auto outputPath = protectedOutput.path().string();
    const std::array<std::string_view, 9> arguments{
        "vm"sv, "protect"sv, inputPath, "--function=vm-function.obj::cli_vm_add"sv,
        "--abi=windows-x64"sv, "--args=2"sv, "-o"sv, outputPath,
        "--seed=16016"sv};
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
    REQUIRE_CONTAINS(output.str(), "protected-member: vm-function.obj");
    REQUIRE(errors.str().empty());
    const auto parsed = binobf::parse_archive(
        read_all(protectedOutput.path()), "protected.lib");
    REQUIRE(parsed.has_value());
    const auto member = std::find_if(
        parsed.value().members.begin(), parsed.value().members.end(),
        [](const auto& candidate) { return candidate.name == "vm-function.obj"; });
    REQUIRE(member != parsed.value().members.end());
    const auto object = binobf::parse_object(member->contents, member->name);
    REQUIRE(object.has_value());
    REQUIRE(std::any_of(object.value().symbols.begin(), object.value().symbols.end(),
        [](const auto& symbol) { return symbol.name == "binobf_vm_execute_embedded_u32"; }));
}

TEST_CASE(vm_lower_command_accepts_qualified_archive_members) {
    const TemporaryFile input{"binobf-cli-vm-lower-input.lib", make_vm_archive()};
    const TemporaryOutput loweredOutput{"binobf-cli-vm-lower-output.bvm"};
    const auto inputPath = input.path().string();
    const auto outputPath = loweredOutput.path().string();
    const std::array<std::string_view, 9> arguments{
        "vm"sv, "lower"sv, inputPath, "--function=vm-function.obj::cli_vm_add"sv,
        "--abi=windows-x64"sv, "--args=2"sv, "-o"sv, outputPath,
        "--seed=16016"sv};
    std::ostringstream output;
    std::ostringstream errors;

    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
    REQUIRE(std::filesystem::exists(loweredOutput.path()));
    const auto bytes = read_all(loweredOutput.path());
    REQUIRE(bytes.size() > 4);
    REQUIRE_EQ(bytes[0], std::byte{'B'});
    REQUIRE_EQ(bytes[1], std::byte{'V'});
    REQUIRE_CONTAINS(output.str(), "function: vm-function.obj::cli_vm_add");
    REQUIRE(errors.str().empty());
}

int main() {
    return binobf::test::run_all();
}

#include "../test_support.hpp"

#include <binobf/formats/linked_image.hpp>
#include <binobf/formats/linked_writer.hpp>
#include <binobf/verify/structural_verifier.hpp>
#include <binobf/cli/command.hpp>

#include <cstddef>
#include <array>
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <sstream>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace {

std::vector<std::filesystem::path> fixtures;
std::filesystem::path llvmReadobj;
std::filesystem::path outputDirectory;

auto quote(const std::filesystem::path& path) -> std::string {
    return '"' + path.string() + '"';
}

auto read_file(const std::filesystem::path& path) -> std::vector<std::byte> {
    std::error_code sizeError;
    const auto size = std::filesystem::file_size(path, sizeError);
    if (sizeError) throw std::runtime_error("could not size fixture: " + path.string());
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    std::ifstream stream(path, std::ios::binary);
    stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!stream) throw std::runtime_error("could not read fixture: " + path.string());
    return bytes;
}

void write_file(const std::filesystem::path& path, const std::vector<std::byte>& bytes) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!stream) throw std::runtime_error("could not write output: " + path.string());
}

auto parse_file(const std::filesystem::path& path) -> binobf::LinkedImage {
    const auto bytes = read_file(path);
    auto parsed = binobf::parse_linked_image(bytes, path.filename().string());
    if (!parsed.has_value()) {
        throw std::runtime_error(
            "linked parser rejected " + path.string() + ": " + parsed.error().code
            + ": " + parsed.error().message);
    }
    return std::move(parsed).value();
}

auto stripped_path(const std::filesystem::path& fixture) -> std::filesystem::path {
    return outputDirectory
        / (fixture.stem().string() + "-stripped" + fixture.extension().string());
}

} // namespace

TEST_CASE(real_linked_images_parse_verify_and_round_trip_exactly) {
    for (const auto& fixture : fixtures) {
        const auto parsed = parse_file(fixture);
        REQUIRE_EQ(parsed.image.architecture, binobf::Architecture::X86_64);
        REQUIRE(!parsed.image.sections.empty());
        REQUIRE(!parsed.image.segments.empty());
        const auto rewritten = binobf::rewrite_linked_image(parsed);
        REQUIRE(rewritten.has_value());
        REQUIRE_EQ(rewritten.value().bytes, parsed.sourceBytes);
        const auto verified = binobf::verify_linked_image(
            rewritten.value().bytes, fixture.filename().string());
        REQUIRE(verified.has_value());
    }
    const auto shared = parse_file(fixtures[4]);
    REQUIRE(!shared.image.imports.empty());
    REQUIRE(!shared.image.relocations.empty());
    REQUIRE(std::any_of(
        shared.image.sections.begin(), shared.image.sections.end(),
        [](const auto& section) { return section.name == ".plt"; }));
    REQUIRE(std::any_of(
        shared.image.sections.begin(), shared.image.sections.end(),
        [](const auto& section) { return section.name == ".got.plt"; }));
    const auto peExecutable = parse_file(fixtures[0]);
    REQUIRE(std::any_of(
        peExecutable.image.imports.begin(), peExecutable.image.imports.end(),
        [](const auto& imported) {
            return imported.library == "KERNEL32.dll" && imported.name == "ExitProcess";
        }));
    REQUIRE(std::any_of(
        peExecutable.image.functions.begin(), peExecutable.image.functions.end(),
        [](const auto& function) {
            return function.name == "binobf_linked_export"
                && function.discovery == binobf::FunctionDiscovery::Export
                && function.externallyVisible;
        }));
}

TEST_CASE(real_linked_debug_stripping_preserves_loader_contracts) {
    for (const auto& fixture : fixtures) {
        const auto parsed = parse_file(fixture);
        REQUIRE(!parsed.image.debugInfo.empty());
        const auto rewritten = binobf::rewrite_linked_image(
            parsed, binobf::LinkedRewriteOptions{.stripDebug = true});
        REQUIRE(rewritten.has_value());
        REQUIRE(rewritten.value().image.image.debugInfo.empty());
        REQUIRE_EQ(rewritten.value().image.image.imports.size(), parsed.image.imports.size());
        REQUIRE_EQ(rewritten.value().image.image.exports.size(), parsed.image.exports.size());
        const auto output = stripped_path(fixture);
        write_file(output, rewritten.value().bytes);
        const auto command = llvmReadobj.filename().string()
            + " --file-headers --sections " + quote(output) + " > NUL";
        REQUIRE_EQ(std::system(command.c_str()), 0);
    }
}

#ifdef _WIN32
TEST_CASE(rewritten_pe_executable_and_dll_still_run) {
    const auto executable = stripped_path(fixtures[0]);
    const auto library = stripped_path(fixtures[1]);
    REQUIRE_EQ(std::system(quote(executable).c_str()), 0);
    const auto module = LoadLibraryW(library.c_str());
    REQUIRE(module != nullptr);
    const auto address = GetProcAddress(module, "binobf_linked_export");
    REQUIRE(address != nullptr);
    using ExportedFunction = int (*)();
    const auto function = reinterpret_cast<ExportedFunction>(address);
    REQUIRE_EQ(function(), 42);
    REQUIRE(FreeLibrary(module) != 0);

    const auto imagehlp = LoadLibraryW(L"imagehlp.dll");
    REQUIRE(imagehlp != nullptr);
    const auto checksumAddress = GetProcAddress(imagehlp, "MapFileAndCheckSumW");
    REQUIRE(checksumAddress != nullptr);
    using MapChecksum = DWORD(WINAPI*)(PCWSTR, PDWORD, PDWORD);
    const auto mapChecksum = reinterpret_cast<MapChecksum>(checksumAddress);
    DWORD headerChecksum = 0;
    DWORD computedChecksum = 0;
    REQUIRE_EQ(mapChecksum(executable.c_str(), &headerChecksum, &computedChecksum), DWORD{0});
    REQUIRE_EQ(headerChecksum, computedChecksum);
    REQUIRE(FreeLibrary(imagehlp) != 0);
}
#endif

TEST_CASE(linked_cli_analyzes_verifies_and_transforms_real_images) {
    std::ostringstream output;
    std::ostringstream errors;
    const auto peText = fixtures[0].string();
    const std::array analyzeArgs{
        std::string_view{"analyze"}, std::string_view{peText}};
    REQUIRE_EQ(binobf::cli::run_cli(analyzeArgs, output, errors), 0);
    REQUIRE_CONTAINS(output.str(), "format: PE");
    REQUIRE_CONTAINS(output.str(), "segments:");
    REQUIRE_CONTAINS(output.str(), "debug-records:");

    output.str({});
    errors.str({});
    const auto elfText = fixtures[4].string();
    const std::array verifyArgs{
        std::string_view{"verify"}, std::string_view{elfText}};
    REQUIRE_EQ(binobf::cli::run_cli(verifyArgs, output, errors), 0);
    REQUIRE_CONTAINS(output.str(), "format-directories: passed");
    REQUIRE_CONTAINS(output.str(), "verification: passed");

    const auto transformed = outputDirectory / "linked-pe-cli-stripped.exe";
    std::error_code ignored;
    std::filesystem::remove(transformed, ignored);
    std::filesystem::remove(transformed.string() + ".manifest.json", ignored);
    output.str({});
    errors.str({});
    const auto transformedText = transformed.string();
    const std::array transformArgs{
        std::string_view{"transform"}, std::string_view{peText},
        std::string_view{"-o"}, std::string_view{transformedText},
        std::string_view{"--passes=strip-debug"}, std::string_view{"--seed=123"}};
    REQUIRE_EQ(binobf::cli::run_cli(transformArgs, output, errors), 0);
    REQUIRE_CONTAINS(output.str(), "strip-debug: applied");
    REQUIRE_CONTAINS(output.str(), "verification: reparsed");
    REQUIRE(errors.str().empty());
    REQUIRE(binobf::parse_linked_image(
        read_file(transformed), transformed.filename().string()).value().image.debugInfo.empty());
}

TEST_CASE(linked_cli_lowers_exported_pe_functions) {
    const auto outputPath = outputDirectory / "linked-pe-cli-lowered.bvm";
    std::error_code ignored;
    std::filesystem::remove(outputPath, ignored);
    std::ostringstream output;
    std::ostringstream errors;
    const auto inputText = fixtures[0].string();
    const auto outputText = outputPath.string();
    const std::array arguments{
        std::string_view{"vm"}, std::string_view{"lower"}, std::string_view{inputText},
        std::string_view{"--function=binobf_linked_export"},
        std::string_view{"--abi=windows-x64"}, std::string_view{"--args=0"},
        std::string_view{"-o"}, std::string_view{outputText}, std::string_view{"--seed=1"}};
    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
    REQUIRE(std::filesystem::exists(outputPath));
    const auto bytes = read_file(outputPath);
    REQUIRE(bytes.size() >= 4U);
    REQUIRE_EQ(bytes[0], std::byte{'B'});
    REQUIRE_EQ(bytes[1], std::byte{'V'});
    REQUIRE_CONTAINS(output.str(), "function: binobf_linked_export");
    REQUIRE(errors.str().empty());
}

int main(int argc, char** argv) {
    if (argc != 8) {
        return 2;
    }
    for (int index = 1; index <= 5; ++index) fixtures.emplace_back(argv[index]);
    llvmReadobj = argv[6];
    outputDirectory = argv[7];
    return binobf::test::run_all();
}

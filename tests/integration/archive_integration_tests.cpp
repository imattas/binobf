#include "../test_support.hpp"

#include <binobf/cli/command.hpp>
#include <binobf/formats/archive.hpp>
#include <binobf/formats/archive_writer.hpp>
#include <binobf/verify/structural_verifier.hpp>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace {

std::filesystem::path gnuArchive;
std::filesystem::path coffLibrary;
std::filesystem::path importLibrary;
std::filesystem::path originalPeExecutable;
std::filesystem::path originalElfExecutable;
std::filesystem::path compiler;
std::filesystem::path llvmAr;
std::filesystem::path llvmNm;
std::filesystem::path ldLld;
std::filesystem::path outputDirectory;

auto quote(const std::filesystem::path& path) -> std::string {
    return '"' + path.string() + '"';
}

auto null_device() -> std::string_view {
#ifdef _WIN32
    return "NUL";
#else
    return "/dev/null";
#endif
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

auto parse_file(const std::filesystem::path& path) -> binobf::ArchiveImage {
    const auto parsed = binobf::parse_archive(read_file(path), path.filename().string());
    if (!parsed.has_value()) {
        throw std::runtime_error(
            "archive parser rejected " + path.string() + ": " + parsed.error().code);
    }
    return parsed.value();
}

auto run_transform(
    const std::filesystem::path& input,
    const std::filesystem::path& output,
    std::string_view passes = "strip-debug") -> std::string {
    const auto inputText = input.string();
    const auto outputText = output.string();
    const auto passText = std::string{"--passes="} + std::string{passes};
    const std::array<std::string_view, 6> arguments{
        "transform", inputText, "-o", outputText, passText, "--seed=9031",
    };
    std::ostringstream stdoutStream;
    std::ostringstream stderrStream;
    const auto status = binobf::cli::run_cli(arguments, stdoutStream, stderrStream);
    if (status != 0) {
        throw std::runtime_error(
            "archive transform failed: " + stderrStream.str() + stdoutStream.str());
    }
    return stdoutStream.str();
}

#ifdef _WIN32
auto run_and_get_exit_code(const std::filesystem::path& executable) -> DWORD {
    auto command = quote(executable);
    std::vector<wchar_t> wide(command.begin(), command.end());
    wide.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (CreateProcessW(
            nullptr, wide.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr,
            &startup, &process) == FALSE) {
        throw std::runtime_error("could not start linked archive fixture");
    }
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return exitCode;
}
#endif

} // namespace

TEST_CASE(real_gnu_coff_and_import_archives_parse_verify_and_round_trip) {
    const auto gnu = parse_file(gnuArchive);
    const auto coff = parse_file(coffLibrary);
    const auto imported = parse_file(importLibrary);
    REQUIRE_EQ(gnu.flavor, binobf::ArchiveFlavor::Gnu);
    REQUIRE_EQ(coff.flavor, binobf::ArchiveFlavor::Coff);
    REQUIRE_EQ(gnu.type, binobf::BinaryType::StaticLibrary);
    REQUIRE_EQ(coff.type, binobf::BinaryType::StaticLibrary);
    REQUIRE_EQ(imported.type, binobf::BinaryType::ImportLibrary);
    REQUIRE_EQ(gnu.architecture, binobf::Architecture::X86_64);
    REQUIRE_EQ(coff.architecture, binobf::Architecture::X86_64);
    REQUIRE_EQ(gnu.symbols.size(), std::size_t{2});
    REQUIRE_EQ(coff.symbols.size(), std::size_t{2});
    REQUIRE(std::any_of(
        gnu.members.begin(), gnu.members.end(), [](const binobf::ArchiveMember& member) {
            return member.name == "archive-double-with-a-deliberately-long-member-name.o";
        }));
    REQUIRE(std::any_of(
        imported.members.begin(), imported.members.end(), [](const binobf::ArchiveMember& member) {
            return member.kind == binobf::ArchiveMemberKind::ImportObject;
        }));
    for (const auto& fixture : {gnuArchive, coffLibrary, importLibrary}) {
        const auto bytes = read_file(fixture);
        const auto parsed = parse_file(fixture);
        const auto written = binobf::write_archive(parsed);
        REQUIRE(written.has_value());
        REQUIRE_EQ(written.value(), bytes);
        REQUIRE(binobf::verify_archive(bytes, fixture.filename().string()).has_value());
    }
}

TEST_CASE(transformed_archives_are_deterministic_indexed_and_accepted_by_llvm) {
    const auto transformedA = outputDirectory / "transformed.a";
    const auto transformedASecond = outputDirectory / "transformed-second.a";
    const auto transformedLib = outputDirectory / "transformed.lib";
    const auto transformedLibSecond = outputDirectory / "transformed-second.lib";
    const auto transformedImport = outputDirectory / "transformed-import.lib";
    const auto aReport = run_transform(gnuArchive, transformedA);
    run_transform(gnuArchive, transformedASecond);
    const auto libReport = run_transform(coffLibrary, transformedLib);
    run_transform(coffLibrary, transformedLibSecond);
    const auto importReport = run_transform(importLibrary, transformedImport);
    REQUIRE(read_file(transformedA) != read_file(gnuArchive));
    REQUIRE(read_file(transformedLib) != read_file(coffLibrary));
    REQUIRE_EQ(read_file(transformedA), read_file(transformedASecond));
    REQUIRE_EQ(read_file(transformedLib), read_file(transformedLibSecond));
    REQUIRE_EQ(read_file(transformedImport), read_file(importLibrary));
    REQUIRE_CONTAINS(aReport, "object-members: 2");
    REQUIRE_CONTAINS(libReport, "archive-symbols: 2");
    REQUIRE_CONTAINS(importReport, "type: import-library");
    REQUIRE_CONTAINS(importReport, "preserved-members: 4");

    const auto parsedA = parse_file(transformedA);
    const auto parsedLib = parse_file(transformedLib);
    REQUIRE_EQ(parsedA.symbols.size(), std::size_t{2});
    REQUIRE_EQ(parsedLib.symbols.size(), std::size_t{2});
    REQUIRE_EQ(parsedLib.flavor, binobf::ArchiveFlavor::Coff);
    REQUIRE_EQ(std::count_if(
        parsedLib.members.begin(), parsedLib.members.end(),
        [](const binobf::ArchiveMember& member) {
            return member.kind == binobf::ArchiveMemberKind::SymbolIndex;
        }), std::ptrdiff_t{2});
    REQUIRE(binobf::verify_archive(read_file(transformedA), "transformed.a").has_value());
    REQUIRE(binobf::verify_archive(read_file(transformedLib), "transformed.lib").has_value());

    const auto listA = llvmAr.filename().string() + " t " + quote(transformedA)
        + " > " + std::string{null_device()};
    const auto listLib = llvmAr.filename().string() + " t " + quote(transformedLib)
        + " > " + std::string{null_device()};
    const auto symbolsA = llvmNm.filename().string() + " --defined-only " + quote(transformedA)
        + " > " + std::string{null_device()};
    const auto symbolsLib = llvmNm.filename().string() + " --defined-only " + quote(transformedLib)
        + " > " + std::string{null_device()};
    REQUIRE_EQ(std::system(listA.c_str()), 0);
    REQUIRE_EQ(std::system(listLib.c_str()), 0);
    REQUIRE_EQ(std::system(symbolsA.c_str()), 0);
    REQUIRE_EQ(std::system(symbolsLib.c_str()), 0);
}

TEST_CASE(transformed_static_libraries_link_and_preserve_runtime_behavior) {
    const auto transformedA = outputDirectory / "transformed.a";
    const auto transformedLib = outputDirectory / "transformed.lib";
    if (!std::filesystem::exists(transformedA)) run_transform(gnuArchive, transformedA);
    if (!std::filesystem::exists(transformedLib)) run_transform(coffLibrary, transformedLib);
    const auto fixtureDirectory = gnuArchive.parent_path();
    const auto peDriver = fixtureDirectory / "archive-driver.obj";
    const auto elfDriver = fixtureDirectory / "archive-driver.o";
    const auto peOutput = outputDirectory / "archive-transformed.exe";
    const auto elfOutput = outputDirectory / "archive-transformed-elf";
    const auto linkPe = compiler.filename().string()
        + " --target=x86_64-pc-windows-msvc -nostdlib -fuse-ld=lld "
        + quote(peDriver) + " " + quote(transformedLib)
        + " -Wl,/entry:archive_entry -Wl,/subsystem:console -lkernel32 -o "
        + quote(peOutput);
    const auto linkElf = ldLld.filename().string() + " --entry=_start -o " + quote(elfOutput)
        + " " + quote(elfDriver) + " " + quote(transformedA);
    REQUIRE_EQ(std::system(linkPe.c_str()), 0);
    REQUIRE_EQ(std::system(linkElf.c_str()), 0);
#ifdef _WIN32
    REQUIRE_EQ(run_and_get_exit_code(originalPeExecutable), DWORD{42});
    REQUIRE_EQ(run_and_get_exit_code(peOutput), DWORD{42});
#else
    REQUIRE_EQ(std::system(quote(originalElfExecutable).c_str()), 42 << 8);
    REQUIRE_EQ(std::system(quote(elfOutput).c_str()), 42 << 8);
#endif
}

int main(int argc, char** argv) {
    if (argc != 11) return 2;
    gnuArchive = argv[1];
    coffLibrary = argv[2];
    importLibrary = argv[3];
    originalPeExecutable = argv[4];
    originalElfExecutable = argv[5];
    compiler = argv[6];
    llvmAr = argv[7];
    llvmNm = argv[8];
    ldLld = argv[9];
    outputDirectory = argv[10];
    std::error_code cleanupError;
    std::filesystem::remove_all(outputDirectory, cleanupError);
    if (cleanupError) return 2;
    std::filesystem::create_directories(outputDirectory);
    return binobf::test::run_all();
}

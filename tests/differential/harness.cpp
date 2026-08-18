#include "harness.hpp"

#include <cstdlib>
#include <fstream>
#include <stdexcept>
#include <utility>

namespace binobf::test {
namespace {

auto quote(const std::filesystem::path& path) -> std::string {
    return '"' + path.string() + '"';
}

auto command_for(const std::vector<std::filesystem::path>& arguments) -> std::string {
    std::string command;
    for (const auto& argument : arguments) {
        if (!command.empty()) command.push_back(' ');
        command += quote(argument);
    }
#ifdef _WIN32
    command = '"' + command + '"';
#endif
    return command;
}

void write_file(const std::filesystem::path& path, std::span<const std::byte> bytes) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    if (!stream) throw std::runtime_error("could not write differential object: " + path.string());
}

auto read_file(const std::filesystem::path& path) -> std::vector<std::byte> {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("could not open differential output: " + path.string());
    const auto end = stream.tellg();
    if (end < 0) throw std::runtime_error("could not size differential output: " + path.string());
    std::vector<std::byte> bytes(static_cast<std::size_t>(end));
    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!stream) throw std::runtime_error("could not read differential output: " + path.string());
    return bytes;
}

auto as_text(const std::vector<std::byte>& bytes) -> std::string {
    std::string text;
    text.reserve(bytes.size());
    for (const auto value : bytes) text.push_back(static_cast<char>(value));
    return text;
}

} // namespace

auto ExecutionObservation::standardOutputText() const -> std::string {
    return as_text(standardOutput);
}

auto ExecutionObservation::deterministicFileText() const -> std::string {
    return as_text(deterministicFile);
}

DifferentialHarness::DifferentialHarness(
    std::filesystem::path compiler,
    std::filesystem::path driverSource,
    std::filesystem::path originalObject,
    std::filesystem::path supportObject,
    std::filesystem::path outputDirectory)
    : compiler_(std::move(compiler)),
      driverSource_(std::move(driverSource)),
      originalObject_(std::move(originalObject)),
      supportObject_(std::move(supportObject)),
      outputDirectory_(std::move(outputDirectory)),
      transformedObject_(outputDirectory_ / "transformed-fixture.o"),
      originalExecutable_(outputDirectory_ / "original-differential.exe"),
      transformedExecutable_(outputDirectory_ / "transformed-differential.exe") {}

void DifferentialHarness::compile(
    const std::filesystem::path& object,
    const std::filesystem::path& executable) const {
    const auto status = std::system(command_for({
        compiler_, driverSource_, object, supportObject_, "-o", executable,
    }).c_str());
    if (status != 0) {
        throw std::runtime_error("differential executable compilation failed");
    }
}

void DifferentialHarness::prepare(std::span<const std::byte> transformedObject) {
    std::error_code directoryError;
    std::filesystem::create_directories(outputDirectory_, directoryError);
    if (directoryError) {
        throw std::runtime_error("could not create differential output directory");
    }
    write_file(transformedObject_, transformedObject);
    compile(originalObject_, originalExecutable_);
    compile(transformedObject_, transformedExecutable_);
}

auto DifferentialHarness::run(
    const std::filesystem::path& executable,
    int input,
    std::string_view prefix,
    std::string_view caseName) const -> ExecutionObservation {
    const auto stem = std::string{prefix} + '-' + std::string{caseName};
    const auto standardOutput = outputDirectory_ / (stem + ".stdout");
    const auto standardError = outputDirectory_ / (stem + ".stderr");
    const auto deterministicFile = outputDirectory_ / (stem + ".side-effect");
    std::error_code ignored;
    std::filesystem::remove(standardOutput, ignored);
    std::filesystem::remove(standardError, ignored);
    std::filesystem::remove(deterministicFile, ignored);

    auto command = quote(executable) + ' ' + std::to_string(input) + ' '
        + quote(deterministicFile) + " > " + quote(standardOutput)
        + " 2> " + quote(standardError);
#ifdef _WIN32
    command = '"' + command + '"';
#endif
    const auto status = std::system(command.c_str());
    return ExecutionObservation{
        .exitStatus = status,
        .standardOutput = read_file(standardOutput),
        .standardError = read_file(standardError),
        .deterministicFile = read_file(deterministicFile),
    };
}

auto DifferentialHarness::run_original(int input, std::string_view caseName) const
    -> ExecutionObservation {
    return run(originalExecutable_, input, "original", caseName);
}

auto DifferentialHarness::run_transformed(int input, std::string_view caseName) const
    -> ExecutionObservation {
    return run(transformedExecutable_, input, "transformed", caseName);
}

} // namespace binobf::test

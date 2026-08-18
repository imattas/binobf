#pragma once

#include <cstddef>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace binobf::test {

struct ExecutionObservation {
    int exitStatus{0};
    std::vector<std::byte> standardOutput;
    std::vector<std::byte> standardError;
    std::vector<std::byte> deterministicFile;

    [[nodiscard]] auto standardOutputText() const -> std::string;
    [[nodiscard]] auto deterministicFileText() const -> std::string;
};

class DifferentialHarness {
public:
    DifferentialHarness(
        std::filesystem::path compiler,
        std::filesystem::path driverSource,
        std::filesystem::path originalObject,
        std::filesystem::path supportObject,
        std::filesystem::path outputDirectory);

    void prepare(std::span<const std::byte> transformedObject);
    [[nodiscard]] auto run_original(int input, std::string_view caseName) const
        -> ExecutionObservation;
    [[nodiscard]] auto run_transformed(int input, std::string_view caseName) const
        -> ExecutionObservation;

private:
    void compile(const std::filesystem::path& object, const std::filesystem::path& executable) const;
    [[nodiscard]] auto run(
        const std::filesystem::path& executable,
        int input,
        std::string_view prefix,
        std::string_view caseName) const -> ExecutionObservation;

    std::filesystem::path compiler_;
    std::filesystem::path driverSource_;
    std::filesystem::path originalObject_;
    std::filesystem::path supportObject_;
    std::filesystem::path outputDirectory_;
    std::filesystem::path transformedObject_;
    std::filesystem::path originalExecutable_;
    std::filesystem::path transformedExecutable_;
};

} // namespace binobf::test

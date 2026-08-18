#include <binobf/support/artifact_transaction.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace binobf {
namespace {

auto failure(std::string code, std::string message)
    -> Result<std::size_t, Diagnostic> {
    return Result<std::size_t, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

auto destination_key(const std::filesystem::path& path) -> std::string {
    std::error_code error;
    auto absolute = std::filesystem::absolute(path, error);
    if (error) absolute = path;
    auto key = absolute.lexically_normal().generic_string();
#ifdef _WIN32
    std::transform(key.begin(), key.end(), key.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
#endif
    return key;
}

void remove_temporaries(
    std::span<const std::filesystem::path> temporaries,
    std::size_t begin = 0) noexcept {
    for (std::size_t index = begin; index < temporaries.size(); ++index) {
        std::error_code ignored;
        std::filesystem::remove(temporaries[index], ignored);
    }
}

} // namespace

auto commit_artifacts(std::span<const ArtifactPayload> artifacts)
    -> Result<std::size_t, Diagnostic> {
    std::vector<std::string> destinationKeys;
    std::vector<std::filesystem::path> temporaries;
    destinationKeys.reserve(artifacts.size());
    temporaries.reserve(artifacts.size());

    for (const auto& artifact : artifacts) {
        if (artifact.destination.empty()) {
            return failure("io.output_invalid", "artifact destination must not be empty");
        }
        const auto key = destination_key(artifact.destination);
        if (std::find(destinationKeys.begin(), destinationKeys.end(), key) !=
            destinationKeys.end()) {
            return failure(
                "io.output_conflict",
                "artifact destinations must be distinct: " + artifact.destination.string());
        }
        destinationKeys.push_back(key);

        std::error_code existsError;
        if (std::filesystem::exists(artifact.destination, existsError)) {
            return failure(
                "io.output_exists",
                "refusing to overwrite existing output: " + artifact.destination.string());
        }
        if (existsError) {
            return failure(
                "io.open_failed",
                "could not inspect output path: " + artifact.destination.string());
        }
        auto temporary = artifact.destination;
        temporary += ".binobf.tmp";
        if (std::filesystem::exists(temporary, existsError) || existsError) {
            return failure(
                "io.temp_exists",
                "transaction temporary path is unavailable: " + temporary.string());
        }
        temporaries.push_back(std::move(temporary));
    }

    for (std::size_t index = 0; index < artifacts.size(); ++index) {
        if (artifacts[index].bytes.size() >
            static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
            remove_temporaries(temporaries);
            return failure(
                "io.output_too_large",
                "artifact is too large for the output stream: " +
                    artifacts[index].destination.string());
        }
        std::ofstream stream(temporaries[index], std::ios::binary | std::ios::trunc);
        if (!stream) {
            remove_temporaries(temporaries);
            return failure(
                "io.write_failed",
                "could not create transaction temporary: " + temporaries[index].string());
        }
        if (!artifacts[index].bytes.empty()) {
            stream.write(
                reinterpret_cast<const char*>(artifacts[index].bytes.data()),
                static_cast<std::streamsize>(artifacts[index].bytes.size()));
        }
        stream.close();
        if (!stream) {
            remove_temporaries(temporaries);
            return failure(
                "io.write_failed",
                "could not write transaction temporary: " + temporaries[index].string());
        }
    }

    std::size_t committed = 0;
    for (; committed < artifacts.size(); ++committed) {
        std::error_code renameError;
        std::filesystem::rename(
            temporaries[committed], artifacts[committed].destination, renameError);
        if (!renameError) continue;

        remove_temporaries(temporaries, committed);
        bool rollbackFailed = false;
        for (std::size_t index = 0; index < committed; ++index) {
            std::error_code removeError;
            std::filesystem::remove(artifacts[index].destination, removeError);
            rollbackFailed = rollbackFailed || static_cast<bool>(removeError);
        }
        if (rollbackFailed) {
            return failure(
                "io.rollback_failed",
                "artifact commit failed and at least one committed output could not be rolled back");
        }
        return failure(
            "io.commit_failed",
            "could not commit output file: " + artifacts[committed].destination.string());
    }
    return Result<std::size_t, Diagnostic>::success(committed);
}

} // namespace binobf

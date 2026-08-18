#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace binobf::evidence {

struct ManifestPassReport {
    std::string name;
    std::string status;
    std::size_t examined{0};
    std::size_t changed{0};
    std::size_t skipped{0};
};

struct BuildManifest {
    std::uint32_t schemaVersion{1};
    std::string toolVersion;
    std::string inputName;
    std::string outputName;
    std::string inputSha256;
    std::string outputSha256;
    std::string configSha256;
    std::uint64_t seed{0};
    std::vector<std::string> passes;
    std::string format;
    std::string architecture;
    std::uint64_t inputSize{0};
    std::uint64_t outputSize{0};
    std::vector<ManifestPassReport> reports;
    std::string verification;
};

[[nodiscard]] auto tool_version() noexcept -> std::string_view;
[[nodiscard]] auto serialize_manifest(const BuildManifest& manifest) -> std::string;

} // namespace binobf::evidence

#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/result.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace binobf::config {

struct ConfigParseLimits {
    std::size_t maxInputBytes{1U << 20U};
    std::size_t maxStringBytes{4096};
    std::size_t maxArrayEntries{1024};
};

struct ManifestConfig {
    std::optional<bool> enabled;
    std::optional<std::filesystem::path> path;

    auto operator==(const ManifestConfig&) const -> bool = default;
};

enum class SelectionVisibility : std::uint8_t {
    Local,
    Hidden,
    External,
};

struct SelectionConfig {
    std::vector<std::string> includeNames;
    std::vector<std::string> excludeNames;
    std::vector<std::string> includeRegex;
    std::vector<std::string> excludeRegex;
    std::vector<std::string> sections;
    std::vector<SelectionVisibility> visibilities;
    std::optional<std::uint8_t> percentage;
    std::optional<std::uint64_t> seed;

    auto operator==(const SelectionConfig&) const -> bool = default;
};

struct TransformConfig {
    std::uint32_t version{1};
    std::optional<std::filesystem::path> input;
    std::optional<std::filesystem::path> output;
    std::optional<std::uint64_t> seed;
    std::optional<std::vector<std::string>> passes;
    std::optional<std::string> passDescription;
    std::optional<bool> dryRun;
    std::optional<bool> allowSignatureInvalidation;
    std::vector<std::string> preservedSymbols;
    std::optional<SelectionConfig> selection;
    ManifestConfig manifest;
    std::optional<std::filesystem::path> lineagePath;

    auto operator==(const TransformConfig&) const -> bool = default;
};

struct ParsedConfig {
    TransformConfig config;
    std::filesystem::path source;
    std::string canonicalJson;
};

[[nodiscard]] auto parse_transform_config(
    std::span<const std::byte> bytes,
    const std::filesystem::path& source,
    const ConfigParseLimits& limits = {}) -> Result<ParsedConfig, Diagnostic>;

[[nodiscard]] auto canonicalize_transform_config(const TransformConfig& config)
    -> std::string;

[[nodiscard]] auto expand_profile(std::string_view profile)
    -> std::optional<std::vector<std::string>>;
[[nodiscard]] auto is_supported_pass(std::string_view pass) noexcept -> bool;

} // namespace binobf::config

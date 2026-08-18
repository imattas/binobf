#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/result.hpp>

#include <cstddef>
#include <filesystem>
#include <span>
#include <vector>

namespace binobf {

struct ArtifactPayload {
    std::filesystem::path destination;
    std::vector<std::byte> bytes;
};

[[nodiscard]] auto commit_artifacts(std::span<const ArtifactPayload> artifacts)
    -> Result<std::size_t, Diagnostic>;

} // namespace binobf

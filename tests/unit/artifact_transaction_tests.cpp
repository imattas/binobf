#include "../test_support.hpp"

#include <binobf/support/artifact_transaction.hpp>

#include <array>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

auto fixture_path(std::string_view name) -> std::filesystem::path {
    const auto path = std::filesystem::temp_directory_path() / std::string{name};
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    auto temporary = path;
    temporary += ".binobf.tmp";
    std::filesystem::remove(temporary, ignored);
    return path;
}

void cleanup(const std::filesystem::path& path) {
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    auto temporary = path;
    temporary += ".binobf.tmp";
    std::filesystem::remove(temporary, ignored);
}

auto payload(std::byte value) -> std::vector<std::byte> {
    return {value};
}

} // namespace

TEST_CASE(artifact_transaction_commits_all_distinct_outputs) {
    const auto binary = fixture_path("binobf-transaction-binary.obj");
    const auto manifest = fixture_path("binobf-transaction-manifest.json");
    const std::array artifacts{
        binobf::ArtifactPayload{binary, payload(std::byte{1})},
        binobf::ArtifactPayload{manifest, payload(std::byte{2})},
    };
    const auto committed = binobf::commit_artifacts(artifacts);
    REQUIRE(committed.has_value());
    REQUIRE_EQ(committed.value(), std::size_t{2});
    REQUIRE(std::filesystem::exists(binary));
    REQUIRE(std::filesystem::exists(manifest));
    cleanup(binary);
    cleanup(manifest);
}

TEST_CASE(artifact_transaction_refuses_existing_or_duplicate_destinations_without_partial_output) {
    const auto binary = fixture_path("binobf-transaction-no-partial.obj");
    const auto manifest = fixture_path("binobf-transaction-existing.json");
    {
        std::ofstream existing(manifest);
        existing << "owned";
    }
    const std::array artifacts{
        binobf::ArtifactPayload{binary, payload(std::byte{1})},
        binobf::ArtifactPayload{manifest, payload(std::byte{2})},
    };
    const auto refused = binobf::commit_artifacts(artifacts);
    REQUIRE(!refused.has_value());
    REQUIRE_EQ(refused.error().code, std::string{"io.output_exists"});
    REQUIRE(!std::filesystem::exists(binary));

    cleanup(manifest);
    const std::array duplicate{
        binobf::ArtifactPayload{binary, payload(std::byte{1})},
        binobf::ArtifactPayload{binary, payload(std::byte{2})},
    };
    const auto conflict = binobf::commit_artifacts(duplicate);
    REQUIRE(!conflict.has_value());
    REQUIRE_EQ(conflict.error().code, std::string{"io.output_conflict"});
    REQUIRE(!std::filesystem::exists(binary));
    cleanup(binary);
}

int main() {
    return binobf::test::run_all();
}

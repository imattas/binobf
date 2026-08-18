#include "../test_support.hpp"

#include <binobf/config/config.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>

namespace {

auto bytes_of(std::string_view value) -> std::span<const std::byte> {
    return std::as_bytes(std::span{value.data(), value.size()});
}

auto parse(std::string_view value) {
    return binobf::config::parse_transform_config(
        bytes_of(value), std::filesystem::path{"D:/project/config/binobf.toml"});
}

} // namespace

TEST_CASE(config_parses_strict_schema_resolves_paths_and_expands_profile) {
    const auto parsed = parse(R"(
version = 1
input = "../objects/app.obj"
output = "../out/app.obf.obj"
seed = 123456
profile = "balanced"
dry_run = false
allow_signature_invalidation = false
preserve_symbols = ["public_api", "stable_data"]

[manifest]
enabled = true
path = "../out/build.manifest.json"

[lineage]
path = "../out/build.lineage.json"
)");

    REQUIRE(parsed.has_value());
    const auto& config = parsed.value().config;
    REQUIRE_EQ(config.version, std::uint32_t{1});
    REQUIRE_EQ(config.input, std::optional{std::filesystem::path{"D:/project/objects/app.obj"}});
    REQUIRE_EQ(config.output, std::optional{std::filesystem::path{"D:/project/out/app.obf.obj"}});
    REQUIRE_EQ(config.seed, std::optional<std::uint64_t>{123456});
    REQUIRE(config.passes.has_value());
    REQUIRE_EQ(config.passes->size(), std::size_t{11});
    REQUIRE_EQ(config.passes->front(), std::string{"strip-debug"});
    REQUIRE_EQ(config.passes->back(), std::string{"function-reordering"});
    REQUIRE_EQ(config.passDescription, std::optional{std::string{"balanced"}});
    REQUIRE_EQ(config.preservedSymbols.size(), std::size_t{2});
    REQUIRE_EQ(config.manifest.enabled, std::optional<bool>{true});
    REQUIRE_EQ(
        config.manifest.path,
        std::optional{std::filesystem::path{"D:/project/out/build.manifest.json"}});
    REQUIRE_EQ(
        config.lineagePath,
        std::optional{std::filesystem::path{"D:/project/out/build.lineage.json"}});
    REQUIRE_CONTAINS(parsed.value().canonicalJson, "\"pass_description\":\"balanced\"");
    REQUIRE_CONTAINS(parsed.value().canonicalJson, "D:/project/objects/app.obj");
}

TEST_CASE(config_accepts_explicit_ordered_passes_and_canonicalizes_deterministically) {
    const auto parsed = parse(R"(
passes = ["constant-rewriting", "strip-debug"]
version = 1
seed = 9
)");
    REQUIRE(parsed.has_value());
    REQUIRE_EQ(
        parsed.value().config.passes,
        (std::optional{std::vector<std::string>{"constant-rewriting", "strip-debug"}}));
    REQUIRE_EQ(parsed.value().canonicalJson,
               binobf::config::canonicalize_transform_config(parsed.value().config));
    const auto repeated = parse(R"(
seed=9
version=1
passes=["constant-rewriting","strip-debug"]
)");
    REQUIRE(repeated.has_value());
    REQUIRE_EQ(parsed.value().canonicalJson, repeated.value().canonicalJson);
}

TEST_CASE(config_rejects_unknown_keys_types_conflicts_duplicates_and_unsupported_passes) {
    const auto unknown = parse("version=1\nsead=1\n");
    REQUIRE(!unknown.has_value());
    REQUIRE_EQ(unknown.error().code, std::string{"config.unknown_key"});

    const auto wrongType = parse("version=1\nseed=\"nine\"\n");
    REQUIRE(!wrongType.has_value());
    REQUIRE_EQ(wrongType.error().code, std::string{"config.type"});

    const auto conflict = parse("version=1\nprofile=\"minimal\"\npasses=[\"strip-debug\"]\n");
    REQUIRE(!conflict.has_value());
    REQUIRE_EQ(conflict.error().code, std::string{"config.pass_conflict"});

    const auto duplicate = parse("version=1\npreserve_symbols=[\"same\",\"same\"]\n");
    REQUIRE(!duplicate.has_value());
    REQUIRE_EQ(duplicate.error().code, std::string{"config.duplicate"});

    const auto unsupported = parse("version=1\npasses=[\"not-a-pass\"]\n");
    REQUIRE(!unsupported.has_value());
    REQUIRE_EQ(unsupported.error().code, std::string{"config.pass"});
}

TEST_CASE(config_rejects_schema_and_resource_limit_violations) {
    const auto malformed = parse("version=1\nprofile=\"balanced\n");
    REQUIRE(!malformed.has_value());
    REQUIRE_EQ(malformed.error().code, std::string{"config.syntax"});

    const std::array invalidText{
        std::byte{'v'}, std::byte{'='}, std::byte{0}, std::byte{'1'}};
    const auto invalidEncoding = binobf::config::parse_transform_config(
        invalidText, std::filesystem::path{"config.toml"});
    REQUIRE(!invalidEncoding.has_value());
    REQUIRE_EQ(invalidEncoding.error().code, std::string{"config.syntax"});

    const auto version = parse("version=2\n");
    REQUIRE(!version.has_value());
    REQUIRE_EQ(version.error().code, std::string{"config.version"});

    auto limits = binobf::config::ConfigParseLimits{};
    limits.maxInputBytes = 4;
    const auto oversized = binobf::config::parse_transform_config(
        bytes_of("version=1\n"), std::filesystem::path{"config.toml"}, limits);
    REQUIRE(!oversized.has_value());
    REQUIRE_EQ(oversized.error().code, std::string{"config.limit"});

    limits = {};
    limits.maxStringBytes = 3;
    const auto longString = binobf::config::parse_transform_config(
        bytes_of("version=1\ninput=\"long\"\n"),
        std::filesystem::path{"config.toml"}, limits);
    REQUIRE(!longString.has_value());
    REQUIRE_EQ(longString.error().code, std::string{"config.limit"});

    const std::array unsafeBareUnicode{
        std::byte{'v'}, std::byte{'e'}, std::byte{'r'}, std::byte{'s'},
        std::byte{'i'}, std::byte{'o'}, std::byte{'n'}, std::byte{'='},
        std::byte{'1'}, std::byte{'\n'}, std::byte{0xcf}, std::byte{0x90}};
    const auto bareUnicode = binobf::config::parse_transform_config(
        unsafeBareUnicode, std::filesystem::path{"config.toml"});
    REQUIRE(!bareUnicode.has_value());
    REQUIRE_EQ(bareUnicode.error().code, std::string{"config.syntax"});

    const auto quotedUnicode = parse(
        "version=1\npreserve_symbols=[\"\xcf\x80\"]\n");
    REQUIRE(quotedUnicode.has_value());

    const auto splitHeader = parse(
        "version=1\n[\nmanifest]\nenabled=false\n");
    REQUIRE(!splitHeader.has_value());
    REQUIRE_EQ(splitHeader.error().code, std::string{"config.syntax"});
}

TEST_CASE(config_rejects_manifest_and_lineage_table_mistakes) {
    const auto manifestUnknown = parse("version=1\n[manifest]\nextra=true\n");
    REQUIRE(!manifestUnknown.has_value());
    REQUIRE_EQ(manifestUnknown.error().code, std::string{"config.unknown_key"});

    const auto disabledPath = parse(
        "version=1\n[manifest]\nenabled=false\npath=\"manifest.json\"\n");
    REQUIRE(!disabledPath.has_value());
    REQUIRE_EQ(disabledPath.error().code, std::string{"config.manifest_conflict"});

    const auto wrongLineage = parse("version=1\n[lineage]\npath=4\n");
    REQUIRE(!wrongLineage.has_value());
    REQUIRE_EQ(wrongLineage.error().code, std::string{"config.type"});
}

TEST_CASE(config_parses_and_canonicalizes_function_selection) {
    const auto parsed = parse(R"(
version = 1
seed = 11
[selection]
include = ["critical"]
exclude = ["public_api"]
include_regex = ["^crypto_.*$"]
exclude_regex = [".*_test$"]
sections = [".text"]
visibility = ["local", "external"]
percentage = 37
seed = 99
)");
    REQUIRE(parsed.has_value());
    REQUIRE(parsed.value().config.selection.has_value());
    const auto& selection = *parsed.value().config.selection;
    REQUIRE_EQ(selection.includeNames, (std::vector<std::string>{"critical"}));
    REQUIRE_EQ(selection.percentage, std::optional<std::uint8_t>{37});
    REQUIRE_EQ(selection.seed, std::optional<std::uint64_t>{99});
    REQUIRE_EQ(selection.visibilities.size(), std::size_t{2});
    REQUIRE_CONTAINS(parsed.value().canonicalJson, "\"include_regex\":[\"^crypto_.*$\"]");
    REQUIRE_CONTAINS(parsed.value().canonicalJson, "\"percentage\":37");
}

TEST_CASE(config_rejects_invalid_function_selection) {
    const auto regex = parse("version=1\n[selection]\ninclude_regex=[\"[bad\"]\n");
    REQUIRE(!regex.has_value());
    REQUIRE_EQ(regex.error().code, "selection.regex");

    const auto percentage = parse("version=1\n[selection]\npercentage=101\n");
    REQUIRE(!percentage.has_value());
    REQUIRE_EQ(percentage.error().code, "config.value");

    const auto visibility = parse(
        "version=1\n[selection]\nvisibility=[\"package\"]\n");
    REQUIRE(!visibility.has_value());
    REQUIRE_EQ(visibility.error().code, "config.value");

    const auto unknown = parse("version=1\n[selection]\nmodule=\"core\"\n");
    REQUIRE(!unknown.has_value());
    REQUIRE_EQ(unknown.error().code, "config.unknown_key");
}

int main() {
    return binobf::test::run_all();
}

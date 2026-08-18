#include "../test_support.hpp"

#include <binobf/evidence/manifest.hpp>

#include <string>

TEST_CASE(manifest_serialization_is_deterministic_bounded_to_selected_names_and_versioned) {
    const binobf::evidence::BuildManifest manifest{
        .schemaVersion = 1,
        .toolVersion = "0.1.0",
        .inputName = "input.obj",
        .outputName = "output.obj",
        .inputSha256 = "1111",
        .outputSha256 = "2222",
        .configSha256 = "3333",
        .seed = 77,
        .passes = {"strip-debug"},
        .format = "COFF",
        .architecture = "x86-64",
        .inputSize = 10,
        .outputSize = 9,
        .reports = {{"strip-debug", "applied", 4, 1, 0}},
        .verification = "reparsed",
    };

    const auto first = binobf::evidence::serialize_manifest(manifest);
    const auto second = binobf::evidence::serialize_manifest(manifest);
    REQUIRE_EQ(first, second);
    REQUIRE_CONTAINS(first, "\"schema_version\":1");
    REQUIRE_CONTAINS(first, "\"config_sha256\":\"3333\"");
    REQUIRE_CONTAINS(first, "\"name\":\"input.obj\"");
    REQUIRE_CONTAINS(first, "\"verification\":\"reparsed\"");
    REQUIRE(first.find("timestamp") == std::string::npos);
    REQUIRE(first.find("D:/") == std::string::npos);
    REQUIRE_EQ(binobf::evidence::tool_version(), std::string_view{"0.1.0"});
}

int main() {
    return binobf::test::run_all();
}

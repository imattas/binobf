#include "../test_support.hpp"
#include "harness.hpp"

#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/transforms/baseline.hpp>
#include <binobf/transforms/instruction.hpp>
#include <binobf/transforms/pass_manager.hpp>
#include <binobf/verify/structural_verifier.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::filesystem::path objectFixture;
std::filesystem::path driverSource;
std::filesystem::path supportObject;
std::filesystem::path cCompiler;
std::filesystem::path outputDirectory;

auto read_file(const std::filesystem::path& path) -> std::vector<std::byte> {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("could not open differential fixture");
    const auto end = stream.tellg();
    if (end < 0) throw std::runtime_error("could not size differential fixture");
    std::vector<std::byte> bytes(static_cast<std::size_t>(end));
    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!stream) throw std::runtime_error("could not read differential fixture");
    return bytes;
}

auto transform_fixture() -> std::vector<std::byte> {
    const auto originalBytes = read_file(objectFixture);
    const auto originalVerified = binobf::verify_object(originalBytes, objectFixture.filename().string());
    if (!originalVerified.has_value()) {
        throw std::runtime_error(originalVerified.error().message);
    }
    binobf::PassManager manager;
    if (!manager.add(binobf::make_strip_debug_pass()).has_value()
        || !manager.add(binobf::make_metadata_cleanup_pass()).has_value()
        || !manager.add(binobf::make_strip_local_symbols_pass()).has_value()
        || !manager.add(binobf::make_rename_private_symbols_pass()).has_value()
        || !manager.add(binobf::make_instruction_substitution_pass()).has_value()
        || !manager.add(binobf::make_constant_rewriting_pass()).has_value()
        || !manager.add(binobf::make_branch_inversion_pass()).has_value()
        || !manager.add(binobf::make_dead_code_insertion_pass()).has_value()
        || !manager.add(binobf::make_block_splitting_pass()).has_value()
        || !manager.add(binobf::make_block_reordering_pass()).has_value()
        || !manager.add(binobf::make_function_reordering_pass()).has_value()) {
        throw std::runtime_error("could not assemble differential pass pipeline");
    }
    binobf::TransformContext context{UINT64_C(0xd1ff3e7a), false};
    const auto transformed = manager.run(context, originalVerified.value().image);
    if (!transformed.has_value()) throw std::runtime_error(transformed.error().message);
    constexpr std::array requiredPasses{
        "instruction-substitution", "constant-rewriting", "branch-inversion",
        "dead-code-insertion", "block-splitting", "block-reordering",
        "function-reordering"};
    for (const auto required : requiredPasses) {
        const auto report = std::find_if(
            transformed.value().reports.begin(), transformed.value().reports.end(),
            [required](const auto& candidate) { return candidate.name == required; });
        if (report == transformed.value().reports.end()
            || report->status != binobf::PassStatus::Applied) {
            throw std::runtime_error(std::string{required} + " did not apply to the fixture");
        }
    }
    const auto written = binobf::write_object(transformed.value().image);
    if (!written.has_value()) throw std::runtime_error(written.error().message);
    const auto verified = binobf::verify_object(written.value(), "differential-transformed.o");
    if (!verified.has_value()) throw std::runtime_error(verified.error().message);
    return written.value();
}

} // namespace

TEST_CASE(differential_harness_compares_all_required_observables) {
    binobf::test::DifferentialHarness harness{
        cCompiler, driverSource, objectFixture, supportObject, outputDirectory};
    harness.prepare(transform_fixture());

    constexpr std::array inputs{-17, -1, 0, 1, 7, 31};
    for (std::size_t index = 0; index < inputs.size(); ++index) {
        const auto caseName = "case-" + std::to_string(index);
        const auto original = harness.run_original(inputs[index], caseName);
        const auto transformed = harness.run_transformed(inputs[index], caseName);
        REQUIRE_EQ(transformed.exitStatus, original.exitStatus);
        REQUIRE_EQ(transformed.standardOutput, original.standardOutput);
        REQUIRE_EQ(transformed.standardError, original.standardError);
        REQUIRE_EQ(transformed.deterministicFile, original.deterministicFile);
        REQUIRE(!original.standardOutput.empty());
        REQUIRE(!original.deterministicFile.empty());
        REQUIRE_CONTAINS(original.standardOutputText(), "input=" + std::to_string(inputs[index]));
        REQUIRE_CONTAINS(original.standardOutputText(), " add=");
        REQUIRE_CONTAINS(original.standardOutputText(), " accumulate=");
        REQUIRE_CONTAINS(
            original.standardOutputText(), " pattern=42 secondary=7 blocks=42");
        REQUIRE_CONTAINS(original.deterministicFileText(), "bias_before=3");
        REQUIRE_CONTAINS(original.deterministicFileText(), "bias_after=");
    }
}

int main(int argc, char** argv) {
    if (argc != 6) return 2;
    objectFixture = argv[1];
    supportObject = argv[2];
    driverSource = argv[3];
    cCompiler = argv[4];
    outputDirectory = argv[5];
    return binobf::test::run_all();
}

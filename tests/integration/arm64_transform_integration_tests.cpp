#include "../test_support.hpp"

#include <binobf/analysis/object_analyzer.hpp>
#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/transforms/instruction.hpp>
#include <binobf/transforms/pass_manager.hpp>

#include <array>
#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::filesystem::path coffFixture;
std::filesystem::path elfFixture;

auto read_file(const std::filesystem::path& path) -> std::vector<std::byte> {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("could not open ARM64 transform fixture");
    const auto end = stream.tellg();
    if (end < 0) throw std::runtime_error("could not size ARM64 transform fixture");
    std::vector<std::byte> result(static_cast<std::size_t>(end));
    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(result.data()), static_cast<std::streamsize>(result.size()));
    if (!stream) throw std::runtime_error("could not read ARM64 transform fixture");
    return result;
}

auto passes() -> std::array<std::unique_ptr<binobf::TransformPass>, 7> {
    return {
        binobf::make_instruction_substitution_pass(),
        binobf::make_constant_rewriting_pass(),
        binobf::make_branch_inversion_pass(),
        binobf::make_block_splitting_pass(),
        binobf::make_dead_code_insertion_pass(),
        binobf::make_block_reordering_pass(),
        binobf::make_function_reordering_pass(),
    };
}

auto run_fixture(const std::filesystem::path& path) -> void {
    const auto originalBytes = read_file(path);
    const auto parsed = binobf::parse_object(originalBytes, path.filename().string());
    REQUIRE(parsed.has_value());
    REQUIRE_EQ(parsed.value().architecture, binobf::Architecture::ARM64);
    REQUIRE(parsed.value().type == binobf::BinaryType::RelocatableObject);
    REQUIRE(binobf::analyze_object(parsed.value()).has_value());

    for (auto&& pass : passes()) {
        const auto passName = std::string{pass->name()};
        binobf::PassManager manager;
        REQUIRE(manager.add(std::move(pass)).has_value());
        binobf::TransformContext context{UINT64_C(0xa16407), false};
        const auto transformed = manager.run(context, parsed.value());
        if (!transformed.has_value()) {
            throw std::runtime_error(
                passName + ": " + transformed.error().code + ": " + transformed.error().message);
        }
        REQUIRE_EQ(transformed.value().reports.size(), std::size_t{1});
        if (transformed.value().reports.front().status != binobf::PassStatus::Applied) {
            throw std::runtime_error(passName + " status="
                + std::to_string(static_cast<unsigned int>(
                    transformed.value().reports.front().status)));
        }
        REQUIRE(transformed.value().reports.front().statistics.changed > 0U);
        REQUIRE(transformed.value().changed);
        const auto written = binobf::write_object(transformed.value().image);
        REQUIRE(written.has_value());
        REQUIRE(written.value() != originalBytes);
        const auto reparsed = binobf::parse_object(written.value(), "arm64-transformed.o");
        REQUIRE(reparsed.has_value());
        REQUIRE_EQ(reparsed.value().architecture, binobf::Architecture::ARM64);
        const auto reanalyzed = binobf::analyze_object(reparsed.value());
        REQUIRE(reanalyzed.has_value());
        REQUIRE(std::ranges::all_of(
            reanalyzed.value().image.functions,
            [](const auto& function) { return function.complete; }));
    }
}

} // namespace

TEST_CASE(all_seven_machine_passes_transform_owned_arm64_objects) {
    // Each format is independently parsed, transformed, serialized, and reparsed.
    run_fixture(coffFixture);
    run_fixture(elfFixture);
}

int main(int argc, char** argv) {
    if (argc != 3) return 2;
    coffFixture = argv[1];
    elfFixture = argv[2];
    return binobf::test::run_all();
}

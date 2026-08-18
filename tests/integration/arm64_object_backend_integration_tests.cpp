#include "../test_support.hpp"

#include <binobf/analysis/object_analyzer.hpp>
#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/transforms/instruction.hpp>
#include <binobf/transforms/pass_manager.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::filesystem::path corpus;
std::vector<std::filesystem::path> extraObjects;

auto read_file(const std::filesystem::path& path) -> std::vector<std::byte> {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("could not open corpus object");
    const auto end = stream.tellg();
    if (end < 0) throw std::runtime_error("could not size corpus object");
    std::vector<std::byte> bytes(static_cast<std::size_t>(end));
    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!stream) throw std::runtime_error("could not read corpus object");
    return bytes;
}

auto pass_factories() -> std::array<std::unique_ptr<binobf::TransformPass>, 7> {
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

auto corpus_objects() -> std::vector<std::filesystem::path> {
    std::ifstream manifest(corpus / "manifest.txt");
    if (!manifest) throw std::runtime_error("missing corpus manifest");
    std::vector<std::filesystem::path> result;
    std::string line;
    while (std::getline(manifest, line)) {
        if (!line.starts_with("object|")) continue;
        const auto last = line.rfind('|');
        const auto previous = line.rfind('|', last == std::string::npos ? last : last - 1U);
        if (last == std::string::npos || previous == std::string::npos) continue;
        result.emplace_back(line.substr(previous + 1U, last - previous - 1U));
    }
    result.insert(result.end(), extraObjects.begin(), extraObjects.end());
    return result;
}

} // namespace

TEST_CASE(arm64_compiler_corpus_transforms_and_reparses_every_object) {
    REQUIRE(!corpus.empty());
    const auto objects = corpus_objects();
    REQUIRE(objects.size() >= std::size_t{24});
    std::map<std::string, std::array<bool, 2>> applied;
    const auto output = corpus / "transformed";
    std::filesystem::create_directories(output);

    for (const auto& object : objects) {
        const auto parsed = binobf::parse_object(read_file(object), object.filename().string());
        REQUIRE(parsed.has_value());
        REQUIRE_EQ(parsed.value().architecture, binobf::Architecture::ARM64);
        REQUIRE(binobf::analyze_object(parsed.value()).has_value());
        const auto formatIndex = parsed.value().format == binobf::BinaryFormat::COFF ? 0U : 1U;
        for (auto&& pass : pass_factories()) {
            const auto name = std::string{pass->name()};
            binobf::PassManager manager;
            REQUIRE(manager.add(std::move(pass)).has_value());
            binobf::TransformContext context{UINT64_C(0x9a64c0de), false};
            const auto transformed = manager.run(context, parsed.value());
            if (!transformed.has_value()) {
                throw std::runtime_error(name + ": " + transformed.error().code);
            }
            REQUIRE_EQ(transformed.value().reports.size(), std::size_t{1});
            const auto status = transformed.value().reports.front().status;
            REQUIRE(status == binobf::PassStatus::Applied
                || status == binobf::PassStatus::Unchanged
                || status == binobf::PassStatus::Unsupported);
            if (status == binobf::PassStatus::Applied) applied[name][formatIndex] = true;
            const auto bytes = binobf::write_object(transformed.value().image);
            REQUIRE(bytes.has_value());
            const auto reparsed = binobf::parse_object(bytes.value(), name + ".o");
            REQUIRE(reparsed.has_value());
            REQUIRE_EQ(reparsed.value().architecture, binobf::Architecture::ARM64);
            REQUIRE(binobf::analyze_object(reparsed.value()).has_value());
            const auto destination = output /
                (object.stem().string() + "." + name + object.extension().string());
            std::ofstream stream(destination, std::ios::binary);
            REQUIRE(stream.good());
            stream.write(reinterpret_cast<const char*>(bytes.value().data()),
                         static_cast<std::streamsize>(bytes.value().size()));
            REQUIRE(stream.good());
        }
    }
    for (const auto& [name, formats] : applied) {
        if (!formats[0] || !formats[1]) {
            throw std::runtime_error(name + " coverage=" + std::to_string(formats[0])
                + "," + std::to_string(formats[1]));
        }
    }
}

int main(int argc, char** argv) {
    if (argc < 2) return 2;
    corpus = argv[1];
    for (int index = 2; index < argc; ++index) extraObjects.emplace_back(argv[index]);
    return binobf::test::run_all();
}

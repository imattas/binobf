#include <binobf/analysis/object_analyzer.hpp>
#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/transforms/instruction.hpp>
#include <binobf/transforms/pass_manager.hpp>

#include <array>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

auto read_file(const std::filesystem::path& path) -> std::vector<std::byte> {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("could not open native fixture");
    const auto end = stream.tellg();
    if (end < 0) throw std::runtime_error("could not size native fixture");
    std::vector<std::byte> bytes(static_cast<std::size_t>(end));
    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!stream) throw std::runtime_error("could not read native fixture");
    return bytes;
}

void write_file(const std::filesystem::path& path, const std::vector<std::byte>& bytes) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    if (!stream) throw std::runtime_error("could not write transformed native fixture");
}

auto make_pass(std::size_t index) -> std::unique_ptr<binobf::TransformPass> {
    switch (index) {
    case 0: return binobf::make_instruction_substitution_pass();
    case 1: return binobf::make_constant_rewriting_pass();
    case 2: return binobf::make_branch_inversion_pass();
    case 3: return binobf::make_block_splitting_pass();
    case 4: return binobf::make_dead_code_insertion_pass();
    case 5: return binobf::make_block_reordering_pass();
    case 6: return binobf::make_function_reordering_pass();
    default: throw std::runtime_error("invalid native differential pass index");
    }
}

auto transform_once(
    const binobf::BinaryImage& source,
    std::size_t passIndex,
    std::string& passName) -> std::vector<std::byte> {
    auto pass = make_pass(passIndex);
    passName = std::string{pass->name()};
    binobf::PassManager manager;
    const auto added = manager.add(std::move(pass));
    if (!added.has_value()) throw std::runtime_error(added.error().message);
    binobf::TransformContext context{UINT64_C(0x386d1ff), false};
    const auto outcome = manager.run(context, source);
    if (!outcome.has_value()) {
        throw std::runtime_error(
            passName + ": " + outcome.error().code + ": " + outcome.error().message);
    }
    if (outcome.value().reports.size() != 1
        || outcome.value().reports.front().status != binobf::PassStatus::Applied) {
        throw std::runtime_error(passName + " did not apply to the native fixture");
    }
    const auto written = binobf::write_object(outcome.value().image);
    if (!written.has_value()) {
        throw std::runtime_error(
            passName + ": " + written.error().code + ": " + written.error().message);
    }
    const auto reparsed = binobf::parse_object(written.value(), passName + ".obj");
    if (!reparsed.has_value() || reparsed.value().architecture != binobf::Architecture::X86) {
        throw std::runtime_error(passName + " did not produce a valid i386 object");
    }
    return written.value();
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 3) return 2;
        const std::filesystem::path fixture = argv[1];
        const std::filesystem::path outputDirectory = argv[2];
        std::filesystem::create_directories(outputDirectory);
        const auto parsed = binobf::parse_object(read_file(fixture), fixture.filename().string());
        if (!parsed.has_value()) throw std::runtime_error(parsed.error().message);
        const auto analyzed = binobf::analyze_object(parsed.value());
        if (!analyzed.has_value()) throw std::runtime_error(analyzed.error().message);
        std::ofstream manifest(outputDirectory / "manifest.txt", std::ios::trunc);
        if (!manifest) throw std::runtime_error("could not create native output manifest");
        for (std::size_t index = 0; index < 7; ++index) {
            std::string firstName;
            std::string secondName;
            const auto first = transform_once(analyzed.value().image, index, firstName);
            const auto second = transform_once(analyzed.value().image, index, secondName);
            if (firstName != secondName || first != second) {
                throw std::runtime_error(firstName + " native output was nondeterministic");
            }
            const auto output = outputDirectory / (firstName + ".obj");
            write_file(output, first);
            manifest << firstName << '|' << output.string() << '\n';
        }
        if (!manifest) throw std::runtime_error("could not write native output manifest");
        return 0;
    } catch (const std::exception& exception) {
        std::ofstream error("x86-native-differential-error.txt", std::ios::trunc);
        error << exception.what() << '\n';
        return 1;
    }
}

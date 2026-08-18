#include "../test_support.hpp"

#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/transforms/instruction.hpp>
#include <binobf/transforms/pass_manager.hpp>
#include <binobf/verify/structural_verifier.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::filesystem::path coffFixture;
std::filesystem::path elfFixture;
std::filesystem::path llvmReadobj;
std::filesystem::path elfLinker;
std::filesystem::path outputDirectory;

auto read_file(const std::filesystem::path& path) -> std::vector<std::byte> {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("could not open instruction fixture");
    const auto end = stream.tellg();
    if (end < 0) throw std::runtime_error("could not size instruction fixture");
    std::vector<std::byte> result(static_cast<std::size_t>(end));
    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(result.data()), static_cast<std::streamsize>(result.size()));
    if (!stream) throw std::runtime_error("could not read instruction fixture");
    return result;
}

void write_file(const std::filesystem::path& path, const std::vector<std::byte>& data) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(data.data()),
                 static_cast<std::streamsize>(data.size()));
    if (!stream) throw std::runtime_error("could not write transformed instruction fixture");
}

auto quote(const std::filesystem::path& path) -> std::string {
    return '"' + path.string() + '"';
}

auto run_command(const std::vector<std::filesystem::path>& arguments) -> int {
    std::string command;
    for (const auto& argument : arguments) {
        if (!command.empty()) command.push_back(' ');
        command += quote(argument);
    }
#ifdef _WIN32
    command = '"' + command + '"';
#endif
    return std::system(command.c_str());
}

auto transform_all(const std::filesystem::path& input) -> std::vector<std::byte> {
    const auto parsed = binobf::parse_object(read_file(input), input.filename().string());
    if (!parsed.has_value()) throw std::runtime_error(parsed.error().message);
    binobf::PassManager manager;
    REQUIRE(manager.add(binobf::make_instruction_substitution_pass()).has_value());
    REQUIRE(manager.add(binobf::make_constant_rewriting_pass()).has_value());
    REQUIRE(manager.add(binobf::make_branch_inversion_pass()).has_value());
    REQUIRE(manager.add(binobf::make_dead_code_insertion_pass()).has_value());
    REQUIRE(manager.add(binobf::make_block_splitting_pass()).has_value());
    REQUIRE(manager.add(binobf::make_block_reordering_pass()).has_value());
    REQUIRE(manager.add(binobf::make_function_reordering_pass()).has_value());
    binobf::TransformContext context{UINT64_C(0x601d5eed), false};
    const auto transformed = manager.run(context, parsed.value());
    if (!transformed.has_value()) throw std::runtime_error(transformed.error().message);
    for (const auto& report : transformed.value().reports) {
        REQUIRE_EQ(report.status, binobf::PassStatus::Applied);
        REQUIRE(report.statistics.changed > 0);
    }
    const auto written = binobf::write_object(transformed.value().image);
    if (!written.has_value()) throw std::runtime_error(written.error().message);
    const auto verified = binobf::verify_object(written.value(), "instruction-transformed.o");
    if (!verified.has_value()) throw std::runtime_error(verified.error().message);
    return written.value();
}

} // namespace

TEST_CASE(real_coff_and_elf_instruction_patterns_transform_and_standard_tools_accept_them) {
    std::filesystem::create_directories(outputDirectory);
    const auto coffOutput = outputDirectory / "transform-patterns-transformed.obj";
    const auto elfOutput = outputDirectory / "transform-patterns-transformed.o";
    write_file(coffOutput, transform_all(coffFixture));
    write_file(elfOutput, transform_all(elfFixture));

    const auto transformedElf = binobf::parse_object(
        read_file(elfOutput), elfOutput.filename().string());
    REQUIRE(transformedElf.has_value());
    std::set<std::int64_t> textSectionAddends;
    for (const auto& relocation : transformedElf.value().relocations) {
        if (!relocation.targetSymbol.has_value()) continue;
        const auto target = std::find_if(
            transformedElf.value().symbols.begin(), transformedElf.value().symbols.end(),
            [&](const auto& symbol) { return symbol.id == *relocation.targetSymbol; });
        if (target == transformedElf.value().symbols.end()
            || target->kind != binobf::SymbolKind::Section
            || !target->section.has_value()) continue;
        const auto targetSection = std::find_if(
            transformedElf.value().sections.begin(), transformedElf.value().sections.end(),
            [&](const auto& section) { return section.id == *target->section; });
        if (targetSection != transformedElf.value().sections.end()
            && targetSection->name == ".text") {
            textSectionAddends.insert(relocation.addend);
        }
    }
    std::set<std::int64_t> textFunctionAddresses;
    for (const auto& symbol : transformedElf.value().symbols) {
        if (!symbol.defined || symbol.kind != binobf::SymbolKind::Function
            || !symbol.section.has_value()) {
            continue;
        }
        const auto section = std::find_if(
            transformedElf.value().sections.begin(), transformedElf.value().sections.end(),
            [&](const auto& candidate) { return candidate.id == *symbol.section; });
        if (section != transformedElf.value().sections.end() && section->name == ".text") {
            textFunctionAddresses.insert(static_cast<std::int64_t>(symbol.address.value));
        }
    }
    REQUIRE_EQ(textSectionAddends, textFunctionAddresses);

    const auto transformedCoff = binobf::parse_object(
        read_file(coffOutput), coffOutput.filename().string());
    REQUIRE(transformedCoff.has_value());
    const auto textSectionSymbol = std::find_if(
        transformedCoff.value().symbols.begin(), transformedCoff.value().symbols.end(),
        [](const auto& symbol) {
            return symbol.kind == binobf::SymbolKind::Section && symbol.name == ".text";
        });
    REQUIRE(textSectionSymbol != transformedCoff.value().symbols.end());
    REQUIRE(textSectionSymbol->auxiliaryData.size() >= std::size_t{12});
    REQUIRE(std::all_of(
        textSectionSymbol->auxiliaryData.begin() + 8,
        textSectionSymbol->auxiliaryData.begin() + 12,
        [](std::byte value) { return value == std::byte{0}; }));

    REQUIRE_EQ(run_command({llvmReadobj, "--sections", "--symbols", "--relocations", coffOutput}), 0);
    REQUIRE_EQ(run_command({llvmReadobj, "--sections", "--symbols", "--relocations", elfOutput}), 0);
    const auto linkedElf = outputDirectory / "transform-patterns-linked.o";
    REQUIRE_EQ(run_command({elfLinker, "-r", elfOutput, "-o", linkedElf}), 0);
    const auto reparsed = binobf::parse_object(read_file(linkedElf), linkedElf.filename().string());
    REQUIRE(reparsed.has_value());
    REQUIRE(std::any_of(
        reparsed.value().symbols.begin(), reparsed.value().symbols.end(), [](const auto& symbol) {
            return symbol.name == "binobf_transform_pattern";
        }));
}

int main(int argc, char** argv) {
    if (argc != 6) return 2;
    coffFixture = argv[1];
    elfFixture = argv[2];
    llvmReadobj = argv[3];
    elfLinker = argv[4];
    outputDirectory = argv[5];
    return binobf::test::run_all();
}

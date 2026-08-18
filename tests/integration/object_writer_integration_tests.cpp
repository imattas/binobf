#include "../test_support.hpp"

#include <binobf/analysis/object_analyzer.hpp>
#include <binobf/cli/command.hpp>
#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/transforms/baseline.hpp>
#include <binobf/transforms/pass_manager.hpp>
#include <binobf/verify/structural_verifier.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::filesystem::path coffFixture;
std::filesystem::path elfFixture;
std::filesystem::path driverSource;
std::filesystem::path cCompiler;
std::filesystem::path llvmReadobj;
std::filesystem::path elfLinker;
std::filesystem::path outputDirectory;

auto read_file(const std::filesystem::path& path) -> std::vector<std::byte> {
    std::error_code sizeError;
    const auto fileSize = std::filesystem::file_size(path, sizeError);
    if (sizeError || fileSize > static_cast<std::uintmax_t>(SIZE_MAX)) {
        throw std::runtime_error("could not size fixture: " + path.string());
    }
    std::vector<std::byte> bytes(static_cast<std::size_t>(fileSize));
    std::ifstream stream(path, std::ios::binary);
    stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!stream) {
        throw std::runtime_error("could not read fixture: " + path.string());
    }
    return bytes;
}

void write_file(const std::filesystem::path& path, const std::vector<std::byte>& bytes) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    if (!stream) {
        throw std::runtime_error("could not write round-trip object: " + path.string());
    }
}

auto parse_bytes(const std::vector<std::byte>& bytes, std::string_view name)
    -> binobf::BinaryImage {
    auto parsed = binobf::parse_object(bytes, name);
    if (!parsed.has_value()) {
        throw std::runtime_error(
            "parser rejected object: " + parsed.error().code + ": " + parsed.error().message);
    }
    return std::move(parsed).value();
}

auto has_symbol(const binobf::BinaryImage& image, std::string_view name) -> bool {
    return std::any_of(image.symbols.begin(), image.symbols.end(), [name](const auto& symbol) {
        return symbol.name == name;
    });
}

auto has_symbol_id(const binobf::BinaryImage& image, binobf::EntityId id) -> bool {
    return std::any_of(image.symbols.begin(), image.symbols.end(), [id](const auto& symbol) {
        return symbol.id == id;
    });
}

auto has_section_id(const binobf::BinaryImage& image, binobf::EntityId id) -> bool {
    return std::any_of(image.sections.begin(), image.sections.end(), [id](const auto& section) {
        return section.id == id;
    });
}

auto has_section(const binobf::BinaryImage& image, std::string_view name) -> bool {
    return std::any_of(image.sections.begin(), image.sections.end(), [name](const auto& section) {
        return section.name == name;
    });
}

auto transform_object(const std::filesystem::path& input, const std::filesystem::path& output)
    -> binobf::BinaryImage {
    const auto source = parse_bytes(read_file(input), input.filename().string());
    binobf::PassManager manager;
    REQUIRE(manager.add(binobf::make_strip_debug_pass()).has_value());
    REQUIRE(manager.add(binobf::make_metadata_cleanup_pass()).has_value());
    REQUIRE(manager.add(binobf::make_rename_private_symbols_pass()).has_value());
    binobf::TransformContext context{UINT64_C(0x12345678), false};
    const auto transformed = manager.run(context, source);
    if (!transformed.has_value()) {
        throw std::runtime_error(
            "transform failed: " + transformed.error().code + ": "
            + transformed.error().message);
    }
    const auto written = binobf::write_object(transformed.value().image);
    if (!written.has_value()) {
        throw std::runtime_error(
            "transformed writer failed: " + written.error().code + ": "
            + written.error().message);
    }
    write_file(output, written.value());
    return parse_bytes(written.value(), output.filename().string());
}

auto rewrite(const std::filesystem::path& input, const std::filesystem::path& output)
    -> binobf::BinaryImage {
    const auto inputBytes = read_file(input);
    const auto original = parse_bytes(inputBytes, input.filename().string());
    const auto written = binobf::write_object(original);
    if (!written.has_value()) {
        throw std::runtime_error(
            "writer rejected object: " + written.error().code + ": " + written.error().message);
    }
    REQUIRE(written.value() != inputBytes);
    write_file(output, written.value());
    const auto reparsed = parse_bytes(written.value(), output.filename().string());
    REQUIRE_EQ(reparsed.format, original.format);
    REQUIRE_EQ(reparsed.architecture, original.architecture);
    REQUIRE_EQ(reparsed.sections.size(), original.sections.size());
    REQUIRE_EQ(reparsed.symbols.size(), original.symbols.size());
    REQUIRE_EQ(reparsed.relocations.size(), original.relocations.size());
    std::set<std::string> originalNames;
    std::set<std::string> rewrittenNames;
    for (const auto& symbol : original.symbols) originalNames.insert(symbol.name);
    for (const auto& symbol : reparsed.symbols) rewrittenNames.insert(symbol.name);
    REQUIRE_EQ(rewrittenNames, originalNames);
    return reparsed;
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

} // namespace

TEST_CASE(real_objects_round_trip_and_standard_tools_accept_them) {
    std::filesystem::create_directories(outputDirectory);
    const auto rewrittenCoff = outputDirectory / "arithmetic-rewritten.obj";
    const auto rewrittenElf = outputDirectory / "arithmetic-rewritten.o";
    rewrite(coffFixture, rewrittenCoff);
    const auto rewrittenElfImage = rewrite(elfFixture, rewrittenElf);

    REQUIRE_EQ(run_command({llvmReadobj, "--sections", "--symbols", "--relocations", rewrittenCoff}), 0);
    REQUIRE_EQ(run_command({llvmReadobj, "--sections", "--symbols", "--relocations", rewrittenElf}), 0);

    const auto linkedElf = outputDirectory / "arithmetic-linked.o";
    REQUIRE_EQ(run_command({elfLinker, "-r", rewrittenElf, "-o", linkedElf}), 0);
    const auto linkedImage = parse_bytes(read_file(linkedElf), linkedElf.filename().string());
    REQUIRE_EQ(linkedImage.format, binobf::BinaryFormat::ELF);
    REQUIRE_EQ(linkedImage.relocations.size(), rewrittenElfImage.relocations.size());
    REQUIRE(has_symbol(linkedImage, "binobf_fixture_add"));
    REQUIRE(has_symbol(linkedImage, "binobf_fixture_accumulate"));
    REQUIRE(has_symbol(linkedImage, "binobf_fixture_bias"));
    for (const auto& relocation : linkedImage.relocations) {
        REQUIRE(has_section_id(linkedImage, relocation.section));
        if (relocation.targetSymbol.has_value()) {
            REQUIRE(has_symbol_id(linkedImage, *relocation.targetSymbol));
        }
    }
}

TEST_CASE(public_structural_verifier_accepts_compiler_produced_objects) {
    const auto coffVerified = binobf::verify_object(
        read_file(coffFixture), coffFixture.filename().string());
    const auto elfVerified = binobf::verify_object(
        read_file(elfFixture), elfFixture.filename().string());
    REQUIRE(coffVerified.has_value());
    REQUIRE(elfVerified.has_value());
    REQUIRE_EQ(coffVerified.value().image.format, binobf::BinaryFormat::COFF);
    REQUIRE_EQ(elfVerified.value().image.format, binobf::BinaryFormat::ELF);
    REQUIRE_EQ(coffVerified.value().checks.size(), std::size_t{8});
    REQUIRE_EQ(elfVerified.value().checks.size(), std::size_t{8});
    for (std::size_t index = 0; index < 5; ++index) {
        REQUIRE_EQ(coffVerified.value().checks[index].status, binobf::VerificationStatus::Passed);
        REQUIRE_EQ(elfVerified.value().checks[index].status, binobf::VerificationStatus::Passed);
    }
}

TEST_CASE(machine_code_analysis_recovers_real_object_functions_cfg_and_references) {
    const auto coff = binobf::analyze_object(
        parse_bytes(read_file(coffFixture), coffFixture.filename().string()));
    const auto elf = binobf::analyze_object(
        parse_bytes(read_file(elfFixture), elfFixture.filename().string()));
    REQUIRE(coff.has_value());
    REQUIRE(elf.has_value());
    for (const auto* report : {&coff.value(), &elf.value()}) {
        REQUIRE(report->image.functions.size() >= std::size_t{2});
        REQUIRE(!report->image.instructions.empty());
        REQUIRE(!report->image.basicBlocks.empty());
        REQUIRE(std::all_of(
            report->image.functions.begin(), report->image.functions.end(), [](const auto& function) {
                return function.complete;
            }));
        REQUIRE(has_symbol(report->image, "binobf_fixture_add"));
        REQUIRE(has_symbol(report->image, "binobf_fixture_accumulate"));
        REQUIRE(std::any_of(
            report->image.functions.begin(), report->image.functions.end(), [](const auto& function) {
                return function.name == "binobf_fixture_add" && !function.instructions.empty()
                    && !function.basicBlocks.empty() && !function.lineage.parents.empty();
            }));
        REQUIRE(std::any_of(
            report->image.instructions.begin(), report->image.instructions.end(), [](const auto& instruction) {
                return std::any_of(
                    instruction.references.begin(), instruction.references.end(), [](const auto& reference) {
                        return reference.relocation.has_value();
                    });
            }));
    }
}

TEST_CASE(original_and_rewritten_coff_objects_link_and_run_identically) {
    const auto rewrittenCoff = outputDirectory / "arithmetic-rewritten.obj";
    if (!std::filesystem::exists(rewrittenCoff)) {
        rewrite(coffFixture, rewrittenCoff);
    }
    const auto originalExecutable = outputDirectory / "original-runtime.exe";
    const auto rewrittenExecutable = outputDirectory / "rewritten-runtime.exe";
    REQUIRE_EQ(run_command({cCompiler, driverSource, coffFixture, "-o", originalExecutable}), 0);
    REQUIRE_EQ(run_command({cCompiler, driverSource, rewrittenCoff, "-o", rewrittenExecutable}), 0);
    REQUIRE_EQ(run_command({originalExecutable}), 0);
    REQUIRE_EQ(run_command({rewrittenExecutable}), 0);
}

TEST_CASE(real_baseline_transformations_link_and_preserve_runtime_behavior) {
    std::filesystem::create_directories(outputDirectory);
    const auto transformedCoff = outputDirectory / "arithmetic-transformed.obj";
    const auto transformedElf = outputDirectory / "arithmetic-transformed.o";
    const auto originalCoff = parse_bytes(read_file(coffFixture), coffFixture.filename().string());
    const auto coffImage = transform_object(coffFixture, transformedCoff);
    const auto elfImage = transform_object(elfFixture, transformedElf);

    REQUIRE(!has_section(coffImage, ".debug$S"));
    REQUIRE(!has_section(coffImage, ".debug$T"));
    REQUIRE(!has_section(coffImage, ".llvm_addrsig"));
    REQUIRE(has_section(coffImage, ".drectve"));
    for (const auto* sectionName : {".xdata", ".pdata", ".rsrc"}) {
        REQUIRE_EQ(has_section(coffImage, sectionName), has_section(originalCoff, sectionName));
    }
    REQUIRE(!has_section(elfImage, ".comment"));
    REQUIRE(!has_section(elfImage, ".llvm_addrsig"));
    REQUIRE(has_symbol(coffImage, "binobf_fixture_add"));
    REQUIRE(has_symbol(coffImage, "binobf_fixture_accumulate"));
    REQUIRE(has_symbol(elfImage, "binobf_fixture_add"));
    REQUIRE(has_symbol(elfImage, "binobf_fixture_accumulate"));

    REQUIRE_EQ(run_command({llvmReadobj, "--sections", "--symbols", "--relocations", transformedCoff}), 0);
    REQUIRE_EQ(run_command({llvmReadobj, "--sections", "--symbols", "--relocations", transformedElf}), 0);
    const auto linkedElf = outputDirectory / "arithmetic-transformed-linked.o";
    REQUIRE_EQ(run_command({elfLinker, "-r", transformedElf, "-o", linkedElf}), 0);
    const auto executable = outputDirectory / "transformed-runtime.exe";
    REQUIRE_EQ(run_command({cCompiler, driverSource, transformedCoff, "-o", executable}), 0);
    REQUIRE_EQ(run_command({executable}), 0);
}

TEST_CASE(cli_minimal_profile_transforms_real_objects_and_links_outputs) {
    std::filesystem::create_directories(outputDirectory);
    const auto cliCoff = outputDirectory / "arithmetic-cli-minimal.obj";
    const auto cliElf = outputDirectory / "arithmetic-cli-minimal.o";
    std::error_code ignored;
    std::filesystem::remove(cliCoff, ignored);
    std::filesystem::remove(cliElf, ignored);
    std::filesystem::remove(cliCoff.string() + ".manifest.json", ignored);
    std::filesystem::remove(cliElf.string() + ".manifest.json", ignored);

    const auto runTransform = [](const auto& input, const auto& outputPath) {
        const auto inputText = input.string();
        const auto outputText = outputPath.string();
        const std::array<std::string_view, 6> arguments{
            "transform", inputText, "-o", outputText, "--passes=minimal", "--seed=305419896"};
        std::ostringstream output;
        std::ostringstream errors;
        REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
        REQUIRE_CONTAINS(output.str(), "verification: reparsed");
        REQUIRE(errors.str().empty());
    };
    runTransform(coffFixture, cliCoff);
    runTransform(elfFixture, cliElf);

    REQUIRE_EQ(run_command({llvmReadobj, "--sections", "--symbols", "--relocations", cliCoff}), 0);
    REQUIRE_EQ(run_command({llvmReadobj, "--sections", "--symbols", "--relocations", cliElf}), 0);
    const auto cliLinkedElf = outputDirectory / "arithmetic-cli-minimal-linked.o";
    REQUIRE_EQ(run_command({elfLinker, "-r", cliElf, "-o", cliLinkedElf}), 0);
    const auto cliExecutable = outputDirectory / "cli-minimal-runtime.exe";
    REQUIRE_EQ(run_command({cCompiler, driverSource, cliCoff, "-o", cliExecutable}), 0);
    REQUIRE_EQ(run_command({cliExecutable}), 0);
}

int main(int argc, char** argv) {
    if (argc != 8) {
        std::cerr << "expected COFF, ELF, driver, compiler, llvm-readobj, ld.lld, and output paths\n";
        return 2;
    }
    coffFixture = argv[1];
    elfFixture = argv[2];
    driverSource = argv[3];
    cCompiler = argv[4];
    llvmReadobj = argv[5];
    elfLinker = argv[6];
    outputDirectory = argv[7];
    return binobf::test::run_all();
}

#include <binobf/analysis/object_analyzer.hpp>
#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/transforms/instruction.hpp>
#include <binobf/transforms/pass_manager.hpp>

#include "../test_support.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::filesystem::path corpusDirectory;
std::filesystem::path llvmReadobj;
std::filesystem::path llvmObjdump;
std::filesystem::path llvmNm;
std::filesystem::path lldLink;
std::filesystem::path elfLinker;
std::filesystem::path outputDirectory;

struct CorpusMember {
    std::string format;
    std::string optimization;
    std::string language;
    std::filesystem::path path;
};

auto read_file(const std::filesystem::path& path) -> std::vector<std::byte> {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("could not open " + path.string());
    const auto end = stream.tellg();
    if (end < 0) throw std::runtime_error("could not size " + path.string());
    std::vector<std::byte> bytes(static_cast<std::size_t>(end));
    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!stream) throw std::runtime_error("could not read " + path.string());
    return bytes;
}

void write_file(const std::filesystem::path& path, const std::vector<std::byte>& bytes) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    if (!stream) throw std::runtime_error("could not write " + path.string());
}

auto split(std::string_view value, char delimiter) -> std::vector<std::string> {
    std::vector<std::string> fields;
    std::size_t begin = 0;
    while (begin <= value.size()) {
        const auto end = value.find(delimiter, begin);
        fields.emplace_back(value.substr(begin, end == std::string_view::npos
            ? value.size() - begin : end - begin));
        if (end == std::string_view::npos) break;
        begin = end + 1;
    }
    return fields;
}

auto load_manifest() -> std::vector<CorpusMember> {
    std::ifstream stream(corpusDirectory / "manifest.txt");
    if (!stream) throw std::runtime_error("missing x86 corpus manifest");
    std::vector<CorpusMember> members;
    std::string line;
    while (std::getline(stream, line)) {
        const auto fields = split(line, '|');
        if (fields.size() >= 6 && fields[0] == "object") {
            members.push_back(CorpusMember{fields[1], fields[2], fields[3], fields[4]});
        }
    }
    return members;
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
    default: throw std::runtime_error("invalid pass index");
    }
}

auto quote(const std::filesystem::path& path) -> std::string {
    return '"' + path.string() + '"';
}

void run_checked(
    const std::vector<std::string>& arguments,
    const std::filesystem::path& logPath) {
    std::string command;
    for (const auto& argument : arguments) {
        if (!command.empty()) command.push_back(' ');
        command += '"' + argument + '"';
    }
    command += " > " + quote(logPath) + " 2>&1";
#ifdef _WIN32
    command = '"' + command + '"';
#endif
    const auto result = std::system(command.c_str());
    if (result != 0) {
        std::ifstream log(logPath);
        std::ostringstream captured;
        captured << log.rdbuf();
        throw std::runtime_error(
            "command failed (" + std::to_string(result) + "): " + command + "\n"
            + captured.str());
    }
}

void inspect_in_chunks(
    const std::filesystem::path& tool,
    const std::vector<std::string>& options,
    const std::vector<std::filesystem::path>& paths,
    std::string_view label) {
    constexpr std::size_t chunkSize = 12;
    for (std::size_t offset = 0; offset < paths.size(); offset += chunkSize) {
        std::vector<std::string> arguments{tool.string()};
        arguments.insert(arguments.end(), options.begin(), options.end());
        const auto end = std::min(paths.size(), offset + chunkSize);
        for (std::size_t index = offset; index < end; ++index) {
            arguments.push_back(paths[index].string());
        }
        run_checked(arguments, outputDirectory /
            (std::string{label} + '-' + std::to_string(offset / chunkSize) + ".log"));
    }
}

auto has_pass_lineage(const binobf::BinaryImage& image, std::string_view passName) -> bool {
    const auto contains = [passName](const auto& entity) {
        return std::ranges::any_of(entity.lineage.parents, [passName](const auto& parent) {
            return parent.passName == passName;
        });
    };
    return std::ranges::any_of(image.sections, contains)
        || std::ranges::any_of(image.symbols, contains)
        || std::ranges::any_of(image.functions, contains)
        || std::ranges::any_of(image.instructions, contains)
        || std::ranges::any_of(image.basicBlocks, contains)
        || std::ranges::any_of(image.relocations, contains)
        || std::ranges::any_of(image.unwindInfo, contains);
}

} // namespace

TEST_CASE(full_i386_compiler_matrix_transforms_deterministically_and_passes_standard_tools) {
    std::filesystem::create_directories(outputDirectory);
    const auto members = load_manifest();
    REQUIRE_EQ(members.size(), std::size_t{36});

    std::array<bool, 7> passApplied{};
    std::vector<std::filesystem::path> allObjects;
    std::vector<std::filesystem::path> coffOriginals;
    for (const auto& member : members) {
        const auto originalBytes = read_file(member.path);
        const auto parsed = binobf::parse_object(originalBytes, member.path.filename().string());
        REQUIRE(parsed.has_value());
        REQUIRE_EQ(parsed.value().architecture, binobf::Architecture::X86);
        const auto analyzed = binobf::analyze_object(parsed.value());
        REQUIRE(analyzed.has_value());
        REQUIRE(std::ranges::any_of(analyzed.value().image.functions, [](const auto& function) {
            return function.complete && !function.instructions.empty();
        }));
        allObjects.push_back(member.path);
        if (member.format == "coff") coffOriginals.push_back(member.path);

        for (std::size_t passIndex = 0; passIndex < passApplied.size(); ++passIndex) {
            std::vector<std::byte> deterministicBytes;
            std::string passName;
            for (std::size_t repeat = 0; repeat < 2; ++repeat) {
                auto pass = make_pass(passIndex);
                passName = std::string{pass->name()};
                binobf::PassManager manager;
                REQUIRE(manager.add(std::move(pass)).has_value());
                binobf::TransformContext context{UINT64_C(0x386c0f5), false};
                const auto outcome = manager.run(context, analyzed.value().image);
                if (!outcome.has_value()) {
                    throw std::runtime_error(
                        member.path.string() + " / " + passName + ": "
                        + outcome.error().code + ": " + outcome.error().message);
                }
                REQUIRE_EQ(outcome.value().reports.size(), std::size_t{1});
                const auto written = binobf::write_object(outcome.value().image);
                REQUIRE(written.has_value());
                const auto reparsed = binobf::parse_object(written.value(), "corpus-output.o");
                REQUIRE(reparsed.has_value());
                REQUIRE_EQ(reparsed.value().architecture, binobf::Architecture::X86);
                if (repeat == 0) {
                    deterministicBytes = written.value();
                    const auto safePassName = std::string{passName};
                    const auto output = outputDirectory / member.format /
                        (member.optimization + '-' + member.language + '-' + safePassName
                         + (member.format == "coff" ? ".obj" : ".o"));
                    write_file(output, written.value());
                    allObjects.push_back(output);
                    if (outcome.value().reports.front().status == binobf::PassStatus::Applied) {
                        passApplied[passIndex] = true;
                        REQUIRE(has_pass_lineage(outcome.value().image, passName));
                    }
                } else {
                    REQUIRE_EQ(written.value(), deterministicBytes);
                }
            }
        }
    }
    REQUIRE(std::ranges::all_of(passApplied, [](bool applied) { return applied; }));

    inspect_in_chunks(llvmReadobj,
        {"--file-headers", "--sections", "--symbols", "--relocations", "--unwind"},
        allObjects, "readobj");
    inspect_in_chunks(llvmObjdump, {"-dr"}, allObjects, "objdump");
    inspect_in_chunks(llvmNm, {}, allObjects, "nm");

    std::vector<std::string> coffLibraryArguments{
        lldLink.string(), "/lib", "/machine:x86",
        "/out:" + (outputDirectory / "corpus.lib").string()};
    for (const auto& path : coffOriginals) coffLibraryArguments.push_back(path.string());
    run_checked(coffLibraryArguments, outputDirectory / "lld-link-lib.log");
    const auto consumer = std::ranges::find_if(coffOriginals, [](const auto& path) {
        return path.filename().string().starts_with("O0-asm");
    });
    REQUIRE(consumer != coffOriginals.end());
    run_checked({lldLink.string(), "/dll", "/noentry", "/nodefaultlib", "/machine:x86",
        "/safeseh:no",
        "/out:" + (outputDirectory / "corpus-consumer.dll").string(), consumer->string(),
        (outputDirectory / "corpus.lib").string()}, outputDirectory / "lld-link-consumer.log");

    for (const auto optimization : {"O0", "O1", "O2", "O3", "Os", "Oz"}) {
        std::vector<std::string> elfArguments{
            elfLinker.string(), "-m", "elf_i386", "-r", "-o",
            (outputDirectory / (std::string{"corpus-linked-"} + optimization + ".o")).string()};
        for (const auto& member : members) {
            if (member.format == "elf" && member.optimization == optimization) {
                elfArguments.push_back(member.path.string());
            }
        }
        REQUIRE_EQ(elfArguments.size(), std::size_t{9});
        run_checked(elfArguments,
            outputDirectory / (std::string{"ld-lld-"} + optimization + ".log"));
    }
}

int main(int argc, char** argv) {
    if (argc != 8) return 2;
    corpusDirectory = argv[1];
    llvmReadobj = argv[2];
    llvmObjdump = argv[3];
    llvmNm = argv[4];
    lldLink = argv[5];
    elfLinker = argv[6];
    outputDirectory = argv[7];
    return binobf::test::run_all();
}

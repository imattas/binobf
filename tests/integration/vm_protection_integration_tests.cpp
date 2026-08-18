#include "../test_support.hpp"

#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/verify/structural_verifier.hpp>
#include <binobf/vm/protection.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
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
    if (!stream)
        throw std::runtime_error("could not open VM protection fixture");
    const auto end = stream.tellg();
    if (end < 0)
        throw std::runtime_error("could not size VM protection fixture");
    std::vector<std::byte> result(static_cast<std::size_t>(end));
    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(result.data()),
                static_cast<std::streamsize>(result.size()));
    if (!stream)
        throw std::runtime_error("could not read VM protection fixture");
    return result;
}

void write_file(const std::filesystem::path& path, const std::vector<std::byte>& data) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(data.data()),
                 static_cast<std::streamsize>(data.size()));
    if (!stream)
        throw std::runtime_error("could not write VM protection artifact");
}

auto quote(const std::filesystem::path& path) -> std::string { return '"' + path.string() + '"'; }

auto run_command(const std::vector<std::filesystem::path>& arguments) -> int {
    std::string command;
    for (const auto& argument : arguments) {
        if (!command.empty())
            command.push_back(' ');
        command += quote(argument);
    }
#ifdef _WIN32
    command = '"' + command + '"';
#endif
    return std::system(command.c_str());
}

auto protect(const std::filesystem::path& input, binobf::ir::NativeAbi abi)
    -> std::vector<std::byte> {
    const auto parsed = binobf::parse_object(read_file(input), input.filename().string());
    if (!parsed.has_value())
        throw std::runtime_error(parsed.error().message);
    const auto protectedResult = binobf::vm::protect_function(
        parsed.value(),
        binobf::vm::VmProtectionOptions{
            .function = "binobf_vm_add", .abi = abi, .argumentCount = 2, .seed = 16016});
    if (!protectedResult.has_value()) {
        throw std::runtime_error(protectedResult.error().message);
    }
    const auto written = binobf::write_object(protectedResult.value().image);
    if (!written.has_value())
        throw std::runtime_error(written.error().message);
    const auto verified = binobf::verify_object(written.value(), "vm-protected.o");
    if (!verified.has_value())
        throw std::runtime_error(verified.error().message);
    return written.value();
}

} // namespace

TEST_CASE(vm_protection_outputs_are_accepted_by_standard_coff_and_elf_tools) {
    std::filesystem::create_directories(outputDirectory);
    const auto coffOutput = outputDirectory / "vm-protected.obj";
    const auto elfOutput = outputDirectory / "vm-protected.o";
    write_file(coffOutput, protect(coffFixture, binobf::ir::NativeAbi::WindowsX64));
    write_file(elfOutput, protect(elfFixture, binobf::ir::NativeAbi::SystemVAMD64));

    REQUIRE_EQ(run_command({llvmReadobj, "--sections", "--symbols", "--relocations", coffOutput}),
               0);
    REQUIRE_EQ(run_command({llvmReadobj, "--sections", "--symbols", "--relocations", elfOutput}),
               0);
    const auto relinked = outputDirectory / "vm-protected-relinked.o";
    REQUIRE_EQ(run_command({elfLinker, "-r", elfOutput, "-o", relinked}), 0);

    const auto parsed = binobf::parse_object(read_file(relinked), relinked.filename().string());
    REQUIRE(parsed.has_value());
    const auto runtime = std::find_if(
        parsed.value().symbols.begin(), parsed.value().symbols.end(),
        [](const auto& symbol) { return symbol.name == binobf::vm::embeddedRuntimeSymbol; });
    REQUIRE(runtime != parsed.value().symbols.end());
    REQUIRE(!runtime->defined);
    REQUIRE(std::any_of(parsed.value().relocations.begin(), parsed.value().relocations.end(),
                        [&](const auto& relocation) {
                            return relocation.rawType == 4 &&
                                   relocation.targetSymbol == std::optional{runtime->id} &&
                                   relocation.addend == -4;
                        }));
}

int main(int argc, char** argv) {
    if (argc != 6)
        return 2;
    coffFixture = argv[1];
    elfFixture = argv[2];
    llvmReadobj = argv[3];
    elfLinker = argv[4];
    outputDirectory = argv[5];
    return binobf::test::run_all();
}

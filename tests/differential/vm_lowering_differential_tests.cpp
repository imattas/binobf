#include "../test_support.hpp"

#include <binobf/analysis/object_analyzer.hpp>
#include <binobf/cli/command.hpp>
#include <binobf/formats/object_parser.hpp>
#include <binobf/ir/native_lifter.hpp>
#include <binobf/ir/control_flow.hpp>
#include <binobf/ir/outlining.hpp>
#include <binobf/ir/vm_lowering.hpp>
#include <binobf/vm/bytecode.hpp>
#include <binobf/vm/runtime.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

extern "C" std::uint32_t binobf_vm_add(std::uint32_t left, std::uint32_t right);
extern "C" std::uint32_t binobf_vm_branch(std::uint32_t left, std::uint32_t right);
extern "C" std::uint32_t binobf_vm_mix(std::uint32_t value);

namespace {

std::filesystem::path coffFixture;
std::filesystem::path elfFixture;

class TemporaryOutput final {
public:
    explicit TemporaryOutput(std::filesystem::path path) : path_(std::move(path)) {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
        auto temporary = path_;
        temporary += ".binobf.tmp";
        std::filesystem::remove(temporary, ignored);
    }
    ~TemporaryOutput() {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
        auto temporary = path_;
        temporary += ".binobf.tmp";
        std::filesystem::remove(temporary, ignored);
    }
    TemporaryOutput(const TemporaryOutput&) = delete;
    auto operator=(const TemporaryOutput&) -> TemporaryOutput& = delete;
    [[nodiscard]] auto path() const -> const std::filesystem::path& { return path_; }

private:
    std::filesystem::path path_;
};

auto read_file(const std::filesystem::path& path) -> std::vector<std::byte> {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("could not open VM lowering fixture");
    const auto end = stream.tellg();
    if (end < 0) throw std::runtime_error("could not size VM lowering fixture");
    std::vector<std::byte> result(static_cast<std::size_t>(end));
    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(result.data()), static_cast<std::streamsize>(result.size()));
    if (!stream) throw std::runtime_error("could not read VM lowering fixture");
    return result;
}

auto analyzed_file(const std::filesystem::path& path) -> binobf::BinaryImage {
    const auto parsed = binobf::parse_object(read_file(path), path.filename().string());
    if (!parsed.has_value()) {
        throw std::runtime_error(parsed.error().code + ": " + parsed.error().message);
    }
    const auto analyzed = binobf::analyze_object(parsed.value());
    if (!analyzed.has_value()) {
        throw std::runtime_error(analyzed.error().code + ": " + analyzed.error().message);
    }
    return analyzed.value().image;
}

auto find_function(const binobf::BinaryImage& image, std::string_view name)
    -> const binobf::Function& {
    const auto found = std::find_if(image.functions.begin(), image.functions.end(),
        [name](const auto& function) { return function.name == name; });
    if (found == image.functions.end()) {
        throw std::runtime_error("recovered function not found: " + std::string{name});
    }
    return *found;
}

auto lower(
    const binobf::BinaryImage& image,
    std::string_view name,
    binobf::ir::NativeAbi abi,
    std::size_t argumentCount) -> binobf::vm::VmProgram {
    const auto& function = find_function(image, name);
    binobf::ir::NativeFunctionSignature signature;
    signature.abi = abi;
    signature.arguments.assign(argumentCount, binobf::ir::IrType{binobf::ir::IrWidth::U32});
    signature.returnType = binobf::ir::IrType{binobf::ir::IrWidth::U32};
    const auto lifted = binobf::ir::lift_function(image, function.id, signature);
    if (!lifted.has_value()) {
        throw std::runtime_error(lifted.error().code + ": " + lifted.error().message);
    }
    if (!lifted.value().complete) {
        const auto& diagnostic = lifted.value().diagnostics.front();
        throw std::runtime_error(diagnostic.code + ": " + diagnostic.message);
    }
    const auto lowered = binobf::ir::lower_to_vm(lifted.value().function);
    if (!lowered.has_value()) {
        throw std::runtime_error(lowered.error().code + ": " + lowered.error().message);
    }
    const auto assembled = binobf::vm::assemble_program(
        lowered.value().program, binobf::vm::VmAssemblyOptions{UINT64_C(0x8d1f5eed)});
    if (!assembled.has_value()) {
        throw std::runtime_error(assembled.error().code + ": " + assembled.error().message);
    }
    const auto decoded = binobf::vm::decode_program(assembled.value());
    if (!decoded.has_value()) {
        throw std::runtime_error(decoded.error().code + ": " + decoded.error().message);
    }
    return decoded.value().program;
}

auto execute(const binobf::vm::VmProgram& program, std::initializer_list<std::uint32_t> inputs)
    -> std::uint32_t {
    binobf::vm::VmExecutionInput input;
    for (const auto value : inputs) {
        input.arguments.push_back(
            binobf::vm::VmValue::from_bits(binobf::vm::VmWidth::U32, value));
    }
    binobf::vm::LinearVmMemory memory{0};
    binobf::vm::RejectingVmNativeCallBridge bridge;
    const auto executed = binobf::vm::execute_program(program, memory, bridge, input);
    if (!executed.has_value()) {
        throw std::runtime_error(executed.error().code + ": " + executed.error().message);
    }
    return static_cast<std::uint32_t>(executed.value().returnValue.bits());
}

void compare_image(const binobf::BinaryImage& image, binobf::ir::NativeAbi abi) {
    const auto add = lower(image, "binobf_vm_add", abi, 2);
    const auto branch = lower(image, "binobf_vm_branch", abi, 2);
    const auto mix = lower(image, "binobf_vm_mix", abi, 1);

    constexpr std::array pairs{
        std::pair{UINT32_C(0), UINT32_C(0)},
        std::pair{UINT32_C(1), UINT32_C(2)},
        std::pair{UINT32_C(9), UINT32_C(4)},
        std::pair{UINT32_C(0xffffffff), UINT32_C(1)},
        std::pair{UINT32_C(0x80000000), UINT32_C(0x7fffffff)},
        std::pair{UINT32_C(0x7fffffff), UINT32_C(0x80000000)},
    };
    for (const auto [left, right] : pairs) {
        REQUIRE_EQ(execute(add, {left, right}), binobf_vm_add(left, right));
        REQUIRE_EQ(execute(branch, {left, right}), binobf_vm_branch(left, right));
    }
    constexpr std::array values{
        UINT32_C(0), UINT32_C(1), UINT32_C(7), UINT32_C(0x7fffffff),
        UINT32_C(0x80000000), UINT32_C(0xffffffff)};
    for (const auto value : values) {
        REQUIRE_EQ(execute(mix, {value}), binobf_vm_mix(value));
    }
}

} // namespace

TEST_CASE(coff_native_machine_code_matches_lowered_and_decoded_vm_execution) {
    const auto image = analyzed_file(coffFixture);
    REQUIRE_EQ(image.format, binobf::BinaryFormat::COFF);
    compare_image(image, binobf::ir::NativeAbi::WindowsX64);
}

TEST_CASE(elf_native_machine_code_lowers_with_system_v_argument_registers) {
    const auto image = analyzed_file(elfFixture);
    REQUIRE_EQ(image.format, binobf::BinaryFormat::ELF);
    compare_image(image, binobf::ir::NativeAbi::SystemVAMD64);
}

TEST_CASE(vm_lower_cli_emits_standalone_deterministic_bytecode) {
    TemporaryOutput bytecode{coffFixture.parent_path() / "vm-lowering-cli.bvm"};
    TemporaryOutput secondBytecode{coffFixture.parent_path() / "vm-lowering-cli-second.bvm"};
    const auto input = coffFixture.string();
    auto run = [&](const std::filesystem::path& destination) {
        const std::array<std::string, 9> storage{
            "vm", "lower", input, "--function=binobf_vm_add", "--abi=windows-x64",
            "--args=2", "--seed=91", "-o", destination.string()};
        std::array<std::string_view, storage.size()> arguments;
        for (std::size_t index = 0; index < arguments.size(); ++index) {
            arguments[index] = storage[index];
        }
        std::ostringstream output;
        std::ostringstream errors;
        REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
        REQUIRE(errors.str().empty());
        REQUIRE_CONTAINS(output.str(), "function: binobf_vm_add");
        REQUIRE_CONTAINS(output.str(), "bytecode:");
    };
    run(bytecode.path());
    run(secondBytecode.path());
    REQUIRE_EQ(read_file(bytecode.path()), read_file(secondBytecode.path()));
    const auto decoded = binobf::vm::decode_program(read_file(bytecode.path()));
    REQUIRE(decoded.has_value());
    REQUIRE_EQ(execute(decoded.value().program, {17, 25}), UINT32_C(42));
}

TEST_CASE(vm_lower_cli_rejects_incomplete_selection_options) {
    const auto input = coffFixture.string();
    const std::array<std::string_view, 3> arguments{"vm", "lower", input};
    std::ostringstream output;
    std::ostringstream errors;
    REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 2);
    REQUIRE(output.str().empty());
    REQUIRE_CONTAINS(errors.str(), "Usage:");
}

TEST_CASE(advanced_cfg_lowering_matches_native_execution_and_warns_in_the_cli) {
    const auto image = analyzed_file(coffFixture);
    const auto& nativeFunction = find_function(image, "binobf_vm_branch");
    const binobf::ir::NativeFunctionSignature signature{
        .abi = binobf::ir::NativeAbi::WindowsX64,
        .arguments = {binobf::ir::IrWidth::U32, binobf::ir::IrWidth::U32},
        .returnType = binobf::ir::IrType{binobf::ir::IrWidth::U32},
    };
    const auto lifted = binobf::ir::lift_function(image, nativeFunction.id, signature);
    REQUIRE(lifted.has_value());
    REQUIRE(lifted.value().complete);

    const auto flattened = binobf::ir::flatten_control_flow(
        lifted.value().function, UINT64_C(0x91a7));
    const auto split = binobf::ir::split_function(lifted.value().function, UINT64_C(0x91a7));
    REQUIRE(flattened.has_value());
    REQUIRE(split.has_value());
    const auto flattenedVm = binobf::ir::lower_to_vm(flattened.value().function);
    const auto splitVm = binobf::ir::lower_module_to_vm(split.value().module);
    REQUIRE(flattenedVm.has_value());
    REQUIRE(splitVm.has_value());

    const auto outlineCandidate = std::find_if(
        lifted.value().function.blocks.begin(), lifted.value().function.blocks.end(),
        [&](const auto& block) {
            return block.id != lifted.value().function.entry
                && !block.instructions.empty()
                && std::holds_alternative<binobf::ir::IrReturn>(block.instructions.back());
        });
    REQUIRE(outlineCandidate != lifted.value().function.blocks.end());
    const auto outlined = binobf::ir::outline_block(
        lifted.value().function, outlineCandidate->id, UINT64_C(0x91a7));
    REQUIRE(outlined.has_value());
    const auto outlinedVm = binobf::ir::lower_module_to_vm(outlined.value().module);
    REQUIRE(outlinedVm.has_value());

    constexpr std::array pairs{
        std::pair{UINT32_C(0), UINT32_C(0)},
        std::pair{UINT32_C(2), UINT32_C(5)},
        std::pair{UINT32_C(9), UINT32_C(4)},
        std::pair{UINT32_C(0xffffffff), UINT32_C(1)},
        std::pair{UINT32_C(0x80000000), UINT32_C(0x7fffffff)},
    };
    for (const auto [left, right] : pairs) {
        const auto native = binobf_vm_branch(left, right);
        REQUIRE_EQ(execute(flattenedVm.value().program, {left, right}), native);
        REQUIRE_EQ(execute(splitVm.value().program, {left, right}), native);
        REQUIRE_EQ(execute(outlinedVm.value().program, {left, right}), native);
    }

    auto runAdvancedCli = [&](std::string option, std::string fileName) {
        TemporaryOutput bytecode{coffFixture.parent_path() / std::move(fileName)};
        const std::vector<std::string> storage{
            "vm", "lower", coffFixture.string(), "--function=binobf_vm_branch",
            "--abi=windows-x64", "--args=2", "--seed=37287", std::move(option),
            "-o", bytecode.path().string()};
        std::vector<std::string_view> arguments;
        for (const auto& argument : storage) arguments.push_back(argument);
        std::ostringstream output;
        std::ostringstream errors;
        REQUIRE_EQ(binobf::cli::run_cli(arguments, output, errors), 0);
        REQUIRE_CONTAINS(errors.str(), "high-risk");
        const auto decoded = binobf::vm::decode_program(read_file(bytecode.path()));
        REQUIRE(decoded.has_value());
        REQUIRE_EQ(execute(decoded.value().program, {2, 5}), binobf_vm_branch(2, 5));
    };
    runAdvancedCli("--cfg=flatten", "vm-lowering-cfg-cli.bvm");
    runAdvancedCli("--split-function", "vm-lowering-split-cli.bvm");
    runAdvancedCli(
        "--outline-block=" + std::to_string(outlineCandidate->id.value),
        "vm-lowering-outline-cli.bvm");
}

int main(int argc, char** argv) {
    if (argc != 3) return 2;
    coffFixture = argv[1];
    elfFixture = argv[2];
    return binobf::test::run_all();
}

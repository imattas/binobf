#include "../test_support.hpp"

#include <binobf/ir/native_lifter.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <variant>
#include <vector>

namespace {

auto bytes(std::initializer_list<unsigned int> values) -> std::vector<std::byte> {
    std::vector<std::byte> result;
    result.reserve(values.size());
    for (const auto value : values) result.push_back(static_cast<std::byte>(value));
    return result;
}
auto instruction(
    std::uint64_t id,
    std::uint64_t address,
    std::initializer_list<unsigned int> encoding,
    binobf::InstructionKind kind = binobf::InstructionKind::Normal)
    -> binobf::Instruction {
    return binobf::Instruction{
        .id = binobf::EntityId{id},
        .section = binobf::EntityId{1},
        .sectionOffset = address - UINT64_C(0x1000),
        .address = binobf::BinaryAddress{address, binobf::AddressKind::Virtual},
        .encoding = bytes(encoding),
        .mnemonic = {},
        .operands = {},
        .kind = kind,
        .directTarget = std::nullopt,
        .hasFallthrough = kind == binobf::InstructionKind::Normal,
        .registersRead = {},
        .registersWritten = {},
        .references = {},
        .lineage = {},
    };
}

auto one_block_image(std::vector<binobf::Instruction> instructions) -> binobf::BinaryImage {
    std::vector<binobf::EntityId> instructionIds;
    std::uint64_t size = 0;
    for (const auto& item : instructions) {
        instructionIds.push_back(item.id);
        size += item.encoding.size();
    }
    binobf::BinaryImage image;
    image.architecture = binobf::Architecture::X86_64;
    image.type = binobf::BinaryType::RelocatableObject;
    image.instructions = std::move(instructions);
    image.basicBlocks.push_back(binobf::BasicBlock{
        .id = binobf::EntityId{20},
        .function = binobf::EntityId{10},
        .section = binobf::EntityId{1},
        .sectionOffset = 0,
        .address = binobf::BinaryAddress{UINT64_C(0x1000), binobf::AddressKind::Virtual},
        .instructions = instructionIds,
        .successors = {},
        .edges = {},
        .liveIn = {},
        .liveOut = {},
        .hasUnresolvedSuccessor = false,
        .lineage = {},
    });
    image.functions.push_back(binobf::Function{
        .id = binobf::EntityId{10},
        .name = "fixture",
        .section = binobf::EntityId{1},
        .symbol = std::nullopt,
        .address = binobf::BinaryAddress{UINT64_C(0x1000), binobf::AddressKind::Virtual},
        .size = size,
        .discovery = binobf::FunctionDiscovery::Symbol,
        .instructions = instructionIds,
        .basicBlocks = {binobf::EntityId{20}},
        .entryBlock = binobf::EntityId{20},
        .externallyVisible = true,
        .complete = true,
        .lineage = {},
    });
    return image;
}

auto u32_binary_signature() -> binobf::ir::NativeFunctionSignature {
    return binobf::ir::NativeFunctionSignature{
        .abi = binobf::ir::NativeAbi::WindowsX64,
        .arguments = {binobf::ir::IrWidth::U32, binobf::ir::IrWidth::U32},
        .returnWidth = binobf::ir::IrWidth::U32,
    };
}

} // namespace

TEST_CASE(native_lifter_decodes_real_register_arithmetic_and_return_bytes) {
    auto image = one_block_image({
        instruction(30, UINT64_C(0x1000), {0x89, 0xc8}),
        instruction(31, UINT64_C(0x1002), {0x01, 0xd0}),
        instruction(32, UINT64_C(0x1004), {0xc3}, binobf::InstructionKind::Return),
    });
    const auto lifted = binobf::ir::lift_function(
        image, binobf::EntityId{10}, u32_binary_signature());
    REQUIRE(lifted.has_value());
    REQUIRE(lifted.value().complete);
    REQUIRE(!binobf::ir::function_contains_fallback(lifted.value().function));
    REQUIRE(binobf::ir::validate_function(lifted.value().function).has_value());
    REQUIRE_EQ(lifted.value().function.arguments.size(), std::size_t{2});
    REQUIRE_EQ(lifted.value().function.blocks.size(), std::size_t{1});
    REQUIRE_EQ(lifted.value().function.blocks[0].instructions.size(), std::size_t{3});
    REQUIRE(std::holds_alternative<binobf::ir::IrMove>(
        lifted.value().function.blocks[0].instructions[0]));
    REQUIRE(std::holds_alternative<binobf::ir::IrBinaryOperation>(
        lifted.value().function.blocks[0].instructions[1]));
    REQUIRE(std::holds_alternative<binobf::ir::IrReturn>(
        lifted.value().function.blocks[0].instructions[2]));
}

TEST_CASE(native_lifter_preserves_memory_access_as_a_non_lowerable_fallback) {
    auto image = one_block_image({
        instruction(30, UINT64_C(0x1000), {0x8b, 0x01}),
        instruction(31, UINT64_C(0x1002), {0xc3}, binobf::InstructionKind::Return),
    });
    const auto lifted = binobf::ir::lift_function(
        image, binobf::EntityId{10}, u32_binary_signature());
    REQUIRE(lifted.has_value());
    REQUIRE(!lifted.value().complete);
    REQUIRE(binobf::ir::function_contains_fallback(lifted.value().function));
    REQUIRE(!lifted.value().diagnostics.empty());
    REQUIRE_EQ(lifted.value().diagnostics[0].code, "ir.unsupported_memory_operand");
}

TEST_CASE(native_lifter_rejects_ambiguous_signatures_and_incomplete_functions) {
    auto image = one_block_image({
        instruction(30, UINT64_C(0x1000), {0xc3}, binobf::InstructionKind::Return),
    });
    auto signature = u32_binary_signature();
    signature.arguments.push_back(binobf::ir::IrWidth::U32);
    signature.arguments.push_back(binobf::ir::IrWidth::U32);
    signature.arguments.push_back(binobf::ir::IrWidth::U32);
    auto lifted = binobf::ir::lift_function(image, binobf::EntityId{10}, signature);
    REQUIRE(!lifted.has_value());
    REQUIRE_EQ(lifted.error().code, "ir.unsupported_signature");

    image.functions[0].complete = false;
    lifted = binobf::ir::lift_function(
        image, binobf::EntityId{10}, u32_binary_signature());
    REQUIRE(!lifted.has_value());
    REQUIRE_EQ(lifted.error().code, "ir.incomplete_function");
}

TEST_CASE(native_lifter_rejects_missing_functions_and_non_x86_64_images) {
    auto image = one_block_image({
        instruction(30, UINT64_C(0x1000), {0xc3}, binobf::InstructionKind::Return),
    });
    auto result = binobf::ir::lift_function(
        image, binobf::EntityId{99}, u32_binary_signature());
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.function_not_found");
    image.architecture = binobf::Architecture::ARM64;
    result = binobf::ir::lift_function(
        image, binobf::EntityId{10}, u32_binary_signature());
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.unsupported_architecture");
}

int main() {
    return binobf::test::run_all();
}

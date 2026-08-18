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

auto one_block_image(
    std::vector<binobf::Instruction> instructions,
    binobf::Architecture architecture = binobf::Architecture::X86_64)
    -> binobf::BinaryImage {
    std::vector<binobf::EntityId> instructionIds;
    std::uint64_t size = 0;
    for (const auto& item : instructions) {
        instructionIds.push_back(item.id);
        size += item.encoding.size();
    }
    binobf::BinaryImage image;
    image.architecture = architecture;
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
        .returnType = binobf::ir::IrType{binobf::ir::IrWidth::U32},
        .variadic = false,
    };
}

auto x86_fastcall_signature() -> binobf::ir::NativeFunctionSignature {
    return binobf::ir::NativeFunctionSignature{
        .abi = binobf::ir::NativeAbi::WindowsI386Fastcall,
        .arguments = {binobf::ir::IrWidth::U32, binobf::ir::IrWidth::U32},
        .returnType = binobf::ir::IrType{binobf::ir::IrWidth::U32},
        .variadic = false,
    };
}

auto x86_cdecl_signature() -> binobf::ir::NativeFunctionSignature {
    return binobf::ir::NativeFunctionSignature{
        .abi = binobf::ir::NativeAbi::WindowsI386Cdecl,
        .arguments = {binobf::ir::IrWidth::U32, binobf::ir::IrWidth::U32},
        .returnType = binobf::ir::IrType{binobf::ir::IrWidth::U32},
        .variadic = false,
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

TEST_CASE(native_lifter_decodes_an_i386_fastcall_register_function) {
    auto image = one_block_image({
        instruction(30, UINT64_C(0x1000), {0x89, 0xc8}),
        instruction(31, UINT64_C(0x1002), {0x01, 0xd0}),
        instruction(32, UINT64_C(0x1004), {0xc3}, binobf::InstructionKind::Return),
    }, binobf::Architecture::X86);

    const auto lifted = binobf::ir::lift_function(
        image, binobf::EntityId{10}, x86_fastcall_signature());

    REQUIRE(lifted.has_value());
    REQUIRE(lifted.value().complete);
    REQUIRE_EQ(lifted.value().function.signature.callingConvention,
               binobf::ir::IrCallingConvention::MicrosoftI386Fastcall);
    REQUIRE_EQ(lifted.value().function.arguments.size(), std::size_t{2});
    REQUIRE_EQ(lifted.value().function.variableTypes.size(), std::size_t{3});
    REQUIRE_EQ(lifted.value().function.blocks[0].instructions.size(), std::size_t{3});
    REQUIRE(binobf::ir::validate_function(lifted.value().function).has_value());
}

TEST_CASE(native_lifter_rejects_an_x64_abi_for_an_i386_image) {
    auto image = one_block_image({
        instruction(30, UINT64_C(0x1000), {0xc3}, binobf::InstructionKind::Return),
    }, binobf::Architecture::X86);

    const auto lifted = binobf::ir::lift_function(
        image, binobf::EntityId{10}, u32_binary_signature());

    REQUIRE(!lifted.has_value());
    REQUIRE_EQ(lifted.error().code, "ir.abi_architecture_mismatch");
}

TEST_CASE(native_lifter_binds_i386_cdecl_stack_arguments) {
    auto image = one_block_image({
        instruction(30, UINT64_C(0x1000), {0x8b, 0x44, 0x24, 0x04}),
        instruction(31, UINT64_C(0x1004), {0x03, 0x44, 0x24, 0x08}),
        instruction(32, UINT64_C(0x1008), {0xc3}, binobf::InstructionKind::Return),
    }, binobf::Architecture::X86);

    const auto lifted = binobf::ir::lift_function(
        image, binobf::EntityId{10}, x86_cdecl_signature());

    REQUIRE(lifted.has_value());
    REQUIRE(lifted.value().complete);
    REQUIRE(!binobf::ir::function_contains_fallback(lifted.value().function));
    REQUIRE_EQ(lifted.value().function.signature.parameterBindings.size(), std::size_t{2});
    REQUIRE_EQ(lifted.value().function.signature.parameterBindings[0].kind,
               binobf::ir::IrStorageKind::Stack);
    REQUIRE_EQ(lifted.value().function.signature.parameterBindings[0].offset, std::int64_t{4});
    REQUIRE_EQ(lifted.value().function.signature.parameterBindings[1].offset, std::int64_t{8});
    REQUIRE_EQ(lifted.value().function.storageLocations.size(), std::size_t{2});
    REQUIRE(binobf::ir::validate_function(lifted.value().function).has_value());
}

TEST_CASE(native_lifter_elides_a_canonical_i386_frame_and_resolves_ebp_arguments) {
    auto image = one_block_image({
        instruction(30, UINT64_C(0x1000), {0x55}),
        instruction(31, UINT64_C(0x1001), {0x89, 0xe5}),
        instruction(32, UINT64_C(0x1003), {0x8b, 0x45, 0x08}),
        instruction(33, UINT64_C(0x1006), {0x03, 0x45, 0x0c}),
        instruction(34, UINT64_C(0x1009), {0xc9}),
        instruction(35, UINT64_C(0x100a), {0xc3}, binobf::InstructionKind::Return),
    }, binobf::Architecture::X86);

    const auto lifted = binobf::ir::lift_function(
        image, binobf::EntityId{10}, x86_cdecl_signature());

    REQUIRE(lifted.has_value());
    REQUIRE(lifted.value().complete);
    REQUIRE_EQ(lifted.value().function.blocks[0].instructions.size(), std::size_t{3});
    REQUIRE(std::holds_alternative<binobf::ir::IrMove>(
        lifted.value().function.blocks[0].instructions[0]));
    REQUIRE(std::holds_alternative<binobf::ir::IrBinaryOperation>(
        lifted.value().function.blocks[0].instructions[1]));
    REQUIRE(std::holds_alternative<binobf::ir::IrReturn>(
        lifted.value().function.blocks[0].instructions[2]));
    REQUIRE(binobf::ir::validate_function(lifted.value().function).has_value());
}

TEST_CASE(native_lifter_places_the_third_i386_fastcall_argument_on_the_stack) {
    auto image = one_block_image({
        instruction(30, UINT64_C(0x1000), {0x89, 0xc8}),
        instruction(31, UINT64_C(0x1002), {0x01, 0xd0}),
        instruction(32, UINT64_C(0x1004), {0x03, 0x44, 0x24, 0x04}),
        instruction(33, UINT64_C(0x1008), {0xc3}, binobf::InstructionKind::Return),
    }, binobf::Architecture::X86);
    auto signature = x86_fastcall_signature();
    signature.arguments.push_back(binobf::ir::IrWidth::U32);

    const auto lifted = binobf::ir::lift_function(
        image, binobf::EntityId{10}, signature);

    REQUIRE(lifted.has_value());
    REQUIRE(lifted.value().complete);
    REQUIRE_EQ(lifted.value().function.signature.parameterBindings.size(), std::size_t{3});
    REQUIRE_EQ(lifted.value().function.signature.parameterBindings[2].kind,
               binobf::ir::IrStorageKind::Stack);
    REQUIRE_EQ(lifted.value().function.signature.parameterBindings[2].offset, std::int64_t{4});
}

TEST_CASE(native_lifter_accepts_variadic_cdecl_and_rejects_variadic_stdcall) {
    auto image = one_block_image({
        instruction(30, UINT64_C(0x1000), {0x8b, 0x44, 0x24, 0x04}),
        instruction(31, UINT64_C(0x1004), {0xc3}, binobf::InstructionKind::Return),
    }, binobf::Architecture::X86);
    auto cdecl = x86_cdecl_signature();
    cdecl.variadic = true;
    REQUIRE(binobf::ir::lift_function(image, binobf::EntityId{10}, cdecl).has_value());

    cdecl.abi = binobf::ir::NativeAbi::WindowsI386Stdcall;
    const auto stdcall = binobf::ir::lift_function(image, binobf::EntityId{10}, cdecl);
    REQUIRE(!stdcall.has_value());
    REQUIRE_EQ(stdcall.error().code, "ir.unsupported_variadic_abi");
}

TEST_CASE(native_lifter_builds_stdcall_thiscall_and_system_v_i386_bindings) {
    auto image = one_block_image({
        instruction(30, UINT64_C(0x1000), {0xc3}, binobf::InstructionKind::Return),
    }, binobf::Architecture::X86);
    binobf::ir::NativeFunctionSignature signature{};
    signature.arguments = {binobf::ir::IrWidth::U32, binobf::ir::IrWidth::U32};
    signature.returnType = binobf::ir::IrType{};

    signature.abi = binobf::ir::NativeAbi::WindowsI386Stdcall;
    const auto stdcall = binobf::ir::lift_function(image, binobf::EntityId{10}, signature);
    REQUIRE(stdcall.has_value());
    REQUIRE(stdcall.value().complete);
    REQUIRE_EQ(stdcall.value().function.signature.callingConvention,
               binobf::ir::IrCallingConvention::MicrosoftI386Stdcall);
    REQUIRE_EQ(stdcall.value().function.signature.parameterBindings[0].offset, std::int64_t{4});
    REQUIRE_EQ(stdcall.value().function.signature.parameterBindings[1].offset, std::int64_t{8});

    signature.abi = binobf::ir::NativeAbi::WindowsI386Thiscall;
    const auto thiscall = binobf::ir::lift_function(image, binobf::EntityId{10}, signature);
    REQUIRE(thiscall.has_value());
    REQUIRE(thiscall.value().complete);
    REQUIRE_EQ(thiscall.value().function.signature.callingConvention,
               binobf::ir::IrCallingConvention::MicrosoftI386Thiscall);
    REQUIRE_EQ(thiscall.value().function.signature.parameterBindings[0].name, "ecx");
    REQUIRE_EQ(thiscall.value().function.signature.parameterBindings[1].offset, std::int64_t{4});

    signature.abi = binobf::ir::NativeAbi::SystemVI386;
    signature.variadic = true;
    const auto systemV = binobf::ir::lift_function(image, binobf::EntityId{10}, signature);
    REQUIRE(systemV.has_value());
    REQUIRE(systemV.value().complete);
    REQUIRE_EQ(systemV.value().function.signature.callingConvention,
               binobf::ir::IrCallingConvention::SystemVI386);
    REQUIRE_EQ(systemV.value().function.signature.parameterBindings[0].offset, std::int64_t{4});
    REQUIRE_EQ(systemV.value().function.signature.parameterBindings[1].offset, std::int64_t{8});
}

TEST_CASE(native_lifter_rejects_a_64_bit_pointer_in_an_i386_signature) {
    auto image = one_block_image({
        instruction(30, UINT64_C(0x1000), {0xc3}, binobf::InstructionKind::Return),
    }, binobf::Architecture::X86);
    binobf::ir::NativeFunctionSignature signature{};
    signature.abi = binobf::ir::NativeAbi::WindowsI386Cdecl;
    signature.arguments = {binobf::ir::IrType{binobf::ir::IrTypeKind::Pointer, 64U}};
    signature.returnType = binobf::ir::IrType{};

    const auto lifted = binobf::ir::lift_function(
        image, binobf::EntityId{10}, signature);

    REQUIRE(!lifted.has_value());
    REQUIRE_EQ(lifted.error().code, "ir.unsupported_signature");
}

TEST_CASE(native_lifter_preserves_a_canonical_32_bit_pointer_signature) {
    auto image = one_block_image({
        instruction(30, UINT64_C(0x1000), {0x8b, 0x44, 0x24, 0x04}),
        instruction(31, UINT64_C(0x1004), {0xc3}, binobf::InstructionKind::Return),
    }, binobf::Architecture::X86);
    binobf::ir::NativeFunctionSignature signature{};
    signature.abi = binobf::ir::NativeAbi::WindowsI386Cdecl;
    signature.arguments = {binobf::ir::IrType{binobf::ir::IrTypeKind::Pointer, 32U}};
    signature.returnType = binobf::ir::IrType{binobf::ir::IrTypeKind::Pointer, 32U};

    const auto lifted = binobf::ir::lift_function(
        image, binobf::EntityId{10}, signature);

    REQUIRE(lifted.has_value());
    REQUIRE(lifted.value().complete);
    REQUIRE_EQ(lifted.value().function.arguments[0].type, signature.arguments[0]);
    REQUIRE_EQ(lifted.value().function.returnType, signature.returnType);
    REQUIRE_EQ(lifted.value().function.variableTypes[0], signature.arguments[0]);
    REQUIRE(binobf::ir::validate_function(lifted.value().function).has_value());
}

TEST_CASE(native_lifter_maps_i386_sse2_scalar_arithmetic_to_typed_ir) {
    auto image = one_block_image({
        instruction(30, UINT64_C(0x1000), {0xf3, 0x0f, 0x10, 0x44, 0x24, 0x04}),
        instruction(31, UINT64_C(0x1006), {0xf3, 0x0f, 0x58, 0x44, 0x24, 0x08}),
        instruction(32, UINT64_C(0x100c), {0xb8, 0x00, 0x00, 0x00, 0x00}),
        instruction(33, UINT64_C(0x1011), {0xc3}, binobf::InstructionKind::Return),
    }, binobf::Architecture::X86);
    binobf::ir::NativeFunctionSignature signature{};
    signature.abi = binobf::ir::NativeAbi::WindowsI386Cdecl;
    signature.arguments = {
        binobf::ir::IrType{binobf::ir::IrTypeKind::FloatingPoint, 32U},
        binobf::ir::IrType{binobf::ir::IrTypeKind::FloatingPoint, 32U},
    };
    signature.returnType = binobf::ir::IrType{binobf::ir::IrWidth::U32};

    const auto lifted = binobf::ir::lift_function(
        image, binobf::EntityId{10}, signature);

    REQUIRE(lifted.has_value());
    REQUIRE(lifted.value().complete);
    REQUIRE_EQ(lifted.value().function.blocks[0].instructions.size(), std::size_t{4});
    const auto* move = std::get_if<binobf::ir::IrMove>(
        &lifted.value().function.blocks[0].instructions[0]);
    REQUIRE(move != nullptr);
    REQUIRE_EQ(move->type, signature.arguments[0]);
    const auto* add = std::get_if<binobf::ir::IrBinaryOperation>(
        &lifted.value().function.blocks[0].instructions[1]);
    REQUIRE(add != nullptr);
    REQUIRE_EQ(add->opcode, binobf::ir::IrBinaryOpcode::Add);
    REQUIRE_EQ(add->type, signature.arguments[0]);
    REQUIRE(binobf::ir::validate_function(lifted.value().function).has_value());
}

TEST_CASE(native_lifter_maps_an_i386_x87_scalar_return) {
    auto image = one_block_image({
        instruction(30, UINT64_C(0x1000), {0xd9, 0x44, 0x24, 0x04}),
        instruction(31, UINT64_C(0x1004), {0xc3}, binobf::InstructionKind::Return),
    }, binobf::Architecture::X86);
    const auto f32 = binobf::ir::IrType{binobf::ir::IrTypeKind::FloatingPoint, 32U};
    binobf::ir::NativeFunctionSignature signature{};
    signature.abi = binobf::ir::NativeAbi::WindowsI386Cdecl;
    signature.arguments = {f32};
    signature.returnType = f32;

    const auto lifted = binobf::ir::lift_function(
        image, binobf::EntityId{10}, signature);

    REQUIRE(lifted.has_value());
    REQUIRE(lifted.value().complete);
    REQUIRE(lifted.value().function.signature.returnBinding.has_value());
    REQUIRE_EQ(lifted.value().function.signature.returnBinding->name, "st0");
    REQUIRE(std::holds_alternative<binobf::ir::IrMove>(
        lifted.value().function.blocks[0].instructions[0]));
    const auto* result = std::get_if<binobf::ir::IrReturn>(
        &lifted.value().function.blocks[0].instructions[1]);
    REQUIRE(result != nullptr);
    REQUIRE_EQ(result->type, f32);
    REQUIRE(result->value.has_value());
    REQUIRE(binobf::ir::validate_function(lifted.value().function).has_value());
}

TEST_CASE(native_lifter_does_not_allocate_a_phantom_variable_when_a_register_type_changes) {
    auto image = one_block_image({
        instruction(30, UINT64_C(0x1000), {0xf3, 0x0f, 0x10, 0x4c, 0x24, 0x04}),
        instruction(31, UINT64_C(0x1006), {0xf3, 0x0f, 0x10, 0xc1}),
        instruction(32, UINT64_C(0x100a), {0xf2, 0x0f, 0x10, 0x54, 0x24, 0x08}),
        instruction(33, UINT64_C(0x1010), {0xf2, 0x0f, 0x10, 0xc2}),
        instruction(34, UINT64_C(0x1014), {0xc3}, binobf::InstructionKind::Return),
    }, binobf::Architecture::X86);
    binobf::ir::NativeFunctionSignature signature{};
    signature.abi = binobf::ir::NativeAbi::WindowsI386Cdecl;
    signature.arguments = {
        binobf::ir::IrType{binobf::ir::IrTypeKind::FloatingPoint, 32U},
        binobf::ir::IrType{binobf::ir::IrTypeKind::FloatingPoint, 64U},
    };
    signature.returnType = binobf::ir::IrType{};

    const auto lifted = binobf::ir::lift_function(
        image, binobf::EntityId{10}, signature);

    REQUIRE(lifted.has_value());
    REQUIRE(lifted.value().complete);
    REQUIRE_EQ(lifted.value().function.variableTypes.size(), std::size_t{6});
    REQUIRE(binobf::ir::validate_function(lifted.value().function).has_value());
}

TEST_CASE(native_lifter_models_an_i386_u64_return_in_edx_eax) {
    auto image = one_block_image({
        instruction(30, UINT64_C(0x1000), {0x8b, 0x44, 0x24, 0x04}),
        instruction(31, UINT64_C(0x1004), {0x8b, 0x54, 0x24, 0x08}),
        instruction(32, UINT64_C(0x1008), {0xc3}, binobf::InstructionKind::Return),
    }, binobf::Architecture::X86);
    binobf::ir::NativeFunctionSignature signature{};
    signature.abi = binobf::ir::NativeAbi::SystemVI386;
    signature.arguments = {binobf::ir::IrType{binobf::ir::IrWidth::U64}};
    signature.returnType = binobf::ir::IrType{binobf::ir::IrWidth::U64};

    const auto lifted = binobf::ir::lift_function(
        image, binobf::EntityId{10}, signature);

    REQUIRE(lifted.has_value());
    REQUIRE(lifted.value().complete);
    REQUIRE_EQ(lifted.value().function.returnType, signature.returnType);
    REQUIRE(lifted.value().function.signature.returnBinding.has_value());
    REQUIRE_EQ(lifted.value().function.signature.returnBinding->name, "edx:eax");
    const auto* result = std::get_if<binobf::ir::IrReturn>(
        &lifted.value().function.blocks[0].instructions.back());
    REQUIRE(result != nullptr);
    REQUIRE_EQ(result->type, signature.returnType);
    REQUIRE(result->value.has_value());
    REQUIRE(binobf::ir::validate_function(lifted.value().function).has_value());
}

TEST_CASE(native_lifter_maps_a_declared_relocation_backed_external_call) {
    auto call = instruction(
        30, UINT64_C(0x1000), {0xe8, 0x00, 0x00, 0x00, 0x00},
        binobf::InstructionKind::DirectCall);
    call.references.push_back(binobf::InstructionReference{
        .kind = binobf::InstructionReferenceKind::CallTarget,
        .address = std::nullopt,
        .relocation = binobf::EntityId{40},
        .symbol = binobf::EntityId{41},
    });
    auto image = one_block_image({
        std::move(call),
        instruction(31, UINT64_C(0x1005), {0xc3}, binobf::InstructionKind::Return),
    }, binobf::Architecture::X86);
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{41},
        .formatIndex = 0,
        .formatTableIndex = 0,
        .formatType = 0,
        .formatStorage = 2,
        .formatOther = 0,
        .formatSectionIndex = 0,
        .auxiliaryData = {},
        .name = "declared_external",
        .section = std::nullopt,
        .address = {},
        .size = 0,
        .kind = binobf::SymbolKind::Function,
        .visibility = binobf::SymbolVisibility::External,
        .defined = false,
        .definition = binobf::SymbolDefinitionKind::Undefined,
        .commonAlignment = 0,
        .tlsModel = binobf::TlsModel::None,
        .lineage = {},
    });
    binobf::ir::NativeFunctionSignature signature{};
    signature.abi = binobf::ir::NativeAbi::WindowsI386Cdecl;
    signature.returnType = binobf::ir::IrType{binobf::ir::IrWidth::U32};
    binobf::ir::NativeLiftOptions options{};
    options.externalDeclarations.push_back(binobf::ir::IrExternalDeclaration{
        .symbol = "declared_external",
        .signature = binobf::ir::IrFunctionSignature{
            .callingConvention = binobf::ir::IrCallingConvention::MicrosoftI386Cdecl,
            .parameterTypes = {},
            .returnType = binobf::ir::IrType{binobf::ir::IrWidth::U32},
            .variadic = false,
            .parameterBindings = {},
            .returnBinding = std::nullopt,
            .clobbers = binobf::ir::IrCallClobbers{{"eax", "ecx", "edx"}, true, true},
            .mayUnwind = false,
        },
    });

    const auto lifted = binobf::ir::lift_function(
        image, binobf::EntityId{10}, signature, options);

    REQUIRE(lifted.has_value());
    REQUIRE(lifted.value().complete);
    const auto* external = std::get_if<binobf::ir::IrExternalCall>(
        &lifted.value().function.blocks[0].instructions[0]);
    REQUIRE(external != nullptr);
    REQUIRE_EQ(external->symbol, "declared_external");
    REQUIRE(external->destination.has_value());
    REQUIRE(binobf::ir::validate_function(lifted.value().function).has_value());
}

TEST_CASE(native_lifter_maps_typed_stack_arguments_for_a_declared_i386_call) {
    auto call = instruction(
        34, UINT64_C(0x100a), {0xe8, 0x00, 0x00, 0x00, 0x00},
        binobf::InstructionKind::DirectCall);
    call.references.push_back(binobf::InstructionReference{
        .kind = binobf::InstructionReferenceKind::CallTarget,
        .address = std::nullopt,
        .relocation = binobf::EntityId{40},
        .symbol = binobf::EntityId{41},
    });
    auto image = one_block_image({
        instruction(30, UINT64_C(0x1000), {0x8b, 0x44, 0x24, 0x04}),
        instruction(31, UINT64_C(0x1004), {0x8b, 0x54, 0x24, 0x08}),
        instruction(32, UINT64_C(0x1008), {0x52}),
        instruction(33, UINT64_C(0x1009), {0x50}),
        std::move(call),
        instruction(35, UINT64_C(0x100f), {0x83, 0xc4, 0x08}),
        instruction(36, UINT64_C(0x1012), {0xc3}, binobf::InstructionKind::Return),
    }, binobf::Architecture::X86);
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{41},
        .formatIndex = 0,
        .formatTableIndex = 0,
        .formatType = 0,
        .formatStorage = 2,
        .formatOther = 0,
        .formatSectionIndex = 0,
        .auxiliaryData = {},
        .name = "sum_external",
        .section = std::nullopt,
        .address = {},
        .size = 0,
        .kind = binobf::SymbolKind::Function,
        .visibility = binobf::SymbolVisibility::External,
        .defined = false,
        .definition = binobf::SymbolDefinitionKind::Undefined,
        .commonAlignment = 0,
        .tlsModel = binobf::TlsModel::None,
        .lineage = {},
    });
    const auto u32 = binobf::ir::IrType{binobf::ir::IrWidth::U32};
    binobf::ir::NativeLiftOptions options{};
    options.externalDeclarations.push_back(binobf::ir::IrExternalDeclaration{
        .symbol = "sum_external",
        .signature = binobf::ir::IrFunctionSignature{
            .callingConvention = binobf::ir::IrCallingConvention::MicrosoftI386Cdecl,
            .parameterTypes = {u32, u32},
            .returnType = u32,
            .variadic = false,
            .parameterBindings = {
                binobf::ir::IrStorageLocation{
                    .kind = binobf::ir::IrStorageKind::Stack,
                    .type = u32,
                    .name = "argument-0",
                    .offset = 4,
                    .size = 4,
                    .alignment = 4,
                    .index = 0,
                    .readonly = false,
                },
                binobf::ir::IrStorageLocation{
                    .kind = binobf::ir::IrStorageKind::Stack,
                    .type = u32,
                    .name = "argument-1",
                    .offset = 8,
                    .size = 4,
                    .alignment = 4,
                    .index = 1,
                    .readonly = false,
                },
            },
            .returnBinding = std::nullopt,
            .clobbers = binobf::ir::IrCallClobbers{{"eax", "ecx", "edx"}, true, true},
            .mayUnwind = false,
        },
    });

    const auto lifted = binobf::ir::lift_function(
        image, binobf::EntityId{10}, x86_cdecl_signature(), options);

    REQUIRE(lifted.has_value());
    REQUIRE(lifted.value().complete);
    REQUIRE_EQ(lifted.value().function.blocks[0].instructions.size(), std::size_t{4});
    const auto* external = std::get_if<binobf::ir::IrExternalCall>(
        &lifted.value().function.blocks[0].instructions[2]);
    REQUIRE(external != nullptr);
    REQUIRE_EQ(external->arguments.size(), std::size_t{2});
    REQUIRE(external->destination.has_value());
    REQUIRE(binobf::ir::validate_function(lifted.value().function).has_value());
}

TEST_CASE(native_lifter_maps_a_declared_relocation_backed_global_address) {
    auto address = instruction(
        30, UINT64_C(0x1000), {0x8d, 0x05, 0x00, 0x00, 0x00, 0x00});
    address.references.push_back(binobf::InstructionReference{
        .kind = binobf::InstructionReferenceKind::Relocation,
        .address = std::nullopt,
        .relocation = binobf::EntityId{40},
        .symbol = binobf::EntityId{41},
    });
    auto image = one_block_image({
        std::move(address),
        instruction(31, UINT64_C(0x1006), {0xc3}, binobf::InstructionKind::Return),
    }, binobf::Architecture::X86);
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{41},
        .formatIndex = 0,
        .formatTableIndex = 0,
        .formatType = 0,
        .formatStorage = 2,
        .formatOther = 0,
        .formatSectionIndex = 0,
        .auxiliaryData = {},
        .name = "global_value",
        .section = std::nullopt,
        .address = {},
        .size = 4,
        .kind = binobf::SymbolKind::Object,
        .visibility = binobf::SymbolVisibility::External,
        .defined = false,
        .definition = binobf::SymbolDefinitionKind::Undefined,
        .commonAlignment = 0,
        .tlsModel = binobf::TlsModel::None,
        .lineage = {},
    });
    binobf::ir::NativeFunctionSignature signature{};
    signature.abi = binobf::ir::NativeAbi::SystemVI386;
    signature.returnType = binobf::ir::IrType{binobf::ir::IrTypeKind::Pointer, 32U};
    binobf::ir::NativeLiftOptions options{};
    options.symbolStorage.push_back(binobf::ir::IrStorageLocation{
        .kind = binobf::ir::IrStorageKind::Global,
        .type = binobf::ir::IrType{binobf::ir::IrWidth::U32},
        .name = "global_value",
        .offset = 0,
        .size = 4,
        .alignment = 4,
        .index = 0,
        .readonly = false,
    });

    const auto lifted = binobf::ir::lift_function(
        image, binobf::EntityId{10}, signature, options);

    REQUIRE(lifted.has_value());
    REQUIRE(lifted.value().complete);
    const auto* addressOf = std::get_if<binobf::ir::IrAddressOf>(
        &lifted.value().function.blocks[0].instructions[0]);
    REQUIRE(addressOf != nullptr);
    REQUIRE_EQ(lifted.value().function.storageLocations[addressOf->storageIndex].name,
               "global_value");
    REQUIRE_EQ(lifted.value().function.storageLocations[addressOf->storageIndex].kind,
               binobf::ir::IrStorageKind::Global);
    REQUIRE(binobf::ir::validate_function(lifted.value().function).has_value());
}

TEST_CASE(native_lifter_maps_a_declared_relocation_backed_tls_load) {
    auto load = instruction(
        30, UINT64_C(0x1000), {0xa1, 0x00, 0x00, 0x00, 0x00});
    load.references.push_back(binobf::InstructionReference{
        .kind = binobf::InstructionReferenceKind::Relocation,
        .address = std::nullopt,
        .relocation = binobf::EntityId{40},
        .symbol = binobf::EntityId{41},
    });
    auto image = one_block_image({
        std::move(load),
        instruction(31, UINT64_C(0x1005), {0xc3}, binobf::InstructionKind::Return),
    }, binobf::Architecture::X86);
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{41},
        .formatIndex = 0,
        .formatTableIndex = 0,
        .formatType = 0,
        .formatStorage = 2,
        .formatOther = 0,
        .formatSectionIndex = 0,
        .auxiliaryData = {},
        .name = "tls_value",
        .section = std::nullopt,
        .address = {},
        .size = 4,
        .kind = binobf::SymbolKind::Object,
        .visibility = binobf::SymbolVisibility::External,
        .defined = false,
        .definition = binobf::SymbolDefinitionKind::Undefined,
        .commonAlignment = 0,
        .tlsModel = binobf::TlsModel::None,
        .lineage = {},
    });
    binobf::ir::NativeFunctionSignature signature{};
    signature.abi = binobf::ir::NativeAbi::SystemVI386;
    signature.returnType = binobf::ir::IrType{binobf::ir::IrWidth::U32};
    binobf::ir::NativeLiftOptions options{};
    options.symbolStorage.push_back(binobf::ir::IrStorageLocation{
        .kind = binobf::ir::IrStorageKind::ThreadLocal,
        .type = binobf::ir::IrType{binobf::ir::IrWidth::U32},
        .name = "tls_value",
        .offset = 0,
        .size = 4,
        .alignment = 4,
        .index = 0,
        .readonly = false,
    });

    const auto lifted = binobf::ir::lift_function(
        image, binobf::EntityId{10}, signature, options);

    REQUIRE(lifted.has_value());
    REQUIRE(lifted.value().complete);
    REQUIRE_EQ(lifted.value().function.blocks[0].instructions.size(), std::size_t{3});
    const auto* addressOf = std::get_if<binobf::ir::IrAddressOf>(
        &lifted.value().function.blocks[0].instructions[0]);
    REQUIRE(addressOf != nullptr);
    REQUIRE_EQ(lifted.value().function.storageLocations[addressOf->storageIndex].kind,
               binobf::ir::IrStorageKind::ThreadLocal);
    const auto* irLoad = std::get_if<binobf::ir::IrLoad>(
        &lifted.value().function.blocks[0].instructions[1]);
    REQUIRE(irLoad != nullptr);
    REQUIRE_EQ(irLoad->address.addressSpace, std::uint16_t{1});
    REQUIRE(binobf::ir::validate_function(lifted.value().function).has_value());
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

TEST_CASE(native_lifter_does_not_silently_drop_an_unconsumed_i386_push) {
    auto image = one_block_image({
        instruction(30, UINT64_C(0x1000), {0x50}),
        instruction(31, UINT64_C(0x1001), {0xc3}, binobf::InstructionKind::Return),
    }, binobf::Architecture::X86);
    binobf::ir::NativeFunctionSignature signature{};
    signature.abi = binobf::ir::NativeAbi::WindowsI386Cdecl;
    signature.returnType = binobf::ir::IrType{};

    const auto lifted = binobf::ir::lift_function(
        image, binobf::EntityId{10}, signature);

    REQUIRE(lifted.has_value());
    REQUIRE(!lifted.value().complete);
    REQUIRE(binobf::ir::function_contains_fallback(lifted.value().function));
    REQUIRE_EQ(lifted.value().diagnostics[0].code, "ir.unconsumed_stack_argument");
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
        image, binobf::EntityId{99}, u32_binary_signature(), binobf::ir::IrLimits{});
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.function_not_found");
    image.architecture = binobf::Architecture::ARM64;
    result = binobf::ir::lift_function(
        image, binobf::EntityId{10}, u32_binary_signature());
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.unsupported_architecture");
}

TEST_CASE(native_lifter_rejects_arm64_abis_until_arm64_lifting_is_supported) {
    auto image = one_block_image({
        instruction(30, UINT64_C(0x1000), {0xc3},
                    binobf::InstructionKind::Return),
    });
    auto signature = u32_binary_signature();
    signature.abi = binobf::ir::NativeAbi::WindowsARM64;

    auto result = binobf::ir::lift_function(
        image, binobf::EntityId{10}, signature);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.abi_architecture_mismatch");

    image.architecture = binobf::Architecture::ARM64;
    result = binobf::ir::lift_function(
        image, binobf::EntityId{10}, signature);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.unsupported_architecture");

    signature.abi = binobf::ir::NativeAbi::AAPCS64;
    result = binobf::ir::lift_function(
        image, binobf::EntityId{10}, signature);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.unsupported_architecture");
}

int main() {
    return binobf::test::run_all();
}

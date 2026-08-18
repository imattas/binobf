#include "../test_support.hpp"

#include <binobf/ir/native.hpp>

#include <cstddef>
#include <cstdint>

namespace {

auto binary_signature() -> binobf::ir::IrFunctionSignature {
    using namespace binobf::ir;
    return IrFunctionSignature{
        .callingConvention = IrCallingConvention::C,
        .parameterTypes = {IrWidth::U32, IrWidth::U32},
        .returnType = IrWidth::U32,
        .parameterBindings = {
            IrStorageLocation{IrStorageKind::Register, IrWidth::U32, "arg0", 0, 4U, 4U},
            IrStorageLocation{IrStorageKind::Register, IrWidth::U32, "arg1", 0, 4U, 4U},
        },
        .returnBinding = IrStorageLocation{
            IrStorageKind::Register, IrWidth::U32, "result", 0, 4U, 4U},
        .clobbers = {},
        .mayUnwind = false,
    };
}

auto helper_function() -> binobf::ir::IrFunction {
    using namespace binobf::ir;
    return IrFunction{
        .sourceFunction = binobf::EntityId{11},
        .name = "helper",
        .arguments = {
            IrArgumentBinding{0, IrVariable{0}, IrWidth::U32},
            IrArgumentBinding{1, IrVariable{1}, IrWidth::U32},
        },
        .returnType = IrWidth::U32,
        .variableTypes = {IrWidth::U32, IrWidth::U32, IrWidth::U32},
        .storageLocations = {},
        .signature = binary_signature(),
        .entry = IrBlockId{0},
        .blocks = {IrBlock{IrBlockId{0}, binobf::EntityId{20}, {
            IrMove{IrWidth::U32, IrVariable{2}, IrVariableOperand{IrVariable{0}},
                   binobf::EntityId{30}},
            IrBinaryOperation{IrBinaryOpcode::Add, IrWidth::U32, IrVariable{2},
                              IrVariableOperand{IrVariable{1}}, binobf::EntityId{31}},
            IrReturn{IrWidth::U32, IrVariable{2}, binobf::EntityId{32}},
        }}},
        .unwindRegions = {},
    };
}

auto wrapper_function() -> binobf::ir::IrFunction {
    using namespace binobf::ir;
    return IrFunction{
        .sourceFunction = binobf::EntityId{10},
        .name = "wrapper",
        .arguments = {
            IrArgumentBinding{0, IrVariable{0}, IrWidth::U32},
            IrArgumentBinding{1, IrVariable{1}, IrWidth::U32},
        },
        .returnType = IrWidth::U32,
        .variableTypes = {IrWidth::U32, IrWidth::U32, IrWidth::U32},
        .storageLocations = {},
        .signature = binary_signature(),
        .entry = IrBlockId{0},
        .blocks = {IrBlock{IrBlockId{0}, binobf::EntityId{21}, {
            IrInternalCall{
                binobf::EntityId{11}, IrWidth::U32, IrVariable{2},
                {IrVariableOperand{IrVariable{0}}, IrVariableOperand{IrVariable{1}}},
                binobf::EntityId{40}, std::nullopt},
            IrReturn{IrWidth::U32, IrVariable{2}, binobf::EntityId{41}},
        }}},
        .unwindRegions = {},
    };
}

auto valid_module() -> binobf::ir::IrModule {
    return binobf::ir::IrModule{
        .entryFunction = binobf::EntityId{10},
        .declarations = {},
        .functions = {wrapper_function(), helper_function()},
    };
}


TEST_CASE(ir_module_validator_checks_external_declarations_signatures_and_abi_bindings) {
    using namespace binobf::ir;
    auto module = valid_module();
    module.declarations.push_back(IrExternalDeclaration{"external_add", binary_signature()});
    module.functions[0].blocks[0].instructions[0] = IrExternalCall{
        "external_add", binary_signature(), IrVariable{2},
        {IrVariableOperand{IrVariable{0}}, IrVariableOperand{IrVariable{1}}},
        binobf::EntityId{40}, std::nullopt};
    auto result = validate_module(module);
    REQUIRE(result.has_value());

    auto undeclared = module;
    undeclared.declarations.clear();
    result = validate_module(undeclared);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.external_declaration_missing");

    auto mismatch = module;
    mismatch.declarations[0].signature.returnType = IrWidth::U16;
    mismatch.declarations[0].signature.returnBinding->type = IrWidth::U16;
    mismatch.declarations[0].signature.returnBinding->size = 2U;
    mismatch.declarations[0].signature.returnBinding->alignment = 2U;
    result = validate_module(mismatch);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.external_call_signature_mismatch");

    auto invalidAbi = module;
    invalidAbi.declarations[0].signature.parameterBindings[0].kind = IrStorageKind::Local;
    result = validate_module(invalidAbi);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.invalid_abi_binding");
}

TEST_CASE(ir_module_validator_rejects_illegal_tail_calls_and_declaration_limits) {
    using namespace binobf::ir;
    auto module = valid_module();
    module.functions[0].blocks[0].instructions = {
        IrTailCall{IrCallTarget{binobf::EntityId{11}}, binary_signature(),
                   {IrVariableOperand{IrVariable{0}}, IrVariableOperand{IrVariable{1}}},
                   binobf::EntityId{40}, std::nullopt},
    };
    auto result = validate_module(module);
    REQUIRE(result.has_value());

    auto incompatible = module;
    std::get<IrTailCall>(
        incompatible.functions[0].blocks[0].instructions[0]).signature.callingConvention =
        IrCallingConvention::SystemV;
    result = validate_module(incompatible);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.illegal_tail_call");

    IrLimits limits{};
    limits.maxExternalDeclarations = 0U;
    module.declarations.push_back(IrExternalDeclaration{"external", binary_signature()});
    result = validate_module(module, limits);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.external_declaration_limit");
}

} // namespace

TEST_CASE(ir_module_validator_accepts_typed_acyclic_internal_calls) {
    const auto validated = binobf::ir::validate_module(valid_module());
    REQUIRE(validated.has_value());
    REQUIRE_EQ(validated.value(), std::size_t{5});
}

TEST_CASE(ir_module_validator_rejects_missing_entry_duplicate_and_missing_targets) {
    auto missingEntry = valid_module();
    missingEntry.entryFunction = binobf::EntityId{99};
    auto result = binobf::ir::validate_module(missingEntry);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.module_entry_missing");

    auto duplicate = valid_module();
    duplicate.functions.push_back(duplicate.functions.back());
    result = binobf::ir::validate_module(duplicate);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.duplicate_function");

    auto missingTarget = valid_module();
    auto& call = std::get<binobf::ir::IrInternalCall>(
        missingTarget.functions[0].blocks[0].instructions[0]);
    call.targetFunction = binobf::EntityId{99};
    result = binobf::ir::validate_module(missingTarget);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.internal_call_target_missing");
}

TEST_CASE(ir_module_validator_rejects_call_signature_mismatches) {
    auto wrongCount = valid_module();
    std::get<binobf::ir::IrInternalCall>(
        wrongCount.functions[0].blocks[0].instructions[0]).arguments.pop_back();
    auto result = binobf::ir::validate_module(wrongCount);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.internal_call_signature_mismatch");

    auto wrongWidth = valid_module();
    auto& wrongCall = std::get<binobf::ir::IrInternalCall>(
        wrongWidth.functions[0].blocks[0].instructions[0]);
    wrongCall.resultType = binobf::ir::IrWidth::U16;
    wrongWidth.functions[0].variableTypes[2] = binobf::ir::IrWidth::U16;
    wrongWidth.functions[0].returnType = binobf::ir::IrWidth::U16;
    wrongWidth.functions[0].signature.returnType = binobf::ir::IrWidth::U16;
    wrongWidth.functions[0].signature.returnBinding->type = binobf::ir::IrWidth::U16;
    wrongWidth.functions[0].signature.returnBinding->size = 2U;
    wrongWidth.functions[0].signature.returnBinding->alignment = 2U;
    auto& wrongReturn = std::get<binobf::ir::IrReturn>(
        wrongWidth.functions[0].blocks[0].instructions[1]);
    wrongReturn.type = binobf::ir::IrWidth::U16;
    result = binobf::ir::validate_module(wrongWidth);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.internal_call_signature_mismatch");
}

TEST_CASE(ir_module_validator_rejects_recursive_calls_and_function_limits) {
    auto recursive = valid_module();
    auto helper = wrapper_function();
    helper.sourceFunction = binobf::EntityId{11};
    helper.name = "recursive-helper";
    std::get<binobf::ir::IrInternalCall>(
        helper.blocks[0].instructions[0]).targetFunction = binobf::EntityId{10};
    recursive.functions[1] = std::move(helper);
    auto result = binobf::ir::validate_module(recursive);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.recursive_internal_call");

    binobf::ir::IrLimits limits;
    limits.maxFunctions = 1;
    result = binobf::ir::validate_module(valid_module(), limits);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.function_limit");
}

int main() {
    return binobf::test::run_all();
}

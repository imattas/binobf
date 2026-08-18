#include "../test_support.hpp"

#include <binobf/ir/native.hpp>

#include <cstddef>
#include <cstdint>

namespace {

auto helper_function() -> binobf::ir::IrFunction {
    using namespace binobf::ir;
    return IrFunction{
        .sourceFunction = binobf::EntityId{11},
        .name = "helper",
        .arguments = {
            IrArgumentBinding{0, IrVariable{0}, IrWidth::U32},
            IrArgumentBinding{1, IrVariable{1}, IrWidth::U32},
        },
        .returnWidth = IrWidth::U32,
        .variableWidths = {IrWidth::U32, IrWidth::U32, IrWidth::U32},
        .entry = IrBlockId{0},
        .blocks = {IrBlock{IrBlockId{0}, binobf::EntityId{20}, {
            IrMove{IrWidth::U32, IrVariable{2}, IrVariableOperand{IrVariable{0}},
                   binobf::EntityId{30}},
            IrBinaryOperation{IrBinaryOpcode::Add, IrWidth::U32, IrVariable{2},
                              IrVariableOperand{IrVariable{1}}, binobf::EntityId{31}},
            IrReturn{IrWidth::U32, IrVariable{2}, binobf::EntityId{32}},
        }}},
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
        .returnWidth = IrWidth::U32,
        .variableWidths = {IrWidth::U32, IrWidth::U32, IrWidth::U32},
        .entry = IrBlockId{0},
        .blocks = {IrBlock{IrBlockId{0}, binobf::EntityId{21}, {
            IrInternalCall{
                binobf::EntityId{11}, IrWidth::U32, IrVariable{2},
                {IrVariableOperand{IrVariable{0}}, IrVariableOperand{IrVariable{1}}},
                binobf::EntityId{40}},
            IrReturn{IrWidth::U32, IrVariable{2}, binobf::EntityId{41}},
        }}},
    };
}

auto valid_module() -> binobf::ir::IrModule {
    return binobf::ir::IrModule{
        .entryFunction = binobf::EntityId{10},
        .functions = {wrapper_function(), helper_function()},
    };
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
    wrongCall.resultWidth = binobf::ir::IrWidth::U16;
    wrongWidth.functions[0].variableWidths[2] = binobf::ir::IrWidth::U16;
    wrongWidth.functions[0].returnWidth = binobf::ir::IrWidth::U16;
    auto& wrongReturn = std::get<binobf::ir::IrReturn>(
        wrongWidth.functions[0].blocks[0].instructions[1]);
    wrongReturn.width = binobf::ir::IrWidth::U16;
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

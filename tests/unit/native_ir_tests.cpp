#include "../test_support.hpp"

#include <binobf/ir/native.hpp>

#include <cstddef>
#include <cstdint>
#include <string>

namespace {

auto arithmetic_function() -> binobf::ir::IrFunction {
    using namespace binobf::ir;
    return IrFunction{
        .sourceFunction = binobf::EntityId{10},
        .name = "add",
        .arguments = {
            IrArgumentBinding{0, IrVariable{0}, IrWidth::U32},
            IrArgumentBinding{1, IrVariable{1}, IrWidth::U32},
        },
        .returnWidth = IrWidth::U32,
        .variableWidths = {IrWidth::U32, IrWidth::U32, IrWidth::U32},
        .entry = IrBlockId{0},
        .blocks = {
            IrBlock{
                .id = IrBlockId{0},
                .sourceBlock = binobf::EntityId{20},
                .instructions = {
                    IrMove{IrWidth::U32, IrVariable{2}, IrVariableOperand{IrVariable{0}},
                           binobf::EntityId{30}},
                    IrBinaryOperation{IrBinaryOpcode::Add, IrWidth::U32, IrVariable{2},
                                      IrVariableOperand{IrVariable{1}},
                                      binobf::EntityId{31}},
                    IrReturn{IrWidth::U32, IrVariable{2}, binobf::EntityId{32}},
                },
            },
        },
    };
}

} // namespace

TEST_CASE(native_ir_validator_accepts_typed_arithmetic) {
    const auto result = binobf::ir::validate_function(arithmetic_function());
    REQUIRE(result.has_value());
    REQUIRE_EQ(result.value(), std::size_t{3});
}

TEST_CASE(native_ir_validator_rejects_duplicate_blocks_and_missing_entry) {
    auto duplicate = arithmetic_function();
    duplicate.blocks.push_back(duplicate.blocks.front());
    auto result = binobf::ir::validate_function(duplicate);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.duplicate_block");

    auto missing = arithmetic_function();
    missing.entry = binobf::ir::IrBlockId{99};
    result = binobf::ir::validate_function(missing);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.entry_block_missing");
}

TEST_CASE(native_ir_validator_rejects_bad_variables_and_use_before_definition) {
    using namespace binobf::ir;
    auto outOfRange = arithmetic_function();
    outOfRange.blocks[0].instructions[0] = IrMove{
        IrWidth::U32, IrVariable{3}, IrVariableOperand{IrVariable{0}},
        binobf::EntityId{30}};
    auto result = validate_function(outOfRange);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.variable_out_of_range");

    auto undefined = arithmetic_function();
    undefined.arguments.clear();
    result = validate_function(undefined);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.use_before_definition");
}

TEST_CASE(native_ir_validator_rejects_invalid_targets_and_unterminated_blocks) {
    using namespace binobf::ir;
    auto badTarget = arithmetic_function();
    badTarget.blocks[0].instructions.back() = IrJump{IrBlockId{42}, binobf::EntityId{32}};
    auto result = validate_function(badTarget);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.branch_target_missing");

    auto unterminated = arithmetic_function();
    unterminated.blocks[0].instructions.pop_back();
    result = validate_function(unterminated);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.block_unterminated");
}

TEST_CASE(native_ir_validator_accepts_preserved_fallback_but_marks_it_non_lowerable) {
    using namespace binobf::ir;
    auto function = arithmetic_function();
    function.blocks[0].instructions.insert(
        function.blocks[0].instructions.begin(),
        IrFallback{binobf::EntityId{29}, {}, "unsupported native instruction"});
    const auto result = validate_function(function);
    REQUIRE(result.has_value());
    REQUIRE(function_contains_fallback(function));
}

TEST_CASE(native_ir_validator_enforces_resource_limits) {
    auto function = arithmetic_function();
    binobf::ir::IrLimits limits;
    limits.maxInstructions = 2;
    auto result = binobf::ir::validate_function(function, limits);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.instruction_limit");
    limits.maxInstructions = 10;
    limits.maxVariables = 2;
    result = binobf::ir::validate_function(function, limits);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.variable_limit");
}

TEST_CASE(native_ir_validator_requires_explicit_flags_before_conditional_branches) {
    using namespace binobf::ir;
    auto function = arithmetic_function();
    function.blocks[0].instructions.erase(function.blocks[0].instructions.begin() + 1);
    function.blocks[0].instructions.back() = IrConditionalJump{
        IrCondition::Equal, IrBlockId{1}, IrBlockId{1}, binobf::EntityId{32}};
    function.blocks.push_back(IrBlock{
        IrBlockId{1}, binobf::EntityId{21}, {
            IrReturn{IrWidth::U32, IrVariable{2}, binobf::EntityId{33}},
        }});
    const auto result = validate_function(function);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.flags_undefined");
}

int main() {
    return binobf::test::run_all();
}

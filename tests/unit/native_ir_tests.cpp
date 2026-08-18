#include "../test_support.hpp"

#include <binobf/ir/native.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
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
        .returnType = IrWidth::U32,
        .variableTypes = {IrWidth::U32, IrWidth::U32, IrWidth::U32},
        .storageLocations = {},
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

auto memory_function() -> binobf::ir::IrFunction {
    using namespace binobf::ir;
    const IrType pointer{IrTypeKind::Pointer, 64U};
    const IrType integer{IrTypeKind::Integer, 64U};
    return IrFunction{
        .sourceFunction = binobf::EntityId{40},
        .name = "memory",
        .arguments = {},
        .returnType = integer,
        .variableTypes = {pointer, integer, IrType{IrTypeKind::Integer, 32U}},
        .storageLocations = {
            IrStorageLocation{
                IrStorageKind::Local, integer, "value", 0, 8U, 8U, 0U, false},
        },
        .entry = IrBlockId{0},
        .blocks = {
            IrBlock{
                .id = IrBlockId{0},
                .sourceBlock = binobf::EntityId{41},
                .instructions = {
                    IrAddressOf{IrVariable{0}, 0U, binobf::EntityId{42}},
                    IrLoad{
                        integer,
                        IrVariable{1},
                        IrAddress{IrVariable{0}, std::nullopt, 1U, 0, 0U, 8U},
                        IrByteOrder::Little,
                        false,
                        IrAtomicOrdering::None,
                        binobf::EntityId{43},
                    },
                    IrCast{
                        IrCastKind::Truncate,
                        integer,
                        IrType{IrTypeKind::Integer, 32U},
                        IrVariable{2},
                        IrValue{IrVariableOperand{IrVariable{1}}},
                        binobf::EntityId{44},
                    },
                    IrStore{
                        integer,
                        IrAddress{IrVariable{0}, std::nullopt, 1U, 0, 0U, 8U},
                        IrValue{IrVariableOperand{IrVariable{1}}},
                        IrByteOrder::Little,
                        false,
                        IrAtomicOrdering::None,
                        binobf::EntityId{45},
                    },
                    IrReturn{integer, IrVariable{1}, binobf::EntityId{46}},
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

TEST_CASE(native_ir_canonical_types_validate_integer_pointer_float_and_vector_shapes) {
    using namespace binobf::ir;
    const auto integer = integer_type(IrWidth::U32);
    REQUIRE_EQ(integer.kind, IrTypeKind::Integer);
    REQUIRE_EQ(integer.bits, 32U);
    REQUIRE_EQ(integer_width(integer).value(), IrWidth::U32);

    const std::array validTypes{
        IrType{IrTypeKind::Pointer, 64U, 1U, 0U, IrByteOrder::Little},
        IrType{IrTypeKind::FloatingPoint, 32U, 1U, 0U, IrByteOrder::Little},
        IrType{IrTypeKind::FloatingPoint, 64U, 1U, 0U, IrByteOrder::Little},
        IrType{IrTypeKind::Vector, 32U, 4U, 0U, IrByteOrder::Little},
    };
    for (const auto& type : validTypes) {
        const auto checked = validate_type(type);
        REQUIRE(checked.has_value());
    }

    const std::array invalidTypes{
        IrType{IrTypeKind::Integer, 24U, 1U, 0U, IrByteOrder::Little},
        IrType{IrTypeKind::Pointer, 48U, 1U, 0U, IrByteOrder::Little},
        IrType{IrTypeKind::FloatingPoint, 16U, 1U, 0U, IrByteOrder::Little},
        IrType{IrTypeKind::Vector, 32U, 3U, 0U, IrByteOrder::Little},
        IrType{IrTypeKind::Pointer, 64U, 1U, 256U, IrByteOrder::Little},
    };
    for (const auto& type : invalidTypes) {
        const auto checked = validate_type(type);
        REQUIRE(!checked.has_value());
        REQUIRE_EQ(checked.error().code, "ir.invalid_type");
    }
}

TEST_CASE(native_ir_validator_accepts_typed_storage_memory_and_casts) {
    const auto result = binobf::ir::validate_function(memory_function());
    REQUIRE(result.has_value());
    REQUIRE_EQ(result.value(), std::size_t{5});
}

TEST_CASE(native_ir_validator_rejects_invalid_storage_addresses_and_readonly_stores) {
    auto invalidAlignment = memory_function();
    invalidAlignment.storageLocations[0].alignment = 3U;
    auto result = binobf::ir::validate_function(invalidAlignment);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.invalid_alignment");

    auto invalidAddress = memory_function();
    std::get<binobf::ir::IrLoad>(invalidAddress.blocks[0].instructions[1]).address.scale = 3U;
    result = binobf::ir::validate_function(invalidAddress);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.invalid_address");

    auto readonly = memory_function();
    readonly.storageLocations[0].readonly = true;
    result = binobf::ir::validate_function(readonly);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.readonly_store");
}

TEST_CASE(native_ir_validator_rejects_memory_type_cast_atomic_and_limit_errors) {
    using namespace binobf::ir;
    auto mismatch = memory_function();
    std::get<IrLoad>(mismatch.blocks[0].instructions[1]).type =
        IrType{IrTypeKind::Integer, 32U};
    auto result = validate_function(mismatch);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.type_mismatch");

    auto invalidCast = memory_function();
    auto& cast = std::get<IrCast>(invalidCast.blocks[0].instructions[2]);
    cast.kind = IrCastKind::ZeroExtend;
    cast.sourceType = IrType{IrTypeKind::Integer, 64U};
    cast.destinationType = IrType{IrTypeKind::Integer, 32U};
    result = validate_function(invalidCast);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.invalid_cast");

    auto invalidAtomic = memory_function();
    std::get<IrLoad>(invalidAtomic.blocks[0].instructions[1]).atomicOrdering =
        IrAtomicOrdering::Release;
    result = validate_function(invalidAtomic);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.invalid_atomic");

    auto badSymbolAddend = memory_function();
    auto& symbolCast = std::get<IrCast>(badSymbolAddend.blocks[0].instructions[2]);
    symbolCast.kind = IrCastKind::PointerToInteger;
    symbolCast.sourceType = IrType{IrTypeKind::Pointer, 32U};
    symbolCast.destinationType = IrType{IrTypeKind::Integer, 32U};
    symbolCast.source = IrSymbolAddressConstant{
        IrType{IrTypeKind::Pointer, 32U},
        "external",
        std::numeric_limits<std::int64_t>::max(),
    };
    result = validate_function(badSymbolAddend);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.invalid_address");

    IrLimits limits{};
    limits.maxMemoryOperations = 1U;
    result = validate_function(memory_function(), limits);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.memory_operation_limit");

    limits = {};
    limits.maxAggregateStorageBytes = 7U;
    result = validate_function(memory_function(), limits);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.storage_limit");
}

int main() {
    return binobf::test::run_all();
}

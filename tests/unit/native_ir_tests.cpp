#include "../test_support.hpp"

#include <binobf/ir/native.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>

namespace {

auto u32_signature() -> binobf::ir::IrFunctionSignature {
    using namespace binobf::ir;
    return IrFunctionSignature{
        .callingConvention = IrCallingConvention::C,
        .parameterTypes = {IrWidth::U32, IrWidth::U32},
        .returnType = IrWidth::U32,
        .variadic = false,
        .parameterBindings = {
            IrStorageLocation{IrStorageKind::Register, IrWidth::U32, "arg0", 0, 4U, 4U},
            IrStorageLocation{IrStorageKind::Register, IrWidth::U32, "arg1", 0, 4U, 4U},
        },
        .returnBinding = IrStorageLocation{
            IrStorageKind::Register, IrWidth::U32, "result", 0, 4U, 4U},
        .clobbers = IrCallClobbers{{"flags"}, true, false},
        .mayUnwind = false,
    };
}

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
        .signature = u32_signature(),
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
        .unwindRegions = {},
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
        .signature = IrFunctionSignature{
            .callingConvention = IrCallingConvention::C,
            .parameterTypes = {},
            .returnType = integer,
            .variadic = false,
            .parameterBindings = {},
            .returnBinding = std::nullopt,
            .clobbers = {},
            .mayUnwind = false,
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
                        std::nullopt,
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
                        std::nullopt,
                    },
                    IrReturn{integer, IrVariable{1}, binobf::EntityId{46}},
                },
            },
        },
        .unwindRegions = {},
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
    undefined.signature.parameterTypes.clear();
    undefined.signature.parameterBindings.clear();
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
        IrFallback{
            binobf::EntityId{29}, {}, "unsupported native instruction",
            IrFallbackEffects{{}, {}, {}, false, false, false, false, true},
            std::nullopt});
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

TEST_CASE(native_ir_validator_checks_switch_indirect_fallback_and_unwind_semantics) {
    using namespace binobf::ir;
    auto function = arithmetic_function();
    function.blocks[0].instructions.back() = IrSwitch{
        IrVariable{2},
        {IrSwitchCase{1U, IrBlockId{1}}, IrSwitchCase{2U, IrBlockId{1}}},
        IrBlockId{1},
        binobf::EntityId{32},
    };
    function.blocks.push_back(IrBlock{
        IrBlockId{1}, binobf::EntityId{21},
        {IrReturn{IrWidth::U32, IrVariable{2}, binobf::EntityId{33}}}});
    auto result = validate_function(function);
    REQUIRE(result.has_value());

    auto duplicateSwitch = function;
    auto& duplicateCases = std::get<IrSwitch>(
        duplicateSwitch.blocks[0].instructions.back()).cases;
    duplicateCases[1].value = duplicateCases[0].value;
    result = validate_function(duplicateSwitch);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.invalid_switch");

    auto emptyIndirect = arithmetic_function();
    emptyIndirect.blocks[0].instructions.back() = IrIndirectJump{
        IrVariable{2}, {}, binobf::EntityId{32}};
    result = validate_function(emptyIndirect);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.invalid_indirect_jump");

    auto incompleteFallback = arithmetic_function();
    incompleteFallback.blocks[0].instructions.insert(
        incompleteFallback.blocks[0].instructions.begin(),
        IrFallback{
            binobf::EntityId{29}, {}, "opaque", IrFallbackEffects{}, std::nullopt});
    result = validate_function(incompleteFallback);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.incomplete_fallback_effects");

    auto unwindCycle = arithmetic_function();
    unwindCycle.unwindRegions = {
        IrUnwindRegion{1U, IrUnwindRegionKind::Cleanup, 2U, IrBlockId{0}, {IrBlockId{0}}, {}},
        IrUnwindRegion{2U, IrUnwindRegionKind::Cleanup, 1U, IrBlockId{0}, {}, {}},
    };
    result = validate_function(unwindCycle);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.invalid_unwind");
}

TEST_CASE(native_ir_validator_rejects_missing_targets_unwind_ownership_and_new_limits) {
    using namespace binobf::ir;
    auto missingSwitchTarget = arithmetic_function();
    missingSwitchTarget.blocks[0].instructions.back() = IrSwitch{
        IrVariable{2}, {IrSwitchCase{1U, IrBlockId{99}}}, IrBlockId{99},
        binobf::EntityId{32}};
    auto result = validate_function(missingSwitchTarget);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.branch_target_missing");

    auto missingLanding = arithmetic_function();
    missingLanding.unwindRegions = {
        IrUnwindRegion{1U, IrUnwindRegionKind::Cleanup, std::nullopt,
                       IrBlockId{99}, {IrBlockId{0}}, {}},
    };
    result = validate_function(missingLanding);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.invalid_unwind");

    auto overlapping = arithmetic_function();
    overlapping.unwindRegions = {
        IrUnwindRegion{1U, IrUnwindRegionKind::Cleanup, std::nullopt,
                       IrBlockId{0}, {IrBlockId{0}}, {}},
        IrUnwindRegion{2U, IrUnwindRegionKind::Catch, std::nullopt,
                       IrBlockId{0}, {IrBlockId{0}}, {}},
    };
    result = validate_function(overlapping);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.invalid_unwind");

    IrLimits limits{};
    limits.maxSwitchCases = 1U;
    auto tooManyCases = arithmetic_function();
    tooManyCases.blocks[0].instructions.back() = IrSwitch{
        IrVariable{2},
        {IrSwitchCase{1U, IrBlockId{1}}, IrSwitchCase{2U, IrBlockId{1}}},
        IrBlockId{1}, binobf::EntityId{32}};
    tooManyCases.blocks.push_back(IrBlock{
        IrBlockId{1}, binobf::EntityId{21},
        {IrReturn{IrWidth::U32, IrVariable{2}, binobf::EntityId{33}}}});
    result = validate_function(tooManyCases, limits);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "ir.switch_case_limit");
}

TEST_CASE(native_ir_fallback_effects_define_transform_boundaries) {
    using namespace binobf::ir;
    auto function = arithmetic_function();
    function.blocks[0].instructions.insert(
        function.blocks[0].instructions.begin(),
        IrFallback{
            binobf::EntityId{29}, {}, "opaque",
            IrFallbackEffects{{IrVariable{0}}, {IrVariable{2}}, {"flags"},
                              true, true, false, false, true},
            std::nullopt});
    const auto result = validate_function(function);
    REQUIRE(result.has_value());
    REQUIRE(fallback_blocks_rewrite(function, {IrBlockId{0}}));
    REQUIRE(!fallback_blocks_rewrite(function, {IrBlockId{99}}));
}

int main() {
    return binobf::test::run_all();
}

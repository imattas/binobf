#include <binobf/ir/native.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace binobf::ir {
namespace {

auto failure(std::string code, std::string message) -> Result<std::size_t, Diagnostic> {
    return Result<std::size_t, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

auto variable_valid(const IrFunction& function, IrVariable variable) -> bool {
    return static_cast<std::size_t>(variable.index) < function.variableTypes.size();
}

auto operand_valid(
    const IrFunction& function,
    const IrOperand& operand,
    const IrType& type) -> Result<std::size_t, Diagnostic> {
    if (const auto* variable = std::get_if<IrVariableOperand>(&operand)) {
        if (!variable_valid(function, variable->variable)) {
            return failure("ir.variable_out_of_range", "IR operand variable is out of range");
        }
        if (function.variableTypes[variable->variable.index] != type) {
            return failure("ir.type_mismatch", "IR operand variable type does not match");
        }
    } else if (std::get<IrImmediateOperand>(operand).type != type) {
        return failure("ir.type_mismatch", "IR immediate type does not match");
    }
    return Result<std::size_t, Diagnostic>::success(0);
}

auto valid_alignment(std::uint32_t alignment, const IrLimits& limits) noexcept -> bool {
    return alignment > 0U && alignment <= limits.maxAlignment &&
        (alignment & (alignment - 1U)) == 0U;
}

auto type_size_bytes(const IrType& type) -> std::uint64_t {
    if (type.kind == IrTypeKind::Void) return 0U;
    return (static_cast<std::uint64_t>(type.bits) / 8U) * type.lanes;
}

auto value_type(const IrFunction& function, const IrValue& value)
    -> Result<IrType, Diagnostic> {
    return std::visit([&](const auto& item) -> Result<IrType, Diagnostic> {
        using T = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<T, IrVariableOperand>) {
            if (!variable_valid(function, item.variable)) {
                return Result<IrType, Diagnostic>::failure(Diagnostic{
                    DiagnosticSeverity::Error,
                    "ir.variable_out_of_range",
                    "IR value variable is out of range",
                });
            }
            return Result<IrType, Diagnostic>::success(
                function.variableTypes[item.variable.index]);
        } else {
            const auto checked = validate_type(item.type);
            if (!checked.has_value()) {
                return Result<IrType, Diagnostic>::failure(checked.error());
            }
            if constexpr (std::is_same_v<T, IrIntegerConstant>) {
                if (item.type.kind != IrTypeKind::Integer) {
                    return Result<IrType, Diagnostic>::failure(Diagnostic{
                        DiagnosticSeverity::Error, "ir.invalid_type",
                        "integer constant requires an integer type"});
                }
            } else if constexpr (std::is_same_v<T, IrFloatingConstant>) {
                if (item.type.kind != IrTypeKind::FloatingPoint) {
                    return Result<IrType, Diagnostic>::failure(Diagnostic{
                        DiagnosticSeverity::Error, "ir.invalid_type",
                        "floating constant requires a floating-point type"});
                }
            } else if constexpr (std::is_same_v<T, IrNullPointerConstant>) {
                if (item.type.kind != IrTypeKind::Pointer) {
                    return Result<IrType, Diagnostic>::failure(Diagnostic{
                        DiagnosticSeverity::Error, "ir.invalid_type",
                        "null constant requires a pointer type"});
                }
            } else if constexpr (std::is_same_v<T, IrSymbolAddressConstant>) {
                const bool addendFits = item.type.bits != 32U ||
                    (item.addend >= std::numeric_limits<std::int32_t>::min() &&
                     item.addend <= std::numeric_limits<std::int32_t>::max());
                if (item.type.kind != IrTypeKind::Pointer || item.symbol.empty() ||
                    !addendFits) {
                    return Result<IrType, Diagnostic>::failure(Diagnostic{
                        DiagnosticSeverity::Error, "ir.invalid_address",
                        "symbol address constant requires a named pointer"});
                }
            } else if constexpr (std::is_same_v<T, IrZeroVectorConstant>) {
                if (item.type.kind != IrTypeKind::Vector) {
                    return Result<IrType, Diagnostic>::failure(Diagnostic{
                        DiagnosticSeverity::Error, "ir.invalid_type",
                        "zero-vector constant requires a vector type"});
                }
            }
            return Result<IrType, Diagnostic>::success(item.type);
        }
    }, value);
}

auto validate_address(
    const IrFunction& function,
    const IrAddress& address,
    const IrLimits& limits) -> Result<std::size_t, Diagnostic> {
    if (!variable_valid(function, address.base) ||
        (address.scale != 1U && address.scale != 2U &&
         address.scale != 4U && address.scale != 8U) ||
        !valid_alignment(address.alignment, limits)) {
        return failure("ir.invalid_address", "IR memory address shape is invalid");
    }
    const auto& baseType = function.variableTypes[address.base.index];
    if (baseType.kind != IrTypeKind::Pointer ||
        baseType.addressSpace != address.addressSpace) {
        return failure("ir.invalid_address", "IR address base is not a matching pointer");
    }
    if (address.index.has_value()) {
        if (!variable_valid(function, *address.index) ||
            function.variableTypes[address.index->index].kind != IrTypeKind::Integer) {
            return failure("ir.invalid_address", "IR address index is not an integer variable");
        }
    }
    return Result<std::size_t, Diagnostic>::success(0U);
}

auto valid_cast(IrCastKind kind, const IrType& source, const IrType& destination)
    noexcept -> bool {
    switch (kind) {
    case IrCastKind::ZeroExtend:
    case IrCastKind::SignExtend:
        return source.kind == IrTypeKind::Integer &&
            destination.kind == IrTypeKind::Integer && source.bits < destination.bits;
    case IrCastKind::Truncate:
        return source.kind == IrTypeKind::Integer &&
            destination.kind == IrTypeKind::Integer && source.bits > destination.bits;
    case IrCastKind::Bitcast:
        return type_size_bytes(source) == type_size_bytes(destination) &&
            (!(source.kind == IrTypeKind::Pointer &&
               destination.kind == IrTypeKind::Pointer) ||
             source.addressSpace == destination.addressSpace);
    case IrCastKind::IntegerToPointer:
        return source.kind == IrTypeKind::Integer &&
            destination.kind == IrTypeKind::Pointer && source.bits == destination.bits;
    case IrCastKind::PointerToInteger:
        return source.kind == IrTypeKind::Pointer &&
            destination.kind == IrTypeKind::Integer && source.bits == destination.bits;
    case IrCastKind::FloatingExtend:
        return source.kind == IrTypeKind::FloatingPoint &&
            destination.kind == IrTypeKind::FloatingPoint && source.bits < destination.bits;
    case IrCastKind::FloatingTruncate:
        return source.kind == IrTypeKind::FloatingPoint &&
            destination.kind == IrTypeKind::FloatingPoint && source.bits > destination.bits;
    }
    return false;
}

auto validate_signature(const IrFunctionSignature& signature, const IrLimits& limits)
    -> Result<std::size_t, Diagnostic> {
    if (signature.parameterTypes.size() > limits.maxArguments) {
        return failure("ir.argument_limit", "IR signature argument count exceeds the limit");
    }
    for (const auto& type : signature.parameterTypes) {
        const auto checked = validate_type(type);
        if (!checked.has_value() || type.kind == IrTypeKind::Void) {
            return failure("ir.invalid_type", "IR signature parameter type is invalid");
        }
    }
    const auto returnType = validate_type(signature.returnType);
    if (!returnType.has_value()) return returnType;
    if (!signature.parameterBindings.empty() &&
        signature.parameterBindings.size() != signature.parameterTypes.size()) {
        return failure("ir.invalid_abi_binding", "IR ABI parameter bindings are incomplete");
    }
    std::set<std::string> registerBindings;
    std::set<std::int64_t> stackBindings;
    for (std::size_t index = 0; index < signature.parameterBindings.size(); ++index) {
        const auto& binding = signature.parameterBindings[index];
        const bool supportedKind = binding.kind == IrStorageKind::Register ||
            binding.kind == IrStorageKind::Stack || binding.kind == IrStorageKind::Argument;
        if (!supportedKind || binding.type != signature.parameterTypes[index] ||
            binding.size < type_size_bytes(binding.type) ||
            !valid_alignment(binding.alignment, limits)) {
            return failure("ir.invalid_abi_binding", "IR ABI parameter binding is invalid");
        }
        if (binding.kind == IrStorageKind::Register) {
            if (binding.name.empty() || !registerBindings.insert(binding.name).second) {
                return failure("ir.invalid_abi_binding", "IR ABI register binding is invalid");
            }
        } else if (!stackBindings.insert(binding.offset).second) {
            return failure("ir.invalid_abi_binding", "IR ABI stack binding is duplicated");
        }
    }
    if (signature.returnBinding.has_value()) {
        const auto& binding = *signature.returnBinding;
        const bool supportedKind = binding.kind == IrStorageKind::Register ||
            binding.kind == IrStorageKind::Stack;
        if (signature.returnType.kind == IrTypeKind::Void || !supportedKind ||
            binding.type != signature.returnType || binding.size < type_size_bytes(binding.type) ||
            !valid_alignment(binding.alignment, limits) ||
            (binding.kind == IrStorageKind::Register && binding.name.empty())) {
            return failure("ir.invalid_abi_binding", "IR ABI return binding is invalid");
        }
    }
    std::set<std::string> clobbers;
    for (const auto& clobber : signature.clobbers.registers) {
        if (clobber.empty() || !clobbers.insert(clobber).second) {
            return failure("ir.invalid_abi_binding", "IR call clobber list is invalid");
        }
    }
    return Result<std::size_t, Diagnostic>::success(0U);
}

auto operand_type(const IrFunction& function, const IrOperand& operand)
    -> Result<IrType, Diagnostic> {
    if (const auto* variable = std::get_if<IrVariableOperand>(&operand)) {
        if (!variable_valid(function, variable->variable)) {
            return Result<IrType, Diagnostic>::failure(Diagnostic{
                DiagnosticSeverity::Error, "ir.variable_out_of_range",
                "IR call argument variable is out of range"});
        }
        return Result<IrType, Diagnostic>::success(
            function.variableTypes[variable->variable.index]);
    }
    const auto& immediate = std::get<IrImmediateOperand>(operand);
    return Result<IrType, Diagnostic>::success(immediate.type);
}

auto arguments_match_signature(
    const IrFunction& function,
    const std::vector<IrOperand>& arguments,
    const IrFunctionSignature& signature) -> bool {
    if ((!signature.variadic && arguments.size() != signature.parameterTypes.size()) ||
        (signature.variadic && arguments.size() < signature.parameterTypes.size())) {
        return false;
    }
    for (std::size_t index = 0; index < signature.parameterTypes.size(); ++index) {
        const auto actual = operand_type(function, arguments[index]);
        if (!actual.has_value() || actual.value() != signature.parameterTypes[index]) return false;
    }
    return true;
}

auto is_terminator(const IrInstruction& instruction) -> bool {
    return std::holds_alternative<IrJump>(instruction)
        || std::holds_alternative<IrConditionalJump>(instruction)
        || std::holds_alternative<IrSwitch>(instruction)
        || std::holds_alternative<IrIndirectJump>(instruction)
        || std::holds_alternative<IrTailCall>(instruction)
        || std::holds_alternative<IrReturn>(instruction);
}

void add_operand_read(const IrOperand& operand, std::vector<IrVariable>& reads) {
    if (const auto* variable = std::get_if<IrVariableOperand>(&operand)) {
        reads.push_back(variable->variable);
    }
}

void add_value_read(const IrValue& value, std::vector<IrVariable>& reads) {
    if (const auto* variable = std::get_if<IrVariableOperand>(&value)) {
        reads.push_back(variable->variable);
    }
}

void add_address_reads(const IrAddress& address, std::vector<IrVariable>& reads) {
    reads.push_back(address.base);
    if (address.index.has_value()) reads.push_back(*address.index);
}

auto reads_of(const IrInstruction& instruction) -> std::vector<IrVariable> {
    std::vector<IrVariable> reads;
    std::visit([&](const auto& item) {
        using T = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<T, IrMove>) {
            add_operand_read(item.source, reads);
        } else if constexpr (std::is_same_v<T, IrBinaryOperation>) {
            reads.push_back(item.destination);
            add_operand_read(item.source, reads);
        } else if constexpr (std::is_same_v<T, IrUnaryOperation>) {
            reads.push_back(item.destination);
        } else if constexpr (std::is_same_v<T, IrCompare> || std::is_same_v<T, IrTest>) {
            reads.push_back(item.left);
            add_operand_read(item.right, reads);
        } else if constexpr (std::is_same_v<T, IrInternalCall>) {
            for (const auto& argument : item.arguments) add_operand_read(argument, reads);
        } else if constexpr (std::is_same_v<T, IrExternalCall> ||
                             std::is_same_v<T, IrTailCall>) {
            for (const auto& argument : item.arguments) add_operand_read(argument, reads);
        } else if constexpr (std::is_same_v<T, IrSwitch>) {
            reads.push_back(item.selector);
        } else if constexpr (std::is_same_v<T, IrIndirectJump>) {
            reads.push_back(item.target);
        } else if constexpr (std::is_same_v<T, IrReturn>) {
            reads.push_back(item.value);
        } else if constexpr (std::is_same_v<T, IrLoad>) {
            add_address_reads(item.address, reads);
        } else if constexpr (std::is_same_v<T, IrStore>) {
            add_address_reads(item.address, reads);
            add_value_read(item.value, reads);
        } else if constexpr (std::is_same_v<T, IrPointerOffset>) {
            reads.push_back(item.pointer);
            add_value_read(item.offset, reads);
        } else if constexpr (std::is_same_v<T, IrCast>) {
            add_value_read(item.source, reads);
        } else if constexpr (std::is_same_v<T, IrFallback>) {
            reads.insert(reads.end(), item.effects.reads.begin(), item.effects.reads.end());
        }
    }, instruction);
    return reads;
}

auto writes_of(const IrInstruction& instruction) -> std::vector<IrVariable> {
    return std::visit([](const auto& item) -> std::vector<IrVariable> {
        using T = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<T, IrMove>
            || std::is_same_v<T, IrBinaryOperation>
            || std::is_same_v<T, IrUnaryOperation>
            || std::is_same_v<T, IrInternalCall>
            || std::is_same_v<T, IrLoad>
            || std::is_same_v<T, IrAddressOf>
            || std::is_same_v<T, IrPointerOffset>
            || std::is_same_v<T, IrCast>) {
            return {item.destination};
        } else if constexpr (std::is_same_v<T, IrExternalCall>) {
            return item.destination.has_value() ? std::vector<IrVariable>{*item.destination}
                                                : std::vector<IrVariable>{};
        } else if constexpr (std::is_same_v<T, IrFallback>) {
            return item.effects.writes;
        }
        return {};
    }, instruction);
}

auto defines_flags(const IrInstruction& instruction) -> bool {
    return std::holds_alternative<IrBinaryOperation>(instruction)
        || std::holds_alternative<IrUnaryOperation>(instruction)
        || std::holds_alternative<IrCompare>(instruction)
        || std::holds_alternative<IrTest>(instruction);
}

} // namespace

auto ir_width_bits(IrWidth width) noexcept -> std::uint32_t {
    switch (width) {
    case IrWidth::U8: return 8;
    case IrWidth::U16: return 16;
    case IrWidth::U32: return 32;
    case IrWidth::U64: return 64;
    }
    return 0;
}

auto integer_type(IrWidth width) noexcept -> IrType {
    return IrType{
        IrTypeKind::Integer,
        static_cast<std::uint16_t>(ir_width_bits(width)),
        1U,
        0U,
        IrByteOrder::Little,
    };
}

auto validate_type(const IrType& type) -> Result<std::size_t, Diagnostic> {
    const auto validScalarWidth = type.bits == 8U || type.bits == 16U ||
        type.bits == 32U || type.bits == 64U;
    bool valid = false;
    switch (type.kind) {
    case IrTypeKind::Void:
        valid = type.bits == 0U && type.lanes == 1U && type.addressSpace == 0U;
        break;
    case IrTypeKind::Integer:
        valid = validScalarWidth && type.lanes == 1U && type.addressSpace == 0U;
        break;
    case IrTypeKind::Pointer:
        valid = (type.bits == 32U || type.bits == 64U) && type.lanes == 1U &&
            type.addressSpace <= 255U;
        break;
    case IrTypeKind::FloatingPoint:
        valid = (type.bits == 32U || type.bits == 64U) && type.lanes == 1U &&
            type.addressSpace == 0U;
        break;
    case IrTypeKind::Vector:
        valid = validScalarWidth &&
            (type.lanes == 2U || type.lanes == 4U || type.lanes == 8U ||
             type.lanes == 16U) &&
            type.addressSpace == 0U;
        break;
    }
    if (!valid) {
        return failure("ir.invalid_type", "IR type shape is invalid");
    }
    return Result<std::size_t, Diagnostic>::success(0U);
}

auto integer_width(const IrType& type) -> Result<IrWidth, Diagnostic> {
    const auto checked = validate_type(type);
    if (!checked.has_value() || type.kind != IrTypeKind::Integer) {
        return Result<IrWidth, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "ir.invalid_type",
            "IR type is not a supported scalar integer",
        });
    }
    switch (type.bits) {
    case 8U: return Result<IrWidth, Diagnostic>::success(IrWidth::U8);
    case 16U: return Result<IrWidth, Diagnostic>::success(IrWidth::U16);
    case 32U: return Result<IrWidth, Diagnostic>::success(IrWidth::U32);
    case 64U: return Result<IrWidth, Diagnostic>::success(IrWidth::U64);
    default:
        return Result<IrWidth, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "ir.invalid_type",
            "IR integer width is unsupported",
        });
    }
}

auto function_contains_fallback(const IrFunction& function) noexcept -> bool {
    for (const auto& block : function.blocks) {
        for (const auto& instruction : block.instructions) {
            if (std::holds_alternative<IrFallback>(instruction)) return true;
        }
    }
    return false;
}

auto fallback_blocks_rewrite(
    const IrFunction& function,
    const std::vector<IrBlockId>& blocks) noexcept -> bool {
    for (const auto blockId : blocks) {
        const auto block = std::find_if(
            function.blocks.begin(), function.blocks.end(),
            [blockId](const IrBlock& candidate) { return candidate.id == blockId; });
        if (block == function.blocks.end()) continue;
        if (std::any_of(
                block->instructions.begin(), block->instructions.end(),
                [](const IrInstruction& instruction) {
                    return std::holds_alternative<IrFallback>(instruction);
                })) {
            return true;
        }
    }
    return false;
}

auto validate_function(const IrFunction& function, const IrLimits& limits)
    -> Result<std::size_t, Diagnostic> {
    if (!function.sourceFunction.valid()) {
        return failure("ir.invalid_source_function", "IR source function ID is invalid");
    }
    if (function.blocks.size() > limits.maxBlocks) {
        return failure("ir.block_limit", "IR block count exceeds the configured limit");
    }
    if (function.variableTypes.size() > limits.maxVariables) {
        return failure("ir.variable_limit", "IR variable count exceeds the configured limit");
    }
    if (function.arguments.size() > limits.maxArguments) {
        return failure("ir.argument_limit", "IR argument count exceeds the configured limit");
    }
    const auto returnType = validate_type(function.returnType);
    if (!returnType.has_value()) return returnType;
    const auto signature = validate_signature(function.signature, limits);
    if (!signature.has_value()) return signature;
    if (function.signature.returnType != function.returnType ||
        function.signature.parameterTypes.size() != function.arguments.size()) {
        return failure(
            "ir.function_signature_mismatch",
            "IR function signature does not match its arguments and return type");
    }
    for (const auto& type : function.variableTypes) {
        const auto checked = validate_type(type);
        if (!checked.has_value() || type.kind == IrTypeKind::Void) {
            return failure("ir.invalid_type", "IR variable type is invalid");
        }
    }
    if (function.storageLocations.size() > limits.maxStorageLocations) {
        return failure(
            "ir.storage_limit", "IR storage-location count exceeds the configured limit");
    }
    std::uint64_t aggregateStorageBytes = 0U;
    for (const auto& storage : function.storageLocations) {
        const auto checked = validate_type(storage.type);
        if (!checked.has_value() || storage.type.kind == IrTypeKind::Void ||
            storage.size < type_size_bytes(storage.type)) {
            return failure("ir.invalid_type", "IR storage type or size is invalid");
        }
        if (!valid_alignment(storage.alignment, limits)) {
            return failure("ir.invalid_alignment", "IR storage alignment is invalid");
        }
        if (storage.size > limits.maxAggregateStorageBytes - std::min(
                aggregateStorageBytes, limits.maxAggregateStorageBytes)) {
            return failure(
                "ir.storage_limit", "IR aggregate storage exceeds the configured byte limit");
        }
        aggregateStorageBytes += storage.size;
    }

    std::set<std::uint16_t> argumentIndices;
    std::set<std::uint16_t> argumentVariables;
    for (const auto& argument : function.arguments) {
        if (!argumentIndices.insert(argument.argumentIndex).second) {
            return failure("ir.duplicate_argument", "IR argument index is duplicated");
        }
        if (!variable_valid(function, argument.destination)) {
            return failure("ir.variable_out_of_range", "IR argument variable is out of range");
        }
        if (!argumentVariables.insert(argument.destination.index).second) {
            return failure("ir.duplicate_argument_variable", "IR argument variable is duplicated");
        }
        if (function.variableTypes[argument.destination.index] != argument.type) {
            return failure("ir.type_mismatch", "IR argument type does not match its variable");
        }
    }
    for (std::size_t index = 0; index < function.arguments.size(); ++index) {
        if (!argumentIndices.contains(static_cast<std::uint16_t>(index))) {
            return failure("ir.noncontiguous_arguments", "IR argument indices must be contiguous");
        }
    }
    for (const auto& argument : function.arguments) {
        if (function.signature.parameterTypes[argument.argumentIndex] != argument.type) {
            return failure(
                "ir.function_signature_mismatch",
                "IR function signature parameter type does not match its argument");
        }
    }

    std::map<std::uint32_t, std::size_t> blockIndices;
    std::size_t instructionCount = 0;
    for (std::size_t index = 0; index < function.blocks.size(); ++index) {
        const auto& block = function.blocks[index];
        if (!blockIndices.emplace(block.id.value, index).second) {
            return failure("ir.duplicate_block", "IR block ID is duplicated");
        }
        if (!block.sourceBlock.valid()) {
            return failure("ir.invalid_source_block", "IR source block ID is invalid");
        }
        if (block.instructions.size() > limits.maxInstructions - std::min(
                instructionCount, limits.maxInstructions)) {
            return failure("ir.instruction_limit", "IR instruction count exceeds the configured limit");
        }
        instructionCount += block.instructions.size();
    }
    if (!blockIndices.contains(function.entry.value)) {
        return failure("ir.entry_block_missing", "IR entry block does not exist");
    }

    if (function.unwindRegions.size() > limits.maxUnwindRegions) {
        return failure("ir.unwind_region_limit", "IR unwind-region count exceeds the limit");
    }
    std::map<std::uint32_t, const IrUnwindRegion*> unwindRegions;
    std::map<std::uint32_t, std::uint32_t> protectedOwners;
    std::size_t unwindActionCount = 0U;
    for (const auto& region : function.unwindRegions) {
        if (region.id == 0U || !unwindRegions.emplace(region.id, &region).second ||
            !blockIndices.contains(region.landingBlock.value)) {
            return failure("ir.invalid_unwind", "IR unwind region or landing block is invalid");
        }
        if (region.actions.size() > limits.maxUnwindActions - std::min(
                unwindActionCount, limits.maxUnwindActions)) {
            return failure("ir.unwind_action_limit", "IR unwind-action count exceeds the limit");
        }
        unwindActionCount += region.actions.size();
        for (const auto block : region.protectedBlocks) {
            if (!blockIndices.contains(block.value) ||
                !protectedOwners.emplace(block.value, region.id).second) {
                return failure("ir.invalid_unwind", "IR unwind protected-block ownership is invalid");
            }
        }
    }
    for (const auto& [id, region] : unwindRegions) {
        if (region->parent.has_value() && !unwindRegions.contains(*region->parent)) {
            return failure("ir.invalid_unwind", "IR unwind parent does not exist");
        }
        std::set<std::uint32_t> ancestors{id};
        auto parent = region->parent;
        while (parent.has_value()) {
            if (!ancestors.insert(*parent).second) {
                return failure("ir.invalid_unwind", "IR unwind parent graph contains a cycle");
            }
            parent = unwindRegions.at(*parent)->parent;
        }
    }

    std::vector<std::optional<std::size_t>> storageProvenance(
        function.variableTypes.size());
    for (std::size_t iteration = 0U;
         iteration <= function.variableTypes.size(); ++iteration) {
        bool changedProvenance = false;
        for (const auto& block : function.blocks) {
            for (const auto& instruction : block.instructions) {
                if (const auto* addressOf = std::get_if<IrAddressOf>(&instruction)) {
                    if (variable_valid(function, addressOf->destination) &&
                        addressOf->storageIndex < function.storageLocations.size() &&
                        storageProvenance[addressOf->destination.index] !=
                            addressOf->storageIndex) {
                        storageProvenance[addressOf->destination.index] =
                            addressOf->storageIndex;
                        changedProvenance = true;
                    }
                } else if (const auto* offset = std::get_if<IrPointerOffset>(&instruction)) {
                    if (variable_valid(function, offset->destination) &&
                        variable_valid(function, offset->pointer) &&
                        storageProvenance[offset->destination.index] !=
                            storageProvenance[offset->pointer.index]) {
                        storageProvenance[offset->destination.index] =
                            storageProvenance[offset->pointer.index];
                        changedProvenance = true;
                    }
                } else if (const auto* cast = std::get_if<IrCast>(&instruction)) {
                    const auto* source = std::get_if<IrVariableOperand>(&cast->source);
                    if (cast->kind == IrCastKind::Bitcast && source != nullptr &&
                        variable_valid(function, cast->destination) &&
                        variable_valid(function, source->variable) &&
                        storageProvenance[cast->destination.index] !=
                            storageProvenance[source->variable.index]) {
                        storageProvenance[cast->destination.index] =
                            storageProvenance[source->variable.index];
                        changedProvenance = true;
                    }
                }
            }
        }
        if (!changedProvenance) break;
    }

    std::vector<std::vector<std::size_t>> predecessors(function.blocks.size());
    std::size_t memoryOperationCount = 0U;
    std::size_t callCount = 0U;
    for (std::size_t blockIndex = 0; blockIndex < function.blocks.size(); ++blockIndex) {
        const auto& block = function.blocks[blockIndex];
        if (block.instructions.empty() || !is_terminator(block.instructions.back())) {
            return failure("ir.block_unterminated", "IR block has no control-flow terminator");
        }
        for (std::size_t index = 0; index + 1 < block.instructions.size(); ++index) {
            if (is_terminator(block.instructions[index])) {
                return failure("ir.instruction_after_terminator", "IR block contains an early terminator");
            }
        }
        auto add_target = [&](IrBlockId target) -> bool {
            const auto found = blockIndices.find(target.value);
            if (found == blockIndices.end()) return false;
            predecessors[found->second].push_back(blockIndex);
            return true;
        };
        if (const auto* jump = std::get_if<IrJump>(&block.instructions.back())) {
            if (!add_target(jump->target)) {
                return failure("ir.branch_target_missing", "IR branch target does not exist");
            }
        } else if (const auto* branch = std::get_if<IrConditionalJump>(&block.instructions.back())) {
            if (!add_target(branch->trueTarget) || !add_target(branch->falseTarget)) {
                return failure("ir.branch_target_missing", "IR conditional target does not exist");
            }
        } else if (const auto* switchBranch = std::get_if<IrSwitch>(
                       &block.instructions.back())) {
            if (switchBranch->cases.size() > limits.maxSwitchCases) {
                return failure("ir.switch_case_limit", "IR switch case count exceeds the limit");
            }
            if (!add_target(switchBranch->defaultTarget)) {
                return failure("ir.branch_target_missing", "IR switch default target does not exist");
            }
            std::optional<std::uint64_t> previous;
            for (const auto& item : switchBranch->cases) {
                if ((previous.has_value() && item.value <= *previous)) {
                    return failure("ir.invalid_switch", "IR switch values must be unique and sorted");
                }
                previous = item.value;
                if (!add_target(item.target)) {
                    return failure("ir.branch_target_missing", "IR switch target does not exist");
                }
            }
        } else if (const auto* indirect = std::get_if<IrIndirectJump>(
                       &block.instructions.back())) {
            if (indirect->targets.empty()) {
                return failure("ir.invalid_indirect_jump", "IR indirect jump needs proven targets");
            }
            if (indirect->targets.size() > limits.maxIndirectTargets) {
                return failure(
                    "ir.indirect_target_limit", "IR indirect target count exceeds the limit");
            }
            std::optional<std::uint32_t> previous;
            for (const auto target : indirect->targets) {
                if (previous.has_value() && target.value <= *previous) {
                    return failure(
                        "ir.invalid_indirect_jump",
                        "IR indirect targets must be unique and sorted");
                }
                previous = target.value;
                if (!add_target(target)) {
                    return failure("ir.branch_target_missing", "IR indirect target does not exist");
                }
            }
        }

        for (const auto& instruction : block.instructions) {
            auto checked = std::visit([&](const auto& item) -> Result<std::size_t, Diagnostic> {
                using T = std::decay_t<decltype(item)>;
                if constexpr (std::is_same_v<T, IrMove>
                    || std::is_same_v<T, IrBinaryOperation>) {
                    if (!validate_type(item.type).has_value()) {
                        return failure("ir.invalid_type", "IR instruction type is invalid");
                    }
                    if (!variable_valid(function, item.destination)) {
                        return failure("ir.variable_out_of_range", "IR destination variable is out of range");
                    }
                    if (function.variableTypes[item.destination.index] != item.type) {
                        return failure("ir.type_mismatch", "IR destination type does not match");
                    }
                    return operand_valid(function, item.source, item.type);
                } else if constexpr (std::is_same_v<T, IrUnaryOperation>) {
                    if (!validate_type(item.type).has_value()) {
                        return failure("ir.invalid_type", "IR instruction type is invalid");
                    }
                    if (!variable_valid(function, item.destination)) {
                        return failure("ir.variable_out_of_range", "IR destination variable is out of range");
                    }
                    if (function.variableTypes[item.destination.index] != item.type) {
                        return failure("ir.type_mismatch", "IR destination type does not match");
                    }
                } else if constexpr (std::is_same_v<T, IrCompare>
                    || std::is_same_v<T, IrTest>) {
                    if (!validate_type(item.type).has_value()) {
                        return failure("ir.invalid_type", "IR instruction type is invalid");
                    }
                    if (!variable_valid(function, item.left)) {
                        return failure("ir.variable_out_of_range", "IR comparison variable is out of range");
                    }
                    if (function.variableTypes[item.left.index] != item.type) {
                        return failure("ir.type_mismatch", "IR comparison type does not match");
                    }
                    return operand_valid(function, item.right, item.type);
                } else if constexpr (std::is_same_v<T, IrReturn>) {
                    if (!variable_valid(function, item.value)) {
                        return failure("ir.variable_out_of_range", "IR return variable is out of range");
                    }
                    if (item.type != function.returnType
                        || function.variableTypes[item.value.index] != item.type) {
                        return failure("ir.type_mismatch", "IR return type does not match");
                    }
                } else if constexpr (std::is_same_v<T, IrInternalCall>) {
                    ++callCount;
                    if (callCount > limits.maxCalls) {
                        return failure("ir.call_limit", "IR call count exceeds the limit");
                    }
                    if (!item.targetFunction.valid()) {
                        return failure(
                            "ir.invalid_internal_call_target",
                            "IR internal call target ID is invalid");
                    }
                    if (!variable_valid(function, item.destination)) {
                        return failure(
                            "ir.variable_out_of_range",
                            "IR internal-call destination is out of range");
                    }
                    if (function.variableTypes[item.destination.index] != item.resultType) {
                        return failure(
                            "ir.type_mismatch",
                            "IR internal-call result type does not match its destination");
                    }
                    if (item.arguments.size() > limits.maxArguments) {
                        return failure(
                            "ir.argument_limit",
                            "IR internal-call argument count exceeds the limit");
                    }
                    for (const auto& argument : item.arguments) {
                        if (const auto* variable = std::get_if<IrVariableOperand>(&argument)) {
                            if (!variable_valid(function, variable->variable)) {
                                return failure(
                                    "ir.variable_out_of_range",
                                    "IR internal-call argument is out of range");
                            }
                        }
                    }
                    if (item.unwindRegion.has_value() &&
                        !unwindRegions.contains(*item.unwindRegion)) {
                        return failure("ir.invalid_unwind", "IR call unwind region does not exist");
                    }
                } else if constexpr (std::is_same_v<T, IrExternalCall>) {
                    ++callCount;
                    if (callCount > limits.maxCalls) {
                        return failure("ir.call_limit", "IR call count exceeds the limit");
                    }
                    const auto checkedSignature = validate_signature(item.signature, limits);
                    if (!checkedSignature.has_value()) return checkedSignature;
                    if (item.symbol.empty() ||
                        !arguments_match_signature(function, item.arguments, item.signature)) {
                        return failure(
                            "ir.external_call_signature_mismatch",
                            "IR external call shape does not match its signature");
                    }
                    if (item.signature.returnType.kind == IrTypeKind::Void) {
                        if (item.destination.has_value()) {
                            return failure(
                                "ir.external_call_signature_mismatch",
                                "void external call cannot have a result destination");
                        }
                    } else if (!item.destination.has_value() ||
                               !variable_valid(function, *item.destination) ||
                               function.variableTypes[item.destination->index] !=
                                   item.signature.returnType) {
                        return failure(
                            "ir.external_call_signature_mismatch",
                            "IR external-call result does not match its signature");
                    }
                    if (item.unwindRegion.has_value() &&
                        !unwindRegions.contains(*item.unwindRegion)) {
                        return failure("ir.invalid_unwind", "IR call unwind region does not exist");
                    }
                } else if constexpr (std::is_same_v<T, IrTailCall>) {
                    ++callCount;
                    if (callCount > limits.maxCalls) {
                        return failure("ir.call_limit", "IR call count exceeds the limit");
                    }
                    const auto checkedSignature = validate_signature(item.signature, limits);
                    if (!checkedSignature.has_value()) return checkedSignature;
                    if (!arguments_match_signature(function, item.arguments, item.signature) ||
                        item.signature.callingConvention !=
                            function.signature.callingConvention ||
                        item.signature.returnType != function.signature.returnType) {
                        return failure("ir.illegal_tail_call", "IR tail call is not ABI compatible");
                    }
                    if (const auto* internal = std::get_if<EntityId>(&item.target);
                        internal != nullptr && !internal->valid()) {
                        return failure("ir.illegal_tail_call", "IR tail-call target is invalid");
                    }
                    if (const auto* external = std::get_if<std::string>(&item.target);
                        external != nullptr && external->empty()) {
                        return failure("ir.illegal_tail_call", "IR tail-call target is empty");
                    }
                    if (item.unwindRegion.has_value() &&
                        !unwindRegions.contains(*item.unwindRegion)) {
                        return failure("ir.invalid_unwind", "IR tail-call unwind region does not exist");
                    }
                } else if constexpr (std::is_same_v<T, IrSwitch>) {
                    if (!variable_valid(function, item.selector) ||
                        function.variableTypes[item.selector.index].kind != IrTypeKind::Integer) {
                        return failure("ir.invalid_switch", "IR switch selector is not an integer");
                    }
                } else if constexpr (std::is_same_v<T, IrIndirectJump>) {
                    if (!variable_valid(function, item.target)) {
                        return failure(
                            "ir.invalid_indirect_jump", "IR indirect-jump variable is invalid");
                    }
                } else if constexpr (std::is_same_v<T, IrAddressOf>) {
                    if (!variable_valid(function, item.destination) ||
                        item.storageIndex >= function.storageLocations.size() ||
                        function.variableTypes[item.destination.index].kind !=
                            IrTypeKind::Pointer) {
                        return failure(
                            "ir.invalid_address", "IR address-of operation is invalid");
                    }
                } else if constexpr (std::is_same_v<T, IrLoad>) {
                    ++memoryOperationCount;
                    if (memoryOperationCount > limits.maxMemoryOperations) {
                        return failure(
                            "ir.memory_operation_limit",
                            "IR memory-operation count exceeds the configured limit");
                    }
                    if (!variable_valid(function, item.destination) ||
                        function.variableTypes[item.destination.index] != item.type ||
                        item.byteOrder != item.type.byteOrder) {
                        return failure("ir.type_mismatch", "IR load type does not match");
                    }
                    const auto address = validate_address(function, item.address, limits);
                    if (!address.has_value()) return address;
                    if (item.atomicOrdering == IrAtomicOrdering::Release ||
                        item.atomicOrdering == IrAtomicOrdering::AcquireRelease) {
                        return failure("ir.invalid_atomic", "IR load atomic ordering is invalid");
                    }
                    if (item.unwindRegion.has_value() &&
                        !unwindRegions.contains(*item.unwindRegion)) {
                        return failure("ir.invalid_unwind", "IR load unwind region does not exist");
                    }
                } else if constexpr (std::is_same_v<T, IrStore>) {
                    ++memoryOperationCount;
                    if (memoryOperationCount > limits.maxMemoryOperations) {
                        return failure(
                            "ir.memory_operation_limit",
                            "IR memory-operation count exceeds the configured limit");
                    }
                    const auto address = validate_address(function, item.address, limits);
                    if (!address.has_value()) return address;
                    const auto storedType = value_type(function, item.value);
                    if (!storedType.has_value() || storedType.value() != item.type ||
                        item.byteOrder != item.type.byteOrder) {
                        return failure("ir.type_mismatch", "IR store value type does not match");
                    }
                    if (item.atomicOrdering == IrAtomicOrdering::Acquire ||
                        item.atomicOrdering == IrAtomicOrdering::AcquireRelease) {
                        return failure("ir.invalid_atomic", "IR store atomic ordering is invalid");
                    }
                    const auto provenance = storageProvenance[item.address.base.index];
                    if (provenance.has_value() &&
                        function.storageLocations[*provenance].readonly) {
                        return failure("ir.readonly_store", "IR store targets readonly storage");
                    }
                    if (item.unwindRegion.has_value() &&
                        !unwindRegions.contains(*item.unwindRegion)) {
                        return failure("ir.invalid_unwind", "IR store unwind region does not exist");
                    }
                } else if constexpr (std::is_same_v<T, IrPointerOffset>) {
                    if (!variable_valid(function, item.destination) ||
                        !variable_valid(function, item.pointer)) {
                        return failure("ir.invalid_address", "IR pointer offset is out of range");
                    }
                    const auto& destination = function.variableTypes[item.destination.index];
                    const auto& pointer = function.variableTypes[item.pointer.index];
                    const auto offsetType = value_type(function, item.offset);
                    if (destination.kind != IrTypeKind::Pointer || destination != pointer ||
                        !offsetType.has_value() ||
                        offsetType.value().kind != IrTypeKind::Integer) {
                        return failure("ir.invalid_address", "IR pointer offset types are invalid");
                    }
                } else if constexpr (std::is_same_v<T, IrCast>) {
                    if (!variable_valid(function, item.destination)) {
                        return failure(
                            "ir.variable_out_of_range", "IR cast destination is out of range");
                    }
                    const auto sourceType = value_type(function, item.source);
                    if (!sourceType.has_value()) return Result<std::size_t, Diagnostic>::failure(
                        sourceType.error());
                    if (sourceType.value() != item.sourceType ||
                        function.variableTypes[item.destination.index] !=
                            item.destinationType ||
                        !valid_cast(item.kind, item.sourceType, item.destinationType)) {
                        return failure("ir.invalid_cast", "IR cast types are invalid");
                    }
                } else if constexpr (std::is_same_v<T, IrFallback>) {
                    if (item.encoding.size() > limits.maxFallbackBytes) {
                        return failure("ir.fallback_size_limit", "IR fallback encoding exceeds the limit");
                    }
                    if (item.reason.empty()) {
                        return failure("ir.fallback_reason_missing", "IR fallback requires a reason");
                    }
                    if (!item.effects.complete) {
                        return failure(
                            "ir.incomplete_fallback_effects",
                            "IR fallback requires complete effect declarations");
                    }
                    for (const auto variable : item.effects.reads) {
                        if (!variable_valid(function, variable)) {
                            return failure(
                                "ir.variable_out_of_range",
                                "IR fallback read variable is out of range");
                        }
                    }
                    for (const auto variable : item.effects.writes) {
                        if (!variable_valid(function, variable)) {
                            return failure(
                                "ir.variable_out_of_range",
                                "IR fallback write variable is out of range");
                        }
                    }
                    std::set<std::string> clobbers;
                    for (const auto& clobber : item.effects.clobberedRegisters) {
                        if (clobber.empty() || !clobbers.insert(clobber).second) {
                            return failure(
                                "ir.incomplete_fallback_effects",
                                "IR fallback clobber declarations are invalid");
                        }
                    }
                    if (item.unwindRegion.has_value() &&
                        !unwindRegions.contains(*item.unwindRegion)) {
                        return failure(
                            "ir.invalid_unwind", "IR fallback unwind region does not exist");
                    }
                }
                return Result<std::size_t, Diagnostic>::success(0);
            }, instruction);
            if (!checked.has_value()) return checked;
        }
    }

    const auto variableCount = function.variableTypes.size();
    std::vector<std::vector<bool>> in(function.blocks.size(), std::vector<bool>(variableCount, true));
    std::vector<std::vector<bool>> out = in;
    std::vector<bool> flagsIn(function.blocks.size(), true);
    std::vector<bool> flagsOut(function.blocks.size(), true);
    const auto entryIndex = blockIndices.at(function.entry.value);
    std::fill(in[entryIndex].begin(), in[entryIndex].end(), false);
    flagsIn[entryIndex] = false;
    for (const auto& argument : function.arguments) in[entryIndex][argument.destination.index] = true;
    bool changed = true;
    for (std::size_t iteration = 0; changed && iteration <= function.blocks.size(); ++iteration) {
        changed = false;
        for (std::size_t index = 0; index < function.blocks.size(); ++index) {
            if (index != entryIndex) {
                std::vector<bool> next(variableCount, false);
                bool nextFlags = false;
                if (!predecessors[index].empty()) {
                    next.assign(variableCount, true);
                    nextFlags = true;
                    for (const auto predecessor : predecessors[index]) {
                        for (std::size_t variable = 0; variable < variableCount; ++variable) {
                            next[variable] = next[variable] && out[predecessor][variable];
                        }
                        nextFlags = nextFlags && flagsOut[predecessor];
                    }
                }
                if (next != in[index]) {
                    in[index] = std::move(next);
                    changed = true;
                }
                if (nextFlags != flagsIn[index]) {
                    flagsIn[index] = nextFlags;
                    changed = true;
                }
            }
            auto nextOut = in[index];
            auto nextFlagsOut = flagsIn[index];
            for (const auto& instruction : function.blocks[index].instructions) {
                for (const auto written : writes_of(instruction)) nextOut[written.index] = true;
                if (defines_flags(instruction)) nextFlagsOut = true;
                else if (std::holds_alternative<IrFallback>(instruction)) nextFlagsOut = false;
            }
            if (nextOut != out[index]) {
                out[index] = std::move(nextOut);
                changed = true;
            }
            if (nextFlagsOut != flagsOut[index]) {
                flagsOut[index] = nextFlagsOut;
                changed = true;
            }
        }
    }
    for (std::size_t index = 0; index < function.blocks.size(); ++index) {
        auto defined = in[index];
        auto flagsDefined = flagsIn[index];
        for (const auto& instruction : function.blocks[index].instructions) {
            for (const auto variable : reads_of(instruction)) {
                if (!defined[variable.index]) {
                    return failure("ir.use_before_definition", "IR variable is used before definition");
                }
            }
            if (std::holds_alternative<IrConditionalJump>(instruction) && !flagsDefined) {
                return failure(
                    "ir.flags_undefined",
                    "IR conditional branch uses flags before an explicit definition");
            }
            for (const auto written : writes_of(instruction)) defined[written.index] = true;
            if (defines_flags(instruction)) flagsDefined = true;
            else if (std::holds_alternative<IrFallback>(instruction)) flagsDefined = false;
        }
    }
    return Result<std::size_t, Diagnostic>::success(instructionCount);
}

auto validate_module(const IrModule& module, const IrLimits& limits)
    -> Result<std::size_t, Diagnostic> {
    if (module.functions.size() > limits.maxFunctions) {
        return failure("ir.function_limit", "IR module function count exceeds the limit");
    }
    if (module.declarations.size() > limits.maxExternalDeclarations) {
        return failure(
            "ir.external_declaration_limit",
            "IR external declaration count exceeds the limit");
    }
    std::map<std::string, const IrExternalDeclaration*> declarations;
    for (const auto& declaration : module.declarations) {
        const auto signature = validate_signature(declaration.signature, limits);
        if (!signature.has_value()) return signature;
        if (declaration.symbol.empty() ||
            !declarations.emplace(declaration.symbol, &declaration).second) {
            return failure(
                "ir.invalid_external_declaration",
                "IR external declaration symbol is empty or duplicated");
        }
    }
    std::map<std::uint64_t, std::size_t> functionIndices;
    std::size_t instructionCount = 0;
    for (std::size_t index = 0; index < module.functions.size(); ++index) {
        const auto& function = module.functions[index];
        if (!functionIndices.emplace(function.sourceFunction.value(), index).second) {
            return failure("ir.duplicate_function", "IR module function ID is duplicated");
        }
        const auto validated = validate_function(function, limits);
        if (!validated.has_value()) return validated;
        if (validated.value() > limits.maxInstructions
            - std::min(instructionCount, limits.maxInstructions)) {
            return failure(
                "ir.instruction_limit", "IR module instruction count exceeds the limit");
        }
        instructionCount += validated.value();
    }
    if (!functionIndices.contains(module.entryFunction.value())) {
        return failure("ir.module_entry_missing", "IR module entry function does not exist");
    }

    std::vector<std::vector<std::size_t>> edges(module.functions.size());
    for (std::size_t functionIndex = 0; functionIndex < module.functions.size();
         ++functionIndex) {
        const auto& function = module.functions[functionIndex];
        for (const auto& block : function.blocks) {
            for (const auto& instruction : block.instructions) {
                const auto* call = std::get_if<IrInternalCall>(&instruction);
                if (call != nullptr) {
                    const auto targetIndex = functionIndices.find(call->targetFunction.value());
                    if (targetIndex == functionIndices.end()) {
                        return failure(
                            "ir.internal_call_target_missing",
                            "IR internal call target does not exist in the module");
                    }
                    const auto& target = module.functions[targetIndex->second];
                    if (call->resultType != target.signature.returnType ||
                        !arguments_match_signature(function, call->arguments, target.signature)) {
                        return failure(
                            "ir.internal_call_signature_mismatch",
                            "IR internal call does not match the target signature");
                    }
                    edges[functionIndex].push_back(targetIndex->second);
                    continue;
                }
                if (const auto* external = std::get_if<IrExternalCall>(&instruction)) {
                    const auto declaration = declarations.find(external->symbol);
                    if (declaration == declarations.end()) {
                        return failure(
                            "ir.external_declaration_missing",
                            "IR external call has no declaration");
                    }
                    if (external->signature != declaration->second->signature ||
                        !arguments_match_signature(
                            function, external->arguments, external->signature)) {
                        return failure(
                            "ir.external_call_signature_mismatch",
                            "IR external call does not match its declaration");
                    }
                    continue;
                }
                if (const auto* tail = std::get_if<IrTailCall>(&instruction)) {
                    bool targetMatches = false;
                    if (const auto* internal = std::get_if<EntityId>(&tail->target)) {
                        const auto targetIndex = functionIndices.find(internal->value());
                        targetMatches = targetIndex != functionIndices.end() &&
                            tail->signature == module.functions[targetIndex->second].signature;
                    } else {
                        const auto& symbol = std::get<std::string>(tail->target);
                        const auto declaration = declarations.find(symbol);
                        targetMatches = declaration != declarations.end() &&
                            tail->signature == declaration->second->signature;
                    }
                    if (!targetMatches ||
                        tail->signature.callingConvention !=
                            function.signature.callingConvention ||
                        tail->signature.returnType != function.signature.returnType ||
                        !arguments_match_signature(function, tail->arguments, tail->signature)) {
                        return failure("ir.illegal_tail_call", "IR tail call is not ABI compatible");
                    }
                }
            }
        }
    }

    std::vector<std::uint8_t> colors(module.functions.size(), 0);
    std::vector<std::size_t> depths(module.functions.size(), 0);
    std::function<Result<std::size_t, Diagnostic>(std::size_t)> visit;
    visit = [&](std::size_t index) -> Result<std::size_t, Diagnostic> {
        if (colors[index] == 1) {
            return failure("ir.recursive_internal_call", "recursive IR internal calls are unsupported");
        }
        if (colors[index] == 2) {
            return Result<std::size_t, Diagnostic>::success(depths[index]);
        }
        colors[index] = 1;
        std::size_t maximumChildDepth = 0;
        for (const auto target : edges[index]) {
            const auto depth = visit(target);
            if (!depth.has_value()) return depth;
            maximumChildDepth = std::max(maximumChildDepth, depth.value());
        }
        colors[index] = 2;
        const auto depth = maximumChildDepth + 1U;
        if (depth > limits.maxCallDepth) {
            return failure("ir.call_depth_limit", "IR internal-call depth exceeds the limit");
        }
        depths[index] = depth;
        return Result<std::size_t, Diagnostic>::success(depth);
    };
    for (std::size_t index = 0; index < module.functions.size(); ++index) {
        const auto acyclic = visit(index);
        if (!acyclic.has_value()) return acyclic;
    }
    return Result<std::size_t, Diagnostic>::success(instructionCount);
}

} // namespace binobf::ir

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

auto is_terminator(const IrInstruction& instruction) -> bool {
    return std::holds_alternative<IrJump>(instruction)
        || std::holds_alternative<IrConditionalJump>(instruction)
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
        }
    }, instruction);
    return reads;
}

auto write_of(const IrInstruction& instruction) -> std::optional<IrVariable> {
    return std::visit([](const auto& item) -> std::optional<IrVariable> {
        using T = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<T, IrMove>
            || std::is_same_v<T, IrBinaryOperation>
            || std::is_same_v<T, IrUnaryOperation>
            || std::is_same_v<T, IrInternalCall>
            || std::is_same_v<T, IrLoad>
            || std::is_same_v<T, IrAddressOf>
            || std::is_same_v<T, IrPointerOffset>
            || std::is_same_v<T, IrCast>) {
            return item.destination;
        }
        return std::nullopt;
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
                if (const auto written = write_of(instruction); written.has_value()) {
                    nextOut[written->index] = true;
                }
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
            if (const auto written = write_of(instruction); written.has_value()) {
                defined[written->index] = true;
            }
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
                if (call == nullptr) continue;
                const auto targetIndex = functionIndices.find(call->targetFunction.value());
                if (targetIndex == functionIndices.end()) {
                    return failure(
                        "ir.internal_call_target_missing",
                        "IR internal call target does not exist in the module");
                }
                const auto& target = module.functions[targetIndex->second];
                if (call->arguments.size() != target.arguments.size()
                    || call->resultType != target.returnType) {
                    return failure(
                        "ir.internal_call_signature_mismatch",
                        "IR internal call does not match the target signature");
                }
                std::vector<IrType> targetTypes(target.arguments.size());
                for (const auto& argument : target.arguments) {
                    targetTypes[argument.argumentIndex] = argument.type;
                }
                for (std::size_t index = 0; index < call->arguments.size(); ++index) {
                    IrType actualType{IrWidth::U32};
                    if (const auto* variable = std::get_if<IrVariableOperand>(
                            &call->arguments[index])) {
                        actualType = function.variableTypes[variable->variable.index];
                    } else {
                        actualType = std::get<IrImmediateOperand>(
                            call->arguments[index]).type;
                    }
                    if (actualType != targetTypes[index]) {
                        return failure(
                            "ir.internal_call_signature_mismatch",
                            "IR internal-call argument type does not match the target");
                    }
                }
                edges[functionIndex].push_back(targetIndex->second);
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

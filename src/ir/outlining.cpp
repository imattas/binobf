#include <binobf/ir/outlining.hpp>

#include <binobf/support/deterministic_rng.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace binobf::ir {
namespace {

auto failure(std::string code, std::string message)
    -> Result<InternalizationReport, Diagnostic> {
    return Result<InternalizationReport, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

auto contains_internal_call(const IrFunction& function) -> bool {
    for (const auto& block : function.blocks) {
        for (const auto& instruction : block.instructions) {
            if (std::holds_alternative<IrInternalCall>(instruction)) return true;
        }
    }
    return false;
}

auto generated_function_id(const IrFunction& function, std::uint64_t seed) -> EntityId {
    DeterministicRng rng{seed ^ function.sourceFunction.value() ^ UINT64_C(0x6f75746c696e652d)};
    for (;;) {
        const auto candidate = EntityId{rng.next_u64()};
        if (candidate.valid() && candidate != function.sourceFunction) return candidate;
    }
}

auto helper_name(const IrFunction& function, EntityId id, std::string_view kind) -> std::string {
    std::ostringstream output;
    output << function.name << '.' << kind << '.' << std::hex << std::setfill('0')
           << std::setw(16) << id.value();
    return output.str();
}

void add_operand_read(const IrOperand& operand, std::vector<IrVariable>& reads) {
    if (const auto* variable = std::get_if<IrVariableOperand>(&operand)) {
        reads.push_back(variable->variable);
    }
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
            || std::is_same_v<T, IrInternalCall>) {
            return item.destination;
        }
        return std::nullopt;
    }, instruction);
}

auto remap_operand(
    IrOperand operand,
    const std::map<std::uint16_t, IrVariable>& variables) -> IrOperand {
    if (auto* variable = std::get_if<IrVariableOperand>(&operand)) {
        variable->variable = variables.at(variable->variable.index);
    }
    return operand;
}

auto remap_instruction(
    const IrInstruction& instruction,
    const std::map<std::uint16_t, IrVariable>& variables) -> IrInstruction {
    return std::visit([&](auto item) -> IrInstruction {
        using T = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<T, IrMove>
            || std::is_same_v<T, IrBinaryOperation>) {
            item.destination = variables.at(item.destination.index);
            item.source = remap_operand(std::move(item.source), variables);
        } else if constexpr (std::is_same_v<T, IrUnaryOperation>) {
            item.destination = variables.at(item.destination.index);
        } else if constexpr (std::is_same_v<T, IrCompare>
            || std::is_same_v<T, IrTest>) {
            item.left = variables.at(item.left.index);
            item.right = remap_operand(std::move(item.right), variables);
        } else if constexpr (std::is_same_v<T, IrInternalCall>) {
            item.destination = variables.at(item.destination.index);
            for (auto& argument : item.arguments) {
                argument = remap_operand(std::move(argument), variables);
            }
        } else if constexpr (std::is_same_v<T, IrReturn>) {
            item.value = variables.at(item.value.index);
        }
        return item;
    }, instruction);
}

auto validate_source(const IrFunction& function, const IrLimits& limits)
    -> std::optional<Diagnostic> {
    if (function_contains_fallback(function)) {
        return Diagnostic{
            DiagnosticSeverity::Error,
            "ir.fallback_not_transformable",
            "functions containing native fallbacks cannot be outlined or split"};
    }
    if (contains_internal_call(function)) {
        return Diagnostic{
            DiagnosticSeverity::Error,
            "ir.internal_call_not_self_contained",
            "a standalone function containing internal calls requires its source module"};
    }
    const auto validated = validate_function(function, limits);
    if (!validated.has_value()) return validated.error();
    return std::nullopt;
}

} // namespace

auto split_function(
    const IrFunction& function,
    std::uint64_t seed,
    const IrLimits& limits) -> Result<InternalizationReport, Diagnostic> {
    if (const auto invalid = validate_source(function, limits); invalid.has_value()) {
        return Result<InternalizationReport, Diagnostic>::failure(*invalid);
    }
    const auto entryBlock = std::find_if(
        function.blocks.begin(), function.blocks.end(),
        [&](const auto& block) { return block.id == function.entry; });
    if (entryBlock == function.blocks.end()) {
        return failure("ir.entry_block_missing", "function split entry block is missing");
    }

    const auto helperId = generated_function_id(function, seed);
    auto helper = function;
    helper.sourceFunction = helperId;
    helper.name = helper_name(function, helperId, "split");

    IrFunction wrapper;
    wrapper.sourceFunction = function.sourceFunction;
    wrapper.name = function.name;
    wrapper.arguments = function.arguments;
    wrapper.returnType = function.returnType;
    std::size_t wrapperVariableCount = 0;
    for (const auto& argument : wrapper.arguments) {
        wrapperVariableCount = std::max(
            wrapperVariableCount, static_cast<std::size_t>(argument.destination.index) + 1U);
    }
    wrapper.variableTypes.assign(wrapperVariableCount, integer_type(IrWidth::U32));
    for (const auto& argument : wrapper.arguments) {
        wrapper.variableTypes[argument.destination.index] = argument.type;
    }
    const auto resultVariable = IrVariable{
        static_cast<std::uint16_t>(wrapper.variableTypes.size())};
    wrapper.variableTypes.push_back(function.returnType);
    wrapper.entry = function.entry;

    std::vector<const IrArgumentBinding*> orderedArguments;
    for (const auto& argument : wrapper.arguments) orderedArguments.push_back(&argument);
    std::sort(orderedArguments.begin(), orderedArguments.end(), [](const auto* left, const auto* right) {
        return left->argumentIndex < right->argumentIndex;
    });
    std::vector<IrOperand> callArguments;
    callArguments.reserve(orderedArguments.size());
    for (const auto* argument : orderedArguments) {
        callArguments.push_back(IrVariableOperand{argument->destination});
    }
    wrapper.blocks.push_back(IrBlock{
        .id = function.entry,
        .sourceBlock = entryBlock->sourceBlock,
        .instructions = {
            IrInternalCall{
                helperId,
                function.returnType,
                resultVariable,
                std::move(callArguments),
                function.sourceFunction,
            },
            IrReturn{function.returnType, resultVariable, function.sourceFunction},
        },
    });

    InternalizationReport report{
        .module = IrModule{
            .entryFunction = function.sourceFunction,
            .functions = {std::move(wrapper), std::move(helper)},
        },
        .helperFunction = helperId,
        .statistics = InternalizationStatistics{
            .movedBlocks = function.blocks.size(),
            .liveInVariables = function.arguments.size(),
        },
    };
    const auto validated = validate_module(report.module, limits);
    if (!validated.has_value()) {
        return Result<InternalizationReport, Diagnostic>::failure(validated.error());
    }
    return Result<InternalizationReport, Diagnostic>::success(std::move(report));
}

auto outline_block(
    const IrFunction& function,
    IrBlockId blockId,
    std::uint64_t seed,
    const IrLimits& limits) -> Result<InternalizationReport, Diagnostic> {
    if (function_contains_fallback(function)) {
        return failure(
            "ir.fallback_not_transformable",
            "functions containing native fallbacks cannot be outlined");
    }
    const auto selected = std::find_if(function.blocks.begin(), function.blocks.end(),
        [blockId](const auto& block) { return block.id == blockId; });
    if (selected == function.blocks.end()) {
        return failure("ir.outline_block_missing", "selected outline block does not exist");
    }
    if (blockId == function.entry) {
        return failure("ir.outline_entry_block", "the entry block cannot be outlined");
    }
    if (const auto invalid = validate_source(function, limits); invalid.has_value()) {
        return Result<InternalizationReport, Diagnostic>::failure(*invalid);
    }
    if (selected->instructions.empty()
        || !std::holds_alternative<IrReturn>(selected->instructions.back())) {
        return failure(
            "ir.outline_requires_return_block",
            "initial block outlining requires a single-return block");
    }

    std::set<std::uint16_t> defined;
    std::set<std::uint16_t> liveIns;
    std::set<std::uint16_t> allVariables;
    for (const auto& instruction : selected->instructions) {
        for (const auto variable : reads_of(instruction)) {
            allVariables.insert(variable.index);
            if (!defined.contains(variable.index)) liveIns.insert(variable.index);
        }
        if (const auto written = write_of(instruction); written.has_value()) {
            allVariables.insert(written->index);
            defined.insert(written->index);
        }
    }

    std::vector<std::uint16_t> variableOrder(liveIns.begin(), liveIns.end());
    for (const auto variable : allVariables) {
        if (!liveIns.contains(variable)) variableOrder.push_back(variable);
    }
    std::map<std::uint16_t, IrVariable> remapping;
    std::vector<IrType> helperTypes;
    helperTypes.reserve(variableOrder.size());
    for (std::size_t index = 0; index < variableOrder.size(); ++index) {
        remapping.emplace(
            variableOrder[index], IrVariable{static_cast<std::uint16_t>(index)});
        helperTypes.push_back(function.variableTypes[variableOrder[index]]);
    }

    const auto helperId = generated_function_id(function, seed);
    IrFunction helper{
        .sourceFunction = helperId,
        .name = helper_name(function, helperId, "outlined"),
        .arguments = {},
        .returnType = function.returnType,
        .variableTypes = std::move(helperTypes),
        .storageLocations = {},
        .entry = selected->id,
        .blocks = {},
    };
    std::uint16_t argumentIndex = 0;
    for (const auto variable : liveIns) {
        helper.arguments.push_back(IrArgumentBinding{
            argumentIndex++, remapping.at(variable), function.variableTypes[variable]});
    }
    IrBlock helperBlock{
        .id = selected->id,
        .sourceBlock = selected->sourceBlock,
        .instructions = {},
    };
    helperBlock.instructions.reserve(selected->instructions.size());
    for (const auto& instruction : selected->instructions) {
        helperBlock.instructions.push_back(remap_instruction(instruction, remapping));
    }
    helper.blocks.push_back(std::move(helperBlock));

    auto main = function;
    auto mainSelected = std::find_if(main.blocks.begin(), main.blocks.end(),
        [blockId](const auto& block) { return block.id == blockId; });
    const auto originalReturn = std::get<IrReturn>(mainSelected->instructions.back());
    std::vector<IrOperand> callArguments;
    callArguments.reserve(liveIns.size());
    for (const auto variable : liveIns) {
        callArguments.push_back(IrVariableOperand{IrVariable{variable}});
    }
    mainSelected->instructions = {
        IrInternalCall{
            helperId,
            function.returnType,
            originalReturn.value,
            std::move(callArguments),
            originalReturn.sourceInstruction,
        },
        originalReturn,
    };

    InternalizationReport report{
        .module = IrModule{
            .entryFunction = function.sourceFunction,
            .functions = {std::move(main), std::move(helper)},
        },
        .helperFunction = helperId,
        .statistics = InternalizationStatistics{
            .movedBlocks = 1,
            .liveInVariables = liveIns.size(),
        },
    };
    const auto validated = validate_module(report.module, limits);
    if (!validated.has_value()) {
        return Result<InternalizationReport, Diagnostic>::failure(validated.error());
    }
    return Result<InternalizationReport, Diagnostic>::success(std::move(report));
}

} // namespace binobf::ir

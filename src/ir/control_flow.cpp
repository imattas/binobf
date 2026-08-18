#include <binobf/ir/control_flow.hpp>

#include <binobf/support/deterministic_rng.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace binobf::ir {
namespace {

auto failure(std::string code, std::string message) -> Result<FlatteningReport, Diagnostic> {
    return Result<FlatteningReport, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

class BlockAllocator final {
public:
    explicit BlockAllocator(const IrFunction& function) {
        for (const auto& block : function.blocks) {
            next_ = std::max(next_, static_cast<std::uint64_t>(block.id.value) + 1U);
        }
    }

    [[nodiscard]] auto allocate() -> std::optional<IrBlockId> {
        if (next_ > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
        return IrBlockId{static_cast<std::uint32_t>(next_++)};
    }

private:
    std::uint64_t next_{0};
};

auto find_block(const IrFunction& function, IrBlockId id) -> const IrBlock* {
    const auto found = std::find_if(function.blocks.begin(), function.blocks.end(),
        [id](const auto& block) { return block.id == id; });
    return found == function.blocks.end() ? nullptr : &*found;
}

auto case_for(
    const std::map<std::uint32_t, std::uint32_t>& cases,
    IrBlockId block) -> std::uint32_t {
    return cases.at(block.value);
}

auto make_state_transition(
    IrBlockId id,
    EntityId sourceBlock,
    EntityId sourceInstruction,
    IrVariable state,
    std::uint32_t value,
    IrBlockId dispatcher,
    IrBlockId bogus) -> IrBlock {
    return IrBlock{
        .id = id,
        .sourceBlock = sourceBlock,
        .instructions = {
            IrMove{
                IrWidth::U32,
                state,
                IrImmediateOperand{IrWidth::U32, value},
                sourceInstruction,
            },
            IrCompare{
                IrWidth::U32,
                state,
                IrVariableOperand{state},
                sourceInstruction,
            },
            IrConditionalJump{
                IrCondition::Equal,
                dispatcher,
                bogus,
                sourceInstruction,
            },
        },
    };
}

} // namespace

auto flatten_control_flow(
    const IrFunction& function,
    std::uint64_t seed,
    const IrLimits& limits) -> Result<FlatteningReport, Diagnostic> {
    if (function_contains_fallback(function)) {
        return failure(
            "ir.fallback_not_transformable",
            "functions containing native fallbacks cannot be CFG-flattened");
    }
    const auto sourceValidated = validate_function(function, limits);
    if (!sourceValidated.has_value()) {
        return Result<FlatteningReport, Diagnostic>::failure(sourceValidated.error());
    }
    if (function.blocks.empty()) {
        return failure("ir.entry_block_missing", "CFG flattening requires an entry block");
    }

    const auto* sourceEntry = find_block(function, function.entry);
    if (sourceEntry == nullptr) {
        return failure("ir.entry_block_missing", "CFG flattening entry block is missing");
    }

    DeterministicRng rng{seed};
    std::vector<IrBlockId> dispatchOrder;
    dispatchOrder.reserve(function.blocks.size());
    for (const auto& block : function.blocks) dispatchOrder.push_back(block.id);
    rng.shuffle(dispatchOrder);

    const auto multiplier = static_cast<std::uint32_t>(rng.next_u64()) | UINT32_C(1);
    const auto offset = static_cast<std::uint32_t>(rng.next_u64());
    std::map<std::uint32_t, std::uint32_t> caseValues;
    for (std::size_t index = 0; index < dispatchOrder.size(); ++index) {
        const auto ordinal = static_cast<std::uint32_t>(index + 1U);
        caseValues.emplace(
            dispatchOrder[index].value,
            static_cast<std::uint32_t>(offset + multiplier * ordinal));
    }

    BlockAllocator allocator{function};
    const auto initializerId = allocator.allocate();
    if (!initializerId.has_value()) {
        return failure("ir.block_id_exhausted", "no block IDs remain for CFG flattening");
    }
    std::vector<IrBlockId> dispatcherIds;
    dispatcherIds.reserve(function.blocks.size());
    for (std::size_t index = 0; index < function.blocks.size(); ++index) {
        const auto id = allocator.allocate();
        if (!id.has_value()) {
            return failure("ir.block_id_exhausted", "no block IDs remain for dispatcher blocks");
        }
        dispatcherIds.push_back(*id);
    }
    const auto bogusId = allocator.allocate();
    if (!bogusId.has_value()) {
        return failure("ir.block_id_exhausted", "no block ID remains for the bogus block");
    }
    const auto dispatcherEntry = dispatcherIds.front();

    FlatteningReport report;
    report.function = function;
    report.function.variableWidths.push_back(IrWidth::U32);
    report.dispatcherState = IrVariable{
        static_cast<std::uint16_t>(report.function.variableWidths.size() - 1U)};
    report.dispatcherEntry = dispatcherEntry;
    report.bogusBlock = *bogusId;
    report.statistics.originalBlocks = function.blocks.size();
    report.statistics.dispatcherBlocks = dispatcherIds.size();
    report.statistics.bogusBlocks = 1;
    report.cases.reserve(function.blocks.size());
    for (const auto& block : function.blocks) {
        report.cases.push_back(DispatcherCase{block.id, case_for(caseValues, block.id)});
    }

    std::set<std::uint16_t> argumentVariables;
    for (const auto& argument : function.arguments) {
        argumentVariables.insert(argument.destination.index);
    }
    IrBlock initializer{
        .id = *initializerId,
        .sourceBlock = sourceEntry->sourceBlock,
        .instructions = {},
    };
    for (std::size_t index = 0; index + 1U < report.function.variableWidths.size(); ++index) {
        const auto variable = IrVariable{static_cast<std::uint16_t>(index)};
        if (argumentVariables.contains(variable.index)) continue;
        initializer.instructions.push_back(IrMove{
            report.function.variableWidths[index],
            variable,
            IrImmediateOperand{report.function.variableWidths[index], 0},
            function.sourceFunction,
        });
    }
    initializer.instructions.push_back(IrMove{
        IrWidth::U32,
        report.dispatcherState,
        IrImmediateOperand{IrWidth::U32, case_for(caseValues, function.entry)},
        function.sourceFunction,
    });
    initializer.instructions.push_back(IrCompare{
        IrWidth::U32,
        report.dispatcherState,
        IrVariableOperand{report.dispatcherState},
        function.sourceFunction,
    });
    initializer.instructions.push_back(IrConditionalJump{
        IrCondition::Equal,
        dispatcherEntry,
        *bogusId,
        function.sourceFunction,
    });

    std::vector<IrBlock> dispatchers;
    dispatchers.reserve(dispatchOrder.size());
    for (std::size_t index = 0; index < dispatchOrder.size(); ++index) {
        const auto falseTarget = index + 1U < dispatchOrder.size()
            ? dispatcherIds[index + 1U] : *bogusId;
        dispatchers.push_back(IrBlock{
            .id = dispatcherIds[index],
            .sourceBlock = sourceEntry->sourceBlock,
            .instructions = {
                IrCompare{
                    IrWidth::U32,
                    report.dispatcherState,
                    IrImmediateOperand{
                        IrWidth::U32, case_for(caseValues, dispatchOrder[index])},
                    function.sourceFunction,
                },
                IrConditionalJump{
                    IrCondition::Equal,
                    dispatchOrder[index],
                    falseTarget,
                    function.sourceFunction,
                },
            },
        });
    }

    IrBlock bogus{
        .id = *bogusId,
        .sourceBlock = sourceEntry->sourceBlock,
        .instructions = {IrJump{dispatcherEntry, function.sourceFunction}},
    };

    std::vector<IrBlock> transformedOriginals = function.blocks;
    std::vector<IrBlock> transitions;
    for (auto& block : transformedOriginals) {
        auto& terminator = block.instructions.back();
        if (const auto* jump = std::get_if<IrJump>(&terminator)) {
            const auto sourceInstruction = jump->sourceInstruction;
            const auto targetValue = case_for(caseValues, jump->target);
            block.instructions.pop_back();
            block.instructions.push_back(IrMove{
                IrWidth::U32,
                report.dispatcherState,
                IrImmediateOperand{IrWidth::U32, targetValue},
                sourceInstruction,
            });
            block.instructions.push_back(IrCompare{
                IrWidth::U32,
                report.dispatcherState,
                IrVariableOperand{report.dispatcherState},
                sourceInstruction,
            });
            block.instructions.push_back(IrConditionalJump{
                IrCondition::Equal,
                dispatcherEntry,
                *bogusId,
                sourceInstruction,
            });
        } else if (const auto* branch = std::get_if<IrConditionalJump>(&terminator)) {
            const auto originalBranch = *branch;
            const auto trueId = allocator.allocate();
            const auto falseId = allocator.allocate();
            if (!trueId.has_value() || !falseId.has_value()) {
                return failure("ir.block_id_exhausted", "no block IDs remain for transitions");
            }
            block.instructions.back() = IrConditionalJump{
                originalBranch.condition,
                *trueId,
                *falseId,
                originalBranch.sourceInstruction,
            };
            transitions.push_back(make_state_transition(
                *trueId,
                block.sourceBlock,
                originalBranch.sourceInstruction,
                report.dispatcherState,
                case_for(caseValues, originalBranch.trueTarget),
                dispatcherEntry,
                *bogusId));
            transitions.push_back(make_state_transition(
                *falseId,
                block.sourceBlock,
                originalBranch.sourceInstruction,
                report.dispatcherState,
                case_for(caseValues, originalBranch.falseTarget),
                dispatcherEntry,
                *bogusId));
        }
    }
    report.statistics.transitionBlocks = transitions.size();
    rng.shuffle(transformedOriginals);

    report.function.entry = *initializerId;
    report.function.blocks.clear();
    report.function.blocks.reserve(
        1U + dispatchers.size() + 1U + transformedOriginals.size() + transitions.size());
    report.function.blocks.push_back(std::move(initializer));
    report.function.blocks.insert(
        report.function.blocks.end(), dispatchers.begin(), dispatchers.end());
    report.function.blocks.push_back(std::move(bogus));
    report.function.blocks.insert(
        report.function.blocks.end(),
        transformedOriginals.begin(), transformedOriginals.end());
    report.function.blocks.insert(
        report.function.blocks.end(), transitions.begin(), transitions.end());

    const auto outputValidated = validate_function(report.function, limits);
    if (!outputValidated.has_value()) {
        return Result<FlatteningReport, Diagnostic>::failure(outputValidated.error());
    }
    return Result<FlatteningReport, Diagnostic>::success(std::move(report));
}

} // namespace binobf::ir

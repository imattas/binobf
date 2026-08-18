#include <binobf/analysis/object_analyzer.hpp>

#include <binobf/architecture/backend.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace binobf {
namespace {

struct Candidate {
    const Symbol* symbol{nullptr};
    const Section* section{nullptr};
    std::uint64_t offset{0};
    bool offsetValid{false};
};

auto error(std::string code, std::string message) -> Diagnostic {
    return Diagnostic{DiagnosticSeverity::Error, std::move(code), std::move(message)};
}

auto warning(std::string code, std::string message) -> Diagnostic {
    return Diagnostic{DiagnosticSeverity::Warning, std::move(code), std::move(message)};
}

auto find_section(const BinaryImage& image, EntityId id) -> const Section* {
    const auto found = std::find_if(image.sections.begin(), image.sections.end(), [id](const auto& section) {
        return section.id == id;
    });
    return found == image.sections.end() ? nullptr : &*found;
}

void include_id(std::uint64_t& maximum, EntityId id) {
    maximum = std::max(maximum, id.value());
}

auto next_entity_id(const BinaryImage& image) -> std::uint64_t {
    std::uint64_t maximum = 0;
    for (const auto& value : image.sections) include_id(maximum, value.id);
    for (const auto& value : image.segments) include_id(maximum, value.id);
    for (const auto& value : image.symbols) include_id(maximum, value.id);
    for (const auto& value : image.imports) include_id(maximum, value.id);
    for (const auto& value : image.exports) include_id(maximum, value.id);
    for (const auto& value : image.relocations) include_id(maximum, value.id);
    for (const auto& value : image.dataObjects) include_id(maximum, value.id);
    for (const auto& value : image.unwindInfo) include_id(maximum, value.id);
    for (const auto& value : image.debugInfo) include_id(maximum, value.id);
    for (const auto& value : image.resources) include_id(maximum, value.id);
    return maximum == std::numeric_limits<std::uint64_t>::max() ? maximum : maximum + 1;
}

auto add_checked(std::uint64_t left, std::uint64_t right) -> std::optional<std::uint64_t> {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) return std::nullopt;
    return left + right;
}

auto fallback_width(Architecture architecture, std::size_t available) -> std::size_t {
    const std::size_t preferred = architecture == Architecture::ARM64 ? 4 : 1;
    return std::min(preferred, available);
}

auto make_opaque_instruction(
    const DecodeRequest& request,
    std::size_t width) -> Instruction {
    return Instruction{
        .id = request.instructionId,
        .section = request.sectionId,
        .sectionOffset = request.sectionOffset,
        .address = request.address,
        .encoding = std::vector<std::byte>(
            request.bytes.begin(), request.bytes.begin() + static_cast<std::ptrdiff_t>(width)),
        .mnemonic = request.architecture == Architecture::ARM64 ? ".inst" : ".byte",
        .operands = {},
        .kind = InstructionKind::Opaque,
        .directTarget = std::nullopt,
        .hasFallthrough = true,
        .registersRead = {},
        .registersWritten = {},
        .references = {},
        .lineage = TransformationLineage{{TransformationRecord{
            .transform = TransformId{request.instructionId.value()},
            .source = request.sectionId,
            .passName = "machine-code-decode-fallback",
        }}},
    };
}

auto find_instruction(BinaryImage& image, EntityId id) -> Instruction* {
    const auto found = std::find_if(
        image.instructions.begin(), image.instructions.end(), [id](const auto& instruction) {
            return instruction.id == id;
        });
    return found == image.instructions.end() ? nullptr : &*found;
}

auto find_symbol(const BinaryImage& image, EntityId id) -> const Symbol* {
    const auto found = std::find_if(image.symbols.begin(), image.symbols.end(), [id](const auto& symbol) {
        return symbol.id == id;
    });
    return found == image.symbols.end() ? nullptr : &*found;
}

void attach_relocation_references(BinaryImage& image, const Function& function) {
    for (const auto instructionId : function.instructions) {
        auto* instruction = find_instruction(image, instructionId);
        if (instruction == nullptr) continue;
        const auto instructionEnd = instruction->sectionOffset + instruction->encoding.size();
        for (const auto& relocation : image.relocations) {
            if (relocation.section != instruction->section
                || relocation.offset < instruction->sectionOffset
                || relocation.offset >= instructionEnd) {
                continue;
            }
            const bool isCall = instruction->kind == InstructionKind::DirectCall
                || instruction->kind == InstructionKind::IndirectCall;
            const bool isBranch = instruction->kind == InstructionKind::DirectBranch
                || instruction->kind == InstructionKind::ConditionalBranch
                || instruction->kind == InstructionKind::IndirectBranch;
            const auto referenceKind = isCall
                ? InstructionReferenceKind::CallTarget
                : (isBranch ? InstructionReferenceKind::BranchTarget
                            : InstructionReferenceKind::Relocation);
            if (isCall || isBranch) {
                instruction->references.erase(
                    std::remove_if(
                        instruction->references.begin(), instruction->references.end(),
                        [referenceKind](const auto& reference) {
                            return reference.kind == referenceKind;
                        }),
                    instruction->references.end());
            }
            std::optional<BinaryAddress> resolvedAddress;
            if (relocation.targetSymbol.has_value()) {
                const auto* symbol = find_symbol(image, *relocation.targetSymbol);
                if (symbol != nullptr && symbol->defined && symbol->section == function.section) {
                    resolvedAddress = symbol->address;
                }
            }
            if (isCall || isBranch) instruction->directTarget = resolvedAddress;
            instruction->references.push_back(InstructionReference{
                .kind = referenceKind,
                .address = resolvedAddress,
                .relocation = relocation.id,
                .symbol = relocation.targetSymbol,
            });
        }
    }
}

void trim_inferred_alignment_padding(
    AnalysisReport& report,
    Function& function,
    std::uint64_t functionOffset) {
    std::size_t paddingCount = 0;
    for (auto iterator = function.instructions.rbegin(); iterator != function.instructions.rend(); ++iterator) {
        const auto* instruction = find_instruction(report.image, *iterator);
        if (instruction == nullptr || instruction->mnemonic != "nop") break;
        ++paddingCount;
    }
    if (paddingCount == 0 || paddingCount >= function.instructions.size()) return;
    const auto terminatorIndex = function.instructions.size() - paddingCount - 1;
    const auto* terminator = find_instruction(report.image, function.instructions[terminatorIndex]);
    if (terminator == nullptr
        || (terminator->kind != InstructionKind::Return
            && terminator->kind != InstructionKind::DirectBranch
            && terminator->kind != InstructionKind::IndirectBranch
            && terminator->kind != InstructionKind::Trap)) {
        return;
    }
    function.size = terminator->sectionOffset + terminator->encoding.size() - functionOffset;
    function.instructions.resize(function.instructions.size() - paddingCount);
    report.image.instructions.resize(report.image.instructions.size() - paddingCount);
    report.diagnostics.push_back(Diagnostic{
        DiagnosticSeverity::Info,
        "analysis.trimmed_alignment_padding",
        "excluded trailing NOP alignment padding from inferred function " + function.name,
    });
}

void add_unique_successor(BasicBlock& block, EntityId successor) {
    if (std::find(block.successors.begin(), block.successors.end(), successor)
        == block.successors.end()) {
        block.successors.push_back(successor);
    }
}

void recover_cfg(
    AnalysisReport& report,
    Function& function,
    std::uint64_t& nextId) {
    if (function.instructions.empty()) return;
    std::vector<const Instruction*> instructions;
    instructions.reserve(function.instructions.size());
    for (const auto id : function.instructions) {
        const auto* instruction = find_instruction(report.image, id);
        if (instruction == nullptr) return;
        instructions.push_back(instruction);
    }

    std::set<std::uint64_t> boundaries{instructions.front()->sectionOffset};
    for (std::size_t index = 0; index < instructions.size(); ++index) {
        const auto& instruction = *instructions[index];
        if ((instruction.kind == InstructionKind::DirectBranch
             || instruction.kind == InstructionKind::ConditionalBranch)
            && instruction.directTarget.has_value()) {
            const auto target = std::find_if(
                instructions.begin(), instructions.end(), [&instruction](const auto* candidate) {
                    return candidate->address == *instruction.directTarget;
                });
            if (target != instructions.end()) boundaries.insert((*target)->sectionOffset);
        }
        const bool endsBlock = instruction.kind != InstructionKind::Normal
            && instruction.kind != InstructionKind::Opaque;
        if (endsBlock && index + 1 < instructions.size()) {
            boundaries.insert(instructions[index + 1]->sectionOffset);
        }
    }

    const std::vector<std::uint64_t> orderedBoundaries(boundaries.begin(), boundaries.end());
    const auto blockBase = report.image.basicBlocks.size();
    for (std::size_t boundaryIndex = 0; boundaryIndex < orderedBoundaries.size(); ++boundaryIndex) {
        const auto begin = orderedBoundaries[boundaryIndex];
        const auto end = boundaryIndex + 1 < orderedBoundaries.size()
            ? orderedBoundaries[boundaryIndex + 1]
            : std::numeric_limits<std::uint64_t>::max();
        std::vector<EntityId> blockInstructions;
        for (const auto* instruction : instructions) {
            if (instruction->sectionOffset >= begin && instruction->sectionOffset < end) {
                blockInstructions.push_back(instruction->id);
            }
        }
        if (blockInstructions.empty()) continue;
        const auto* first = find_instruction(report.image, blockInstructions.front());
        const auto blockId = EntityId{nextId++};
        report.image.basicBlocks.push_back(BasicBlock{
            .id = blockId,
            .function = function.id,
            .section = function.section,
            .sectionOffset = begin,
            .address = first->address,
            .instructions = std::move(blockInstructions),
            .successors = {},
            .edges = {},
            .liveIn = {},
            .liveOut = {},
            .hasUnresolvedSuccessor = false,
            .lineage = TransformationLineage{{TransformationRecord{
                .transform = TransformId{blockId.value()},
                .source = first->id,
                .passName = "cfg-recovery",
            }}},
        });
        function.basicBlocks.push_back(blockId);
    }
    if (!function.basicBlocks.empty()) function.entryBlock = function.basicBlocks.front();

    auto target_block = [&](BinaryAddress target) -> std::optional<EntityId> {
        for (std::size_t index = blockBase; index < report.image.basicBlocks.size(); ++index) {
            if (report.image.basicBlocks[index].address == target) {
                return report.image.basicBlocks[index].id;
            }
        }
        return std::nullopt;
    };
    auto target_is_inside = [&](BinaryAddress target) -> bool {
        if (target.value < function.address.value) return false;
        return target.value - function.address.value < function.size;
    };

    for (std::size_t index = blockBase; index < report.image.basicBlocks.size(); ++index) {
        auto& block = report.image.basicBlocks[index];
        const auto* terminator = find_instruction(report.image, block.instructions.back());
        if (terminator == nullptr) continue;
        const auto nextBlock = index + 1 < report.image.basicBlocks.size()
            && report.image.basicBlocks[index + 1].function == function.id
            ? std::optional{report.image.basicBlocks[index + 1].id}
            : std::nullopt;
        auto add_edge = [&](ControlFlowEdgeKind kind, std::optional<EntityId> target,
                            std::optional<BinaryAddress> address, bool successor) {
            block.edges.push_back(ControlFlowEdge{
                .kind = kind, .targetBlock = target, .targetAddress = address});
            if (successor && target.has_value()) add_unique_successor(block, *target);
        };
        auto add_direct_target = [&](ControlFlowEdgeKind kind, bool successor) {
            if (!terminator->directTarget.has_value()) return;
            const auto target = target_block(*terminator->directTarget);
            if (!target.has_value() && target_is_inside(*terminator->directTarget)) {
                function.complete = false;
                report.diagnostics.push_back(warning(
                    "analysis.invalid_branch_target",
                    "function " + function.name
                        + " has a control-flow target that is not an instruction boundary"));
            }
            add_edge(kind, target, terminator->directTarget, successor);
        };

        switch (terminator->kind) {
        case InstructionKind::Normal:
        case InstructionKind::Opaque:
            if (nextBlock.has_value()) {
                add_edge(ControlFlowEdgeKind::Fallthrough, nextBlock, std::nullopt, true);
            } else if (terminator->hasFallthrough) {
                function.complete = false;
                report.diagnostics.push_back(warning(
                    "analysis.function_falls_through",
                    "function " + function.name + " falls through its proven range"));
            }
            break;
        case InstructionKind::ConditionalBranch:
            add_direct_target(ControlFlowEdgeKind::BranchTaken, true);
            if (nextBlock.has_value()) {
                add_edge(ControlFlowEdgeKind::Fallthrough, nextBlock, std::nullopt, true);
            }
            break;
        case InstructionKind::DirectBranch:
            add_direct_target(ControlFlowEdgeKind::DirectBranch, true);
            break;
        case InstructionKind::DirectCall:
            add_direct_target(ControlFlowEdgeKind::DirectCall, false);
            if (nextBlock.has_value()) {
                add_edge(ControlFlowEdgeKind::Fallthrough, nextBlock, std::nullopt, true);
            }
            break;
        case InstructionKind::IndirectCall:
            block.hasUnresolvedSuccessor = true;
            function.complete = false;
            add_edge(ControlFlowEdgeKind::UnresolvedIndirect, std::nullopt, std::nullopt, false);
            if (nextBlock.has_value()) {
                add_edge(ControlFlowEdgeKind::Fallthrough, nextBlock, std::nullopt, true);
            }
            report.diagnostics.push_back(warning(
                "analysis.unresolved_indirect_flow",
                "function " + function.name + " contains an unresolved indirect call"));
            break;
        case InstructionKind::IndirectBranch:
            block.hasUnresolvedSuccessor = true;
            function.complete = false;
            add_edge(ControlFlowEdgeKind::UnresolvedIndirect, std::nullopt, std::nullopt, false);
            report.diagnostics.push_back(warning(
                "analysis.unresolved_indirect_flow",
                "function " + function.name + " contains an unresolved indirect branch"));
            break;
        case InstructionKind::Return:
        case InstructionKind::Trap:
            break;
        }
    }
}

void recover_liveness(AnalysisReport& report, const Function& function) {
    struct Facts {
        BasicBlock* block{nullptr};
        std::map<std::uint32_t, RegisterAccess> uses;
        std::map<std::uint32_t, RegisterAccess> definitions;
        std::map<std::uint32_t, RegisterAccess> liveIn;
        std::map<std::uint32_t, RegisterAccess> liveOut;
    };
    std::vector<Facts> facts;
    facts.reserve(function.basicBlocks.size());
    for (const auto blockId : function.basicBlocks) {
        const auto found = std::find_if(
            report.image.basicBlocks.begin(), report.image.basicBlocks.end(),
            [blockId](const auto& block) { return block.id == blockId; });
        if (found == report.image.basicBlocks.end()) continue;
        Facts current{
            .block = &*found,
            .uses = {},
            .definitions = {},
            .liveIn = {},
            .liveOut = {},
        };
        for (const auto instructionId : found->instructions) {
            const auto* instruction = find_instruction(report.image, instructionId);
            if (instruction == nullptr) continue;
            for (const auto& reg : instruction->registersRead) {
                if (!current.definitions.contains(reg.id)) current.uses.emplace(reg.id, reg);
            }
            for (const auto& reg : instruction->registersWritten) {
                current.definitions.insert_or_assign(reg.id, reg);
            }
        }
        facts.push_back(std::move(current));
    }
    auto find_facts = [&](EntityId id) -> const Facts* {
        const auto found = std::find_if(facts.begin(), facts.end(), [id](const auto& value) {
            return value.block->id == id;
        });
        return found == facts.end() ? nullptr : &*found;
    };
    bool changed = true;
    while (changed) {
        changed = false;
        for (auto iterator = facts.rbegin(); iterator != facts.rend(); ++iterator) {
            std::map<std::uint32_t, RegisterAccess> liveOut;
            for (const auto successor : iterator->block->successors) {
                const auto* successorFacts = find_facts(successor);
                if (successorFacts == nullptr) continue;
                liveOut.insert(successorFacts->liveIn.begin(), successorFacts->liveIn.end());
            }
            auto liveIn = iterator->uses;
            for (const auto& [id, reg] : liveOut) {
                if (!iterator->definitions.contains(id)) liveIn.emplace(id, reg);
            }
            if (liveOut != iterator->liveOut || liveIn != iterator->liveIn) {
                iterator->liveOut = std::move(liveOut);
                iterator->liveIn = std::move(liveIn);
                changed = true;
            }
        }
    }
    for (auto& value : facts) {
        value.block->liveIn.clear();
        value.block->liveOut.clear();
        for (const auto& [id, reg] : value.liveIn) {
            static_cast<void>(id);
            value.block->liveIn.push_back(reg);
        }
        for (const auto& [id, reg] : value.liveOut) {
            static_cast<void>(id);
            value.block->liveOut.push_back(reg);
        }
    }
}

} // namespace

auto analyze_object(const BinaryImage& input) -> Result<AnalysisReport, Diagnostic> {
    if (input.architecture == Architecture::Unknown) {
        return Result<AnalysisReport, Diagnostic>::failure(error(
            "analysis.unsupported_architecture",
            "cannot analyze an object with unknown architecture"));
    }
    auto backendResult = make_architecture_backend(input.architecture);
    if (!backendResult.has_value()) {
        return Result<AnalysisReport, Diagnostic>::failure(
            std::move(backendResult).error());
    }
    auto backend = std::move(backendResult).value();
    AnalysisReport report{.image = input, .diagnostics = {}};
    report.image.instructions.clear();
    report.image.basicBlocks.clear();
    report.image.functions.clear();

    std::vector<Candidate> candidates;
    for (const auto& symbol : report.image.symbols) {
        if (!symbol.defined || symbol.kind != SymbolKind::Function
            || !symbol.section.has_value()) {
            continue;
        }
        const auto* section = find_section(report.image, *symbol.section);
        if (section == nullptr || section->kind != SectionKind::Code || !section->executable) {
            continue;
        }
        const bool baseValid = symbol.address.value >= section->address.value;
        const auto offset = baseValid
            ? symbol.address.value - section->address.value : UINT64_C(0);
        candidates.push_back(Candidate{
            .symbol = &symbol,
            .section = section,
            .offset = offset,
            .offsetValid = baseValid && offset < section->contents.size(),
        });
    }
    std::sort(candidates.begin(), candidates.end(), [](const auto& left, const auto& right) {
        if (left.section->formatIndex != right.section->formatIndex) {
            return left.section->formatIndex < right.section->formatIndex;
        }
        if (left.offset != right.offset) return left.offset < right.offset;
        return left.symbol->id.value() < right.symbol->id.value();
    });

    auto nextId = next_entity_id(report.image);
    if (nextId == std::numeric_limits<std::uint64_t>::max()) {
        return Result<AnalysisReport, Diagnostic>::failure(error(
            "analysis.id_exhausted", "no stable entity IDs remain for analysis"));
    }
    for (std::size_t candidateIndex = 0; candidateIndex < candidates.size(); ++candidateIndex) {
        const auto& candidate = candidates[candidateIndex];
        const auto functionId = EntityId{nextId++};
        bool complete = candidate.offsetValid;
        std::uint64_t end = candidate.offset;
        if (!candidate.offsetValid) {
            report.diagnostics.push_back(warning(
                "analysis.function_out_of_range",
                "function " + candidate.symbol->name + " starts outside its code section"));
        } else {
            const auto declaredEnd = candidate.symbol->size == 0
                ? std::optional<std::uint64_t>{}
                : add_checked(candidate.offset, candidate.symbol->size);
            const bool hasNext = candidateIndex + 1 < candidates.size()
                && candidates[candidateIndex + 1].section->id == candidate.section->id;
            const auto sectionEnd = static_cast<std::uint64_t>(
                candidate.section->contents.size());
            const auto nextOffset = hasNext
                ? std::min(candidates[candidateIndex + 1].offset, sectionEnd)
                : sectionEnd;
            if (candidate.symbol->size == 0) {
                end = nextOffset;
            } else if (!declaredEnd.has_value()
                || *declaredEnd > candidate.section->contents.size()) {
                end = std::min(
                    nextOffset, static_cast<std::uint64_t>(candidate.section->contents.size()));
                complete = false;
                report.diagnostics.push_back(warning(
                    "analysis.function_out_of_range",
                    "function " + candidate.symbol->name + " extends outside its code section"));
            } else {
                end = *declaredEnd;
                if (hasNext && nextOffset < end) {
                    end = nextOffset;
                    complete = false;
                    report.diagnostics.push_back(warning(
                        "analysis.overlapping_functions",
                        "function " + candidate.symbol->name
                            + " overlaps the next symbol-proven function"));
                }
            }
            if (end <= candidate.offset) {
                complete = false;
                end = candidate.offset;
                report.diagnostics.push_back(warning(
                    "analysis.empty_function_range",
                    "function " + candidate.symbol->name + " has no decodable byte range"));
            }
        }

        Function function{
            .id = functionId,
            .name = candidate.symbol->name,
            .section = candidate.section->id,
            .symbol = candidate.symbol->id,
            .address = candidate.symbol->address,
            .size = end >= candidate.offset ? end - candidate.offset : 0,
            .discovery = FunctionDiscovery::Symbol,
            .instructions = {},
            .basicBlocks = {},
            .entryBlock = std::nullopt,
            .externallyVisible = candidate.symbol->visibility == SymbolVisibility::External,
            .complete = complete,
            .lineage = TransformationLineage{{TransformationRecord{
                .transform = TransformId{functionId.value()},
                .source = candidate.symbol->id,
                .passName = "symbol-function-discovery",
            }}},
        };
        std::uint64_t cursor = candidate.offset;
        while (candidate.offsetValid && cursor < end) {
            const auto cursorSize = static_cast<std::size_t>(cursor);
            const auto remaining = static_cast<std::size_t>(end - cursor);
            const auto addressValue = add_checked(candidate.section->address.value, cursor);
            if (!addressValue.has_value()) {
                function.complete = false;
                report.diagnostics.push_back(warning(
                    "analysis.address_overflow",
                    "function " + function.name + " instruction address overflowed"));
                break;
            }
            const auto instructionId = EntityId{nextId++};
            DecodeRequest request{
                .architecture = report.image.architecture,
                .bytes = std::span<const std::byte>{candidate.section->contents}.subspan(
                    cursorSize, remaining),
                .address = BinaryAddress{*addressValue, candidate.section->address.kind},
                .instructionId = instructionId,
                .sectionId = candidate.section->id,
                .sectionOffset = cursor,
            };
            auto decoded = backend->decode(request);
            Instruction instruction;
            if (!decoded.has_value()) {
                const auto width = fallback_width(report.image.architecture, remaining);
                instruction = make_opaque_instruction(request, width);
                function.complete = false;
                auto diagnostic = decoded.error();
                diagnostic.severity = DiagnosticSeverity::Warning;
                diagnostic.message = "function " + function.name + " at offset "
                    + std::to_string(cursor) + ": " + diagnostic.message;
                report.diagnostics.push_back(std::move(diagnostic));
            } else {
                instruction = std::move(decoded).value();
            }
            if (instruction.encoding.empty() || instruction.encoding.size() > remaining) {
                return Result<AnalysisReport, Diagnostic>::failure(error(
                    "analysis.decoder_contract_violation",
                    "instruction decoder returned an invalid encoding length"));
            }
            function.instructions.push_back(instruction.id);
            cursor += instruction.encoding.size();
            report.image.instructions.push_back(std::move(instruction));
        }
        if (candidate.symbol->size == 0) {
            trim_inferred_alignment_padding(report, function, candidate.offset);
        }
        attach_relocation_references(report.image, function);
        recover_cfg(report, function, nextId);
        recover_liveness(report, function);
        report.image.functions.push_back(std::move(function));
    }
    return Result<AnalysisReport, Diagnostic>::success(std::move(report));
}

} // namespace binobf

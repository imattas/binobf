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
#include <unordered_map>
#include <utility>
#include <vector>

namespace binobf {
namespace {

struct Candidate {
    const Symbol* symbol{nullptr};
    const Section* section{nullptr};
    std::optional<EntityId> preservedId;
    std::string name;
    BinaryAddress address;
    std::uint64_t declaredSize{0};
    FunctionDiscovery discovery{FunctionDiscovery::Symbol};
    bool externallyVisible{false};
    EntityId lineageSource;
    std::uint64_t offset{0};
    bool offsetValid{false};
};

using EntityLocation = std::pair<std::uint64_t, std::uint64_t>;

auto is_aarch64_data_mapping_symbol(std::string_view name) noexcept -> bool {
    return name == "$d" || name.starts_with("$d.");
}

auto is_aarch64_mapping_symbol(std::string_view name) noexcept -> bool {
    return is_aarch64_data_mapping_symbol(name)
        || name == "$x" || name.starts_with("$x.");
}

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
    for (const auto& value : image.instructions) include_id(maximum, value.id);
    for (const auto& value : image.basicBlocks) include_id(maximum, value.id);
    for (const auto& value : image.functions) include_id(maximum, value.id);
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

auto add_signed_checked(std::uint64_t value, std::int64_t addend)
    -> std::optional<std::uint64_t> {
    if (addend >= 0) return add_checked(value, static_cast<std::uint64_t>(addend));
    const auto magnitude = static_cast<std::uint64_t>(-(addend + 1)) + 1U;
    if (magnitude > value) return std::nullopt;
    return value - magnitude;
}

auto is_arm64_call_relocation(const BinaryImage& image, const Relocation& relocation) -> bool {
    if (image.architecture != Architecture::ARM64) return false;
    if (image.format == BinaryFormat::ELF) return relocation.rawType == 0x11bU;
    if (image.format != BinaryFormat::COFF || relocation.rawType != 0x0003U) return false;
    const auto* section = find_section(image, relocation.section);
    if (section == nullptr || relocation.offset > section->contents.size()
        || 4U > section->contents.size() - static_cast<std::size_t>(relocation.offset)) {
        return false;
    }
    std::uint32_t word = 0;
    for (std::size_t index = 0; index < 4U; ++index) {
        word |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(
                    section->contents[static_cast<std::size_t>(relocation.offset) + index]))
            << static_cast<unsigned int>(index * 8U);
    }
    return (word & 0xfc000000U) == 0x94000000U;
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
            const bool isData = std::ranges::any_of(
                instruction->references, [](const auto& reference) {
                    return reference.kind == InstructionReferenceKind::Data;
                });
            const auto referenceKind = isCall
                ? InstructionReferenceKind::CallTarget
                : (isBranch ? InstructionReferenceKind::BranchTarget
                            : (isData ? InstructionReferenceKind::Data
                                      : InstructionReferenceKind::Relocation));
            if (isCall || isBranch || isData) {
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

void trim_exported_return_tail(
    AnalysisReport& report,
    Function& function,
    std::uint64_t functionOffset) {
    if (function.discovery != FunctionDiscovery::Export || function.instructions.empty()) return;
    std::size_t returnIndex = function.instructions.size();
    for (std::size_t index = 0; index < function.instructions.size(); ++index) {
        const auto* instruction = find_instruction(report.image, function.instructions[index]);
        if (instruction == nullptr) return;
        if (instruction->kind == InstructionKind::DirectBranch
            || instruction->kind == InstructionKind::ConditionalBranch
            || instruction->kind == InstructionKind::IndirectBranch) {
            return;
        }
        if (instruction->kind == InstructionKind::Return
            || instruction->kind == InstructionKind::Trap) {
            returnIndex = index;
            break;
        }
    }
    if (returnIndex == function.instructions.size() || returnIndex + 1U == function.instructions.size()) {
        return;
    }
    const auto* terminator = find_instruction(report.image, function.instructions[returnIndex]);
    if (terminator == nullptr) return;
    const auto removed = function.instructions.size() - returnIndex - 1U;
    function.size = terminator->sectionOffset + terminator->encoding.size() - functionOffset;
    function.instructions.resize(returnIndex + 1U);
    report.image.instructions.resize(report.image.instructions.size() - removed);
    report.diagnostics.push_back(Diagnostic{
        DiagnosticSeverity::Info,
        "analysis.trimmed_export_tail",
        "excluded unreachable tail from inferred exported function " + function.name,
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
    std::uint64_t& nextId,
    const std::map<EntityLocation, EntityId>& preservedBlockIds) {
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
        const auto preservedBlock = preservedBlockIds.find(
            EntityLocation{function.id.value(), begin});
        const auto blockId = preservedBlock == preservedBlockIds.end()
            ? EntityId{nextId++} : preservedBlock->second;
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
    const auto* functionSection = find_section(report.image, function.section);
    auto target_is_owned_code = [&](BinaryAddress target) -> bool {
        if (functionSection == nullptr || target.kind != functionSection->address.kind
            || target.value < functionSection->address.value) {
            return false;
        }
        return target.value - functionSection->address.value
            < functionSection->contents.size();
    };
    auto target_is_instruction_boundary = [&](BinaryAddress target) -> bool {
        if (!target_is_owned_code(target)) return false;
        if (report.image.architecture == Architecture::ARM64) {
            return (target.value - functionSection->address.value) % 4U == 0U;
        }
        return std::ranges::any_of(report.image.instructions, [&](const auto& instruction) {
            return instruction.section == function.section && instruction.address == target;
        });
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
            if (!target.has_value() && target_is_owned_code(*terminator->directTarget)
                && !target_is_instruction_boundary(*terminator->directTarget)) {
                function.complete = false;
                report.diagnostics.push_back(warning(
                    "analysis.invalid_branch_target",
                    "function " + function.name
                        + " has a control-flow target that is not an instruction boundary"));
            } else if (!target.has_value()
                && !target_is_owned_code(*terminator->directTarget)
                && (terminator->kind == InstructionKind::DirectBranch
                    || terminator->kind == InstructionKind::ConditionalBranch)) {
                function.complete = false;
                report.diagnostics.push_back(warning(
                    "analysis.branch_target_outside_code",
                    "function " + function.name
                        + " has a branch target outside its owned code section"));
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
    auto nextId = next_entity_id(report.image);
    if (nextId == std::numeric_limits<std::uint64_t>::max()) {
        return Result<AnalysisReport, Diagnostic>::failure(error(
            "analysis.id_exhausted", "no stable entity IDs remain for analysis"));
    }
    std::unordered_map<std::uint64_t, EntityId> functionIdsBySymbol;
    std::map<EntityLocation, EntityId> instructionIdsByLocation;
    std::map<EntityLocation, EntityId> blockIdsByLocation;
    for (const auto& function : report.image.functions) {
        if (function.symbol.has_value()) {
            functionIdsBySymbol.emplace(function.symbol->value(), function.id);
        }
    }
    for (const auto& instruction : report.image.instructions) {
        instructionIdsByLocation.emplace(
            EntityLocation{instruction.section.value(), instruction.sectionOffset},
            instruction.id);
    }
    for (const auto& block : report.image.basicBlocks) {
        blockIdsByLocation.emplace(
            EntityLocation{block.function.value(), block.sectionOffset}, block.id);
    }

    std::vector<Candidate> candidates;
    std::set<EntityLocation> candidateLocations;
    std::set<std::uint64_t> symbolCandidateIds;
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
        const auto preserved = functionIdsBySymbol.find(symbol.id.value());
        candidates.push_back(Candidate{
            .symbol = &symbol,
            .section = section,
            .preservedId = preserved == functionIdsBySymbol.end()
                ? std::optional<EntityId>{} : std::optional{preserved->second},
            .name = symbol.name,
            .address = symbol.address,
            .declaredSize = symbol.size,
            .discovery = FunctionDiscovery::Symbol,
            .externallyVisible = symbol.visibility == SymbolVisibility::External,
            .lineageSource = symbol.id,
            .offset = offset,
            .offsetValid = baseValid && offset < section->contents.size()
                && (report.image.architecture != Architecture::ARM64
                    || offset % 4U == 0U),
        });
        candidateLocations.insert(EntityLocation{section->id.value(), offset});
        symbolCandidateIds.insert(symbol.id.value());
    }
    for (const auto& function : report.image.functions) {
        if (function.symbol.has_value()
            && symbolCandidateIds.contains(function.symbol->value())) {
            continue;
        }
        const auto* section = find_section(report.image, function.section);
        if (section == nullptr || section->kind != SectionKind::Code || !section->executable) {
            continue;
        }
        const bool baseValid = function.address.value >= section->address.value;
        const auto offset = baseValid
            ? function.address.value - section->address.value : UINT64_C(0);
        if (candidateLocations.contains(EntityLocation{section->id.value(), offset})) {
            continue;
        }
        candidates.push_back(Candidate{
            .symbol = nullptr,
            .section = section,
            .preservedId = function.id,
            .name = function.name,
            .address = function.address,
            .declaredSize = function.size,
            .discovery = function.discovery,
            .externallyVisible = function.externallyVisible,
            .lineageSource = function.lineage.parents.empty()
                ? function.section : function.lineage.parents.front().source,
            .offset = offset,
            .offsetValid = baseValid && offset < section->contents.size()
                && (report.image.architecture != Architecture::ARM64
                    || offset % 4U == 0U),
        });
        candidateLocations.insert(EntityLocation{section->id.value(), offset});
    }
    for (const auto& relocation : report.image.relocations) {
        if (!is_arm64_call_relocation(report.image, relocation)
            || !relocation.targetSymbol.has_value()) {
            continue;
        }
        const auto* symbol = find_symbol(report.image, *relocation.targetSymbol);
        if (symbol == nullptr || !symbol->defined || !symbol->section.has_value()
            || is_aarch64_mapping_symbol(symbol->name)) {
            continue;
        }
        const auto* section = find_section(report.image, *symbol->section);
        if (section == nullptr || section->kind != SectionKind::Code || !section->executable
            || symbol->address.value < section->address.value) {
            continue;
        }
        const auto baseOffset = symbol->address.value - section->address.value;
        const auto resolvedOffset = add_signed_checked(baseOffset, relocation.addend);
        const auto resolvedAddress = resolvedOffset.has_value()
            ? add_checked(section->address.value, *resolvedOffset) : std::nullopt;
        if (!resolvedOffset.has_value() || !resolvedAddress.has_value()
            || candidateLocations.contains(EntityLocation{
                section->id.value(), *resolvedOffset})) {
            continue;
        }
        candidates.push_back(Candidate{
            .symbol = symbol->kind == SymbolKind::Section ? nullptr : symbol,
            .section = section,
            .preservedId = {},
            .name = symbol->kind == SymbolKind::Section || symbol->name.empty()
                ? "relocation_" + std::to_string(relocation.id.value()) : symbol->name,
            .address = BinaryAddress{*resolvedAddress, section->address.kind},
            .declaredSize = 0,
            .discovery = FunctionDiscovery::Relocation,
            .externallyVisible = false,
            .lineageSource = relocation.id,
            .offset = *resolvedOffset,
            .offsetValid = *resolvedOffset < section->contents.size()
                && *resolvedOffset % 4U == 0U,
        });
        candidateLocations.insert(EntityLocation{section->id.value(), *resolvedOffset});
    }
    report.image.instructions.clear();
    report.image.basicBlocks.clear();
    report.image.functions.clear();

    std::sort(candidates.begin(), candidates.end(), [](const auto& left, const auto& right) {
        if (left.section->formatIndex != right.section->formatIndex) {
            return left.section->formatIndex < right.section->formatIndex;
        }
        if (left.offset != right.offset) return left.offset < right.offset;
        return left.lineageSource.value() < right.lineageSource.value();
    });
    for (std::size_t candidateIndex = 0; candidateIndex < candidates.size(); ++candidateIndex) {
        const auto& candidate = candidates[candidateIndex];
        const auto functionId = candidate.preservedId.has_value()
            ? *candidate.preservedId : EntityId{nextId++};
        bool complete = candidate.offsetValid;
        std::uint64_t end = candidate.offset;
        if (!candidate.offsetValid) {
            const bool arm64Unaligned = report.image.architecture == Architecture::ARM64
                && candidate.offset < candidate.section->contents.size()
                && candidate.offset % 4U != 0U;
            report.diagnostics.push_back(warning(
                arm64Unaligned ? "analysis.arm64_unaligned_function"
                               : "analysis.function_out_of_range",
                "function " + candidate.name + (arm64Unaligned
                    ? " starts at a non-instruction-aligned offset"
                    : " starts outside its code section")));
        } else {
            const auto declaredEnd = candidate.declaredSize == 0
                ? std::optional<std::uint64_t>{}
                : add_checked(candidate.offset, candidate.declaredSize);
            const bool hasNext = candidateIndex + 1 < candidates.size()
                && candidates[candidateIndex + 1].section->id == candidate.section->id;
            const auto sectionEnd = static_cast<std::uint64_t>(
                candidate.section->contents.size());
            auto nextOffset = hasNext
                ? std::min(candidates[candidateIndex + 1].offset, sectionEnd)
                : sectionEnd;
            if (report.image.architecture == Architecture::ARM64
                && candidate.declaredSize == 0) {
                for (const auto& symbol : report.image.symbols) {
                    if (!symbol.defined || symbol.section != candidate.section->id
                        || !is_aarch64_data_mapping_symbol(symbol.name)
                        || symbol.address.value < candidate.section->address.value) {
                        continue;
                    }
                    const auto mappingOffset = symbol.address.value
                        - candidate.section->address.value;
                    if (mappingOffset > candidate.offset) {
                        nextOffset = std::min(nextOffset, mappingOffset);
                    }
                }
            }
            if (candidate.declaredSize == 0) {
                end = nextOffset;
            } else if (!declaredEnd.has_value()
                || *declaredEnd > candidate.section->contents.size()) {
                end = std::min(
                    nextOffset, static_cast<std::uint64_t>(candidate.section->contents.size()));
                complete = false;
                report.diagnostics.push_back(warning(
                    "analysis.function_out_of_range",
                    "function " + candidate.name + " extends outside its code section"));
            } else {
                end = *declaredEnd;
                if (hasNext && nextOffset < end) {
                    end = nextOffset;
                    complete = false;
                    report.diagnostics.push_back(warning(
                        "analysis.overlapping_functions",
                        "function " + candidate.name
                            + " overlaps the next symbol-proven function"));
                }
            }
            if (report.image.architecture == Architecture::ARM64
                && (end - candidate.offset) % 4U != 0U) {
                end -= (end - candidate.offset) % 4U;
                complete = false;
                report.diagnostics.push_back(warning(
                    "analysis.arm64_incomplete_word",
                    "function " + candidate.name
                        + " ends with an incomplete ARM64 instruction word"));
            }
            if (end <= candidate.offset) {
                complete = false;
                end = candidate.offset;
                report.diagnostics.push_back(warning(
                    "analysis.empty_function_range",
                    "function " + candidate.name + " has no decodable byte range"));
            }
        }

        Function function{
            .id = functionId,
            .name = candidate.name,
            .section = candidate.section->id,
            .symbol = candidate.symbol == nullptr
                ? std::optional<EntityId>{} : std::optional{candidate.symbol->id},
            .address = candidate.address,
            .size = end >= candidate.offset ? end - candidate.offset : 0,
            .discovery = candidate.discovery,
            .instructions = {},
            .basicBlocks = {},
            .entryBlock = std::nullopt,
            .externallyVisible = candidate.externallyVisible,
            .complete = complete,
            .lineage = TransformationLineage{{TransformationRecord{
                .transform = TransformId{functionId.value()},
                .source = candidate.lineageSource,
                .passName = candidate.discovery == FunctionDiscovery::Symbol
                    ? "symbol-function-discovery" : "evidence-function-discovery",
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
            const auto preservedInstruction = instructionIdsByLocation.find(
                EntityLocation{candidate.section->id.value(), cursor});
            const auto instructionId = preservedInstruction == instructionIdsByLocation.end()
                ? EntityId{nextId++} : preservedInstruction->second;
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
            if (instruction.encoding.empty() || instruction.encoding.size() > remaining
                || (report.image.architecture == Architecture::ARM64
                    && instruction.encoding.size() != 4U)) {
                return Result<AnalysisReport, Diagnostic>::failure(error(
                    "analysis.decoder_contract_violation",
                    "instruction decoder returned an invalid encoding length"));
            }
            function.instructions.push_back(instruction.id);
            cursor += instruction.encoding.size();
            report.image.instructions.push_back(std::move(instruction));
        }
        if (candidate.declaredSize == 0) {
            trim_inferred_alignment_padding(report, function, candidate.offset);
            trim_exported_return_tail(report, function, candidate.offset);
        }
        attach_relocation_references(report.image, function);
        recover_cfg(report, function, nextId, blockIdsByLocation);
        recover_liveness(report, function);
        report.image.functions.push_back(std::move(function));
    }
    return Result<AnalysisReport, Diagnostic>::success(std::move(report));
}

} // namespace binobf

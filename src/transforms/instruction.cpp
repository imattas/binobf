#include <binobf/transforms/instruction.hpp>

#include <binobf/analysis/instruction_decoder.hpp>
#include <binobf/analysis/object_analyzer.hpp>
#include <binobf/support/deterministic_rng.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace binobf {
namespace {

constexpr std::uint64_t substitutionSalt = UINT64_C(0x7375627374697475);
constexpr std::uint64_t constantSalt = UINT64_C(0x636f6e7374616e74);
constexpr std::uint64_t deadCodeSalt = UINT64_C(0x646561642d636f64);
constexpr std::uint64_t layoutSalt = UINT64_C(0x6c61796f75742d76);

auto diagnostic(
    DiagnosticSeverity severity,
    std::string code,
    std::string message) -> Diagnostic {
    return Diagnostic{severity, std::move(code), std::move(message)};
}

auto machine_requirements(bool requiresCfg, bool requiresFullRelocations)
    -> PassRequirements {
    return PassRequirements{
        .requiresCfg = requiresCfg,
        .requiresFullRelocations = requiresFullRelocations,
        .requiresLiftedIr = false,
        .changesCodeSize = false,
        .supportedPostLink = false,
        .risk = PassRisk::Medium,
        .formats = {BinaryFormat::COFF, BinaryFormat::ELF},
        .architectures = {Architecture::X86_64},
    };
}

auto supports_machine_pass(const BinaryImage& image) -> bool {
    return image.type == BinaryType::RelocatableObject
        && image.architecture == Architecture::X86_64
        && (image.format == BinaryFormat::COFF || image.format == BinaryFormat::ELF);
}

auto find_section(BinaryImage& image, EntityId id) -> Section* {
    const auto found = std::find_if(
        image.sections.begin(), image.sections.end(), [id](const auto& section) {
            return section.id == id;
        });
    return found == image.sections.end() ? nullptr : &*found;
}

auto find_instruction(const BinaryImage& image, EntityId id) -> const Instruction* {
    const auto found = std::find_if(
        image.instructions.begin(), image.instructions.end(), [id](const auto& instruction) {
            return instruction.id == id;
        });
    return found == image.instructions.end() ? nullptr : &*found;
}

auto find_symbol(const BinaryImage& image, EntityId id) -> const Symbol* {
    const auto found = std::find_if(
        image.symbols.begin(), image.symbols.end(), [id](const auto& symbol) {
            return symbol.id == id;
        });
    return found == image.symbols.end() ? nullptr : &*found;
}

auto relocation_overlaps(
    const BinaryImage& image,
    EntityId section,
    std::uint64_t begin,
    std::uint64_t size) -> bool {
    if (size > std::numeric_limits<std::uint64_t>::max() - begin) return true;
    const auto end = begin + size;
    return std::any_of(
        image.relocations.begin(), image.relocations.end(),
        [section, begin, end](const auto& relocation) {
            return relocation.section == section
                && relocation.offset >= begin && relocation.offset < end;
        });
}

auto range_has_interior_target(
    const BinaryImage& image,
    EntityId section,
    std::uint64_t begin,
    std::uint64_t end) -> bool {
    const auto symbolTargets = std::any_of(
        image.symbols.begin(), image.symbols.end(), [section, begin, end](const auto& symbol) {
            return symbol.defined && symbol.section == section
                && symbol.address.value > begin && symbol.address.value < end;
        });
    if (symbolTargets) return true;
    return std::any_of(
        image.instructions.begin(), image.instructions.end(),
        [section, begin, end](const auto& instruction) {
            return instruction.section == section && instruction.directTarget.has_value()
                && instruction.directTarget->value > begin
                && instruction.directTarget->value < end;
        });
}

void append_lineage(
    Section& section,
    TransformId transform,
    std::string_view passName) {
    section.lineage.parents.push_back(TransformationRecord{
        .transform = transform,
        .source = section.id,
        .passName = std::string{passName},
    });
}

void clear_changed_coff_section_checksums(
    BinaryImage& image,
    const std::unordered_set<std::uint64_t>& sectionIds,
    TransformId transform,
    std::string_view passName) {
    if (image.format != BinaryFormat::COFF) return;
    for (auto& symbol : image.symbols) {
        if (symbol.kind != SymbolKind::Section || !symbol.section.has_value()
            || !sectionIds.contains(symbol.section->value())
            || symbol.auxiliaryData.size() < 12) continue;
        const auto begin = symbol.auxiliaryData.begin() + 8;
        const auto end = symbol.auxiliaryData.begin() + 12;
        if (std::all_of(begin, end, [](std::byte value) { return value == std::byte{0}; })) {
            continue;
        }
        std::fill(begin, end, std::byte{0});
        symbol.lineage.parents.push_back(TransformationRecord{
            .transform = transform,
            .source = symbol.id,
            .passName = std::string{passName},
        });
    }
}

auto verify_functions(
    const BinaryImage& image,
    const std::unordered_set<std::uint64_t>& symbolIds,
    std::string_view passName) -> std::optional<Diagnostic> {
    const auto analyzed = analyze_object(image);
    if (!analyzed.has_value()) {
        return diagnostic(
            DiagnosticSeverity::Error,
            "pass.semantic_verification_failed",
            std::string{passName} + " could not reanalyze its candidate: "
                + analyzed.error().code + ": " + analyzed.error().message);
    }
    for (const auto symbolId : symbolIds) {
        const auto found = std::find_if(
            analyzed.value().image.functions.begin(),
            analyzed.value().image.functions.end(),
            [symbolId](const auto& function) {
                return function.symbol.has_value()
                    && function.symbol->value() == symbolId;
            });
        if (found == analyzed.value().image.functions.end() || !found->complete) {
            return diagnostic(
                DiagnosticSeverity::Error,
                "pass.semantic_verification_failed",
                std::string{passName}
                    + " produced an incomplete or undiscoverable function");
        }
    }
    return std::nullopt;
}

auto unchanged_result(
    PassStatistics statistics,
    std::string_view passName) -> Result<TransformResult, Diagnostic> {
    std::vector<Diagnostic> diagnostics;
    diagnostics.push_back(diagnostic(
        DiagnosticSeverity::Info,
        "pass.no_eligible_instructions",
        std::string{passName} + " found no proven-safe candidate"));
    return Result<TransformResult, Diagnostic>::success(TransformResult{
        .changed = false,
        .statistics = statistics,
        .diagnostics = std::move(diagnostics),
    });
}

auto successful_result(PassStatistics statistics)
    -> Result<TransformResult, Diagnostic> {
    return Result<TransformResult, Diagnostic>::success(TransformResult{
        .changed = true,
        .statistics = statistics,
        .diagnostics = {},
    });
}

auto decoded_replacement(
    const Instruction& source,
    Architecture architecture,
    std::span<const std::byte> replacement) -> std::optional<Instruction> {
    auto decoder = make_instruction_decoder();
    if (!decoder.has_value()) return std::nullopt;
    auto decoded = decoder.value()->decode(DecodeRequest{
        .architecture = architecture,
        .bytes = replacement,
        .address = source.address,
        .instructionId = source.id,
        .sectionId = source.section,
        .sectionOffset = source.sectionOffset,
    });
    if (!decoded.has_value()) return std::nullopt;
    return std::move(decoded).value();
}

class InstructionSubstitutionPass final : public TransformPass {
public:
    auto name() const noexcept -> std::string_view override {
        return "instruction-substitution";
    }
    auto dependencies() const -> std::vector<std::string> override { return {}; }
    auto requirements() const -> PassRequirements override {
        return machine_requirements(false, false);
    }
    auto supports(const TransformContext&, const BinaryImage& image) const -> bool override {
        return supports_machine_pass(image);
    }

    auto run(TransformContext& context, BinaryImage& image) const
        -> Result<TransformResult, Diagnostic> override {
        const auto analyzed = analyze_object(image);
        if (!analyzed.has_value()) {
            return Result<TransformResult, Diagnostic>::failure(analyzed.error());
        }
        PassStatistics statistics;
        DeterministicRng rng{context.seed() ^ substitutionSalt};
        TransformId transform;
        std::unordered_set<std::uint64_t> changedFunctions;
        std::unordered_set<std::uint64_t> changedSections;
        for (const auto& function : analyzed.value().image.functions) {
            if (!function.complete || !function.symbol.has_value()) continue;
            if (!context.is_function_selected(analyzed.value().image, function)) {
                ++statistics.examined;
                ++statistics.skipped;
                continue;
            }
            for (const auto instructionId : function.instructions) {
                const auto* instruction = find_instruction(analyzed.value().image, instructionId);
                if (instruction == nullptr || instruction->mnemonic != "nop"
                    || instruction->encoding.size() < 3
                    || instruction->encoding.at(0) != std::byte{0x0f}
                    || instruction->encoding.at(1) != std::byte{0x1f}) {
                    continue;
                }
                ++statistics.examined;
                if (relocation_overlaps(
                        image, instruction->section, instruction->sectionOffset,
                        instruction->encoding.size())) {
                    ++statistics.skipped;
                    continue;
                }
                auto replacement = instruction->encoding;
                bool accepted = false;
                for (std::size_t attempt = 0; attempt < 32 && !accepted; ++attempt) {
                    replacement = instruction->encoding;
                    const auto mask = static_cast<unsigned int>(rng.uniform(255) + 1U);
                    replacement.back() ^= static_cast<std::byte>(mask);
                    const auto decoded = decoded_replacement(
                        *instruction, image.architecture, replacement);
                    accepted = decoded.has_value()
                        && decoded->encoding.size() == replacement.size()
                        && decoded->mnemonic == "nop"
                        && decoded->registersRead.empty()
                        && decoded->registersWritten.empty();
                }
                if (!accepted || replacement == instruction->encoding) {
                    ++statistics.skipped;
                    continue;
                }
                auto* section = find_section(image, instruction->section);
                if (section == nullptr
                    || instruction->sectionOffset > section->contents.size()
                    || replacement.size()
                        > section->contents.size()
                            - static_cast<std::size_t>(instruction->sectionOffset)) {
                    return Result<TransformResult, Diagnostic>::failure(diagnostic(
                        DiagnosticSeverity::Error,
                        "pass.invalid_instruction_range",
                        "instruction substitution range is outside its section"));
                }
                std::copy(
                    replacement.begin(), replacement.end(),
                    section->contents.begin()
                        + static_cast<std::ptrdiff_t>(instruction->sectionOffset));
                if (!transform.valid()) transform = context.allocate_transform_id();
                if (changedSections.insert(section->id.value()).second) {
                    append_lineage(*section, transform, name());
                }
                changedFunctions.insert(function.symbol->value());
                ++statistics.changed;
            }
        }
        statistics.skipped += statistics.examined - statistics.changed - statistics.skipped;
        if (statistics.changed == 0) return unchanged_result(statistics, name());
        clear_changed_coff_section_checksums(image, changedSections, transform, name());
        if (const auto error = verify_functions(image, changedFunctions, name())) {
            return Result<TransformResult, Diagnostic>::failure(*error);
        }
        return successful_result(statistics);
    }
};

auto read_u32(std::span<const std::byte> bytes, std::size_t offset) -> std::uint32_t {
    std::uint32_t result = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        result |= static_cast<std::uint32_t>(std::to_integer<unsigned int>(bytes[offset + index]))
            << (index * 8U);
    }
    return result;
}

auto read_u64(std::span<const std::byte> bytes, std::size_t offset) -> std::uint64_t {
    std::uint64_t result = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        result |= static_cast<std::uint64_t>(std::to_integer<unsigned int>(bytes[offset + index]))
            << (index * 8U);
    }
    return result;
}

void append_u32(std::vector<std::byte>& output, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        output.push_back(static_cast<std::byte>((value >> (index * 8U)) & 0xffU));
    }
}

class ConstantRewritingPass final : public TransformPass {
public:
    auto name() const noexcept -> std::string_view override {
        return "constant-rewriting";
    }
    auto dependencies() const -> std::vector<std::string> override { return {}; }
    auto requirements() const -> PassRequirements override {
        return machine_requirements(false, false);
    }
    auto supports(const TransformContext&, const BinaryImage& image) const -> bool override {
        return supports_machine_pass(image);
    }

    auto run(TransformContext& context, BinaryImage& image) const
        -> Result<TransformResult, Diagnostic> override {
        const auto analyzed = analyze_object(image);
        if (!analyzed.has_value()) {
            return Result<TransformResult, Diagnostic>::failure(analyzed.error());
        }
        PassStatistics statistics;
        DeterministicRng rng{context.seed() ^ constantSalt};
        TransformId transform;
        std::unordered_set<std::uint64_t> changedFunctions;
        std::unordered_set<std::uint64_t> changedSections;
        for (const auto& function : analyzed.value().image.functions) {
            if (!function.complete || !function.symbol.has_value()) continue;
            if (!context.is_function_selected(analyzed.value().image, function)) {
                ++statistics.examined;
                ++statistics.skipped;
                continue;
            }
            for (std::size_t position = 0; position < function.instructions.size(); ++position) {
                const auto* instruction = find_instruction(
                    analyzed.value().image, function.instructions[position]);
                if (instruction == nullptr
                    || (instruction->mnemonic != "mov"
                        && instruction->mnemonic != "movabs")) continue;
                const auto source = std::span<const std::byte>{instruction->encoding};
                std::size_t opcodeIndex = 0;
                std::uint8_t rex = 0;
                if (!source.empty()) {
                    const auto first = std::to_integer<std::uint8_t>(source.front());
                    if (first >= 0x40U && first <= 0x4fU) {
                        rex = first;
                        opcodeIndex = 1;
                    }
                }
                if (opcodeIndex >= source.size()) continue;
                const auto opcode = std::to_integer<std::uint8_t>(source[opcodeIndex]);
                if (opcode < 0xb8U || opcode > 0xbfU || (rex & 0x06U) != 0) continue;
                const bool wide = (rex & 0x08U) != 0;
                const auto immediateSize = wide ? std::size_t{8} : std::size_t{4};
                if (source.size() != opcodeIndex + 1 + immediateSize) continue;
                ++statistics.examined;
                const auto registerIndex = static_cast<std::uint8_t>(
                    (opcode - 0xb8U) + ((rex & 0x01U) != 0 ? 8U : 0U));
                std::uint32_t immediate = 0;
                std::size_t windowSize = source.size();
                if (wide) {
                    const auto value = read_u64(source, opcodeIndex + 1);
                    immediate = static_cast<std::uint32_t>(value);
                    const auto signedValue = std::bit_cast<std::int64_t>(value);
                    if (signedValue != static_cast<std::int64_t>(
                            static_cast<std::int32_t>(immediate))) {
                        ++statistics.skipped;
                        continue;
                    }
                } else {
                    immediate = read_u32(source, opcodeIndex + 1);
                    if (position + 1 >= function.instructions.size()) {
                        ++statistics.skipped;
                        continue;
                    }
                    const auto* next = find_instruction(
                        analyzed.value().image, function.instructions[position + 1]);
                    if (next == nullptr || next->section != instruction->section
                        || next->sectionOffset != instruction->sectionOffset + source.size()
                        || next->encoding != std::vector<std::byte>{std::byte{0x90}}
                        || range_has_interior_target(
                            analyzed.value().image, instruction->section,
                            instruction->sectionOffset,
                            instruction->sectionOffset + source.size() + 1)) {
                        ++statistics.skipped;
                        continue;
                    }
                    ++windowSize;
                }
                if (relocation_overlaps(
                        image, instruction->section, instruction->sectionOffset, windowSize)) {
                    ++statistics.skipped;
                    continue;
                }
                std::vector<std::byte> replacement;
                replacement.reserve(windowSize);
                std::uint8_t replacementRex = 0;
                if (wide) replacementRex = 0x48U;
                else if (registerIndex >= 8U) replacementRex = 0x41U;
                if (registerIndex >= 8U && wide) replacementRex |= 0x01U;
                if (replacementRex != 0) replacement.push_back(static_cast<std::byte>(replacementRex));
                replacement.push_back(std::byte{0xc7});
                replacement.push_back(static_cast<std::byte>(0xc0U | (registerIndex & 0x07U)));
                append_u32(replacement, immediate);
                while (replacement.size() < windowSize) replacement.push_back(std::byte{0x90});
                if (wide && windowSize - (replacementRex != 0 ? 7U : 6U) >= 3U) {
                    const auto fill = replacement.size() - 3;
                    replacement[fill] = std::byte{0x0f};
                    replacement[fill + 1] = std::byte{0x1f};
                    replacement[fill + 2] = static_cast<std::byte>(rng.uniform(4));
                }
                const auto decoded = decoded_replacement(
                    *instruction, image.architecture,
                    std::span<const std::byte>{replacement}.first(
                        replacementRex != 0 ? 7U : 6U));
                if (!decoded.has_value() || decoded->mnemonic != "mov") {
                    ++statistics.skipped;
                    continue;
                }
                auto* section = find_section(image, instruction->section);
                if (section == nullptr
                    || instruction->sectionOffset > section->contents.size()
                    || windowSize > section->contents.size()
                        - static_cast<std::size_t>(instruction->sectionOffset)) {
                    return Result<TransformResult, Diagnostic>::failure(diagnostic(
                        DiagnosticSeverity::Error,
                        "pass.invalid_instruction_range",
                        "constant rewrite range is outside its section"));
                }
                std::copy(
                    replacement.begin(), replacement.end(),
                    section->contents.begin()
                        + static_cast<std::ptrdiff_t>(instruction->sectionOffset));
                if (!transform.valid()) transform = context.allocate_transform_id();
                if (changedSections.insert(section->id.value()).second) {
                    append_lineage(*section, transform, name());
                }
                changedFunctions.insert(function.symbol->value());
                ++statistics.changed;
                if (!wide) ++position;
            }
        }
        statistics.skipped += statistics.examined - statistics.changed - statistics.skipped;
        if (statistics.changed == 0) return unchanged_result(statistics, name());
        clear_changed_coff_section_checksums(image, changedSections, transform, name());
        if (const auto error = verify_functions(image, changedFunctions, name())) {
            return Result<TransformResult, Diagnostic>::failure(*error);
        }
        return successful_result(statistics);
    }
};

struct BranchEncoding {
    std::size_t displacementOffset{0};
    std::size_t displacementSize{0};
};

auto conditional_encoding(std::span<const std::byte> bytes) -> std::optional<BranchEncoding> {
    if (bytes.size() == 2) {
        const auto opcode = std::to_integer<std::uint8_t>(bytes[0]);
        if (opcode >= 0x70U && opcode <= 0x7fU) return BranchEncoding{1, 1};
    }
    if (bytes.size() == 6 && bytes[0] == std::byte{0x0f}) {
        const auto opcode = std::to_integer<std::uint8_t>(bytes[1]);
        if (opcode >= 0x80U && opcode <= 0x8fU) return BranchEncoding{2, 4};
    }
    return std::nullopt;
}

auto direct_branch_encoding(std::span<const std::byte> bytes) -> std::optional<BranchEncoding> {
    if (bytes.size() == 2 && bytes[0] == std::byte{0xeb}) return BranchEncoding{1, 1};
    if (bytes.size() == 5 && bytes[0] == std::byte{0xe9}) return BranchEncoding{1, 4};
    return std::nullopt;
}

auto write_displacement(
    std::vector<std::byte>& bytes,
    const BranchEncoding& encoding,
    std::uint64_t instructionAddress,
    std::uint64_t target) -> bool {
    if (instructionAddress > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
        || target > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        return false;
    }
    const auto end = static_cast<std::int64_t>(instructionAddress)
        + static_cast<std::int64_t>(bytes.size());
    const auto displacement = static_cast<std::int64_t>(target) - end;
    if (encoding.displacementSize == 1) {
        if (displacement < std::numeric_limits<std::int8_t>::min()
            || displacement > std::numeric_limits<std::int8_t>::max()) return false;
        bytes[encoding.displacementOffset] = static_cast<std::byte>(
            static_cast<std::uint8_t>(static_cast<std::int8_t>(displacement)));
        return true;
    }
    if (displacement < std::numeric_limits<std::int32_t>::min()
        || displacement > std::numeric_limits<std::int32_t>::max()) return false;
    const auto encoded = static_cast<std::uint32_t>(static_cast<std::int32_t>(displacement));
    for (std::size_t index = 0; index < 4; ++index) {
        bytes[encoding.displacementOffset + index] =
            static_cast<std::byte>((encoded >> (index * 8U)) & 0xffU);
    }
    return true;
}

class BranchInversionPass final : public TransformPass {
public:
    auto name() const noexcept -> std::string_view override { return "branch-inversion"; }
    auto dependencies() const -> std::vector<std::string> override { return {}; }
    auto requirements() const -> PassRequirements override {
        return machine_requirements(true, false);
    }
    auto supports(const TransformContext&, const BinaryImage& image) const -> bool override {
        return supports_machine_pass(image);
    }

    auto run(TransformContext& context, BinaryImage& image) const
        -> Result<TransformResult, Diagnostic> override {
        const auto analyzed = analyze_object(image);
        if (!analyzed.has_value()) {
            return Result<TransformResult, Diagnostic>::failure(analyzed.error());
        }
        PassStatistics statistics;
        TransformId transform;
        std::unordered_set<std::uint64_t> changedFunctions;
        std::unordered_set<std::uint64_t> changedSections;
        for (const auto& function : analyzed.value().image.functions) {
            if (!function.complete || !function.symbol.has_value()) {
                ++statistics.examined;
                ++statistics.skipped;
                continue;
            }
            if (!context.is_function_selected(analyzed.value().image, function)) {
                ++statistics.examined;
                ++statistics.skipped;
                continue;
            }
            for (std::size_t position = 0; position + 1 < function.instructions.size(); ++position) {
                const auto* condition = find_instruction(
                    analyzed.value().image, function.instructions[position]);
                const auto* jump = find_instruction(
                    analyzed.value().image, function.instructions[position + 1]);
                if (condition == nullptr || jump == nullptr
                    || condition->kind != InstructionKind::ConditionalBranch
                    || jump->kind != InstructionKind::DirectBranch
                    || !condition->directTarget.has_value() || !jump->directTarget.has_value()
                    || condition->section != jump->section
                    || jump->sectionOffset
                        != condition->sectionOffset + condition->encoding.size()) {
                    continue;
                }
                const auto conditionEncoding = conditional_encoding(condition->encoding);
                const auto jumpEncoding = direct_branch_encoding(jump->encoding);
                if (!conditionEncoding.has_value() || !jumpEncoding.has_value()) continue;
                ++statistics.examined;
                const auto combinedSize = condition->encoding.size() + jump->encoding.size();
                if (relocation_overlaps(
                        image, condition->section, condition->sectionOffset, combinedSize)
                    || range_has_interior_target(
                        analyzed.value().image, condition->section,
                        condition->sectionOffset,
                        condition->sectionOffset + combinedSize)) {
                    ++statistics.skipped;
                    continue;
                }
                auto replacementCondition = condition->encoding;
                auto replacementJump = jump->encoding;
                const auto conditionOpcode = conditionEncoding->displacementOffset - 1;
                replacementCondition[conditionOpcode] ^= std::byte{0x01};
                if (!write_displacement(
                        replacementCondition, *conditionEncoding,
                        condition->address.value, jump->directTarget->value)
                    || !write_displacement(
                        replacementJump, *jumpEncoding,
                        jump->address.value, condition->directTarget->value)) {
                    ++statistics.skipped;
                    continue;
                }
                auto* section = find_section(image, condition->section);
                if (section == nullptr) {
                    return Result<TransformResult, Diagnostic>::failure(diagnostic(
                        DiagnosticSeverity::Error,
                        "pass.invalid_instruction_range",
                        "branch inversion section is missing"));
                }
                auto output = section->contents.begin()
                    + static_cast<std::ptrdiff_t>(condition->sectionOffset);
                output = std::copy(
                    replacementCondition.begin(), replacementCondition.end(), output);
                std::copy(replacementJump.begin(), replacementJump.end(), output);
                if (!transform.valid()) transform = context.allocate_transform_id();
                if (changedSections.insert(section->id.value()).second) {
                    append_lineage(*section, transform, name());
                }
                changedFunctions.insert(function.symbol->value());
                ++statistics.changed;
                ++position;
            }
        }
        statistics.skipped += statistics.examined - statistics.changed - statistics.skipped;
        if (statistics.changed == 0) return unchanged_result(statistics, name());
        clear_changed_coff_section_checksums(image, changedSections, transform, name());
        if (const auto error = verify_functions(image, changedFunctions, name())) {
            return Result<TransformResult, Diagnostic>::failure(*error);
        }
        return successful_result(statistics);
    }
};

class BlockSplittingPass final : public TransformPass {
public:
    auto name() const noexcept -> std::string_view override { return "block-splitting"; }
    auto dependencies() const -> std::vector<std::string> override { return {}; }
    auto requirements() const -> PassRequirements override {
        return machine_requirements(true, false);
    }
    auto supports(const TransformContext&, const BinaryImage& image) const -> bool override {
        return supports_machine_pass(image);
    }

    auto run(TransformContext& context, BinaryImage& image) const
        -> Result<TransformResult, Diagnostic> override {
        const auto analyzed = analyze_object(image);
        if (!analyzed.has_value()) {
            return Result<TransformResult, Diagnostic>::failure(analyzed.error());
        }
        PassStatistics statistics;
        TransformId transform;
        std::unordered_set<std::uint64_t> changedFunctions;
        std::unordered_set<std::uint64_t> changedSections;
        for (const auto& function : analyzed.value().image.functions) {
            if (!function.complete || !function.symbol.has_value()) continue;
            if (!context.is_function_selected(analyzed.value().image, function)) {
                ++statistics.examined;
                ++statistics.skipped;
                continue;
            }
            bool changedFunction = false;
            for (const auto blockId : function.basicBlocks) {
                const auto block = std::find_if(
                    analyzed.value().image.basicBlocks.begin(),
                    analyzed.value().image.basicBlocks.end(),
                    [blockId](const auto& candidate) { return candidate.id == blockId; });
                if (block == analyzed.value().image.basicBlocks.end()
                    || block->instructions.size() < 3) continue;
                for (std::size_t position = 1; position + 1 < block->instructions.size(); ++position) {
                    const auto* instruction = find_instruction(
                        analyzed.value().image, block->instructions[position]);
                    if (instruction == nullptr || instruction->mnemonic != "nop"
                        || instruction->encoding.size() < 2) continue;
                    ++statistics.examined;
                    if (relocation_overlaps(
                            image, instruction->section, instruction->sectionOffset,
                            instruction->encoding.size())
                        || range_has_interior_target(
                            analyzed.value().image, instruction->section,
                            instruction->sectionOffset,
                            instruction->sectionOffset + instruction->encoding.size())) {
                        ++statistics.skipped;
                        continue;
                    }
                    auto* section = find_section(image, instruction->section);
                    if (section == nullptr) {
                        return Result<TransformResult, Diagnostic>::failure(diagnostic(
                            DiagnosticSeverity::Error,
                            "pass.invalid_instruction_range",
                            "block-splitting section is missing"));
                    }
                    const auto offset = static_cast<std::size_t>(instruction->sectionOffset);
                    section->contents[offset] = std::byte{0xeb};
                    section->contents[offset + 1] = std::byte{0x00};
                    std::fill(
                        section->contents.begin() + static_cast<std::ptrdiff_t>(offset + 2),
                        section->contents.begin() + static_cast<std::ptrdiff_t>(
                            offset + instruction->encoding.size()),
                        std::byte{0x90});
                    if (!transform.valid()) transform = context.allocate_transform_id();
                    if (changedSections.insert(section->id.value()).second) {
                        append_lineage(*section, transform, name());
                    }
                    changedFunctions.insert(function.symbol->value());
                    ++statistics.changed;
                    changedFunction = true;
                    break;
                }
                if (changedFunction) break;
            }
        }
        statistics.skipped += statistics.examined - statistics.changed - statistics.skipped;
        if (statistics.changed == 0) return unchanged_result(statistics, name());
        clear_changed_coff_section_checksums(image, changedSections, transform, name());
        if (const auto error = verify_functions(image, changedFunctions, name())) {
            return Result<TransformResult, Diagnostic>::failure(*error);
        }
        const auto after = analyze_object(image);
        if (!after.has_value()
            || after.value().image.basicBlocks.size()
                <= analyzed.value().image.basicBlocks.size()) {
            return Result<TransformResult, Diagnostic>::failure(diagnostic(
                DiagnosticSeverity::Error,
                "pass.semantic_verification_failed",
                "block-splitting did not create an additional CFG block"));
        }
        return successful_result(statistics);
    }
};

class DeadCodeInsertionPass final : public TransformPass {
public:
    auto name() const noexcept -> std::string_view override {
        return "dead-code-insertion";
    }
    auto dependencies() const -> std::vector<std::string> override { return {}; }
    auto requirements() const -> PassRequirements override {
        return machine_requirements(true, false);
    }
    auto supports(const TransformContext&, const BinaryImage& image) const -> bool override {
        return supports_machine_pass(image);
    }

    auto run(TransformContext& context, BinaryImage& image) const
        -> Result<TransformResult, Diagnostic> override {
        const auto analyzed = analyze_object(image);
        if (!analyzed.has_value()) {
            return Result<TransformResult, Diagnostic>::failure(analyzed.error());
        }
        PassStatistics statistics;
        TransformId transform;
        DeterministicRng rng{context.seed() ^ deadCodeSalt};
        std::unordered_set<std::uint64_t> changedFunctions;
        std::unordered_set<std::uint64_t> changedSections;
        for (const auto& function : analyzed.value().image.functions) {
            if (!function.complete || !function.symbol.has_value()) continue;
            if (!context.is_function_selected(analyzed.value().image, function)) {
                ++statistics.examined;
                ++statistics.skipped;
                continue;
            }
            std::vector<const Instruction*> candidates;
            for (const auto instructionId : function.instructions) {
                const auto* instruction = find_instruction(
                    analyzed.value().image, instructionId);
                if (instruction == nullptr || instruction->mnemonic != "nop"
                    || instruction->encoding.size() < 3
                    || instruction->encoding.size() > 129) {
                    continue;
                }
                ++statistics.examined;
                const auto end = instruction->sectionOffset + instruction->encoding.size();
                const bool hasNextInstruction = std::any_of(
                    function.instructions.begin(), function.instructions.end(),
                    [&](const auto nextId) {
                        const auto* next = find_instruction(analyzed.value().image, nextId);
                        return next != nullptr && next->section == instruction->section
                            && next->sectionOffset == end;
                    });
                if (!hasNextInstruction
                    || relocation_overlaps(
                        image, instruction->section, instruction->sectionOffset,
                        instruction->encoding.size())
                    || range_has_interior_target(
                        analyzed.value().image, instruction->section,
                        instruction->sectionOffset, end)) {
                    ++statistics.skipped;
                    continue;
                }
                candidates.push_back(instruction);
            }
            if (candidates.empty()) continue;
            rng.shuffle(candidates);
            const auto* instruction = candidates.front();
            auto* section = find_section(image, instruction->section);
            if (section == nullptr) {
                return Result<TransformResult, Diagnostic>::failure(diagnostic(
                    DiagnosticSeverity::Error,
                    "pass.invalid_instruction_range",
                    "dead-code-insertion section is missing"));
            }
            const auto offset = static_cast<std::size_t>(instruction->sectionOffset);
            const auto skipped = instruction->encoding.size() - 2;
            section->contents[offset] = std::byte{0xeb};
            section->contents[offset + 1] = static_cast<std::byte>(skipped);
            std::fill(
                section->contents.begin() + static_cast<std::ptrdiff_t>(offset + 2),
                section->contents.begin() + static_cast<std::ptrdiff_t>(
                    offset + instruction->encoding.size()),
                std::byte{0x90});
            if (!transform.valid()) transform = context.allocate_transform_id();
            if (changedSections.insert(section->id.value()).second) {
                append_lineage(*section, transform, name());
            }
            changedFunctions.insert(function.symbol->value());
            ++statistics.changed;
        }
        statistics.skipped += statistics.examined - statistics.changed - statistics.skipped;
        if (statistics.changed == 0) return unchanged_result(statistics, name());
        clear_changed_coff_section_checksums(image, changedSections, transform, name());
        if (const auto error = verify_functions(image, changedFunctions, name())) {
            return Result<TransformResult, Diagnostic>::failure(*error);
        }
        return successful_result(statistics);
    }
};

struct BlockChunk {
    std::uint64_t oldBegin{0};
    std::uint64_t oldEnd{0};
    std::uint64_t newBegin{0};
    EntityId block;
};

auto map_block_offset(
    std::span<const BlockChunk> chunks,
    std::uint64_t oldOffset) -> std::optional<std::uint64_t> {
    for (const auto& chunk : chunks) {
        if (oldOffset >= chunk.oldBegin && oldOffset < chunk.oldEnd) {
            return chunk.newBegin + (oldOffset - chunk.oldBegin);
        }
    }
    return std::nullopt;
}

struct RelativeField {
    std::size_t offset{0};
    std::size_t width{0};
};

auto relative_field(const Instruction& instruction) -> std::optional<RelativeField> {
    if (instruction.encoding.empty()) return std::nullopt;
    const auto first = std::to_integer<std::uint8_t>(instruction.encoding[0]);
    if ((first == 0xe8 || first == 0xe9) && instruction.encoding.size() >= 5) {
        return RelativeField{1, 4};
    }
    if ((first == 0xeb || (first >= 0x70 && first <= 0x7f))
        && instruction.encoding.size() >= 2) {
        return RelativeField{1, 1};
    }
    if (first == 0x0f && instruction.encoding.size() >= 6) {
        const auto second = std::to_integer<std::uint8_t>(instruction.encoding[1]);
        if (second >= 0x80 && second <= 0x8f) return RelativeField{2, 4};
    }
    return std::nullopt;
}

auto patch_relative(std::vector<std::byte>& contents,
                    std::uint64_t instructionOffset,
                    std::size_t instructionSize,
                    RelativeField field,
                    std::uint64_t target) -> bool {
    if (instructionOffset > std::numeric_limits<std::uint64_t>::max() - instructionSize) {
        return false;
    }
    const auto next = instructionOffset + instructionSize;
    if (next > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
        || target > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        return false;
    }
    const auto displacement = static_cast<std::int64_t>(target)
        - static_cast<std::int64_t>(next);
    if (instructionOffset > std::numeric_limits<std::size_t>::max() - field.offset) {
        return false;
    }
    const auto position = static_cast<std::size_t>(instructionOffset) + field.offset;
    if (position > contents.size() || field.width > contents.size() - position) return false;
    if (field.width == 1) {
        if (displacement < std::numeric_limits<std::int8_t>::min()
            || displacement > std::numeric_limits<std::int8_t>::max()) {
            return false;
        }
        contents[position] = static_cast<std::byte>(
            static_cast<std::uint8_t>(static_cast<std::int8_t>(displacement)));
        return true;
    }
    if (field.width != 4 || displacement < std::numeric_limits<std::int32_t>::min()
        || displacement > std::numeric_limits<std::int32_t>::max()) {
        return false;
    }
    const auto bits = static_cast<std::uint32_t>(static_cast<std::int32_t>(displacement));
    for (std::size_t index = 0; index < 4; ++index) {
        contents[position + index] = static_cast<std::byte>((bits >> (index * 8U)) & 0xffU);
    }
    return true;
}

class BlockReorderingPass final : public TransformPass {
public:
    auto name() const noexcept -> std::string_view override {
        return "block-reordering";
    }
    auto dependencies() const -> std::vector<std::string> override { return {}; }
    auto requirements() const -> PassRequirements override {
        return machine_requirements(true, true);
    }
    auto supports(const TransformContext&, const BinaryImage& image) const -> bool override {
        return supports_machine_pass(image) && image.unwindInfo.empty();
    }

    auto run(TransformContext& context, BinaryImage& image) const
        -> Result<TransformResult, Diagnostic> override {
        const auto analyzed = analyze_object(image);
        if (!analyzed.has_value()) {
            return Result<TransformResult, Diagnostic>::failure(analyzed.error());
        }
        PassStatistics statistics;
        TransformId transform;
        DeterministicRng rng{context.seed() ^ layoutSalt ^ UINT64_C(0x626c6f636b)};
        std::unordered_set<std::uint64_t> changedFunctions;
        std::unordered_set<std::uint64_t> changedSections;
        for (const auto& function : analyzed.value().image.functions) {
            if (!function.complete || !function.symbol.has_value()
                || !function.entryBlock.has_value() || function.basicBlocks.size() < 3
                || function.size > std::numeric_limits<std::uint64_t>::max()
                    - function.address.value) {
                continue;
            }
            if (!context.is_function_selected(analyzed.value().image, function)) {
                ++statistics.examined;
                ++statistics.skipped;
                continue;
            }
            statistics.examined += function.basicBlocks.size();
            const auto begin = function.address.value;
            const auto end = begin + function.size;
            const bool hasRelocation = std::any_of(
                image.relocations.begin(), image.relocations.end(),
                [&](const auto& relocation) {
                    return relocation.section == function.section
                        && relocation.offset >= begin && relocation.offset < end;
                });
            const bool hasInteriorSymbol = std::any_of(
                image.symbols.begin(), image.symbols.end(), [&](const auto& symbol) {
                    return symbol.id != *function.symbol && symbol.kind != SymbolKind::Section
                        && symbol.defined && symbol.section == function.section
                        && symbol.address.value >= begin && symbol.address.value < end;
                });
            if (hasRelocation || hasInteriorSymbol) {
                statistics.skipped += function.basicBlocks.size();
                continue;
            }

            std::vector<const BasicBlock*> blocks;
            blocks.reserve(function.basicBlocks.size());
            bool valid = true;
            for (const auto blockId : function.basicBlocks) {
                const auto block = std::find_if(
                    analyzed.value().image.basicBlocks.begin(),
                    analyzed.value().image.basicBlocks.end(),
                    [blockId](const auto& candidate) { return candidate.id == blockId; });
                if (block == analyzed.value().image.basicBlocks.end()
                    || block->section != function.section || block->instructions.empty()
                    || block->hasUnresolvedSuccessor
                    || std::any_of(block->edges.begin(), block->edges.end(), [](const auto& edge) {
                        return edge.kind == ControlFlowEdgeKind::Fallthrough;
                    })) {
                    valid = false;
                    break;
                }
                const auto* terminator = find_instruction(
                    analyzed.value().image, block->instructions.back());
                if (terminator == nullptr
                    || (terminator->kind != InstructionKind::DirectBranch
                        && terminator->kind != InstructionKind::IndirectBranch
                        && terminator->kind != InstructionKind::Return
                        && terminator->kind != InstructionKind::Trap)) {
                    valid = false;
                    break;
                }
                blocks.push_back(&*block);
            }
            if (!valid) {
                statistics.skipped += function.basicBlocks.size();
                continue;
            }
            std::sort(blocks.begin(), blocks.end(), [](const auto* left, const auto* right) {
                return left->sectionOffset < right->sectionOffset;
            });
            if (blocks.front()->sectionOffset != begin
                || blocks.front()->id != *function.entryBlock) {
                statistics.skipped += function.basicBlocks.size();
                continue;
            }
            std::vector<BlockChunk> chunks;
            chunks.reserve(blocks.size());
            for (std::size_t index = 0; index < blocks.size(); ++index) {
                const auto chunkBegin = blocks[index]->sectionOffset;
                const auto chunkEnd = index + 1 < blocks.size()
                    ? blocks[index + 1]->sectionOffset : end;
                const auto* last = find_instruction(
                    analyzed.value().image, blocks[index]->instructions.back());
                if (chunkBegin >= chunkEnd || chunkEnd > end || last == nullptr
                    || last->sectionOffset > chunkEnd
                    || last->encoding.size() > chunkEnd - last->sectionOffset) {
                    valid = false;
                    break;
                }
                chunks.push_back(BlockChunk{
                    chunkBegin, chunkEnd, 0, blocks[index]->id});
            }
            for (const auto instructionId : function.instructions) {
                const auto* instruction = find_instruction(
                    analyzed.value().image, instructionId);
                if (instruction == nullptr || instruction->section != function.section
                    || instruction->sectionOffset < begin || instruction->sectionOffset >= end) {
                    valid = false;
                    break;
                }
                if (!instruction->directTarget.has_value()) continue;
                const auto target = instruction->directTarget->value;
                if (target < begin || target >= end
                    || !relative_field(*instruction).has_value()) {
                    valid = false;
                    break;
                }
            }
            if (!valid) {
                statistics.skipped += function.basicBlocks.size();
                continue;
            }

            std::vector<std::size_t> movable;
            movable.reserve(chunks.size() - 1);
            for (std::size_t index = 1; index < chunks.size(); ++index) {
                movable.push_back(index);
            }
            rng.shuffle(movable);
            bool identity = true;
            for (std::size_t index = 0; index < movable.size(); ++index) {
                if (movable[index] != index + 1) identity = false;
            }
            if (identity) std::rotate(movable.begin(), movable.begin() + 1, movable.end());
            std::vector<std::size_t> order{0};
            order.insert(order.end(), movable.begin(), movable.end());
            auto cursor = begin;
            for (const auto index : order) {
                chunks[index].newBegin = cursor;
                cursor += chunks[index].oldEnd - chunks[index].oldBegin;
            }

            auto* section = find_section(image, function.section);
            if (section == nullptr || end > section->contents.size()) {
                return Result<TransformResult, Diagnostic>::failure(diagnostic(
                    DiagnosticSeverity::Error,
                    "pass.invalid_instruction_range",
                    "block-reordering function range is outside its section"));
            }
            const auto original = section->contents;
            for (const auto index : order) {
                const auto oldBegin = static_cast<std::size_t>(chunks[index].oldBegin);
                const auto oldEnd = static_cast<std::size_t>(chunks[index].oldEnd);
                const auto newBegin = static_cast<std::size_t>(chunks[index].newBegin);
                std::copy(
                    original.begin() + static_cast<std::ptrdiff_t>(oldBegin),
                    original.begin() + static_cast<std::ptrdiff_t>(oldEnd),
                    section->contents.begin() + static_cast<std::ptrdiff_t>(newBegin));
            }
            for (const auto instructionId : function.instructions) {
                const auto* instruction = find_instruction(
                    analyzed.value().image, instructionId);
                if (instruction == nullptr || !instruction->directTarget.has_value()) continue;
                const auto newInstruction = map_block_offset(chunks, instruction->sectionOffset);
                const auto newTarget = map_block_offset(chunks, instruction->directTarget->value);
                const auto field = relative_field(*instruction);
                if (!newInstruction.has_value() || !newTarget.has_value()
                    || !field.has_value()
                    || !patch_relative(
                        section->contents, *newInstruction, instruction->encoding.size(),
                        *field, *newTarget)) {
                    return Result<TransformResult, Diagnostic>::failure(diagnostic(
                        DiagnosticSeverity::Error,
                        "pass.branch_out_of_range",
                        "block-reordering could not encode a moved direct branch"));
                }
            }
            if (!transform.valid()) transform = context.allocate_transform_id();
            if (changedSections.insert(section->id.value()).second) {
                append_lineage(*section, transform, name());
            }
            for (auto& symbol : image.symbols) {
                if (!symbol.defined || symbol.section != function.section
                    || symbol.address.value < begin || symbol.address.value >= end) {
                    continue;
                }
                const auto mapped = map_block_offset(chunks, symbol.address.value);
                if (!mapped.has_value()) {
                    return Result<TransformResult, Diagnostic>::failure(diagnostic(
                        DiagnosticSeverity::Error,
                        "pass.unmapped_symbol",
                        "block-reordering could not map a function symbol"));
                }
                if (*mapped != symbol.address.value) {
                    symbol.address.value = *mapped;
                    symbol.lineage.parents.push_back(TransformationRecord{
                        transform, symbol.id, std::string{name()}});
                }
            }
            changedFunctions.insert(function.symbol->value());
            statistics.changed += function.basicBlocks.size();
        }
        statistics.skipped += statistics.examined - statistics.changed - statistics.skipped;
        if (statistics.changed == 0) return unchanged_result(statistics, name());
        clear_changed_coff_section_checksums(image, changedSections, transform, name());
        if (const auto error = verify_functions(image, changedFunctions, name())) {
            return Result<TransformResult, Diagnostic>::failure(*error);
        }
        return successful_result(statistics);
    }
};

struct FunctionChunk {
    std::uint64_t oldBegin{0};
    std::uint64_t oldEnd{0};
    std::uint64_t newBegin{0};
    EntityId symbol;
};

auto map_offset(
    std::span<const FunctionChunk> chunks,
    std::uint64_t oldOffset) -> std::optional<std::uint64_t> {
    for (const auto& chunk : chunks) {
        if (oldOffset >= chunk.oldBegin && oldOffset < chunk.oldEnd) {
            return chunk.newBegin + (oldOffset - chunk.oldBegin);
        }
    }
    return std::nullopt;
}

class FunctionReorderingPass final : public TransformPass {
public:
    auto name() const noexcept -> std::string_view override { return "function-reordering"; }
    auto dependencies() const -> std::vector<std::string> override { return {}; }
    auto requirements() const -> PassRequirements override {
        return machine_requirements(true, true);
    }
    auto supports(const TransformContext&, const BinaryImage& image) const -> bool override {
        return supports_machine_pass(image)
            && image.unwindInfo.empty()
            && std::none_of(image.sections.begin(), image.sections.end(), [](const auto& section) {
                return section.kind == SectionKind::Debug;
            });
    }

    auto run(TransformContext& context, BinaryImage& image) const
        -> Result<TransformResult, Diagnostic> override {
        const auto analyzed = analyze_object(image);
        if (!analyzed.has_value()) {
            return Result<TransformResult, Diagnostic>::failure(analyzed.error());
        }
        PassStatistics statistics;
        TransformId transform;
        DeterministicRng rng{context.seed() ^ layoutSalt};
        std::unordered_set<std::uint64_t> changedFunctions;
        std::unordered_set<std::uint64_t> changedSections;
        for (auto& section : image.sections) {
            if (!section.executable || section.contents.empty()) continue;
            std::vector<const Function*> functions;
            for (const auto& function : analyzed.value().image.functions) {
                if (function.section == section.id) functions.push_back(&function);
            }
            if (functions.size() < 2) continue;
            statistics.examined += functions.size();
            if (std::any_of(functions.begin(), functions.end(), [](const auto* function) {
                    return !function->complete || !function->symbol.has_value();
                })) {
                statistics.skipped += functions.size();
                continue;
            }
            std::sort(functions.begin(), functions.end(), [](const auto* left, const auto* right) {
                return left->address.value < right->address.value;
            });
            std::vector<bool> selected(functions.size(), false);
            for (std::size_t index = 0; index < functions.size(); ++index) {
                selected[index] = context.is_function_selected(
                    analyzed.value().image, *functions[index]);
            }
            std::vector<FunctionChunk> chunks;
            chunks.reserve(functions.size());
            bool rangesValid = true;
            for (std::size_t index = 0; index < functions.size(); ++index) {
                const auto begin = functions[index]->address.value;
                const auto end = index + 1 < functions.size()
                    ? functions[index + 1]->address.value
                    : static_cast<std::uint64_t>(section.contents.size());
                if (begin >= end || end > section.contents.size()
                    || functions[index]->size > end - begin) {
                    rangesValid = false;
                    break;
                }
                chunks.push_back(FunctionChunk{
                    .oldBegin = begin,
                    .oldEnd = end,
                    .newBegin = 0,
                    .symbol = *functions[index]->symbol,
                });
            }
            if (!rangesValid) {
                statistics.skipped += functions.size();
                continue;
            }
            bool controlFlowRelocatable = true;
            for (const auto* function : functions) {
                const auto functionEnd = function->address.value + function->size;
                for (const auto instructionId : function->instructions) {
                    const auto* instruction = find_instruction(
                        analyzed.value().image, instructionId);
                    if (instruction == nullptr || !instruction->directTarget.has_value()) continue;
                    const auto target = instruction->directTarget->value;
                    const bool insideFunction = target >= function->address.value
                        && target < functionEnd;
                    const bool hasRelocation = std::any_of(
                        instruction->references.begin(), instruction->references.end(),
                        [](const auto& reference) { return reference.relocation.has_value(); });
                    if (!insideFunction && !hasRelocation) {
                        controlFlowRelocatable = false;
                        break;
                    }
                }
                if (!controlFlowRelocatable) break;
            }
            if (!controlFlowRelocatable) {
                statistics.skipped += functions.size();
                continue;
            }
            std::vector<std::size_t> order(chunks.size());
            for (std::size_t index = 0; index < order.size(); ++index) order[index] = index;
            std::vector<bool> reordered(chunks.size(), false);
            std::size_t reorderedCount = 0;
            for (std::size_t runBegin = 0; runBegin < selected.size();) {
                if (!selected[runBegin]) {
                    ++runBegin;
                    continue;
                }
                auto runEnd = runBegin + 1;
                while (runEnd < selected.size() && selected[runEnd]) ++runEnd;
                if (runEnd - runBegin >= 2) {
                    std::vector<std::size_t> permutation;
                    permutation.reserve(runEnd - runBegin);
                    for (auto index = runBegin; index < runEnd; ++index) {
                        permutation.push_back(index);
                    }
                    rng.shuffle(permutation);
                    bool identity = true;
                    for (std::size_t index = 0; index < permutation.size(); ++index) {
                        if (permutation[index] != runBegin + index) identity = false;
                    }
                    if (identity) {
                        std::rotate(
                            permutation.begin(), permutation.begin() + 1, permutation.end());
                    }
                    for (std::size_t index = 0; index < permutation.size(); ++index) {
                        order[runBegin + index] = permutation[index];
                        reordered[permutation[index]] = true;
                    }
                    reorderedCount += permutation.size();
                }
                runBegin = runEnd;
            }
            if (reorderedCount == 0) {
                statistics.skipped += functions.size();
                continue;
            }
            auto newCursor = chunks.front().oldBegin;
            for (const auto index : order) {
                chunks[index].newBegin = newCursor;
                newCursor += chunks[index].oldEnd - chunks[index].oldBegin;
            }

            bool referencesSupported = true;
            for (const auto& relocation : image.relocations) {
                if (!relocation.targetSymbol.has_value()) continue;
                const auto* target = find_symbol(image, *relocation.targetSymbol);
                if (target == nullptr || target->kind != SymbolKind::Section
                    || target->section != section.id) continue;
                bool mapped = false;
                if (image.format == BinaryFormat::COFF) {
                    referencesSupported = false;
                    break;
                }
                if (relocation.section != section.id && relocation.addend >= 0) {
                    const auto oldTarget = static_cast<std::uint64_t>(relocation.addend);
                    const auto exactSymbol = std::any_of(
                        functions.begin(), functions.end(), [oldTarget](const auto* function) {
                            return function->address.value == oldTarget;
                        });
                    if (exactSymbol && map_offset(chunks, oldTarget).has_value()) mapped = true;
                }
                if (!mapped && relocation.section == section.id
                    && relocation.kind == RelocationKind::PcRelative
                    && relocation.addend >= -4) {
                    const auto oldTarget = static_cast<std::uint64_t>(relocation.addend + 4);
                    if (map_offset(chunks, oldTarget).has_value()) mapped = true;
                }
                if (!mapped) {
                    referencesSupported = false;
                    break;
                }
            }
            if (!referencesSupported) {
                statistics.skipped += functions.size();
                continue;
            }

            const auto originalContents = section.contents;
            auto outputOffset = static_cast<std::size_t>(chunks.front().oldBegin);
            for (const auto index : order) {
                const auto begin = static_cast<std::size_t>(chunks[index].oldBegin);
                const auto end = static_cast<std::size_t>(chunks[index].oldEnd);
                std::copy(
                    originalContents.begin() + static_cast<std::ptrdiff_t>(begin),
                    originalContents.begin() + static_cast<std::ptrdiff_t>(end),
                    section.contents.begin() + static_cast<std::ptrdiff_t>(outputOffset));
                outputOffset += end - begin;
            }
            if (!transform.valid()) transform = context.allocate_transform_id();
            append_lineage(section, transform, name());
            changedSections.insert(section.id.value());
            for (auto& symbol : image.symbols) {
                if (!symbol.defined || symbol.section != section.id
                    || symbol.kind == SymbolKind::Section) continue;
                if (const auto mapped = map_offset(chunks, symbol.address.value)) {
                    if (*mapped != symbol.address.value) {
                        symbol.address.value = *mapped;
                        symbol.lineage.parents.push_back(TransformationRecord{
                            .transform = transform, .source = symbol.id,
                            .passName = std::string{name()}});
                    }
                }
            }
            for (auto& relocation : image.relocations) {
                if (relocation.section == section.id) {
                    const auto mapped = map_offset(chunks, relocation.offset);
                    if (!mapped.has_value()) {
                        return Result<TransformResult, Diagnostic>::failure(diagnostic(
                            DiagnosticSeverity::Error,
                            "pass.unmapped_relocation",
                            "function reordering could not map a relocation site"));
                    }
                    relocation.offset = *mapped;
                }
                if (!relocation.targetSymbol.has_value()) continue;
                const auto* target = find_symbol(image, *relocation.targetSymbol);
                if (target == nullptr || target->kind != SymbolKind::Section
                    || target->section != section.id) continue;
                if (relocation.section != section.id && relocation.addend >= 0) {
                    const auto oldTarget = static_cast<std::uint64_t>(relocation.addend);
                    const auto exactSymbol = std::any_of(
                        functions.begin(), functions.end(), [oldTarget](const auto* function) {
                            return function->address.value == oldTarget;
                        });
                    if (exactSymbol) {
                        relocation.addend = static_cast<std::int64_t>(*map_offset(chunks, oldTarget));
                        continue;
                    }
                }
                const auto oldTarget = static_cast<std::uint64_t>(relocation.addend + 4);
                relocation.addend = static_cast<std::int64_t>(*map_offset(chunks, oldTarget)) - 4;
            }
            for (std::size_t index = 0; index < functions.size(); ++index) {
                if (reordered[index]) {
                    changedFunctions.insert(functions[index]->symbol->value());
                }
            }
            statistics.changed += reorderedCount;
        }
        statistics.skipped += statistics.examined - statistics.changed - statistics.skipped;
        if (statistics.changed == 0) return unchanged_result(statistics, name());
        clear_changed_coff_section_checksums(image, changedSections, transform, name());
        if (const auto error = verify_functions(image, changedFunctions, name())) {
            return Result<TransformResult, Diagnostic>::failure(*error);
        }
        return successful_result(statistics);
    }
};

} // namespace

auto make_instruction_substitution_pass() -> std::unique_ptr<TransformPass> {
    return std::make_unique<InstructionSubstitutionPass>();
}

auto make_branch_inversion_pass() -> std::unique_ptr<TransformPass> {
    return std::make_unique<BranchInversionPass>();
}

auto make_constant_rewriting_pass() -> std::unique_ptr<TransformPass> {
    return std::make_unique<ConstantRewritingPass>();
}

auto make_block_splitting_pass() -> std::unique_ptr<TransformPass> {
    return std::make_unique<BlockSplittingPass>();
}

auto make_dead_code_insertion_pass() -> std::unique_ptr<TransformPass> {
    return std::make_unique<DeadCodeInsertionPass>();
}

auto make_block_reordering_pass() -> std::unique_ptr<TransformPass> {
    return std::make_unique<BlockReorderingPass>();
}

auto make_function_reordering_pass() -> std::unique_ptr<TransformPass> {
    return std::make_unique<FunctionReorderingPass>();
}

} // namespace binobf

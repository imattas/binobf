#include <binobf/transforms/instruction.hpp>

#include <binobf/analysis/object_analyzer.hpp>
#include <binobf/architecture/backend.hpp>
#include <binobf/support/deterministic_rng.hpp>
#include <binobf/transforms/object_rewrite.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
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

auto diagnostic(DiagnosticSeverity severity, std::string code, std::string message) -> Diagnostic {
    return Diagnostic{severity, std::move(code), std::move(message)};
}

auto machine_requirements(bool requiresCfg, bool requiresFullRelocations) -> PassRequirements {
    return PassRequirements{
        .requiresCfg = requiresCfg,
        .requiresFullRelocations = requiresFullRelocations,
        .requiresLiftedIr = false,
        .changesCodeSize = false,
        .supportedPostLink = false,
        .risk = PassRisk::Medium,
        .formats = {BinaryFormat::COFF, BinaryFormat::ELF, BinaryFormat::MachO},
        .architectures = {Architecture::X86, Architecture::X86_64, Architecture::ARM64},
    };
}

auto supports_machine_pass(const BinaryImage& image) -> bool {
    return image.type == BinaryType::RelocatableObject &&
           (image.architecture == Architecture::X86 || image.architecture == Architecture::X86_64 ||
            image.architecture == Architecture::ARM64) &&
           (image.format == BinaryFormat::COFF || image.format == BinaryFormat::ELF
            || image.format == BinaryFormat::MachO) &&
           std::none_of(image.unwindInfo.begin(), image.unwindInfo.end(), [](const auto& unwind) {
               return unwind.format == UnwindFormat::Unknown;
           });
}

auto uses_object_rewrite(Architecture architecture) noexcept -> bool {
    return architecture == Architecture::X86 || architecture == Architecture::ARM64;
}

auto find_section(BinaryImage& image, EntityId id) -> Section* {
    const auto found = std::find_if(image.sections.begin(),
                                    image.sections.end(),
                                    [id](const auto& section) { return section.id == id; });
    return found == image.sections.end() ? nullptr : &*found;
}

auto find_instruction(const BinaryImage& image, EntityId id) -> const Instruction* {
    const auto found = std::find_if(image.instructions.begin(),
                                    image.instructions.end(),
                                    [id](const auto& instruction) { return instruction.id == id; });
    return found == image.instructions.end() ? nullptr : &*found;
}

auto find_symbol(const BinaryImage& image, EntityId id) -> const Symbol* {
    const auto found = std::find_if(image.symbols.begin(),
                                    image.symbols.end(),
                                    [id](const auto& symbol) { return symbol.id == id; });
    return found == image.symbols.end() ? nullptr : &*found;
}

auto relocation_overlaps(const BinaryImage& image,
                         EntityId section,
                         std::uint64_t begin,
                         std::uint64_t size) -> bool {
    if (size > std::numeric_limits<std::uint64_t>::max() - begin) return true;
    const auto end = begin + size;
    return std::any_of(image.relocations.begin(),
                       image.relocations.end(),
                       [section, begin, end](const auto& relocation) {
                           return relocation.section == section && relocation.offset >= begin &&
                                  relocation.offset < end;
                       });
}

auto range_has_interior_target(const BinaryImage& image,
                               EntityId section,
                               std::uint64_t begin,
                               std::uint64_t end) -> bool {
    const auto symbolTargets = std::any_of(
        image.symbols.begin(), image.symbols.end(), [section, begin, end](const auto& symbol) {
            return symbol.defined && symbol.section == section && symbol.address.value > begin &&
                   symbol.address.value < end;
        });
    if (symbolTargets) return true;
    return std::any_of(image.instructions.begin(),
                       image.instructions.end(),
                       [section, begin, end](const auto& instruction) {
                           return instruction.section == section &&
                                  instruction.directTarget.has_value() &&
                                  instruction.directTarget->value > begin &&
                                  instruction.directTarget->value < end;
                       });
}

void append_lineage(Section& section, TransformId transform, std::string_view passName) {
    section.lineage.parents.push_back(TransformationRecord{
        .transform = transform,
        .source = section.id,
        .passName = std::string{passName},
    });
}

void clear_changed_coff_section_checksums(BinaryImage& image,
                                          const std::unordered_set<std::uint64_t>& sectionIds,
                                          TransformId transform,
                                          std::string_view passName) {
    if (image.format != BinaryFormat::COFF) return;
    for (auto& symbol : image.symbols) {
        if (symbol.kind != SymbolKind::Section || !symbol.section.has_value() ||
            !sectionIds.contains(symbol.section->value()) || symbol.auxiliaryData.size() < 12)
            continue;
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

auto verify_functions(const BinaryImage& image,
                      const std::unordered_set<std::uint64_t>& symbolIds,
                      std::string_view passName) -> std::optional<Diagnostic> {
    const auto analyzed = analyze_object(image);
    if (!analyzed.has_value()) {
        return diagnostic(DiagnosticSeverity::Error,
                          "pass.semantic_verification_failed",
                          std::string{passName} + " could not reanalyze its candidate: " +
                              analyzed.error().code + ": " + analyzed.error().message);
    }
    for (const auto symbolId : symbolIds) {
        const auto found = std::find_if(analyzed.value().image.functions.begin(),
                                        analyzed.value().image.functions.end(),
                                        [symbolId](const auto& function) {
                                            return function.symbol.has_value() &&
                                                   function.symbol->value() == symbolId;
                                        });
        if (found == analyzed.value().image.functions.end() || !found->complete) {
            return diagnostic(DiagnosticSeverity::Error,
                              "pass.semantic_verification_failed",
                              std::string{passName} +
                                  " produced an incomplete or undiscoverable function");
        }
    }
    return std::nullopt;
}

auto unchanged_result(PassStatistics statistics, std::string_view passName)
    -> Result<TransformResult, Diagnostic> {
    std::vector<Diagnostic> diagnostics;
    diagnostics.push_back(diagnostic(DiagnosticSeverity::Info,
                                     "pass.no_eligible_instructions",
                                     std::string{passName} + " found no proven-safe candidate"));
    return Result<TransformResult, Diagnostic>::success(TransformResult{
        .changed = false,
        .statistics = statistics,
        .diagnostics = std::move(diagnostics),
    });
}

auto successful_result(PassStatistics statistics) -> Result<TransformResult, Diagnostic> {
    return Result<TransformResult, Diagnostic>::success(TransformResult{
        .changed = true,
        .statistics = statistics,
        .diagnostics = {},
    });
}

auto decoded_replacement(const ArchitectureBackend& backend,
                         const Instruction& source,
                         std::span<const std::byte> replacement) -> std::optional<Instruction> {
    auto decoded = backend.decode(DecodeRequest{
        .architecture = backend.architecture(),
        .bytes = replacement,
        .address = source.address,
        .instructionId = source.id,
        .sectionId = source.section,
        .sectionOffset = source.sectionOffset,
    });
    if (!decoded.has_value()) return std::nullopt;
    return std::move(decoded).value();
}

auto commit_object_rewrite(BinaryImage& image,
                           const ArchitectureBackend& backend,
                           std::vector<ObjectRewriteRange> ranges,
                           TransformId transform,
                           std::string_view passName) -> Result<std::size_t, Diagnostic> {
    ObjectRewriteRequest request{};
    request.ranges = std::move(ranges);
    request.passName = std::string{passName};
    request.transform = transform;
    const auto plan = ObjectRewritePlan::create(image, backend, request);
    if (!plan.has_value()) {
        return Result<std::size_t, Diagnostic>::failure(plan.error());
    }
    auto committed = plan.value().commit(image);
    if (!committed.has_value()) {
        return Result<std::size_t, Diagnostic>::failure(committed.error());
    }
    const auto validated = plan.value().validate(image);
    if (!validated.has_value()) {
        return Result<std::size_t, Diagnostic>::failure(validated.error());
    }
    image = std::move(committed).value();
    return Result<std::size_t, Diagnostic>::success(validated.value());
}

auto normalized_condition(std::string_view mnemonic) -> std::optional<std::string> {
    if (mnemonic.starts_with("b.") && mnemonic.size() > 2U) {
        return std::string{mnemonic.substr(2U)};
    }
    if (mnemonic == "je" || mnemonic == "jz") return "equal";
    if (mnemonic == "jne" || mnemonic == "jnz") return "not-equal";
    if (mnemonic == "jb" || mnemonic == "jc" || mnemonic == "jnae") {
        return "unsigned-below";
    }
    if (mnemonic == "jae" || mnemonic == "jnb" || mnemonic == "jnc") {
        return "unsigned-above-or-equal";
    }
    if (mnemonic == "jl" || mnemonic == "jnge") return "signed-less";
    if (mnemonic == "jge" || mnemonic == "jnl") return "signed-greater-or-equal";
    return std::nullopt;
}

auto inverse_condition(std::string_view condition) -> std::optional<std::string> {
    if (condition == "eq") return "ne";
    if (condition == "ne") return "eq";
    if (condition == "hs") return "lo";
    if (condition == "lo") return "hs";
    if (condition == "mi") return "pl";
    if (condition == "pl") return "mi";
    if (condition == "vs") return "vc";
    if (condition == "vc") return "vs";
    if (condition == "hi") return "ls";
    if (condition == "ls") return "hi";
    if (condition == "ge") return "lt";
    if (condition == "lt") return "ge";
    if (condition == "gt") return "le";
    if (condition == "le") return "gt";
    if (condition == "equal") return "not-equal";
    if (condition == "not-equal") return "equal";
    if (condition == "unsigned-below") return "unsigned-above-or-equal";
    if (condition == "unsigned-above-or-equal") return "unsigned-below";
    if (condition == "signed-less") return "signed-greater-or-equal";
    if (condition == "signed-greater-or-equal") return "signed-less";
    return std::nullopt;
}

auto emit_dead_fill(const ArchitectureBackend& backend,
                    Architecture architecture,
                    BinaryFormat format,
                    std::size_t size) -> Result<std::vector<std::byte>, Diagnostic> {
    std::vector<std::byte> result;
    result.reserve(size);
    while (result.size() < size) {
        MachineTransformRequest request{};
        request.architecture = architecture;
        request.format = format;
        request.kind = MachineTransformKind::DeadCodeFill;
        request.exactSize = architecture == Architecture::ARM64
                                ? size - result.size()
                                : std::min<std::size_t>(15U, size - result.size());
        const auto emitted = backend.emit_transform(request);
        if (!emitted.has_value()) {
            return Result<std::vector<std::byte>, Diagnostic>::failure(emitted.error());
        }
        result.insert(result.end(),
                      emitted.value().emission.bytes.begin(),
                      emitted.value().emission.bytes.end());
    }
    return Result<std::vector<std::byte>, Diagnostic>::success(std::move(result));
}

class InstructionSubstitutionPass final : public TransformPass {
  public:
    auto name() const noexcept -> std::string_view override {
        return "instruction-substitution";
    }
    auto dependencies() const -> std::vector<std::string> override {
        return {};
    }
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
        auto backendResult = make_architecture_backend(image.architecture);
        if (!backendResult.has_value()) {
            return Result<TransformResult, Diagnostic>::failure(std::move(backendResult).error());
        }
        auto backend = std::move(backendResult).value();
        PassStatistics statistics;
        DeterministicRng rng{context.seed() ^ substitutionSalt};
        TransformId transform;
        std::vector<ObjectRewriteRange> x86Ranges;
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
                if (instruction == nullptr) {
                    continue;
                }
                const bool arm64Candidate =
                    image.architecture == Architecture::ARM64 &&
                    instruction->encoding.size() == 4U &&
                    (instruction->mnemonic == "mov" || instruction->mnemonic == "orr");
                const bool x86Candidate = image.architecture != Architecture::ARM64 &&
                                          instruction->mnemonic == "nop" &&
                                          instruction->encoding.size() >= 3U &&
                                          instruction->encoding.at(0) == std::byte{0x0f} &&
                                          instruction->encoding.at(1) == std::byte{0x1f};
                if (!arm64Candidate && !x86Candidate) {
                    continue;
                }
                ++statistics.examined;
                if (relocation_overlaps(image,
                                        instruction->section,
                                        instruction->sectionOffset,
                                        instruction->encoding.size())) {
                    ++statistics.skipped;
                    continue;
                }
                if (uses_object_rewrite(image.architecture)) {
                    MachineTransformRequest request{};
                    request.architecture = image.architecture;
                    request.format = image.format;
                    request.kind = MachineTransformKind::InstructionEquivalent;
                    request.source = *instruction;
                    request.exactSize = instruction->encoding.size();
                    const auto emitted = backend->emit_transform(request);
                    if (!emitted.has_value()) {
                        ++statistics.skipped;
                        continue;
                    }
                    auto replacement = emitted.value().emission.bytes;
                    if (image.architecture == Architecture::ARM64 &&
                        replacement == instruction->encoding && instruction->registersRead.size() == 1U &&
                        instruction->registersWritten.size() == 1U) {
                        const auto register_index = [](std::string_view name) -> std::optional<std::uint32_t> {
                            if (name.size() < 2U || (name.front() != 'x' && name.front() != 'w'))
                                return std::nullopt;
                            std::uint32_t value = 0;
                            for (std::size_t i = 1; i < name.size(); ++i) {
                                if (name[i] < '0' || name[i] > '9' || value > 31U)
                                    return std::nullopt;
                                value = value * 10U + static_cast<std::uint32_t>(name[i] - '0');
                            }
                            return value <= 31U ? std::optional{value} : std::nullopt;
                        };
                        const auto source = register_index(instruction->registersRead.front().name);
                        const auto destination = register_index(instruction->registersWritten.front().name);
                        if (source.has_value() && destination.has_value() &&
                            instruction->registersRead.front().name.front() ==
                                instruction->registersWritten.front().name.front()) {
                            const auto base = instruction->registersWritten.front().name.front() == 'x'
                                                  ? UINT32_C(0x91000000)
                                                  : UINT32_C(0x11000000);
                            const auto word = base | (*source << 5U) | *destination;
                            replacement = {static_cast<std::byte>(word & 0xffU),
                                           static_cast<std::byte>((word >> 8U) & 0xffU),
                                           static_cast<std::byte>((word >> 16U) & 0xffU),
                                           static_cast<std::byte>((word >> 24U) & 0xffU)};
                        }
                    }
                    const auto decoded = decoded_replacement(*backend, *instruction, replacement);
                    if (!decoded.has_value() || decoded->encoding.size() != replacement.size() ||
                        replacement == instruction->encoding) {
                        ++statistics.skipped;
                        continue;
                    }
                    if (!transform.valid()) transform = context.allocate_transform_id();
                    x86Ranges.push_back(ObjectRewriteRange{
                        instruction->section,
                        instruction->sectionOffset,
                        instruction->sectionOffset + instruction->encoding.size(),
                        instruction->sectionOffset,
                        std::move(replacement),
                    });
                    changedSections.insert(instruction->section.value());
                    changedFunctions.insert(function.symbol->value());
                    ++statistics.changed;
                    continue;
                }
                auto replacement = instruction->encoding;
                bool accepted = false;
                for (std::size_t attempt = 0; attempt < 32 && !accepted; ++attempt) {
                    replacement = instruction->encoding;
                    const auto mask = static_cast<unsigned int>(rng.uniform(255) + 1U);
                    replacement.back() ^= static_cast<std::byte>(mask);
                    const auto decoded = decoded_replacement(*backend, *instruction, replacement);
                    accepted = decoded.has_value() &&
                               decoded->encoding.size() == replacement.size() &&
                               decoded->mnemonic == "nop" && decoded->registersRead.empty() &&
                               decoded->registersWritten.empty();
                }
                if (!accepted || replacement == instruction->encoding) {
                    ++statistics.skipped;
                    continue;
                }
                auto* section = find_section(image, instruction->section);
                if (section == nullptr || instruction->sectionOffset > section->contents.size() ||
                    replacement.size() > section->contents.size() -
                                             static_cast<std::size_t>(instruction->sectionOffset)) {
                    return Result<TransformResult, Diagnostic>::failure(
                        diagnostic(DiagnosticSeverity::Error,
                                   "pass.invalid_instruction_range",
                                   "instruction substitution range is outside its section"));
                }
                std::copy(replacement.begin(),
                          replacement.end(),
                          section->contents.begin() +
                              static_cast<std::ptrdiff_t>(instruction->sectionOffset));
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
        if (uses_object_rewrite(image.architecture)) {
            const auto rewritten =
                commit_object_rewrite(image, *backend, std::move(x86Ranges), transform, name());
            if (!rewritten.has_value()) {
                return Result<TransformResult, Diagnostic>::failure(rewritten.error());
            }
        }
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

auto arm64_immediate(const Instruction& instruction) -> std::optional<std::uint64_t> {
    if (instruction.encoding.size() != 4U || instruction.registersWritten.size() != 1U ||
        (instruction.mnemonic != "mov" && instruction.mnemonic != "movz" &&
         instruction.mnemonic != "movn" &&
         (instruction.mnemonic != "orr" || instruction.operands.find("xzr") == std::string::npos ||
          instruction.registersRead.size() != 1U ||
          instruction.registersRead.front().name != "xzr"))) {
        return std::nullopt;
    }
    const auto marker = instruction.operands.find('#');
    if (marker == std::string::npos || marker + 1U >= instruction.operands.size()) {
        return std::nullopt;
    }
    auto text = std::string_view{instruction.operands}.substr(marker + 1U);
    if (const auto comma = text.find(','); comma != std::string_view::npos) {
        text = text.substr(0U, comma);
    }
    while (!text.empty() && text.front() == ' ')
        text.remove_prefix(1U);
    while (!text.empty() && text.back() == ' ')
        text.remove_suffix(1U);
    if (text.empty() || text.front() == '-') return std::nullopt;
    int base = 10;
    if (text.starts_with("0x")) {
        base = 16;
        text.remove_prefix(2U);
    }
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
        return std::nullopt;
    }
    return value;
}

class ConstantRewritingPass final : public TransformPass {
  public:
    auto name() const noexcept -> std::string_view override {
        return "constant-rewriting";
    }
    auto dependencies() const -> std::vector<std::string> override {
        return {};
    }
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
        auto backendResult = make_architecture_backend(image.architecture);
        if (!backendResult.has_value()) {
            return Result<TransformResult, Diagnostic>::failure(std::move(backendResult).error());
        }
        auto backend = std::move(backendResult).value();
        PassStatistics statistics;
        DeterministicRng rng{context.seed() ^ constantSalt};
        TransformId transform;
        std::vector<ObjectRewriteRange> x86Ranges;
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
                const auto* instruction =
                    find_instruction(analyzed.value().image, function.instructions[position]);
                if (instruction == nullptr) continue;
                if (image.architecture == Architecture::ARM64) {
                    const auto immediate = arm64_immediate(*instruction);
                    if (!immediate.has_value()) continue;
                    ++statistics.examined;
                    if (relocation_overlaps(image,
                                            instruction->section,
                                            instruction->sectionOffset,
                                            instruction->encoding.size())) {
                        ++statistics.skipped;
                        continue;
                    }
                    MachineTransformRequest request{};
                    request.architecture = Architecture::ARM64;
                    request.format = image.format;
                    request.kind = MachineTransformKind::ConstantMaterialization;
                    request.source = *instruction;
                    request.constantBits = *immediate;
                    request.condition = instruction->registersWritten.front().name;
                    request.exactSize = instruction->encoding.size();
                    const auto emitted = backend->emit_transform(request);
                    if (!emitted.has_value() ||
                        emitted.value().emission.bytes == instruction->encoding) {
                        ++statistics.skipped;
                        continue;
                    }
                    if (!transform.valid()) transform = context.allocate_transform_id();
                    x86Ranges.push_back(ObjectRewriteRange{
                        instruction->section,
                        instruction->sectionOffset,
                        instruction->sectionOffset + instruction->encoding.size(),
                        instruction->sectionOffset,
                        emitted.value().emission.bytes,
                    });
                    changedSections.insert(instruction->section.value());
                    changedFunctions.insert(function.symbol->value());
                    ++statistics.changed;
                    continue;
                }
                if (instruction->mnemonic != "mov" && instruction->mnemonic != "movabs") {
                    continue;
                }
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
                const auto registerIndex =
                    static_cast<std::uint8_t>((opcode - 0xb8U) + ((rex & 0x01U) != 0 ? 8U : 0U));
                std::uint32_t immediate = 0;
                std::size_t windowSize = source.size();
                if (wide) {
                    const auto value = read_u64(source, opcodeIndex + 1);
                    immediate = static_cast<std::uint32_t>(value);
                    const auto signedValue = std::bit_cast<std::int64_t>(value);
                    if (signedValue !=
                        static_cast<std::int64_t>(static_cast<std::int32_t>(immediate))) {
                        ++statistics.skipped;
                        continue;
                    }
                } else {
                    immediate = read_u32(source, opcodeIndex + 1);
                    if (position + 1 >= function.instructions.size()) {
                        ++statistics.skipped;
                        continue;
                    }
                    const auto* next = find_instruction(analyzed.value().image,
                                                        function.instructions[position + 1]);
                    if (next == nullptr || next->section != instruction->section ||
                        next->sectionOffset != instruction->sectionOffset + source.size() ||
                        next->encoding != std::vector<std::byte>{std::byte{0x90}} ||
                        range_has_interior_target(analyzed.value().image,
                                                  instruction->section,
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
                if (image.architecture == Architecture::X86) {
                    if (wide || (registerIndex != 0U && registerIndex != 1U)) {
                        ++statistics.skipped;
                        continue;
                    }
                    MachineTransformRequest request{};
                    request.architecture = Architecture::X86;
                    request.format = image.format;
                    request.kind = MachineTransformKind::ConstantMaterialization;
                    request.source = *instruction;
                    request.constantBits = immediate;
                    request.condition = registerIndex == 0U ? "eax" : "ecx";
                    request.exactSize = windowSize;
                    const auto emitted = backend->emit_transform(request);
                    if (!emitted.has_value() ||
                        emitted.value().emission.bytes.size() != windowSize) {
                        ++statistics.skipped;
                        continue;
                    }
                    if (!transform.valid()) transform = context.allocate_transform_id();
                    x86Ranges.push_back(ObjectRewriteRange{
                        instruction->section,
                        instruction->sectionOffset,
                        instruction->sectionOffset + windowSize,
                        instruction->sectionOffset,
                        emitted.value().emission.bytes,
                    });
                    changedSections.insert(instruction->section.value());
                    changedFunctions.insert(function.symbol->value());
                    ++statistics.changed;
                    ++position;
                    continue;
                }
                std::vector<std::byte> replacement;
                replacement.reserve(windowSize);
                std::uint8_t replacementRex = 0;
                if (wide)
                    replacementRex = 0x48U;
                else if (registerIndex >= 8U)
                    replacementRex = 0x41U;
                if (registerIndex >= 8U && wide) replacementRex |= 0x01U;
                if (replacementRex != 0)
                    replacement.push_back(static_cast<std::byte>(replacementRex));
                replacement.push_back(std::byte{0xc7});
                replacement.push_back(static_cast<std::byte>(0xc0U | (registerIndex & 0x07U)));
                append_u32(replacement, immediate);
                while (replacement.size() < windowSize)
                    replacement.push_back(std::byte{0x90});
                if (wide && windowSize - (replacementRex != 0 ? 7U : 6U) >= 3U) {
                    const auto fill = replacement.size() - 3;
                    replacement[fill] = std::byte{0x0f};
                    replacement[fill + 1] = std::byte{0x1f};
                    replacement[fill + 2] = static_cast<std::byte>(rng.uniform(4));
                }
                const auto decoded = decoded_replacement(
                    *backend,
                    *instruction,
                    std::span<const std::byte>{replacement}.first(replacementRex != 0 ? 7U : 6U));
                if (!decoded.has_value() || decoded->mnemonic != "mov") {
                    ++statistics.skipped;
                    continue;
                }
                auto* section = find_section(image, instruction->section);
                if (section == nullptr || instruction->sectionOffset > section->contents.size() ||
                    windowSize > section->contents.size() -
                                     static_cast<std::size_t>(instruction->sectionOffset)) {
                    return Result<TransformResult, Diagnostic>::failure(
                        diagnostic(DiagnosticSeverity::Error,
                                   "pass.invalid_instruction_range",
                                   "constant rewrite range is outside its section"));
                }
                std::copy(replacement.begin(),
                          replacement.end(),
                          section->contents.begin() +
                              static_cast<std::ptrdiff_t>(instruction->sectionOffset));
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
        if (uses_object_rewrite(image.architecture)) {
            const auto rewritten =
                commit_object_rewrite(image, *backend, std::move(x86Ranges), transform, name());
            if (!rewritten.has_value()) {
                return Result<TransformResult, Diagnostic>::failure(rewritten.error());
            }
        }
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

auto write_displacement(std::vector<std::byte>& bytes,
                        const BranchEncoding& encoding,
                        std::uint64_t instructionAddress,
                        std::uint64_t target) -> bool {
    if (instructionAddress > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) ||
        target > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        return false;
    }
    const auto end =
        static_cast<std::int64_t>(instructionAddress) + static_cast<std::int64_t>(bytes.size());
    const auto displacement = static_cast<std::int64_t>(target) - end;
    if (encoding.displacementSize == 1) {
        if (displacement < std::numeric_limits<std::int8_t>::min() ||
            displacement > std::numeric_limits<std::int8_t>::max())
            return false;
        bytes[encoding.displacementOffset] = static_cast<std::byte>(
            static_cast<std::uint8_t>(static_cast<std::int8_t>(displacement)));
        return true;
    }
    if (displacement < std::numeric_limits<std::int32_t>::min() ||
        displacement > std::numeric_limits<std::int32_t>::max())
        return false;
    const auto encoded = static_cast<std::uint32_t>(static_cast<std::int32_t>(displacement));
    for (std::size_t index = 0; index < 4; ++index) {
        bytes[encoding.displacementOffset + index] =
            static_cast<std::byte>((encoded >> (index * 8U)) & 0xffU);
    }
    return true;
}

class BranchInversionPass final : public TransformPass {
  public:
    auto name() const noexcept -> std::string_view override {
        return "branch-inversion";
    }
    auto dependencies() const -> std::vector<std::string> override {
        return {};
    }
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
        auto backendResult = make_architecture_backend(image.architecture);
        if (!backendResult.has_value()) {
            return Result<TransformResult, Diagnostic>::failure(backendResult.error());
        }
        auto backend = std::move(backendResult).value();
        PassStatistics statistics;
        TransformId transform;
        std::vector<ObjectRewriteRange> x86Ranges;
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
            for (std::size_t position = 0; position + 1 < function.instructions.size();
                 ++position) {
                const auto* condition =
                    find_instruction(analyzed.value().image, function.instructions[position]);
                const auto* jump =
                    find_instruction(analyzed.value().image, function.instructions[position + 1]);
                if (condition == nullptr || jump == nullptr ||
                    condition->kind != InstructionKind::ConditionalBranch ||
                    jump->kind != InstructionKind::DirectBranch ||
                    !condition->directTarget.has_value() || !jump->directTarget.has_value() ||
                    condition->section != jump->section ||
                    jump->sectionOffset != condition->sectionOffset + condition->encoding.size()) {
                    continue;
                }
                const auto conditionEncoding = conditional_encoding(condition->encoding);
                const auto jumpEncoding = direct_branch_encoding(jump->encoding);
                const bool arm64Pair = image.architecture == Architecture::ARM64 &&
                                       condition->encoding.size() == 4U &&
                                       jump->encoding.size() == 4U;
                if (!arm64Pair && (!conditionEncoding.has_value() || !jumpEncoding.has_value()))
                    continue;
                ++statistics.examined;
                const auto combinedSize = condition->encoding.size() + jump->encoding.size();
                if (relocation_overlaps(
                        image, condition->section, condition->sectionOffset, combinedSize) ||
                    range_has_interior_target(analyzed.value().image,
                                              condition->section,
                                              condition->sectionOffset,
                                              condition->sectionOffset + combinedSize)) {
                    ++statistics.skipped;
                    continue;
                }
                if (uses_object_rewrite(image.architecture)) {
                    const auto conditionName = normalized_condition(condition->mnemonic);
                    if (!conditionName.has_value()) {
                        ++statistics.skipped;
                        continue;
                    }
                    MachineTransformRequest conditionRequest{};
                    conditionRequest.architecture = image.architecture;
                    conditionRequest.format = image.format;
                    conditionRequest.kind = MachineTransformKind::ConditionalInversion;
                    conditionRequest.source = *condition;
                    conditionRequest.targetAddress = jump->directTarget->value;
                    conditionRequest.condition = *conditionName;
                    conditionRequest.exactSize = condition->encoding.size();
                    MachineTransformRequest jumpRequest{};
                    jumpRequest.architecture = image.architecture;
                    jumpRequest.format = image.format;
                    jumpRequest.kind = MachineTransformKind::DirectJump;
                    jumpRequest.source = *jump;
                    jumpRequest.targetAddress = condition->directTarget->value;
                    jumpRequest.exactSize = jump->encoding.size();
                    const auto emittedCondition = backend->emit_transform(conditionRequest);
                    const auto emittedJump = backend->emit_transform(jumpRequest);
                    if (!emittedCondition.has_value() || !emittedJump.has_value()) {
                        ++statistics.skipped;
                        continue;
                    }
                    auto replacement = emittedCondition.value().emission.bytes;
                    replacement.insert(replacement.end(),
                                       emittedJump.value().emission.bytes.begin(),
                                       emittedJump.value().emission.bytes.end());
                    if (!transform.valid()) transform = context.allocate_transform_id();
                    x86Ranges.push_back(ObjectRewriteRange{
                        condition->section,
                        condition->sectionOffset,
                        condition->sectionOffset + combinedSize,
                        condition->sectionOffset,
                        std::move(replacement),
                    });
                    changedSections.insert(condition->section.value());
                    changedFunctions.insert(function.symbol->value());
                    ++statistics.changed;
                    ++position;
                    continue;
                }
                auto replacementCondition = condition->encoding;
                auto replacementJump = jump->encoding;
                const auto conditionOpcode = conditionEncoding->displacementOffset - 1;
                replacementCondition[conditionOpcode] ^= std::byte{0x01};
                if (!write_displacement(replacementCondition,
                                        *conditionEncoding,
                                        condition->address.value,
                                        jump->directTarget->value) ||
                    !write_displacement(replacementJump,
                                        *jumpEncoding,
                                        jump->address.value,
                                        condition->directTarget->value)) {
                    ++statistics.skipped;
                    continue;
                }
                auto* section = find_section(image, condition->section);
                if (section == nullptr) {
                    return Result<TransformResult, Diagnostic>::failure(
                        diagnostic(DiagnosticSeverity::Error,
                                   "pass.invalid_instruction_range",
                                   "branch inversion section is missing"));
                }
                auto output = section->contents.begin() +
                              static_cast<std::ptrdiff_t>(condition->sectionOffset);
                output =
                    std::copy(replacementCondition.begin(), replacementCondition.end(), output);
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
        if (uses_object_rewrite(image.architecture)) {
            const auto rewritten =
                commit_object_rewrite(image, *backend, std::move(x86Ranges), transform, name());
            if (!rewritten.has_value()) {
                return Result<TransformResult, Diagnostic>::failure(rewritten.error());
            }
        }
        clear_changed_coff_section_checksums(image, changedSections, transform, name());
        if (const auto error = verify_functions(image, changedFunctions, name())) {
            return Result<TransformResult, Diagnostic>::failure(*error);
        }
        return successful_result(statistics);
    }
};

class BlockSplittingPass final : public TransformPass {
  public:
    auto name() const noexcept -> std::string_view override {
        return "block-splitting";
    }
    auto dependencies() const -> std::vector<std::string> override {
        return {};
    }
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
        auto backendResult = make_architecture_backend(image.architecture);
        if (!backendResult.has_value()) {
            return Result<TransformResult, Diagnostic>::failure(backendResult.error());
        }
        auto backend = std::move(backendResult).value();
        PassStatistics statistics;
        TransformId transform;
        std::vector<ObjectRewriteRange> x86Ranges;
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
                if (block == analyzed.value().image.basicBlocks.end() ||
                    block->instructions.size() < 3)
                    continue;
                for (std::size_t position = 1; position + 1 < block->instructions.size();
                     ++position) {
                    const auto* instruction =
                        find_instruction(analyzed.value().image, block->instructions[position]);
                    if (instruction == nullptr || instruction->mnemonic != "nop" ||
                        instruction->encoding.size() < 2)
                        continue;
                    ++statistics.examined;
                    if (relocation_overlaps(image,
                                            instruction->section,
                                            instruction->sectionOffset,
                                            instruction->encoding.size()) ||
                        range_has_interior_target(analyzed.value().image,
                                                  instruction->section,
                                                  instruction->sectionOffset,
                                                  instruction->sectionOffset +
                                                      instruction->encoding.size())) {
                        ++statistics.skipped;
                        continue;
                    }
                    if (uses_object_rewrite(image.architecture)) {
                        const auto jumpSize = image.architecture == Architecture::ARM64
                                                  ? std::size_t{4U}
                                                  : std::size_t{2U};
                        if (instruction->encoding.size() < jumpSize) {
                            ++statistics.skipped;
                            continue;
                        }
                        MachineTransformRequest jumpRequest{};
                        jumpRequest.architecture = image.architecture;
                        jumpRequest.format = image.format;
                        jumpRequest.kind = MachineTransformKind::DirectJump;
                        jumpRequest.source = *instruction;
                        jumpRequest.targetAddress =
                            instruction->address.value + instruction->encoding.size();
                        jumpRequest.exactSize = jumpSize;
                        const auto jump = backend->emit_transform(jumpRequest);
                        if (!jump.has_value()) {
                            ++statistics.skipped;
                            continue;
                        }
                        auto replacement = jump.value().emission.bytes;
                        if (instruction->encoding.size() > jumpSize) {
                            const auto fill =
                                emit_dead_fill(*backend,
                                               image.architecture,
                                               image.format,
                                               instruction->encoding.size() - jumpSize);
                            if (!fill.has_value()) {
                                ++statistics.skipped;
                                continue;
                            }
                            replacement.insert(
                                replacement.end(), fill.value().begin(), fill.value().end());
                        }
                        if (!transform.valid()) transform = context.allocate_transform_id();
                        x86Ranges.push_back(ObjectRewriteRange{
                            instruction->section,
                            instruction->sectionOffset,
                            instruction->sectionOffset + instruction->encoding.size(),
                            instruction->sectionOffset,
                            std::move(replacement),
                        });
                        changedSections.insert(instruction->section.value());
                        changedFunctions.insert(function.symbol->value());
                        ++statistics.changed;
                        changedFunction = true;
                        break;
                    }
                    auto* section = find_section(image, instruction->section);
                    if (section == nullptr) {
                        return Result<TransformResult, Diagnostic>::failure(
                            diagnostic(DiagnosticSeverity::Error,
                                       "pass.invalid_instruction_range",
                                       "block-splitting section is missing"));
                    }
                    const auto offset = static_cast<std::size_t>(instruction->sectionOffset);
                    section->contents[offset] = std::byte{0xeb};
                    section->contents[offset + 1] = std::byte{0x00};
                    std::fill(
                        section->contents.begin() + static_cast<std::ptrdiff_t>(offset + 2),
                        section->contents.begin() +
                            static_cast<std::ptrdiff_t>(offset + instruction->encoding.size()),
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
        if (uses_object_rewrite(image.architecture)) {
            const auto rewritten =
                commit_object_rewrite(image, *backend, std::move(x86Ranges), transform, name());
            if (!rewritten.has_value()) {
                return Result<TransformResult, Diagnostic>::failure(rewritten.error());
            }
        }
        clear_changed_coff_section_checksums(image, changedSections, transform, name());
        if (const auto error = verify_functions(image, changedFunctions, name())) {
            return Result<TransformResult, Diagnostic>::failure(*error);
        }
        const auto after = analyze_object(image);
        if (!after.has_value() ||
            after.value().image.basicBlocks.size() <= analyzed.value().image.basicBlocks.size()) {
            return Result<TransformResult, Diagnostic>::failure(
                diagnostic(DiagnosticSeverity::Error,
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
    auto dependencies() const -> std::vector<std::string> override {
        return {};
    }
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
        auto backendResult = make_architecture_backend(image.architecture);
        if (!backendResult.has_value()) {
            return Result<TransformResult, Diagnostic>::failure(backendResult.error());
        }
        auto backend = std::move(backendResult).value();
        PassStatistics statistics;
        TransformId transform;
        std::vector<ObjectRewriteRange> x86Ranges;
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
                const auto* instruction = find_instruction(analyzed.value().image, instructionId);
                if (instruction == nullptr || instruction->mnemonic != "nop" ||
                    instruction->encoding.size() < 3 || instruction->encoding.size() > 129) {
                    continue;
                }
                ++statistics.examined;
                auto windowSize = instruction->encoding.size();
                if (image.architecture == Architecture::ARM64) {
                    const auto adjacent = std::find_if(
                        function.instructions.begin(),
                        function.instructions.end(),
                        [&](const auto nextId) {
                            const auto* next = find_instruction(analyzed.value().image, nextId);
                            return next != nullptr && next->section == instruction->section &&
                                   next->sectionOffset ==
                                       instruction->sectionOffset + instruction->encoding.size() &&
                                   next->mnemonic == "nop" && next->encoding.size() == 4U;
                        });
                    if (adjacent == function.instructions.end()) {
                        ++statistics.skipped;
                        continue;
                    }
                    windowSize += 4U;
                }
                const auto end = instruction->sectionOffset + windowSize;
                const bool hasNextInstruction = std::any_of(
                    function.instructions.begin(),
                    function.instructions.end(),
                    [&](const auto nextId) {
                        const auto* next = find_instruction(analyzed.value().image, nextId);
                        return next != nullptr && next->section == instruction->section &&
                               next->sectionOffset == end;
                    });
                if (!hasNextInstruction ||
                    relocation_overlaps(
                        image, instruction->section, instruction->sectionOffset, windowSize) ||
                    range_has_interior_target(analyzed.value().image,
                                              instruction->section,
                                              instruction->sectionOffset,
                                              end)) {
                    ++statistics.skipped;
                    continue;
                }
                candidates.push_back(instruction);
            }
            if (candidates.empty()) continue;
            rng.shuffle(candidates);
            const auto* instruction = candidates.front();
            if (uses_object_rewrite(image.architecture)) {
                const auto windowSize = image.architecture == Architecture::ARM64
                                            ? std::size_t{8U}
                                            : instruction->encoding.size();
                const auto jumpSize =
                    image.architecture == Architecture::ARM64 ? std::size_t{4U} : std::size_t{2U};
                MachineTransformRequest jumpRequest{};
                jumpRequest.architecture = image.architecture;
                jumpRequest.format = image.format;
                jumpRequest.kind = MachineTransformKind::DirectJump;
                jumpRequest.source = *instruction;
                jumpRequest.targetAddress = instruction->address.value + windowSize;
                jumpRequest.exactSize = jumpSize;
                const auto jump = backend->emit_transform(jumpRequest);
                const auto fill = emit_dead_fill(
                    *backend, image.architecture, image.format, windowSize - jumpSize);
                if (!jump.has_value() || !fill.has_value()) {
                    ++statistics.skipped;
                    continue;
                }
                auto replacement = jump.value().emission.bytes;
                replacement.insert(replacement.end(), fill.value().begin(), fill.value().end());
                if (!transform.valid()) transform = context.allocate_transform_id();
                x86Ranges.push_back(ObjectRewriteRange{
                    instruction->section,
                    instruction->sectionOffset,
                    instruction->sectionOffset + windowSize,
                    instruction->sectionOffset,
                    std::move(replacement),
                });
                changedSections.insert(instruction->section.value());
                changedFunctions.insert(function.symbol->value());
                ++statistics.changed;
                continue;
            }
            auto* section = find_section(image, instruction->section);
            if (section == nullptr) {
                return Result<TransformResult, Diagnostic>::failure(
                    diagnostic(DiagnosticSeverity::Error,
                               "pass.invalid_instruction_range",
                               "dead-code-insertion section is missing"));
            }
            const auto offset = static_cast<std::size_t>(instruction->sectionOffset);
            const auto skipped = instruction->encoding.size() - 2;
            section->contents[offset] = std::byte{0xeb};
            section->contents[offset + 1] = static_cast<std::byte>(skipped);
            std::fill(section->contents.begin() + static_cast<std::ptrdiff_t>(offset + 2),
                      section->contents.begin() +
                          static_cast<std::ptrdiff_t>(offset + instruction->encoding.size()),
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
        if (uses_object_rewrite(image.architecture)) {
            const auto rewritten =
                commit_object_rewrite(image, *backend, std::move(x86Ranges), transform, name());
            if (!rewritten.has_value()) {
                return Result<TransformResult, Diagnostic>::failure(rewritten.error());
            }
        }
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

auto map_block_offset(std::span<const BlockChunk> chunks, std::uint64_t oldOffset)
    -> std::optional<std::uint64_t> {
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
    if ((first == 0xeb || (first >= 0x70 && first <= 0x7f)) && instruction.encoding.size() >= 2) {
        return RelativeField{1, 1};
    }
    if (first == 0x0f && instruction.encoding.size() >= 6) {
        const auto second = std::to_integer<std::uint8_t>(instruction.encoding[1]);
        if (second >= 0x80 && second <= 0x8f) return RelativeField{2, 4};
    }
    return std::nullopt;
}

auto has_rewritable_direct_field(const Instruction& instruction, Architecture architecture)
    -> bool {
    if (architecture == Architecture::ARM64) {
        return instruction.encoding.size() == 4U &&
               (instruction.kind == InstructionKind::DirectBranch ||
                instruction.kind == InstructionKind::ConditionalBranch);
    }
    return relative_field(instruction).has_value();
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
    if (next > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) ||
        target > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        return false;
    }
    const auto displacement = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(next);
    if (instructionOffset > std::numeric_limits<std::size_t>::max() - field.offset) {
        return false;
    }
    const auto position = static_cast<std::size_t>(instructionOffset) + field.offset;
    if (position > contents.size() || field.width > contents.size() - position) return false;
    if (field.width == 1) {
        if (displacement < std::numeric_limits<std::int8_t>::min() ||
            displacement > std::numeric_limits<std::int8_t>::max()) {
            return false;
        }
        contents[position] = static_cast<std::byte>(
            static_cast<std::uint8_t>(static_cast<std::int8_t>(displacement)));
        return true;
    }
    if (field.width != 4 || displacement < std::numeric_limits<std::int32_t>::min() ||
        displacement > std::numeric_limits<std::int32_t>::max()) {
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
    auto dependencies() const -> std::vector<std::string> override {
        return {};
    }
    auto requirements() const -> PassRequirements override {
        return machine_requirements(true, true);
    }
    auto supports(const TransformContext&, const BinaryImage& image) const -> bool override {
        return supports_machine_pass(image) &&
               (uses_object_rewrite(image.architecture) || image.unwindInfo.empty()) &&
               std::none_of(
                   image.unwindInfo.begin(), image.unwindInfo.end(), [](const auto& unwind) {
                       return unwind.format == UnwindFormat::Unknown;
                   });
    }

    auto run(TransformContext& context, BinaryImage& image) const
        -> Result<TransformResult, Diagnostic> override {
        const auto analyzed = analyze_object(image);
        if (!analyzed.has_value()) {
            return Result<TransformResult, Diagnostic>::failure(analyzed.error());
        }
        auto backendResult = make_architecture_backend(image.architecture);
        if (!backendResult.has_value()) {
            return Result<TransformResult, Diagnostic>::failure(backendResult.error());
        }
        auto backend = std::move(backendResult).value();
        PassStatistics statistics;
        TransformId transform;
        std::vector<ObjectRewriteRange> x86Ranges;
        DeterministicRng rng{context.seed() ^ layoutSalt ^ UINT64_C(0x626c6f636b)};
        std::unordered_set<std::uint64_t> changedFunctions;
        std::unordered_set<std::uint64_t> changedSections;
        for (const auto& function : analyzed.value().image.functions) {
            if (!function.complete || !function.symbol.has_value() ||
                !function.entryBlock.has_value() || function.basicBlocks.size() < 3 ||
                function.size >
                    std::numeric_limits<std::uint64_t>::max() - function.address.value) {
                continue;
            }
            const bool hasOpaqueUnwind =
                std::ranges::any_of(image.unwindInfo, [&](const auto& unwind) {
                    return unwind.function == function.id &&
                           unwind.rewriteState == UnwindRewriteState::Opaque;
                });
            if (hasOpaqueUnwind) {
                statistics.examined += function.basicBlocks.size();
                statistics.skipped += function.basicBlocks.size();
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
                image.relocations.begin(), image.relocations.end(), [&](const auto& relocation) {
                    return relocation.section == function.section && relocation.offset >= begin &&
                           relocation.offset < end;
                });
            const bool hasInteriorSymbol =
                std::any_of(image.symbols.begin(), image.symbols.end(), [&](const auto& symbol) {
                    return symbol.id != *function.symbol && symbol.kind != SymbolKind::Section &&
                           symbol.defined && symbol.section == function.section &&
                           symbol.address.value >= begin && symbol.address.value < end;
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
                if (block == analyzed.value().image.basicBlocks.end() ||
                    block->section != function.section || block->instructions.empty() ||
                    block->hasUnresolvedSuccessor ||
                    std::any_of(block->edges.begin(), block->edges.end(), [](const auto& edge) {
                        return edge.kind == ControlFlowEdgeKind::Fallthrough;
                    })) {
                    valid = false;
                    break;
                }
                const auto* terminator =
                    find_instruction(analyzed.value().image, block->instructions.back());
                if (terminator == nullptr || (terminator->kind != InstructionKind::DirectBranch &&
                                              terminator->kind != InstructionKind::IndirectBranch &&
                                              terminator->kind != InstructionKind::Return &&
                                              terminator->kind != InstructionKind::Trap)) {
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
            if (blocks.front()->sectionOffset != begin ||
                blocks.front()->id != *function.entryBlock) {
                statistics.skipped += function.basicBlocks.size();
                continue;
            }
            std::vector<BlockChunk> chunks;
            chunks.reserve(blocks.size());
            for (std::size_t index = 0; index < blocks.size(); ++index) {
                const auto chunkBegin = blocks[index]->sectionOffset;
                const auto chunkEnd =
                    index + 1 < blocks.size() ? blocks[index + 1]->sectionOffset : end;
                const auto* last =
                    find_instruction(analyzed.value().image, blocks[index]->instructions.back());
                if (chunkBegin >= chunkEnd || chunkEnd > end || last == nullptr ||
                    last->sectionOffset > chunkEnd ||
                    last->encoding.size() > chunkEnd - last->sectionOffset) {
                    valid = false;
                    break;
                }
                chunks.push_back(BlockChunk{chunkBegin, chunkEnd, 0, blocks[index]->id});
            }
            for (const auto instructionId : function.instructions) {
                const auto* instruction = find_instruction(analyzed.value().image, instructionId);
                if (instruction == nullptr || instruction->section != function.section ||
                    instruction->sectionOffset < begin || instruction->sectionOffset >= end) {
                    valid = false;
                    break;
                }
                if (!instruction->directTarget.has_value()) continue;
                const auto target = instruction->directTarget->value;
                if (target < begin || target >= end ||
                    !has_rewritable_direct_field(*instruction, image.architecture) ||
                    instruction->kind == InstructionKind::DirectCall) {
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
                return Result<TransformResult, Diagnostic>::failure(
                    diagnostic(DiagnosticSeverity::Error,
                               "pass.invalid_instruction_range",
                               "block-reordering function range is outside its section"));
            }
            if (uses_object_rewrite(image.architecture)) {
                std::vector<std::vector<std::byte>> replacements;
                replacements.reserve(chunks.size());
                for (const auto& chunk : chunks) {
                    replacements.emplace_back(
                        section->contents.begin() + static_cast<std::ptrdiff_t>(chunk.oldBegin),
                        section->contents.begin() + static_cast<std::ptrdiff_t>(chunk.oldEnd));
                }
                bool encodable = true;
                for (const auto instructionId : function.instructions) {
                    const auto* instruction =
                        find_instruction(analyzed.value().image, instructionId);
                    if (instruction == nullptr || !instruction->directTarget.has_value()) continue;
                    const auto chunk =
                        std::find_if(chunks.begin(), chunks.end(), [&](const auto& candidate) {
                            return instruction->sectionOffset >= candidate.oldBegin &&
                                   instruction->sectionOffset < candidate.oldEnd;
                        });
                    const auto newInstruction =
                        map_block_offset(chunks, instruction->sectionOffset);
                    const auto newTarget =
                        map_block_offset(chunks, instruction->directTarget->value);
                    if (chunk == chunks.end() || !newInstruction.has_value() ||
                        !newTarget.has_value()) {
                        encodable = false;
                        break;
                    }
                    auto source = *instruction;
                    source.address.value = *newInstruction;
                    source.sectionOffset = *newInstruction;
                    MachineTransformRequest request{};
                    request.architecture = image.architecture;
                    request.format = image.format;
                    request.source = source;
                    request.targetAddress = *newTarget;
                    request.exactSize = instruction->encoding.size();
                    if (instruction->kind == InstructionKind::DirectBranch) {
                        request.kind = MachineTransformKind::DirectJump;
                    } else if (instruction->kind == InstructionKind::ConditionalBranch) {
                        const auto normalized = normalized_condition(instruction->mnemonic);
                        const auto preserved =
                            normalized.has_value() ? inverse_condition(*normalized) : std::nullopt;
                        if (!preserved.has_value()) {
                            encodable = false;
                            break;
                        }
                        request.kind = MachineTransformKind::ConditionalInversion;
                        request.condition = *preserved;
                    } else {
                        encodable = false;
                        break;
                    }
                    const auto emitted = backend->emit_transform(request);
                    if (!emitted.has_value() ||
                        emitted.value().emission.bytes.size() != instruction->encoding.size()) {
                        encodable = false;
                        break;
                    }
                    const auto chunkIndex = static_cast<std::size_t>(chunk - chunks.begin());
                    const auto localOffset =
                        static_cast<std::size_t>(instruction->sectionOffset - chunk->oldBegin);
                    std::copy(emitted.value().emission.bytes.begin(),
                              emitted.value().emission.bytes.end(),
                              replacements[chunkIndex].begin() +
                                  static_cast<std::ptrdiff_t>(localOffset));
                }
                if (!encodable) {
                    statistics.skipped += function.basicBlocks.size();
                    continue;
                }
                if (!transform.valid()) transform = context.allocate_transform_id();
                for (std::size_t index = 0; index < chunks.size(); ++index) {
                    x86Ranges.push_back(ObjectRewriteRange{
                        function.section,
                        chunks[index].oldBegin,
                        chunks[index].oldEnd,
                        chunks[index].newBegin,
                        std::move(replacements[index]),
                    });
                }
                changedSections.insert(function.section.value());
                changedFunctions.insert(function.symbol->value());
                statistics.changed += function.basicBlocks.size();
                continue;
            }
            const auto original = section->contents;
            for (const auto index : order) {
                const auto oldBegin = static_cast<std::size_t>(chunks[index].oldBegin);
                const auto oldEnd = static_cast<std::size_t>(chunks[index].oldEnd);
                const auto newBegin = static_cast<std::size_t>(chunks[index].newBegin);
                std::copy(original.begin() + static_cast<std::ptrdiff_t>(oldBegin),
                          original.begin() + static_cast<std::ptrdiff_t>(oldEnd),
                          section->contents.begin() + static_cast<std::ptrdiff_t>(newBegin));
            }
            for (const auto instructionId : function.instructions) {
                const auto* instruction = find_instruction(analyzed.value().image, instructionId);
                if (instruction == nullptr || !instruction->directTarget.has_value()) continue;
                const auto newInstruction = map_block_offset(chunks, instruction->sectionOffset);
                const auto newTarget = map_block_offset(chunks, instruction->directTarget->value);
                const auto field = relative_field(*instruction);
                if (!newInstruction.has_value() || !newTarget.has_value() || !field.has_value() ||
                    !patch_relative(section->contents,
                                    *newInstruction,
                                    instruction->encoding.size(),
                                    *field,
                                    *newTarget)) {
                    return Result<TransformResult, Diagnostic>::failure(
                        diagnostic(DiagnosticSeverity::Error,
                                   "pass.branch_out_of_range",
                                   "block-reordering could not encode a moved direct branch"));
                }
            }
            if (!transform.valid()) transform = context.allocate_transform_id();
            if (changedSections.insert(section->id.value()).second) {
                append_lineage(*section, transform, name());
            }
            for (auto& symbol : image.symbols) {
                if (!symbol.defined || symbol.section != function.section ||
                    symbol.address.value < begin || symbol.address.value >= end) {
                    continue;
                }
                const auto mapped = map_block_offset(chunks, symbol.address.value);
                if (!mapped.has_value()) {
                    return Result<TransformResult, Diagnostic>::failure(
                        diagnostic(DiagnosticSeverity::Error,
                                   "pass.unmapped_symbol",
                                   "block-reordering could not map a function symbol"));
                }
                if (*mapped != symbol.address.value) {
                    symbol.address.value = *mapped;
                    symbol.lineage.parents.push_back(
                        TransformationRecord{transform, symbol.id, std::string{name()}});
                }
            }
            changedFunctions.insert(function.symbol->value());
            statistics.changed += function.basicBlocks.size();
        }
        statistics.skipped += statistics.examined - statistics.changed - statistics.skipped;
        if (statistics.changed == 0) return unchanged_result(statistics, name());
        if (uses_object_rewrite(image.architecture)) {
            const auto rewritten =
                commit_object_rewrite(image, *backend, std::move(x86Ranges), transform, name());
            if (!rewritten.has_value()) {
                return Result<TransformResult, Diagnostic>::failure(rewritten.error());
            }
        }
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

auto map_offset(std::span<const FunctionChunk> chunks, std::uint64_t oldOffset)
    -> std::optional<std::uint64_t> {
    for (const auto& chunk : chunks) {
        if (oldOffset >= chunk.oldBegin && oldOffset < chunk.oldEnd) {
            return chunk.newBegin + (oldOffset - chunk.oldBegin);
        }
    }
    return std::nullopt;
}

class FunctionReorderingPass final : public TransformPass {
  public:
    auto name() const noexcept -> std::string_view override {
        return "function-reordering";
    }
    auto dependencies() const -> std::vector<std::string> override {
        return {};
    }
    auto requirements() const -> PassRequirements override {
        return machine_requirements(true, true);
    }
    auto supports(const TransformContext&, const BinaryImage& image) const -> bool override {
        return supports_machine_pass(image) &&
               (uses_object_rewrite(image.architecture) || image.unwindInfo.empty()) &&
               std::none_of(
                   image.unwindInfo.begin(),
                   image.unwindInfo.end(),
                   [](const auto& unwind) { return unwind.format == UnwindFormat::Unknown; }) &&
               std::none_of(image.sections.begin(), image.sections.end(), [](const auto& section) {
                   return section.kind == SectionKind::Debug;
               });
    }

    auto run(TransformContext& context, BinaryImage& image) const
        -> Result<TransformResult, Diagnostic> override {
        const auto analyzed = analyze_object(image);
        if (!analyzed.has_value()) {
            return Result<TransformResult, Diagnostic>::failure(analyzed.error());
        }
        auto backendResult = make_architecture_backend(image.architecture);
        if (!backendResult.has_value()) {
            return Result<TransformResult, Diagnostic>::failure(backendResult.error());
        }
        auto backend = std::move(backendResult).value();
        PassStatistics statistics;
        TransformId transform;
        std::vector<ObjectRewriteRange> x86Ranges;
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
            const bool hasOpaqueUnwind =
                std::ranges::any_of(image.unwindInfo, [&](const auto& unwind) {
                    return unwind.rewriteState == UnwindRewriteState::Opaque &&
                           std::ranges::any_of(functions, [&](const auto* function) {
                               return unwind.function == function->id;
                           });
                });
            if (hasOpaqueUnwind) {
                statistics.skipped += functions.size();
                continue;
            }
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
                selected[index] =
                    context.is_function_selected(analyzed.value().image, *functions[index]);
            }
            std::vector<FunctionChunk> chunks;
            chunks.reserve(functions.size());
            bool rangesValid = true;
            for (std::size_t index = 0; index < functions.size(); ++index) {
                const auto begin = functions[index]->address.value;
                const auto end = index + 1 < functions.size()
                                     ? functions[index + 1]->address.value
                                     : static_cast<std::uint64_t>(section.contents.size());
                if (begin >= end || end > section.contents.size() ||
                    functions[index]->size > end - begin) {
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
                    const auto* instruction =
                        find_instruction(analyzed.value().image, instructionId);
                    if (instruction == nullptr || !instruction->directTarget.has_value()) continue;
                    const auto target = instruction->directTarget->value;
                    const bool insideFunction =
                        target >= function->address.value && target < functionEnd;
                    const bool hasRelocation = std::any_of(
                        instruction->references.begin(),
                        instruction->references.end(),
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
            for (std::size_t index = 0; index < order.size(); ++index)
                order[index] = index;
            std::vector<bool> reordered(chunks.size(), false);
            std::size_t reorderedCount = 0;
            for (std::size_t runBegin = 0; runBegin < selected.size();) {
                if (!selected[runBegin]) {
                    ++runBegin;
                    continue;
                }
                auto runEnd = runBegin + 1;
                while (runEnd < selected.size() && selected[runEnd])
                    ++runEnd;
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
                if (uses_object_rewrite(image.architecture)) break;
                if (!relocation.targetSymbol.has_value()) continue;
                const auto* target = find_symbol(image, *relocation.targetSymbol);
                if (target == nullptr || target->kind != SymbolKind::Section ||
                    target->section != section.id)
                    continue;
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
                if (!mapped && relocation.section == section.id &&
                    relocation.kind == RelocationKind::PcRelative && relocation.addend >= -4) {
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

            if (uses_object_rewrite(image.architecture)) {
                if (!transform.valid()) transform = context.allocate_transform_id();
                for (const auto& chunk : chunks) {
                    x86Ranges.push_back(ObjectRewriteRange{
                        section.id,
                        chunk.oldBegin,
                        chunk.oldEnd,
                        chunk.newBegin,
                        {},
                    });
                }
                changedSections.insert(section.id.value());
                for (std::size_t index = 0; index < functions.size(); ++index) {
                    if (reordered[index]) {
                        changedFunctions.insert(functions[index]->symbol->value());
                    }
                }
                statistics.changed += reorderedCount;
                continue;
            }

            const auto originalContents = section.contents;
            auto outputOffset = static_cast<std::size_t>(chunks.front().oldBegin);
            for (const auto index : order) {
                const auto begin = static_cast<std::size_t>(chunks[index].oldBegin);
                const auto end = static_cast<std::size_t>(chunks[index].oldEnd);
                std::copy(originalContents.begin() + static_cast<std::ptrdiff_t>(begin),
                          originalContents.begin() + static_cast<std::ptrdiff_t>(end),
                          section.contents.begin() + static_cast<std::ptrdiff_t>(outputOffset));
                outputOffset += end - begin;
            }
            if (!transform.valid()) transform = context.allocate_transform_id();
            append_lineage(section, transform, name());
            changedSections.insert(section.id.value());
            for (auto& symbol : image.symbols) {
                if (!symbol.defined || symbol.section != section.id ||
                    symbol.kind == SymbolKind::Section)
                    continue;
                if (const auto mapped = map_offset(chunks, symbol.address.value)) {
                    if (*mapped != symbol.address.value) {
                        symbol.address.value = *mapped;
                        symbol.lineage.parents.push_back(
                            TransformationRecord{.transform = transform,
                                                 .source = symbol.id,
                                                 .passName = std::string{name()}});
                    }
                }
            }
            for (auto& relocation : image.relocations) {
                if (relocation.section == section.id) {
                    const auto mapped = map_offset(chunks, relocation.offset);
                    if (!mapped.has_value()) {
                        return Result<TransformResult, Diagnostic>::failure(
                            diagnostic(DiagnosticSeverity::Error,
                                       "pass.unmapped_relocation",
                                       "function reordering could not map a relocation site"));
                    }
                    relocation.offset = *mapped;
                }
                if (!relocation.targetSymbol.has_value()) continue;
                const auto* target = find_symbol(image, *relocation.targetSymbol);
                if (target == nullptr || target->kind != SymbolKind::Section ||
                    target->section != section.id)
                    continue;
                if (relocation.section != section.id && relocation.addend >= 0) {
                    const auto oldTarget = static_cast<std::uint64_t>(relocation.addend);
                    const auto exactSymbol = std::any_of(
                        functions.begin(), functions.end(), [oldTarget](const auto* function) {
                            return function->address.value == oldTarget;
                        });
                    if (exactSymbol) {
                        relocation.addend =
                            static_cast<std::int64_t>(*map_offset(chunks, oldTarget));
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
        if (uses_object_rewrite(image.architecture)) {
            const auto rewritten =
                commit_object_rewrite(image, *backend, std::move(x86Ranges), transform, name());
            if (!rewritten.has_value()) {
                return Result<TransformResult, Diagnostic>::failure(rewritten.error());
            }
        }
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

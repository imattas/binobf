#include "../test_support.hpp"

#include <binobf/analysis/object_analyzer.hpp>
#include <binobf/architecture/backend.hpp>
#include <binobf/formats/object_parser.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

std::filesystem::path corpusDirectory;

auto bytes(std::initializer_list<std::uint32_t> words) -> std::vector<std::byte> {
    std::vector<std::byte> result;
    result.reserve(words.size() * 4U);
    for (const auto word : words) {
        for (std::size_t index = 0; index < 4U; ++index) {
            result.push_back(static_cast<std::byte>((word >> (index * 8U)) & 0xffU));
        }
    }
    return result;
}

auto backend_instance() -> std::unique_ptr<binobf::ArchitectureBackend>& {
    static std::unique_ptr<binobf::ArchitectureBackend> instance;
    if (!instance) {
        auto result = binobf::make_architecture_backend(binobf::Architecture::ARM64);
        if (!result.has_value()) throw std::runtime_error(result.error().message);
        instance = std::move(result).value();
    }
    return instance;
}

auto backend() -> binobf::ArchitectureBackend& {
    return *backend_instance();
}

void release_backend() {
    backend_instance().reset();
}

auto decode_word(std::uint32_t word, std::uint64_t address = 0x1000)
    -> binobf::Instruction {
    const auto encoded = bytes({word});
    auto result = backend().decode(binobf::DecodeRequest{
        .architecture = binobf::Architecture::ARM64,
        .bytes = encoded,
        .address = {address, binobf::AddressKind::Virtual},
        .instructionId = binobf::EntityId{1},
        .sectionId = binobf::EntityId{2},
        .sectionOffset = 0,
    });
    if (!result.has_value()) throw std::runtime_error(result.error().message);
    return std::move(result).value();
}

auto emit(std::string assembly, std::uint64_t base = 0x1000) -> std::vector<std::byte> {
    binobf::MachineAssemblyRequest request{};
    request.architecture = binobf::Architecture::ARM64;
    request.format = binobf::BinaryFormat::ELF;
    request.triple = "aarch64-unknown-linux-gnu";
    request.assembly = std::move(assembly);
    request.syntax = binobf::MachineSyntax::GNU;
    request.baseAddress = {base, binobf::AddressKind::Virtual};
    const auto result = backend().codegen()->emit(request);
    if (!result.has_value()) throw std::runtime_error(result.error().message);
    return result.value().bytes;
}

auto decode_at(std::span<const std::byte> encoded, std::size_t offset)
    -> binobf::Instruction {
    auto result = backend().decode(binobf::DecodeRequest{
        .architecture = binobf::Architecture::ARM64,
        .bytes = encoded.subspan(offset),
        .address = {0x1000U + offset, binobf::AddressKind::Virtual},
        .instructionId = binobf::EntityId{1U + offset / 4U},
        .sectionId = binobf::EntityId{2},
        .sectionOffset = offset,
    });
    if (!result.has_value()) throw std::runtime_error(result.error().message);
    return std::move(result).value();
}

auto has_register(
    const std::vector<binobf::RegisterAccess>& registers,
    std::string_view name) -> bool {
    return std::ranges::find(registers, name, &binobf::RegisterAccess::name)
        != registers.end();
}

auto make_image(std::vector<std::byte> code) -> binobf::BinaryImage {
    binobf::BinaryImage image{};
    image.format = binobf::BinaryFormat::ELF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::ARM64;
    image.sections.push_back(binobf::Section{
        .id = binobf::EntityId{1}, .formatIndex = 1, .formatType = 1,
        .formatFlags = 6, .name = ".text", .kind = binobf::SectionKind::Code,
        .address = {}, .logicalSize = code.size(), .alignment = 4,
        .readable = true, .writable = false, .executable = true,
        .contents = std::move(code), .lineage = {}});
    return image;
}

void add_function(
    binobf::BinaryImage& image,
    std::uint64_t id,
    std::string name,
    std::uint64_t offset,
    std::uint64_t size) {
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{id},
        .formatIndex = static_cast<std::uint32_t>(image.symbols.size() + 1U),
        .formatTableIndex = 0, .formatType = 2, .formatStorage = 1,
        .formatSectionIndex = 1, .auxiliaryData = {}, .name = std::move(name),
        .section = binobf::EntityId{1},
        .address = {offset, binobf::AddressKind::RelativeVirtual}, .size = size,
        .kind = binobf::SymbolKind::Function,
        .visibility = binobf::SymbolVisibility::External, .defined = true,
        .definition = binobf::SymbolDefinitionKind::SectionRelative,
        .commonAlignment = 0, .tlsModel = binobf::TlsModel::None, .lineage = {}});
}

auto find_function(const binobf::BinaryImage& image, std::string_view name)
    -> const binobf::Function& {
    const auto found = std::ranges::find(image.functions, name, &binobf::Function::name);
    if (found == image.functions.end()) throw std::runtime_error("missing function");
    return *found;
}

auto find_block(
    const binobf::BinaryImage& image,
    const binobf::Function& function,
    std::uint64_t offset) -> const binobf::BasicBlock& {
    const auto found = std::ranges::find_if(image.basicBlocks, [&](const auto& block) {
        return block.function == function.id && block.sectionOffset == offset;
    });
    if (found == image.basicBlocks.end()) throw std::runtime_error("missing block");
    return *found;
}

auto has_edge(const binobf::BasicBlock& block, binobf::ControlFlowEdgeKind kind) -> bool {
    return std::ranges::any_of(block.edges, [kind](const auto& edge) {
        return edge.kind == kind;
    });
}

auto has_diagnostic(const binobf::AnalysisReport& report, std::string_view code) -> bool {
    return std::ranges::any_of(report.diagnostics, [code](const auto& diagnostic) {
        return diagnostic.code == code;
    });
}

auto read_file(const std::filesystem::path& path) -> std::vector<std::byte> {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("could not open corpus member");
    const auto end = stream.tellg();
    if (end < 0) throw std::runtime_error("could not size corpus member");
    std::vector<std::byte> result(static_cast<std::size_t>(end));
    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(result.data()), static_cast<std::streamsize>(result.size()));
    if (!stream) throw std::runtime_error("could not read corpus member");
    return result;
}

auto corpus_members() -> std::vector<std::filesystem::path> {
    std::ifstream manifest(corpusDirectory / "manifest.txt");
    if (!manifest) throw std::runtime_error("missing ARM64 corpus manifest");
    std::vector<std::filesystem::path> result;
    std::string line;
    while (std::getline(manifest, line)) {
        if (!line.starts_with("object|")) continue;
        std::array<std::string_view, 6> fields{};
        std::size_t begin = 0;
        for (std::size_t index = 0; index < fields.size(); ++index) {
            const auto end = line.find('|', begin);
            fields[index] = std::string_view{line}.substr(
                begin, end == std::string::npos ? line.size() - begin : end - begin);
            begin = end == std::string::npos ? line.size() : end + 1U;
        }
        result.emplace_back(fields[4]);
    }
    return result;
}

} // namespace

TEST_CASE(arm64_decoder_classifies_every_control_flow_family) {
    for (std::uint32_t condition = 0; condition < 16U; ++condition) {
        const auto instruction = decode_word(0x54000040U | condition);
        REQUIRE_EQ(instruction.kind, binobf::InstructionKind::ConditionalBranch);
        REQUIRE_EQ(instruction.directTarget->value, UINT64_C(0x1008));
        REQUIRE(instruction.hasFallthrough);
    }

    struct Golden {
        std::uint32_t word;
        binobf::InstructionKind kind;
        bool fallthrough;
        bool hasTarget;
    };
    constexpr std::array goldens{
        Golden{0x14000002U, binobf::InstructionKind::DirectBranch, false, true},
        Golden{0x94000002U, binobf::InstructionKind::DirectCall, true, true},
        Golden{0xb4000040U, binobf::InstructionKind::ConditionalBranch, true, true},
        Golden{0xb5000040U, binobf::InstructionKind::ConditionalBranch, true, true},
        Golden{0x36000040U, binobf::InstructionKind::ConditionalBranch, true, true},
        Golden{0x37000040U, binobf::InstructionKind::ConditionalBranch, true, true},
        Golden{0xd61f0000U, binobf::InstructionKind::IndirectBranch, false, false},
        Golden{0xd63f0000U, binobf::InstructionKind::IndirectCall, true, false},
        Golden{0xd65f03c0U, binobf::InstructionKind::Return, false, false},
    };
    for (const auto& golden : goldens) {
        const auto instruction = decode_word(golden.word);
        REQUIRE_EQ(instruction.kind, golden.kind);
        REQUIRE_EQ(instruction.hasFallthrough, golden.fallthrough);
        REQUIRE_EQ(instruction.directTarget.has_value(), golden.hasTarget);
    }
}

TEST_CASE(arm64_decoder_normalizes_sp_fp_lr_nzcv_and_vector_effects) {
    const auto storePair = decode_word(0xa9bf7bfdU);
    REQUIRE(has_register(storePair.registersRead, "sp"));
    REQUIRE(has_register(storePair.registersRead, "x29"));
    REQUIRE(has_register(storePair.registersRead, "x30"));
    REQUIRE(has_register(storePair.registersWritten, "sp"));

    const auto compare = decode_word(0xf100001fU);
    REQUIRE(has_register(compare.registersWritten, "nzcv"));
    const auto conditional = decode_word(0x54000040U);
    REQUIRE(has_register(conditional.registersRead, "nzcv"));
    const auto link = decode_word(0x94000002U);
    REQUIRE(has_register(link.registersWritten, "x30"));
    const auto returned = decode_word(0xd65f03c0U);
    REQUIRE(has_register(returned.registersRead, "x30"));

    const auto vectorBytes = emit("add v0.4s, v1.4s, v2.4s\n");
    const auto vector = decode_at(vectorBytes, 0);
    REQUIRE(has_register(vector.registersRead, "v1"));
    REQUIRE(has_register(vector.registersRead, "v2"));
    REQUIRE(has_register(vector.registersWritten, "v0"));
}

TEST_CASE(arm64_decoder_records_literal_and_pc_relative_data_references) {
    const auto encoded = emit(
        "adr x0, target\n"
        "adrp x1, target\n"
        "ldr x2, target\n"
        "target:\n"
        "nop\n");
    for (const auto offset : {std::size_t{0}, std::size_t{4}, std::size_t{8}}) {
        const auto instruction = decode_at(encoded, offset);
        REQUIRE(std::ranges::any_of(instruction.references, [](const auto& reference) {
            return reference.kind == binobf::InstructionReferenceKind::Data
                && reference.address.has_value();
        }));
    }
}

TEST_CASE(arm64_analyzer_builds_fixed_width_cfg_and_calls) {
    release_backend();
    auto image = make_image(bytes({
        0xf100001fU,
        0x54000060U,
        0x94000003U,
        0x14000003U,
        0xb4000041U,
        0xd65f03c0U,
        0xd65f03c0U,
    }));
    add_function(image, 2, "flow", 0, 28);
    const auto report = binobf::analyze_object(image);
    REQUIRE(report.has_value());
    const auto& function = find_function(report.value().image, "flow");
    REQUIRE(function.complete);
    REQUIRE(std::ranges::all_of(report.value().image.instructions, [](const auto& instruction) {
        return instruction.encoding.size() == 4U;
    }));
    REQUIRE(has_edge(find_block(report.value().image, function, 0),
                     binobf::ControlFlowEdgeKind::BranchTaken));
    REQUIRE(has_edge(find_block(report.value().image, function, 8),
                     binobf::ControlFlowEdgeKind::DirectCall));
    REQUIRE(has_edge(find_block(report.value().image, function, 8),
                     binobf::ControlFlowEdgeKind::Fallthrough));
}

TEST_CASE(arm64_analyzer_refuses_unresolved_indirect_flow_without_inventing_targets) {
    auto branchImage = make_image(bytes({0xd61f0000U}));
    add_function(branchImage, 2, "indirect_branch", 0, 4);
    const auto branch = binobf::analyze_object(branchImage);
    REQUIRE(branch.has_value());
    const auto& branchFunction = find_function(branch.value().image, "indirect_branch");
    REQUIRE(!branchFunction.complete);
    REQUIRE(has_edge(find_block(branch.value().image, branchFunction, 0),
                     binobf::ControlFlowEdgeKind::UnresolvedIndirect));
    REQUIRE(has_diagnostic(branch.value(), "analysis.unresolved_indirect_flow"));

    auto callImage = make_image(bytes({0xd63f0020U, 0xd65f03c0U}));
    add_function(callImage, 2, "indirect_call", 0, 8);
    const auto call = binobf::analyze_object(callImage);
    REQUIRE(call.has_value());
    const auto& callFunction = find_function(call.value().image, "indirect_call");
    REQUIRE(!callFunction.complete);
    const auto& callInstruction = call.value().image.instructions.front();
    REQUIRE_EQ(callInstruction.kind, binobf::InstructionKind::IndirectCall);
    REQUIRE(!callInstruction.directTarget.has_value());
}

TEST_CASE(arm64_analyzer_preserves_evidence_ids_and_mapping_symbols_only_refine_ranges) {
    auto image = make_image(bytes({0xaa0003e0U, 0xd65f03c0U, 0xd65f03c0U}));
    image.functions.push_back(binobf::Function{
        .id = binobf::EntityId{50}, .name = "unwind_owned", .section = binobf::EntityId{1},
        .symbol = {}, .address = {}, .size = 8,
        .discovery = binobf::FunctionDiscovery::Unwind,
        .instructions = {binobf::EntityId{60}}, .basicBlocks = {binobf::EntityId{61}},
        .entryBlock = binobf::EntityId{61}, .externallyVisible = false, .complete = true,
        .lineage = {}});
    image.instructions.push_back(binobf::Instruction{
        .id = binobf::EntityId{60}, .section = binobf::EntityId{1}, .sectionOffset = 0,
        .address = {}, .encoding = bytes({0xaa0003e0U}), .mnemonic = "mov",
        .operands = "x0, x0", .kind = binobf::InstructionKind::Normal,
        .directTarget = {}, .hasFallthrough = true, .registersRead = {},
        .registersWritten = {}, .references = {}, .lineage = {}});
    image.basicBlocks.push_back(binobf::BasicBlock{
        .id = binobf::EntityId{61}, .function = binobf::EntityId{50},
        .section = binobf::EntityId{1}, .sectionOffset = 0, .address = {},
        .instructions = {binobf::EntityId{60}}, .successors = {}, .edges = {},
        .liveIn = {}, .liveOut = {}, .hasUnresolvedSuccessor = false, .lineage = {}});
    const auto preserved = binobf::analyze_object(image);
    REQUIRE(preserved.has_value());
    REQUIRE_EQ(preserved.value().image.functions.size(), std::size_t{1});
    REQUIRE_EQ(preserved.value().image.instructions.size(), std::size_t{2});
    REQUIRE_EQ(preserved.value().image.basicBlocks.size(), std::size_t{1});
    REQUIRE_EQ(preserved.value().image.functions.front().id, binobf::EntityId{50});
    REQUIRE_EQ(preserved.value().image.instructions.front().id, binobf::EntityId{60});
    REQUIRE_EQ(preserved.value().image.basicBlocks.front().id, binobf::EntityId{61});

    auto mapped = make_image(bytes({0xaa0003e0U, 0xd65f03c0U, 0xd65f03c0U}));
    add_function(mapped, 2, "mapped", 0, 0);
    mapped.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{3}, .formatIndex = 2, .formatTableIndex = 0,
        .formatType = 0, .formatStorage = 0, .formatSectionIndex = 1,
        .auxiliaryData = {}, .name = "$d", .section = binobf::EntityId{1},
        .address = {8, binobf::AddressKind::RelativeVirtual}, .size = 0,
        .kind = binobf::SymbolKind::Unknown,
        .visibility = binobf::SymbolVisibility::Local, .defined = true,
        .definition = binobf::SymbolDefinitionKind::SectionRelative,
        .commonAlignment = 0, .tlsModel = binobf::TlsModel::None, .lineage = {}});
    const auto refined = binobf::analyze_object(mapped);
    REQUIRE(refined.has_value());
    REQUIRE_EQ(refined.value().image.functions.size(), std::size_t{1});
    REQUIRE_EQ(refined.value().image.functions.front().size, UINT64_C(8));

    auto relocated = make_image(bytes({0x94000000U}));
    relocated.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{2}, .formatIndex = 1, .formatTableIndex = 0,
        .formatType = 0, .formatStorage = 0, .formatSectionIndex = 1,
        .auxiliaryData = {}, .name = "relocation_owned", .section = binobf::EntityId{1},
        .address = {}, .size = 0, .kind = binobf::SymbolKind::Unknown,
        .visibility = binobf::SymbolVisibility::Local, .defined = true,
        .definition = binobf::SymbolDefinitionKind::SectionRelative,
        .commonAlignment = 0, .tlsModel = binobf::TlsModel::None, .lineage = {}});
    relocated.relocations.push_back(binobf::Relocation{
        .id = binobf::EntityId{3}, .formatIndex = 0, .formatTableIndex = 0,
        .section = binobf::EntityId{1}, .offset = 0,
        .kind = binobf::RelocationKind::PcRelative, .rawType = 0x11b,
        .targetSymbol = binobf::EntityId{2}, .addend = 0, .lineage = {}});
    const auto discovered = binobf::analyze_object(relocated);
    REQUIRE(discovered.has_value());
    REQUIRE_EQ(discovered.value().image.functions.size(), std::size_t{1});
    REQUIRE_EQ(discovered.value().image.functions.front().discovery,
               binobf::FunctionDiscovery::Relocation);
}

TEST_CASE(arm64_analyzer_rejects_non_word_ranges_and_outside_branch_targets) {
    auto trailing = make_image({std::byte{0xc0}, std::byte{0x03}, std::byte{0x5f},
                                std::byte{0xd6}, std::byte{0xaa}});
    add_function(trailing, 2, "trailing", 0, 5);
    const auto partial = binobf::analyze_object(trailing);
    REQUIRE(partial.has_value());
    const auto& partialFunction = find_function(partial.value().image, "trailing");
    REQUIRE(!partialFunction.complete);
    REQUIRE(std::ranges::all_of(partial.value().image.instructions, [](const auto& instruction) {
        return instruction.encoding.size() == 4U;
    }));
    REQUIRE(has_diagnostic(partial.value(), "analysis.arm64_incomplete_word"));

    auto outside = make_image(bytes({0x14000003U}));
    add_function(outside, 2, "outside", 0, 4);
    const auto branch = binobf::analyze_object(outside);
    REQUIRE(branch.has_value());
    REQUIRE(!find_function(branch.value().image, "outside").complete);
    REQUIRE(has_diagnostic(branch.value(), "analysis.branch_target_outside_code"));
}

TEST_CASE(arm64_compiler_corpus_analyzes_every_language_format_and_optimization) {
    if (corpusDirectory.empty()) return;
    const auto members = corpus_members();
    REQUIRE_EQ(members.size(), std::size_t{24});
    bool sawCall = false;
    bool sawConditional = false;
    for (const auto& path : members) {
        const auto parsed = binobf::parse_object(read_file(path), path.filename().string());
        REQUIRE(parsed.has_value());
        REQUIRE_EQ(parsed.value().architecture, binobf::Architecture::ARM64);
        const auto analyzed = binobf::analyze_object(parsed.value());
        REQUIRE(analyzed.has_value());
        REQUIRE(std::ranges::any_of(analyzed.value().image.functions, [](const auto& function) {
            return function.complete && !function.instructions.empty();
        }));
        REQUIRE(std::ranges::all_of(
            analyzed.value().image.instructions, [](const auto& instruction) {
                return instruction.encoding.size() == 4U;
            }));
        REQUIRE(std::ranges::none_of(analyzed.value().image.functions, [](const auto& function) {
            return function.name == "$x" || function.name == "$d"
                || function.name.starts_with("$x.") || function.name.starts_with("$d.");
        }));
        sawCall = sawCall || std::ranges::any_of(
            analyzed.value().image.instructions, [](const auto& instruction) {
                return instruction.kind == binobf::InstructionKind::DirectCall
                    || instruction.kind == binobf::InstructionKind::IndirectCall;
            });
        sawConditional = sawConditional || std::ranges::any_of(
            analyzed.value().image.instructions, [](const auto& instruction) {
                return instruction.kind == binobf::InstructionKind::ConditionalBranch;
            });

        const auto reanalyzed = binobf::analyze_object(analyzed.value().image);
        REQUIRE(reanalyzed.has_value());
        REQUIRE_EQ(reanalyzed.value().image.functions.size(),
                   analyzed.value().image.functions.size());
        REQUIRE_EQ(reanalyzed.value().image.instructions.size(),
                   analyzed.value().image.instructions.size());
        for (std::size_t index = 0; index < analyzed.value().image.functions.size(); ++index) {
            REQUIRE_EQ(reanalyzed.value().image.functions[index].id,
                       analyzed.value().image.functions[index].id);
        }
        for (std::size_t index = 0; index < analyzed.value().image.instructions.size(); ++index) {
            REQUIRE_EQ(reanalyzed.value().image.instructions[index].id,
                       analyzed.value().image.instructions[index].id);
        }
    }
    REQUIRE(sawCall);
    REQUIRE(sawConditional);
}

int main(int argc, char** argv) {
    if (argc == 2) corpusDirectory = argv[1];
    return binobf::test::run_all();
}

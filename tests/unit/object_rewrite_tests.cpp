#include <binobf/architecture/backend.hpp>
#include <binobf/transforms/object_rewrite.hpp>

#include "../test_support.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace {

auto backend() -> std::unique_ptr<binobf::ArchitectureBackend> {
    auto result = binobf::make_architecture_backend(binobf::Architecture::X86);
    if (!result.has_value()) throw std::runtime_error(result.error().message);
    return std::move(result).value();
}

auto section_symbol() -> binobf::Symbol {
    binobf::Symbol value{};
    value.id = binobf::EntityId{2};
    value.formatIndex = 0;
    value.formatStorage = 3;
    value.formatSectionIndex = 1;
    value.name = ".text";
    value.section = binobf::EntityId{1};
    value.kind = binobf::SymbolKind::Section;
    value.visibility = binobf::SymbolVisibility::Local;
    value.defined = true;
    value.definition = binobf::SymbolDefinitionKind::SectionRelative;
    value.tlsModel = binobf::TlsModel::None;
    return value;
}

auto function_symbol(
    std::uint64_t id,
    std::uint32_t index,
    std::string name,
    std::uint64_t address) -> binobf::Symbol {
    binobf::Symbol value{};
    value.id = binobf::EntityId{id};
    value.formatIndex = index;
    value.formatStorage = 3;
    value.formatType = 0x20;
    value.formatSectionIndex = 1;
    value.name = std::move(name);
    value.section = binobf::EntityId{1};
    value.address = binobf::BinaryAddress{address, binobf::AddressKind::RelativeVirtual};
    value.size = 4;
    value.kind = binobf::SymbolKind::Function;
    value.visibility = binobf::SymbolVisibility::Local;
    value.defined = true;
    value.definition = binobf::SymbolDefinitionKind::SectionRelative;
    value.tlsModel = binobf::TlsModel::None;
    return value;
}

auto function(
    std::uint64_t id,
    std::string name,
    binobf::EntityId symbol,
    std::uint64_t address) -> binobf::Function {
    binobf::Function value{};
    value.id = binobf::EntityId{id};
    value.name = std::move(name);
    value.section = binobf::EntityId{1};
    value.symbol = symbol;
    value.address = binobf::BinaryAddress{address, binobf::AddressKind::RelativeVirtual};
    value.size = 4;
    value.discovery = binobf::FunctionDiscovery::Symbol;
    value.complete = true;
    return value;
}

auto image(std::size_t size = 8U) -> binobf::BinaryImage {
    binobf::BinaryImage result{};
    result.format = binobf::BinaryFormat::COFF;
    result.type = binobf::BinaryType::RelocatableObject;
    result.architecture = binobf::Architecture::X86;
    binobf::Section text{};
    text.id = binobf::EntityId{1};
    text.formatIndex = 1;
    text.formatFlags = 0x60500020U;
    text.name = ".text";
    text.kind = binobf::SectionKind::Code;
    text.address = binobf::BinaryAddress{0U, binobf::AddressKind::RelativeVirtual};
    text.logicalSize = size;
    text.alignment = 4;
    text.readable = true;
    text.executable = true;
    text.contents.resize(size);
    for (std::size_t index = 0; index < size; ++index) {
        text.contents[index] = static_cast<std::byte>((index + 1U) & 0xffU);
    }
    result.sections.push_back(std::move(text));
    result.symbols = {
        section_symbol(), function_symbol(3, 1, "first", 0),
        function_symbol(4, 2, "second", 4)};
    result.functions = {
        function(5, "first", binobf::EntityId{3}, 0),
        function(6, "second", binobf::EntityId{4}, 4)};
    return result;
}

auto reorder_request(bool reverseInput = false) -> binobf::ObjectRewriteRequest {
    binobf::ObjectRewriteRequest request{};
    request.passName = "test-reorder";
    request.transform = binobf::TransformId{10};
    request.ranges = {
        binobf::ObjectRewriteRange{binobf::EntityId{1}, 0, 4, 4, {}},
        binobf::ObjectRewriteRange{binobf::EntityId{1}, 4, 8, 0, {}},
    };
    if (reverseInput) std::ranges::reverse(request.ranges);
    return request;
}

auto require_create_error(
    const binobf::BinaryImage& source,
    const binobf::ObjectRewriteRequest& request,
    std::string_view code) -> void {
    const auto originalBytes = source.sections.front().contents;
    const auto originalSymbols = source.symbols;
    auto fixed = backend();
    const auto result = binobf::ObjectRewritePlan::create(source, *fixed, request);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, code);
    REQUIRE_EQ(source.sections.front().contents, originalBytes);
    REQUIRE_EQ(source.symbols.size(), originalSymbols.size());
    for (std::size_t index = 0; index < source.symbols.size(); ++index) {
        REQUIRE_EQ(source.symbols[index].address.value, originalSymbols[index].address.value);
        REQUIRE_EQ(source.symbols[index].lineage.parents.size(),
                   originalSymbols[index].lineage.parents.size());
    }
}

auto require_source_mismatch(
    const binobf::ObjectRewritePlan& plan,
    const binobf::BinaryImage& changed) -> void {
    const auto committed = plan.commit(changed);
    REQUIRE(!committed.has_value());
    REQUIRE_EQ(committed.error().code, "rewrite.source_mismatch");
}

} // namespace

TEST_CASE(object_rewrite_reorders_two_owned_functions_transactionally) {
    const auto source = image();
    auto fixed = backend();
    const auto plan = binobf::ObjectRewritePlan::create(source, *fixed, reorder_request());
    REQUIRE(plan.has_value());
    REQUIRE(plan.value().validate(source).has_value());
    const auto output = plan.value().commit(source);
    REQUIRE(output.has_value());
    const std::vector<std::byte> expected{
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8},
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    REQUIRE_EQ(output.value().sections.front().contents, expected);
    REQUIRE_EQ(output.value().symbols[1].address.value, UINT64_C(4));
    REQUIRE_EQ(output.value().symbols[2].address.value, UINT64_C(0));
    REQUIRE_EQ(output.value().functions[0].address.value, UINT64_C(4));
    REQUIRE_EQ(output.value().functions[1].address.value, UINT64_C(0));
    REQUIRE_EQ(output.value().sections.front().lineage.parents.size(), std::size_t{1});
    REQUIRE_EQ(source.sections.front().contents.front(), std::byte{1});
    REQUIRE(source.sections.front().lineage.parents.empty());
}

TEST_CASE(object_rewrite_order_is_deterministic) {
    const auto source = image();
    auto fixed = backend();
    const auto first = binobf::ObjectRewritePlan::create(source, *fixed, reorder_request(false));
    const auto second = binobf::ObjectRewritePlan::create(source, *fixed, reorder_request(true));
    REQUIRE(first.has_value());
    REQUIRE(second.has_value());
    const auto firstOutput = first.value().commit(source);
    const auto secondOutput = second.value().commit(source);
    REQUIRE(firstOutput.has_value());
    REQUIRE(secondOutput.has_value());
    REQUIRE_EQ(firstOutput.value().sections.front().contents,
               secondOutput.value().sections.front().contents);
    REQUIRE_EQ(firstOutput.value().symbols[1].address.value,
               secondOutput.value().symbols[1].address.value);
}

TEST_CASE(object_rewrite_rejects_overlaps_mapping_gaps_and_growth_overflow) {
    auto source = image();
    auto overlap = reorder_request();
    overlap.ranges[1].oldBegin = 3;
    require_create_error(source, overlap, "rewrite.overlap");

    auto gap = reorder_request();
    gap.ranges.resize(1);
    require_create_error(source, gap, "rewrite.mapping_gap");

    binobf::ObjectRewriteRequest expansion{};
    expansion.passName = "insert";
    expansion.transform = binobf::TransformId{11};
    expansion.maxOutputGrowth = 1;
    expansion.ranges = {binobf::ObjectRewriteRange{
        binobf::EntityId{1}, 4, 4, 4, {std::byte{0x90}, std::byte{0x90}}}};
    require_create_error(source, expansion, "rewrite.growth_limit");
}

TEST_CASE(object_rewrite_insertion_maps_the_trailing_function_and_preserves_gaps) {
    const auto source = image();
    binobf::ObjectRewriteRequest request{};
    request.passName = "insert";
    request.transform = binobf::TransformId{12};
    request.ranges = {binobf::ObjectRewriteRange{
        binobf::EntityId{1}, 4, 4, 4, {std::byte{0x90}, std::byte{0x90}}}};
    auto fixed = backend();
    const auto plan = binobf::ObjectRewritePlan::create(source, *fixed, request);
    REQUIRE(plan.has_value());
    const auto output = plan.value().commit(source);
    REQUIRE(output.has_value());
    REQUIRE_EQ(output.value().sections.front().contents.size(), std::size_t{10});
    REQUIRE_EQ(output.value().sections.front().contents[4], std::byte{0x90});
    REQUIRE_EQ(output.value().sections.front().contents[5], std::byte{0x90});
    REQUIRE_EQ(output.value().symbols[2].address.value, UINT64_C(6));
}

TEST_CASE(object_rewrite_insertion_inside_an_owned_function_expands_its_total_range) {
    auto source = image();
    source.symbols.resize(2);
    source.symbols[1].size = 8;
    source.functions.resize(1);
    source.functions[0].size = 8;
    binobf::ObjectRewriteRequest request{};
    request.passName = "insert-owned";
    request.transform = binobf::TransformId{14};
    request.ranges = {binobf::ObjectRewriteRange{
        binobf::EntityId{1}, 4, 4, 4, {std::byte{0x90}, std::byte{0x90}}}};
    auto fixed = backend();
    const auto plan = binobf::ObjectRewritePlan::create(source, *fixed, request);
    REQUIRE(plan.has_value());
    const auto output = plan.value().commit(source);
    REQUIRE(output.has_value());
    REQUIRE_EQ(output.value().symbols[1].size, UINT64_C(10));
    REQUIRE_EQ(output.value().functions[0].size, UINT64_C(10));
}

TEST_CASE(object_rewrite_rejects_unmapped_symbols_and_duplicate_lineage) {
    auto source = image();
    source.symbols[1].address.value = 9;
    source.functions.clear();
    require_create_error(source, reorder_request(), "rewrite.unmapped_symbol");

    source = image();
    source.sections.front().lineage.parents.push_back(binobf::TransformationRecord{
        binobf::TransformId{10}, binobf::EntityId{1}, "already"});
    require_create_error(source, reorder_request(), "rewrite.duplicate_lineage");
}

TEST_CASE(object_rewrite_moves_relocation_sites_targets_and_implicit_addends) {
    auto source = image();
    binobf::Relocation relocation{};
    relocation.id = binobf::EntityId{7};
    relocation.formatIndex = 0;
    relocation.formatTableIndex = 1;
    relocation.section = binobf::EntityId{1};
    relocation.offset = 0;
    relocation.kind = binobf::RelocationKind::PcRelative;
    relocation.rawType = 0x14;
    relocation.targetSymbol = binobf::EntityId{2};
    relocation.addend = 0;
    source.relocations.push_back(relocation);
    auto fixed = backend();
    const auto plan = binobf::ObjectRewritePlan::create(source, *fixed, reorder_request());
    REQUIRE(plan.has_value());
    const auto output = plan.value().commit(source);
    REQUIRE(output.has_value());
    REQUIRE_EQ(output.value().relocations.front().offset, UINT64_C(4));
    REQUIRE_EQ(output.value().relocations.front().addend, INT64_C(-4));
    REQUIRE_EQ(output.value().sections.front().contents[4], std::byte{0});
    REQUIRE_EQ(output.value().sections.front().contents[5], std::byte{0});
    REQUIRE_EQ(output.value().relocations.front().lineage.parents.size(), std::size_t{1});
}

TEST_CASE(object_rewrite_rejects_out_of_range_pc_relative_repairs) {
    auto source = image(40000U);
    source.symbols[1].size = 4;
    source.symbols[2].address.value = 39996U;
    source.functions[1].address.value = 39996U;
    binobf::Relocation relocation{};
    relocation.id = binobf::EntityId{7};
    relocation.formatIndex = 0;
    relocation.formatTableIndex = 1;
    relocation.section = binobf::EntityId{1};
    relocation.offset = 0;
    relocation.kind = binobf::RelocationKind::PcRelative;
    relocation.rawType = 0x02;
    relocation.targetSymbol = binobf::EntityId{2};
    relocation.addend = 39998;
    source.relocations.push_back(relocation);
    binobf::ObjectRewriteRequest request{};
    request.passName = "range-check";
    request.transform = binobf::TransformId{13};
    request.ranges = {binobf::ObjectRewriteRange{
        binobf::EntityId{1}, 0, 40000, 0, {}}};
    require_create_error(source, request, "rewrite.branch_range");
}

TEST_CASE(object_rewrite_rejects_unowned_association_and_opaque_unwind_metadata) {
    auto source = image();
    binobf::SectionAssociation bad{};
    bad.section = binobf::EntityId{1};
    bad.kind = binobf::SectionAssociationKind::CoffComdat;
    bad.coffSelection = binobf::CoffComdatSelection::Any;
    source.sectionAssociations.push_back(bad);
    require_create_error(source, reorder_request(), "object.ownership_signature");

    source = image();
    binobf::UnwindInfo unwind{};
    unwind.id = binobf::EntityId{8};
    unwind.function = binobf::EntityId{5};
    unwind.encoded = {std::byte{0x01}};
    unwind.section = binobf::EntityId{1};
    unwind.sectionOffset = 7;
    unwind.codeOffset = 0;
    unwind.codeSize = 4;
    unwind.format = binobf::UnwindFormat::WindowsI386;
    unwind.rewriteState = binobf::UnwindRewriteState::Opaque;
    source.unwindInfo.push_back(unwind);
    require_create_error(source, reorder_request(), "rewrite.unowned_unwind");
}

TEST_CASE(object_rewrite_commit_refuses_a_different_snapshot_without_mutating_it) {
    const auto source = image();
    auto fixed = backend();
    const auto plan = binobf::ObjectRewritePlan::create(source, *fixed, reorder_request());
    REQUIRE(plan.has_value());
    auto changed = source;
    changed.symbols[1].address.value = 1;
    const auto before = changed.sections.front().contents;
    const auto committed = plan.value().commit(changed);
    REQUIRE(!committed.has_value());
    REQUIRE_EQ(committed.error().code, "rewrite.source_mismatch");
    REQUIRE_EQ(changed.sections.front().contents, before);
    REQUIRE_EQ(changed.symbols[1].address.value, UINT64_C(1));
}

TEST_CASE(object_rewrite_preserves_unknown_relocations_only_when_their_sites_do_not_move) {
    auto source = image();
    binobf::Relocation relocation{};
    relocation.id = binobf::EntityId{7};
    relocation.formatIndex = 0;
    relocation.formatTableIndex = 1;
    relocation.section = binobf::EntityId{1};
    relocation.offset = 1;
    relocation.kind = binobf::RelocationKind::ArchitectureSpecific;
    relocation.rawType = 0xffff;
    relocation.targetSymbol = binobf::EntityId{3};
    source.relocations.push_back(relocation);

    auto fixed = backend();
    const auto moved = binobf::ObjectRewritePlan::create(
        source, *fixed, reorder_request());
    REQUIRE(!moved.has_value());
    REQUIRE_EQ(moved.error().code, "rewrite.unknown_relocation_moved");

    auto identity = reorder_request();
    identity.ranges[0].newBegin = 0;
    identity.ranges[1].newBegin = 4;
    const auto preserved = binobf::ObjectRewritePlan::create(source, *fixed, identity);
    REQUIRE(preserved.has_value());
    const auto output = preserved.value().commit(source);
    REQUIRE(output.has_value());
    REQUIRE_EQ(output.value().relocations.front(), source.relocations.front());

    auto changedBytes = identity;
    changedBytes.ranges[1].replacement = {
        std::byte{0xff}, std::byte{6}, std::byte{7}, std::byte{8}};
    const auto rejectedBytes = binobf::ObjectRewritePlan::create(
        source, *fixed, changedBytes);
    REQUIRE(!rejectedBytes.has_value());
    REQUIRE_EQ(rejectedBytes.error().code, "rewrite.unknown_relocation_moved");
}

TEST_CASE(object_rewrite_snapshot_covers_every_semantic_model_collection) {
    const auto source = image();
    auto fixed = backend();
    const auto plan = binobf::ObjectRewritePlan::create(source, *fixed, reorder_request());
    REQUIRE(plan.has_value());

    auto changed = source;
    binobf::Segment segment{};
    segment.id = binobf::EntityId{20};
    segment.name = "segment";
    changed.segments.push_back(segment);
    require_source_mismatch(plan.value(), changed);

    changed = source;
    changed.extendedSectionIndices.push_back(binobf::ExtendedSectionIndex{
        .symbol = binobf::EntityId{3}, .indexSection = binobf::EntityId{1},
        .section = binobf::EntityId{1}, .rawSectionIndex = 1});
    require_source_mismatch(plan.value(), changed);

    changed = source;
    binobf::Import imported{};
    imported.id = binobf::EntityId{21};
    imported.name = "import";
    changed.imports.push_back(imported);
    require_source_mismatch(plan.value(), changed);

    changed = source;
    binobf::Export exported{};
    exported.id = binobf::EntityId{22};
    exported.name = "export";
    changed.exports.push_back(exported);
    require_source_mismatch(plan.value(), changed);

    changed = source;
    changed.relocationTableEncodings.push_back(binobf::RelocationTableEncoding{
        .section = binobf::EntityId{1}, .coffOverflow = true, .declaredCount = 0xffff});
    require_source_mismatch(plan.value(), changed);

    changed = source;
    changed.coffSafeSehEntries.push_back(binobf::CoffSafeSehEntry{
        .section = binobf::EntityId{1}, .symbol = binobf::EntityId{3}, .formatIndex = 0});
    require_source_mismatch(plan.value(), changed);

    changed = source;
    binobf::Instruction instruction{};
    instruction.id = binobf::EntityId{23};
    instruction.section = binobf::EntityId{1};
    instruction.registersRead = {{1U, "eax"}};
    changed.instructions.push_back(instruction);
    require_source_mismatch(plan.value(), changed);

    changed = source;
    binobf::BasicBlock block{};
    block.id = binobf::EntityId{24};
    block.function = binobf::EntityId{5};
    block.section = binobf::EntityId{1};
    block.edges = {{binobf::ControlFlowEdgeKind::DirectBranch, std::nullopt,
                    binobf::BinaryAddress{4U, binobf::AddressKind::RelativeVirtual}}};
    block.liveIn = {{1U, "eax"}};
    changed.basicBlocks.push_back(block);
    require_source_mismatch(plan.value(), changed);

    changed = source;
    binobf::DataObject data{};
    data.id = binobf::EntityId{25};
    data.name = "data";
    data.bytes = {std::byte{1}};
    changed.dataObjects.push_back(data);
    require_source_mismatch(plan.value(), changed);

    changed = source;
    binobf::DebugInfo debug{};
    debug.id = binobf::EntityId{26};
    debug.format = "debug";
    changed.debugInfo.push_back(debug);
    require_source_mismatch(plan.value(), changed);

    changed = source;
    binobf::Resource resource{};
    resource.id = binobf::EntityId{27};
    resource.type = "type";
    resource.name = "name";
    resource.bytes = {std::byte{2}};
    changed.resources.push_back(resource);
    require_source_mismatch(plan.value(), changed);
}

int main() { return binobf::test::run_all(); }

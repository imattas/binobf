#include "../test_support.hpp"

#include <binobf/architecture/backend.hpp>
#include <binobf/transforms/object_rewrite.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace {

auto backend() -> std::unique_ptr<binobf::ArchitectureBackend> {
    auto result = binobf::make_architecture_backend(binobf::Architecture::X86);
    if (!result.has_value()) throw std::runtime_error(result.error().message);
    return std::move(result).value();
}

auto section_symbol() -> binobf::Symbol {
    binobf::Symbol symbol{};
    symbol.id = binobf::EntityId{2};
    symbol.formatIndex = 0;
    symbol.formatStorage = 3;
    symbol.formatSectionIndex = 1;
    symbol.name = ".text";
    symbol.section = binobf::EntityId{1};
    symbol.kind = binobf::SymbolKind::Section;
    symbol.visibility = binobf::SymbolVisibility::Local;
    symbol.defined = true;
    symbol.definition = binobf::SymbolDefinitionKind::SectionRelative;
    return symbol;
}

auto function_symbol(
    std::uint64_t id, std::uint32_t index, std::string name, std::uint64_t address)
    -> binobf::Symbol {
    binobf::Symbol symbol{};
    symbol.id = binobf::EntityId{id};
    symbol.formatIndex = index;
    symbol.formatStorage = 3;
    symbol.formatType = 0x20;
    symbol.formatSectionIndex = 1;
    symbol.name = std::move(name);
    symbol.section = binobf::EntityId{1};
    symbol.address.value = address;
    symbol.size = 4;
    symbol.kind = binobf::SymbolKind::Function;
    symbol.visibility = binobf::SymbolVisibility::Local;
    symbol.defined = true;
    symbol.definition = binobf::SymbolDefinitionKind::SectionRelative;
    return symbol;
}

auto function(
    std::uint64_t id, std::string name, binobf::EntityId symbol, std::uint64_t address)
    -> binobf::Function {
    binobf::Function function{};
    function.id = binobf::EntityId{id};
    function.name = std::move(name);
    function.section = binobf::EntityId{1};
    function.symbol = symbol;
    function.address.value = address;
    function.size = 4;
    function.complete = true;
    return function;
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
        function_symbol(4, 2, "second", size - 4U)};
    result.functions = {
        function(5, "first", binobf::EntityId{3}, 0),
        function(6, "second", binobf::EntityId{4}, size - 4U)};
    return result;
}

auto reorder_request() -> binobf::ObjectRewriteRequest {
    binobf::ObjectRewriteRequest request{};
    request.passName = "mutation-golden";
    request.transform = binobf::TransformId{91};
    request.ranges = {
        binobf::ObjectRewriteRange{binobf::EntityId{1}, 0, 4, 4, {}},
        binobf::ObjectRewriteRange{binobf::EntityId{1}, 4, 8, 0, {}},
    };
    return request;
}

auto mutant_omits_signed_range_check(std::int64_t) -> bool { return false; }
auto mutant_omits_association_ownership(const binobf::BinaryImage&) -> bool { return false; }
auto mutant_omits_unwind_ownership(const binobf::BinaryImage&) -> bool { return false; }
auto mutant_omits_mapping_overlap(const binobf::ObjectRewriteRequest&) -> bool { return false; }

auto mutant_commit_mutates_before_snapshot_check(binobf::BinaryImage& target) -> bool {
    target.sections.front().contents.front() = std::byte{0xff};
    return false;
}

} // namespace

TEST_CASE(golden_counterexamples_kill_every_critical_x86_backend_mutant) {
    auto fixed = backend();

    const auto relative16 = fixed->fixup_semantics(binobf::BinaryFormat::COFF, 0x02);
    REQUIRE(relative16.has_value());
    const auto rangeGolden = fixed->encode_fixup(relative16.value(), INT64_C(32766));
    REQUIRE(!rangeGolden.has_value());
    REQUIRE_EQ(rangeGolden.error().code, "architecture.fixup_overflow");
    REQUIRE(!mutant_omits_signed_range_check(INT64_C(32766)));

    const auto relative32 = fixed->fixup_semantics(binobf::BinaryFormat::COFF, 0x14);
    REQUIRE(relative32.has_value());
    const auto biased = fixed->encode_fixup(relative32.value(), 0);
    REQUIRE(biased.has_value());
    const std::vector<std::byte> productionBias{
        std::byte{4}, std::byte{0}, std::byte{0}, std::byte{0}};
    const std::vector<std::byte> mutantWithoutBias{
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}};
    REQUIRE_EQ(biased.value().fieldBytes, productionBias);
    REQUIRE(mutantWithoutBias != productionBias);

    auto implicitSource = image();
    binobf::Relocation relocation{};
    relocation.id = binobf::EntityId{7};
    relocation.formatTableIndex = 1;
    relocation.section = binobf::EntityId{1};
    relocation.offset = 0;
    relocation.kind = binobf::RelocationKind::PcRelative;
    relocation.rawType = 0x14;
    relocation.targetSymbol = binobf::EntityId{2};
    implicitSource.relocations.push_back(relocation);
    const auto implicitPlan = binobf::ObjectRewritePlan::create(
        implicitSource, *fixed, reorder_request());
    REQUIRE(implicitPlan.has_value());
    const auto implicitOutput = implicitPlan.value().commit(implicitSource);
    REQUIRE(implicitOutput.has_value());
    REQUIRE_EQ(implicitOutput.value().relocations.front().addend, INT64_C(-4));
    REQUIRE(implicitSource.relocations.front().addend != INT64_C(-4));

    auto associationSource = image();
    binobf::SectionAssociation association{};
    association.section = binobf::EntityId{1};
    association.kind = binobf::SectionAssociationKind::CoffComdat;
    association.coffSelection = binobf::CoffComdatSelection::Any;
    associationSource.sectionAssociations.push_back(association);
    const auto associationGolden = binobf::ObjectRewritePlan::create(
        associationSource, *fixed, reorder_request());
    REQUIRE(!associationGolden.has_value());
    REQUIRE_EQ(associationGolden.error().code, "object.ownership_signature");
    REQUIRE(!mutant_omits_association_ownership(associationSource));

    auto unwindSource = image();
    binobf::UnwindInfo unwind{};
    unwind.id = binobf::EntityId{8};
    unwind.function = binobf::EntityId{5};
    unwind.encoded = {std::byte{1}};
    unwind.section = binobf::EntityId{1};
    unwind.sectionOffset = 7;
    unwind.codeOffset = 0;
    unwind.codeSize = 4;
    unwind.format = binobf::UnwindFormat::WindowsI386;
    unwind.rewriteState = binobf::UnwindRewriteState::Opaque;
    unwindSource.unwindInfo.push_back(unwind);
    const auto unwindGolden = binobf::ObjectRewritePlan::create(
        unwindSource, *fixed, reorder_request());
    REQUIRE(!unwindGolden.has_value());
    REQUIRE_EQ(unwindGolden.error().code, "rewrite.unowned_unwind");
    REQUIRE(!mutant_omits_unwind_ownership(unwindSource));

    auto overlap = reorder_request();
    overlap.ranges[1].oldBegin = 3;
    const auto overlapGolden = binobf::ObjectRewritePlan::create(image(), *fixed, overlap);
    REQUIRE(!overlapGolden.has_value());
    REQUIRE_EQ(overlapGolden.error().code, "rewrite.overlap");
    REQUIRE(!mutant_omits_mapping_overlap(overlap));

    const auto source = image();
    const auto transactionPlan = binobf::ObjectRewritePlan::create(
        source, *fixed, reorder_request());
    REQUIRE(transactionPlan.has_value());
    auto changed = source;
    changed.symbols[1].address.value = 1;
    const auto before = changed.sections.front().contents;
    const auto transactionGolden = transactionPlan.value().commit(changed);
    REQUIRE(!transactionGolden.has_value());
    REQUIRE_EQ(transactionGolden.error().code, "rewrite.source_mismatch");
    REQUIRE_EQ(changed.sections.front().contents, before);
    auto mutantTarget = changed;
    REQUIRE(!mutant_commit_mutates_before_snapshot_check(mutantTarget));
    REQUIRE(mutantTarget.sections.front().contents != before);
}

int main() { return binobf::test::run_all(); }

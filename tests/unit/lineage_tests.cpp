#include "../test_support.hpp"

#include <binobf/evidence/lineage.hpp>

#include <cstddef>
#include <span>
#include <string>
#include <string_view>

namespace {

auto bytes_of(std::string_view text) -> std::span<const std::byte> {
    return std::as_bytes(std::span{text.data(), text.size()});
}

auto document() -> binobf::evidence::LineageDocument {
    return binobf::evidence::LineageDocument{
        .schemaVersion = 1,
        .toolVersion = "0.1.0",
        .inputSha256 = std::string(64, '1'),
        .outputSha256 = std::string(64, '2'),
        .format = "COFF",
        .architecture = "x86-64",
        .entities = {
            binobf::evidence::LineageEntity{
                .id = "original:function:1",
                .domain = "original",
                .kind = "function",
                .name = "work",
                .section = ".text",
                .address = 4,
                .size = 8,
                .addressKind = "relative-virtual",
                .origin = std::nullopt,
                .transforms = {},
            },
            binobf::evidence::LineageEntity{
                .id = "protected:function:9",
                .domain = "protected",
                .kind = "function",
                .name = "obf_work",
                .section = ".text",
                .address = 32,
                .size = 8,
                .addressKind = "relative-virtual",
                .origin = "original:function:1",
                .transforms = {{7, 3, "function-reordering"}},
            },
        },
    };
}

} // namespace

TEST_CASE(lineage_round_trip_and_exact_address_query_are_deterministic) {
    const auto expected = document();
    const auto serialized = binobf::evidence::serialize_lineage(expected);
    REQUIRE_EQ(serialized, binobf::evidence::serialize_lineage(expected));
    const auto parsed = binobf::evidence::parse_lineage(bytes_of(serialized));
    REQUIRE(parsed.has_value());
    REQUIRE_EQ(parsed.value(), expected);

    const auto query = binobf::evidence::query_lineage(parsed.value(), 35);
    REQUIRE(query.has_value());
    REQUIRE_EQ(query.value().protectedEntity.name, std::string{"obf_work"});
    REQUIRE_EQ(query.value().originalEntity.name, std::string{"work"});
    REQUIRE_EQ(query.value().originalEntity.address, std::uint64_t{4});
    REQUIRE_EQ(query.value().transforms.size(), std::size_t{1});
    REQUIRE_EQ(query.value().transforms.front().pass, std::string{"function-reordering"});
}

TEST_CASE(lineage_query_refuses_missing_ambiguous_incomplete_and_cyclic_mappings) {
    auto value = document();
    const auto missing = binobf::evidence::query_lineage(value, 99);
    REQUIRE(!missing.has_value());
    REQUIRE_EQ(missing.error().code, std::string{"lineage.not_found"});

    auto duplicate = value.entities.back();
    duplicate.id = "protected:function:10";
    value.entities.push_back(duplicate);
    const auto ambiguous = binobf::evidence::query_lineage(value, 35);
    REQUIRE(!ambiguous.has_value());
    REQUIRE_EQ(ambiguous.error().code, std::string{"lineage.ambiguous"});

    value = document();
    value.entities.back().origin.reset();
    const auto incomplete = binobf::evidence::query_lineage(value, 35);
    REQUIRE(!incomplete.has_value());
    REQUIRE_EQ(incomplete.error().code, std::string{"lineage.incomplete"});

    value = document();
    value.entities.back().origin = "protected:function:cycle";
    value.entities.push_back(binobf::evidence::LineageEntity{
        .id = "protected:function:cycle",
        .domain = "protected",
        .kind = "function",
        .name = "cycle",
        .section = ".other",
        .address = 1000,
        .size = 1,
        .addressKind = "relative-virtual",
        .origin = "protected:function:9",
        .transforms = {},
    });
    const auto cyclic = binobf::evidence::query_lineage(value, 35);
    REQUIRE(!cyclic.has_value());
    REQUIRE_EQ(cyclic.error().code, std::string{"lineage.cycle"});
}

TEST_CASE(lineage_generation_correlates_reparsed_ids_through_transform_provenance) {
    binobf::BinaryImage original;
    original.format = binobf::BinaryFormat::COFF;
    original.architecture = binobf::Architecture::X86_64;
    original.sections.push_back(binobf::Section{
        .id = binobf::EntityId{1}, .name = ".text", .kind = binobf::SectionKind::Code,
        .address = {0, binobf::AddressKind::RelativeVirtual}, .logicalSize = 16,
        .alignment = 16, .readable = true, .writable = false,
        .executable = true, .contents = {}, .lineage = {}});
    original.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{2}, .formatIndex = 1, .auxiliaryData = {}, .name = "helper",
        .section = binobf::EntityId{1},
        .address = {0, binobf::AddressKind::RelativeVirtual}, .size = 8,
        .kind = binobf::SymbolKind::Function,
        .visibility = binobf::SymbolVisibility::Local, .defined = true, .lineage = {}});
    original.functions.push_back(binobf::Function{
        .id = binobf::EntityId{3}, .name = "helper", .section = binobf::EntityId{1},
        .symbol = binobf::EntityId{2},
        .address = {0, binobf::AddressKind::RelativeVirtual}, .size = 8,
        .discovery = binobf::FunctionDiscovery::Symbol, .instructions = {},
        .basicBlocks = {}, .entryBlock = std::nullopt, .externallyVisible = false,
        .complete = true, .lineage = {}});

    auto provenance = original;
    provenance.symbols.front().name = "obf_helper";
    provenance.symbols.front().lineage.parents.push_back(binobf::TransformationRecord{
        binobf::TransformId{7}, binobf::EntityId{2}, "rename-private-symbols"});

    auto verified = provenance;
    verified.sections.front().id = binobf::EntityId{10};
    verified.symbols.front().id = binobf::EntityId{20};
    verified.symbols.front().section = binobf::EntityId{10};
    verified.symbols.front().lineage = {};
    verified.functions.front().id = binobf::EntityId{30};
    verified.functions.front().name = "obf_helper";
    verified.functions.front().section = binobf::EntityId{10};
    verified.functions.front().symbol = binobf::EntityId{20};
    verified.functions.front().lineage = {};

    const auto generated = binobf::evidence::make_object_lineage(
        original, verified, provenance, std::string(64, '1'), std::string(64, '2'));
    REQUIRE(generated.has_value());
    const auto query = binobf::evidence::query_lineage(generated.value(), 1);
    REQUIRE(query.has_value());
    REQUIRE_EQ(query.value().protectedEntity.name, std::string{"obf_helper"});
    REQUIRE_EQ(query.value().originalEntity.name, std::string{"helper"});
    REQUIRE_EQ(query.value().transforms.size(), std::size_t{1});
    REQUIRE_EQ(query.value().transforms.front().pass, std::string{"rename-private-symbols"});
}

TEST_CASE(lineage_parser_rejects_malformed_duplicate_reference_and_resource_limit_inputs) {
    const auto malformed = binobf::evidence::parse_lineage(bytes_of("{"));
    REQUIRE(!malformed.has_value());
    REQUIRE_EQ(malformed.error().code, std::string{"lineage.syntax"});

    auto value = document();
    value.entities.push_back(value.entities.front());
    const auto duplicateText = binobf::evidence::serialize_lineage(value);
    const auto duplicate = binobf::evidence::parse_lineage(bytes_of(duplicateText));
    REQUIRE(!duplicate.has_value());
    REQUIRE_EQ(duplicate.error().code, std::string{"lineage.duplicate"});

    value = document();
    value.entities.back().origin = "missing";
    const auto referenceText = binobf::evidence::serialize_lineage(value);
    const auto reference = binobf::evidence::parse_lineage(bytes_of(referenceText));
    REQUIRE(!reference.has_value());
    REQUIRE_EQ(reference.error().code, std::string{"lineage.reference"});

    auto limits = binobf::evidence::LineageParseLimits{};
    limits.maxEntities = 1;
    const auto serialized = binobf::evidence::serialize_lineage(document());
    const auto limited = binobf::evidence::parse_lineage(bytes_of(serialized), limits);
    REQUIRE(!limited.has_value());
    REQUIRE_EQ(limited.error().code, std::string{"lineage.limit"});
}

int main() {
    return binobf::test::run_all();
}

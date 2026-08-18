#include "../test_support.hpp"

#include <binobf/formats/object_writer.hpp>
#include <binobf/verify/structural_verifier.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace {

auto make_object() -> binobf::BinaryImage {
    binobf::BinaryImage image;
    image.format = binobf::BinaryFormat::COFF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86_64;
    image.sections.push_back(binobf::Section{
        .id = binobf::EntityId{1}, .formatIndex = 1,
        .formatFlags = 0x40300040, .name = ".data",
        .kind = binobf::SectionKind::InitializedData, .address = {},
        .logicalSize = 1, .alignment = 4, .readable = true,
        .contents = {std::byte{0x2a}}, .lineage = {}});
    return image;
}

auto make_code_object() -> binobf::BinaryImage {
    binobf::BinaryImage image;
    image.format = binobf::BinaryFormat::COFF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86_64;
    image.sections.push_back(binobf::Section{
        .id = binobf::EntityId{1}, .formatIndex = 1,
        .formatFlags = 0x60500020, .name = ".text",
        .kind = binobf::SectionKind::Code, .address = {},
        .logicalSize = 5, .alignment = 4, .readable = true,
        .executable = true,
        .contents = {std::byte{0x74}, std::byte{0x01}, std::byte{0xc3},
                     std::byte{0xc3}, std::byte{0x90}}, .lineage = {}});
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{2}, .formatIndex = 0, .formatTableIndex = 0,
        .formatType = 0x20, .formatStorage = 3, .formatSectionIndex = 1,
        .auxiliaryData = {}, .name = "branching", .section = binobf::EntityId{1},
        .address = {}, .size = 4, .kind = binobf::SymbolKind::Function,
        .visibility = binobf::SymbolVisibility::Local,
        .defined = true,
        .definition = binobf::SymbolDefinitionKind::SectionRelative,
        .commonAlignment = 0,
        .tlsModel = binobf::TlsModel::None,
        .lineage = {}});
    return image;
}

auto find_check(const binobf::StructuralVerificationReport& report, std::string_view name)
    -> const binobf::VerificationCheck& {
    const auto found = std::find_if(report.checks.begin(), report.checks.end(), [name](const auto& check) {
        return check.name == name;
    });
    if (found == report.checks.end()) throw std::runtime_error("missing verification check");
    return *found;
}

} // namespace

TEST_CASE(structural_verifier_reports_supported_object_checks_truthfully) {
    const auto written = binobf::write_object(make_object());
    REQUIRE(written.has_value());

    const auto verified = binobf::verify_object(written.value(), "fixture.obj");

    REQUIRE(verified.has_value());
    REQUIRE_EQ(verified.value().image.format, binobf::BinaryFormat::COFF);
    REQUIRE_EQ(verified.value().checks.size(), std::size_t{8});
    REQUIRE_EQ(find_check(verified.value(), "headers").status, binobf::VerificationStatus::Passed);
    REQUIRE_EQ(find_check(verified.value(), "section-ranges").examined, std::size_t{1});
    REQUIRE_EQ(find_check(verified.value(), "symbols").status, binobf::VerificationStatus::Passed);
    REQUIRE_EQ(find_check(verified.value(), "relocations").status, binobf::VerificationStatus::Passed);
    REQUIRE_EQ(find_check(verified.value(), "entity-references").status, binobf::VerificationStatus::Passed);
    REQUIRE_EQ(find_check(verified.value(), "imports-exports").status,
               binobf::VerificationStatus::NotApplicable);
    REQUIRE_EQ(find_check(verified.value(), "branch-destinations").status,
               binobf::VerificationStatus::NotApplicable);
    REQUIRE_EQ(find_check(verified.value(), "unwind-semantics").status,
               binobf::VerificationStatus::Unsupported);
}

TEST_CASE(structural_verifier_checks_branch_destinations_for_complete_functions) {
    const auto written = binobf::write_object(make_code_object());
    REQUIRE(written.has_value());

    const auto verified = binobf::verify_object(written.value(), "branching.obj");

    REQUIRE(verified.has_value());
    REQUIRE_EQ(find_check(verified.value(), "branch-destinations").status,
               binobf::VerificationStatus::Passed);
    REQUIRE(find_check(verified.value(), "branch-destinations").examined > std::size_t{0});
}

TEST_CASE(structural_verifier_rejects_corrupt_section_ranges) {
    auto written = binobf::write_object(make_object());
    REQUIRE(written.has_value());
    auto bytes = std::move(written).value();
    constexpr std::size_t rawDataPointerOffset = 20 + 20;
    bytes.at(rawDataPointerOffset + 0) = std::byte{0xf0};
    bytes.at(rawDataPointerOffset + 1) = std::byte{0xff};
    bytes.at(rawDataPointerOffset + 2) = std::byte{0xff};
    bytes.at(rawDataPointerOffset + 3) = std::byte{0xff};

    const auto verified = binobf::verify_object(bytes, "corrupt.obj");

    REQUIRE(!verified.has_value());
    REQUIRE(!verified.error().code.empty());
    REQUIRE_CONTAINS(verified.error().message, "corrupt.obj");
}

TEST_CASE(structural_verifier_writer_rejects_invalid_normalized_ownership) {
    auto image = make_code_object();
    image.sectionAssociations.push_back(binobf::SectionAssociation{
        .section = binobf::EntityId{1},
        .kind = binobf::SectionAssociationKind::CoffComdat,
        .coffSelection = binobf::CoffComdatSelection::Any,
        .signatureSymbol = std::nullopt,
        .parentSection = std::nullopt,
        .members = {},
    });

    const auto written = binobf::write_object(image);

    REQUIRE(!written.has_value());
    REQUIRE_EQ(written.error().code, "object.ownership_signature");
}

int main() {
    return binobf::test::run_all();
}

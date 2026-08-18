#include "../test_support.hpp"

#include <binobf/verify/object_ownership.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

auto section(std::uint64_t id, std::uint32_t index, std::uint64_t size = 32)
    -> binobf::Section {
    return binobf::Section{
        .id = binobf::EntityId{id},
        .formatIndex = index,
        .formatType = 1,
        .formatFlags = 0,
        .formatLink = 0,
        .formatInfo = 0,
        .formatEntrySize = 0,
        .isSectionNameTable = false,
        .name = ".section" + std::to_string(index),
        .kind = binobf::SectionKind::InitializedData,
        .address = {},
        .logicalSize = size,
        .alignment = 4,
        .readable = true,
        .writable = false,
        .executable = false,
        .contents = std::vector<std::byte>(static_cast<std::size_t>(size)),
        .lineage = {},
    };
}

auto symbol(
    std::uint64_t id,
    std::uint32_t index,
    std::optional<binobf::EntityId> owner = std::nullopt) -> binobf::Symbol {
    return binobf::Symbol{
        .id = binobf::EntityId{id},
        .formatIndex = index,
        .formatTableIndex = 0,
        .formatType = 0,
        .formatStorage = 2,
        .formatOther = 0,
        .formatSectionIndex = owner.has_value()
            ? static_cast<std::int32_t>(owner->value())
            : 0,
        .auxiliaryData = {},
        .name = "symbol" + std::to_string(index),
        .section = owner,
        .address = {},
        .size = 0,
        .kind = binobf::SymbolKind::Object,
        .visibility = binobf::SymbolVisibility::External,
        .defined = owner.has_value(),
        .definition = owner.has_value()
            ? std::optional{binobf::SymbolDefinitionKind::SectionRelative}
            : std::optional{binobf::SymbolDefinitionKind::Undefined},
        .commonAlignment = 0,
        .tlsModel = binobf::TlsModel::None,
        .lineage = {},
    };
}

auto base_image() -> binobf::BinaryImage {
    binobf::BinaryImage image;
    image.format = binobf::BinaryFormat::COFF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86;
    image.sections = {section(1, 1), section(2, 2), section(3, 3), section(4, 4)};
    image.symbols = {
        symbol(10, 0, binobf::EntityId{1}),
        symbol(11, 1, binobf::EntityId{2}),
    };
    return image;
}

auto require_error(const binobf::BinaryImage& image, std::string_view code) -> void {
    const auto checked = binobf::validate_object_ownership(image);
    REQUIRE(!checked.has_value());
    REQUIRE_EQ(checked.error().code, code);
}

auto add_owned_function(binobf::BinaryImage& image) -> void {
    image.functions.push_back(binobf::Function{
        .id = binobf::EntityId{30},
        .name = "function",
        .section = binobf::EntityId{1},
        .symbol = binobf::EntityId{10},
        .address = {},
        .size = 16,
        .discovery = binobf::FunctionDiscovery::Symbol,
        .instructions = {},
        .basicBlocks = {},
        .entryBlock = std::nullopt,
        .externallyVisible = true,
        .complete = false,
        .lineage = {},
    });
}

} // namespace

TEST_CASE(object_ownership_rejects_duplicate_association_membership) {
    auto image = base_image();
    image.format = binobf::BinaryFormat::ELF;
    image.sectionAssociations = {
        binobf::SectionAssociation{
            .section = binobf::EntityId{3},
            .kind = binobf::SectionAssociationKind::ElfGroup,
            .coffSelection = binobf::CoffComdatSelection::None,
            .signatureSymbol = binobf::EntityId{10},
            .parentSection = std::nullopt,
            .members = {binobf::EntityId{1}},
        },
        binobf::SectionAssociation{
            .section = binobf::EntityId{4},
            .kind = binobf::SectionAssociationKind::ElfGroup,
            .coffSelection = binobf::CoffComdatSelection::None,
            .signatureSymbol = binobf::EntityId{11},
            .parentSection = std::nullopt,
            .members = {binobf::EntityId{1}},
        },
    };
    require_error(image, "object.ownership_duplicate_membership");
}

TEST_CASE(object_ownership_rejects_missing_comdat_or_group_signature) {
    auto image = base_image();
    image.sectionAssociations.push_back(binobf::SectionAssociation{
        .section = binobf::EntityId{1},
        .kind = binobf::SectionAssociationKind::CoffComdat,
        .coffSelection = binobf::CoffComdatSelection::Any,
        .signatureSymbol = std::nullopt,
        .parentSection = std::nullopt,
        .members = {},
    });
    require_error(image, "object.ownership_signature");
}

TEST_CASE(object_ownership_rejects_association_cycles) {
    auto image = base_image();
    image.sectionAssociations = {
        binobf::SectionAssociation{
            .section = binobf::EntityId{1},
            .kind = binobf::SectionAssociationKind::CoffAssociativeComdat,
            .coffSelection = binobf::CoffComdatSelection::Associative,
            .signatureSymbol = binobf::EntityId{10},
            .parentSection = binobf::EntityId{2},
            .members = {},
        },
        binobf::SectionAssociation{
            .section = binobf::EntityId{2},
            .kind = binobf::SectionAssociationKind::CoffAssociativeComdat,
            .coffSelection = binobf::CoffComdatSelection::Associative,
            .signatureSymbol = binobf::EntityId{11},
            .parentSection = binobf::EntityId{1},
            .members = {},
        },
    };
    require_error(image, "object.ownership_association_cycle");
}

TEST_CASE(object_ownership_rejects_a_relocation_table_for_an_absent_section) {
    auto image = base_image();
    image.relocationTableEncodings.push_back(binobf::RelocationTableEncoding{
        .section = binobf::EntityId{99},
        .coffOverflow = false,
        .declaredCount = 0,
    });
    require_error(image, "object.ownership_relocation_table");
}

TEST_CASE(object_ownership_rejects_shn_xindex_without_a_companion) {
    auto image = base_image();
    image.format = binobf::BinaryFormat::ELF;
    image.symbols[0].formatSectionIndex = 0xffff;
    require_error(image, "object.ownership_extended_index");
}

TEST_CASE(object_ownership_rejects_a_common_symbol_with_zero_alignment) {
    auto image = base_image();
    auto& common = image.symbols[0];
    common.section = std::nullopt;
    common.defined = true;
    common.formatSectionIndex = 0;
    common.definition = binobf::SymbolDefinitionKind::Common;
    common.commonAlignment = 0;
    require_error(image, "object.ownership_symbol_definition");
}

TEST_CASE(object_ownership_rejects_a_tls_model_on_a_non_tls_symbol) {
    auto image = base_image();
    image.symbols[0].tlsModel = binobf::TlsModel::InitialExec;
    require_error(image, "object.ownership_tls_model");
}

TEST_CASE(object_ownership_rejects_overlapping_unwind_code_ranges) {
    auto image = base_image();
    add_owned_function(image);
    image.unwindInfo = {
        binobf::UnwindInfo{
            .id = binobf::EntityId{40},
            .function = binobf::EntityId{30},
            .encoded = std::vector<std::byte>(4),
            .section = binobf::EntityId{3},
            .sectionOffset = 0,
            .codeOffset = 0,
            .codeSize = 8,
            .format = binobf::UnwindFormat::WindowsI386,
            .relocations = {},
            .rewriteState = binobf::UnwindRewriteState::Unchanged,
            .lineage = {},
        },
        binobf::UnwindInfo{
            .id = binobf::EntityId{41},
            .function = binobf::EntityId{30},
            .encoded = std::vector<std::byte>(4),
            .section = binobf::EntityId{3},
            .sectionOffset = 8,
            .codeOffset = 4,
            .codeSize = 8,
            .format = binobf::UnwindFormat::WindowsI386,
            .relocations = {},
            .rewriteState = binobf::UnwindRewriteState::Unchanged,
            .lineage = {},
        },
    };
    require_error(image, "object.ownership_unwind_overlap");
}

TEST_CASE(object_ownership_rejects_an_unwind_relocation_outside_its_record) {
    auto image = base_image();
    add_owned_function(image);
    image.relocations.push_back(binobf::Relocation{
        .id = binobf::EntityId{20},
        .formatIndex = 0,
        .formatTableIndex = 3,
        .section = binobf::EntityId{3},
        .offset = 8,
        .kind = binobf::RelocationKind::Absolute,
        .rawType = 1,
        .targetSymbol = binobf::EntityId{10},
        .addend = 0,
        .lineage = {},
    });
    image.unwindInfo.push_back(binobf::UnwindInfo{
        .id = binobf::EntityId{40},
        .function = binobf::EntityId{30},
        .encoded = std::vector<std::byte>(4),
        .section = binobf::EntityId{3},
        .sectionOffset = 0,
        .codeOffset = 0,
        .codeSize = 8,
        .format = binobf::UnwindFormat::WindowsI386,
        .relocations = {binobf::EntityId{20}},
        .rewriteState = binobf::UnwindRewriteState::Unchanged,
        .lineage = {},
    });
    require_error(image, "object.ownership_unwind_relocation");
}

TEST_CASE(object_ownership_accepts_a_valid_coff_associative_comdat) {
    auto image = base_image();
    image.sectionAssociations = {
        binobf::SectionAssociation{
            .section = binobf::EntityId{1},
            .kind = binobf::SectionAssociationKind::CoffComdat,
            .coffSelection = binobf::CoffComdatSelection::Any,
            .signatureSymbol = binobf::EntityId{10},
            .parentSection = std::nullopt,
            .members = {},
        },
        binobf::SectionAssociation{
            .section = binobf::EntityId{2},
            .kind = binobf::SectionAssociationKind::CoffAssociativeComdat,
            .coffSelection = binobf::CoffComdatSelection::Associative,
            .signatureSymbol = binobf::EntityId{11},
            .parentSection = binobf::EntityId{1},
            .members = {},
        },
    };
    REQUIRE(binobf::validate_object_ownership(image).has_value());
}

TEST_CASE(object_ownership_accepts_a_valid_elf_group) {
    auto image = base_image();
    image.format = binobf::BinaryFormat::ELF;
    image.sections[2].formatType = 17;
    image.sectionAssociations.push_back(binobf::SectionAssociation{
        .section = binobf::EntityId{3},
        .kind = binobf::SectionAssociationKind::ElfGroup,
        .coffSelection = binobf::CoffComdatSelection::None,
        .signatureSymbol = binobf::EntityId{10},
        .parentSection = std::nullopt,
        .members = {binobf::EntityId{1}, binobf::EntityId{2}},
    });
    REQUIRE(binobf::validate_object_ownership(image).has_value());
}

TEST_CASE(object_ownership_accepts_a_valid_extended_symbol_section_index) {
    auto image = base_image();
    image.format = binobf::BinaryFormat::ELF;
    auto indexSection = section(5, 5);
    indexSection.formatType = 18;
    indexSection.formatLink = 0;
    image.sections.push_back(std::move(indexSection));
    image.symbols[0].formatSectionIndex = 0xffff;
    image.extendedSectionIndices.push_back(binobf::ExtendedSectionIndex{
        .symbol = binobf::EntityId{10},
        .indexSection = binobf::EntityId{5},
        .section = binobf::EntityId{1},
        .rawSectionIndex = 1,
    });

    REQUIRE(binobf::validate_object_ownership(image).has_value());
}

int main() {
    return binobf::test::run_all();
}

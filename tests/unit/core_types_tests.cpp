#include "../test_support.hpp"

#include <binobf/core/model.hpp>
#include <binobf/core/result.hpp>
#include <binobf/core/types.hpp>

#include <string>
#include <type_traits>

TEST_CASE(core_enum_names_are_stable) {
    REQUIRE_EQ(binobf::to_string(binobf::BinaryFormat::PE), "PE");
    REQUIRE_EQ(binobf::to_string(binobf::BinaryFormat::COFF), "COFF");
    REQUIRE_EQ(binobf::to_string(binobf::BinaryFormat::ELF), "ELF");
    REQUIRE_EQ(binobf::to_string(binobf::BinaryFormat::Archive), "archive");
    REQUIRE_EQ(binobf::to_string(binobf::BinaryFormat::Unknown), "unknown");

    REQUIRE_EQ(binobf::to_string(binobf::Architecture::X86), "x86");
    REQUIRE_EQ(binobf::to_string(binobf::Architecture::X86_64), "x86-64");
    REQUIRE_EQ(binobf::to_string(binobf::Architecture::ARM64), "arm64");
    REQUIRE_EQ(binobf::to_string(binobf::Architecture::Unknown), "unknown");

    REQUIRE_EQ(binobf::to_string(binobf::BinaryType::Executable), "executable");
    REQUIRE_EQ(binobf::to_string(binobf::BinaryType::SharedLibrary), "shared-library");
    REQUIRE_EQ(binobf::to_string(binobf::BinaryType::KernelDriver), "kernel-driver");
    REQUIRE_EQ(binobf::to_string(binobf::BinaryType::RelocatableObject),
               "relocatable-object");
    REQUIRE_EQ(binobf::to_string(binobf::BinaryType::StaticLibrary), "static-library");
    REQUIRE_EQ(binobf::to_string(binobf::BinaryType::ImportLibrary), "import-library");
    REQUIRE_EQ(binobf::to_string(binobf::BinaryType::Unknown), "unknown");
}

TEST_CASE(entity_ids_are_value_identifiers) {
    const binobf::EntityId first{42};
    REQUIRE(first == binobf::EntityId{42});
    REQUIRE(first != binobf::EntityId{43});
    REQUIRE_EQ(first.value(), 42U);
    REQUIRE(!binobf::EntityId{}.valid());
    REQUIRE(first.valid());
}

TEST_CASE(result_exposes_exactly_one_alternative) {
    auto value = binobf::Result<int, std::string>::success(17);
    REQUIRE(value.has_value());
    REQUIRE_EQ(value.value(), 17);

    auto error = binobf::Result<int, std::string>::failure("bad input");
    REQUIRE(!error.has_value());
    REQUIRE_EQ(error.error(), "bad input");
}

TEST_CASE(binary_model_owns_entities_by_value_and_stable_id) {
    binobf::BinaryImage image;
    image.format = binobf::BinaryFormat::ELF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86_64;
    image.sections.push_back(binobf::Section{
        .id = binobf::EntityId{1},
        .formatIndex = 1,
        .name = ".text",
        .kind = binobf::SectionKind::Code,
        .address = {},
        .logicalSize = 0,
        .alignment = 1,
        .readable = true,
        .writable = false,
        .executable = true,
        .contents = {},
        .lineage = {},
    });

    REQUIRE_EQ(image.sections.size(), std::size_t{1});
    REQUIRE_EQ(image.sections.front().id.value(), 1U);
    REQUIRE_EQ(image.sections.front().name, ".text");
    static_assert(std::is_copy_constructible_v<binobf::BinaryImage>);
}

TEST_CASE(source_locations_own_their_file_name) {
    std::string callerOwnedName = "source.cpp";
    const binobf::SourceLocation location{
        .file = callerOwnedName,
        .line = 17,
        .column = 4,
    };

    callerOwnedName = "mutate.cpp";

    REQUIRE_EQ(location.file, "source.cpp");
}

TEST_CASE(object_metadata_survives_value_copies) {
    binobf::BinaryImage image;
    image.objectMetadata = binobf::ObjectMetadata{
        .osAbi = 3,
        .abiVersion = 1,
        .formatFlags = 0x1234,
        .characteristics = 0x200,
    };
    image.sections.push_back(binobf::Section{
        .id = binobf::EntityId{11},
        .formatIndex = 5,
        .formatType = 8,
        .formatFlags = 3,
        .formatLink = 2,
        .formatInfo = 1,
        .formatEntrySize = 24,
        .isSectionNameTable = false,
        .name = ".bss",
        .kind = binobf::SectionKind::UninitializedData,
        .address = {},
        .logicalSize = 128,
        .alignment = 16,
        .readable = true,
        .writable = true,
        .executable = false,
        .contents = {},
        .lineage = {},
    });
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{12},
        .formatIndex = 9,
        .formatTableIndex = 4,
        .formatType = 1,
        .formatStorage = 1,
        .formatOther = 2,
        .formatSectionIndex = 0,
        .auxiliaryData = {std::byte{0x7f}},
        .name = "external_value",
        .section = std::nullopt,
        .address = {},
        .size = 8,
        .kind = binobf::SymbolKind::Object,
        .visibility = binobf::SymbolVisibility::External,
        .defined = false,
        .definition = binobf::SymbolDefinitionKind::Undefined,
        .commonAlignment = 0,
        .tlsModel = binobf::TlsModel::None,
        .lineage = {},
    });
    image.relocations.push_back(binobf::Relocation{
        .id = binobf::EntityId{13},
        .formatIndex = 3,
        .formatTableIndex = 7,
        .section = binobf::EntityId{11},
        .offset = 4,
        .kind = binobf::RelocationKind::ArchitectureSpecific,
        .rawType = 42,
        .targetSymbol = binobf::EntityId{12},
        .addend = -7,
        .lineage = {},
    });
    image.sectionAssociations.push_back(binobf::SectionAssociation{
        .section = binobf::EntityId{11},
        .kind = binobf::SectionAssociationKind::Ordinary,
        .coffSelection = binobf::CoffComdatSelection::None,
        .signatureSymbol = std::nullopt,
        .parentSection = std::nullopt,
        .members = {},
    });
    image.relocationTableEncodings.push_back(binobf::RelocationTableEncoding{
        .section = binobf::EntityId{11},
        .coffOverflow = false,
        .declaredCount = 1,
    });

    const auto copy = image;
    REQUIRE_EQ(copy.objectMetadata.osAbi, 3U);
    REQUIRE_EQ(copy.objectMetadata.formatFlags, UINT64_C(0x1234));
    REQUIRE_EQ(copy.sections.front().formatIndex, 5U);
    REQUIRE_EQ(copy.sections.front().formatType, UINT64_C(8));
    REQUIRE_EQ(copy.sections.front().logicalSize, UINT64_C(128));
    REQUIRE_EQ(copy.sections.front().kind, binobf::SectionKind::UninitializedData);
    REQUIRE_EQ(copy.symbols.front().formatIndex, 9U);
    REQUIRE_EQ(copy.symbols.front().formatTableIndex, 4U);
    REQUIRE_EQ(copy.symbols.front().auxiliaryData.front(), std::byte{0x7f});
    REQUIRE_EQ(copy.symbols.front().kind, binobf::SymbolKind::Object);
    REQUIRE(!copy.symbols.front().defined);
    REQUIRE_EQ(copy.symbols.front().definition,
               binobf::SymbolDefinitionKind::Undefined);
    REQUIRE_EQ(copy.symbols.front().tlsModel, binobf::TlsModel::None);
    REQUIRE(!copy.symbols.front().section.has_value());
    REQUIRE_EQ(copy.relocations.front().formatIndex, 3U);
    REQUIRE_EQ(copy.relocations.front().formatTableIndex, 7U);
    REQUIRE_EQ(copy.relocations.front().rawType, UINT64_C(42));
    REQUIRE_EQ(copy.sectionAssociations.front().kind,
               binobf::SectionAssociationKind::Ordinary);
    REQUIRE_EQ(copy.relocationTableEncodings.front().declaredCount, UINT64_C(1));
}

int main() {
    return binobf::test::run_all();
}

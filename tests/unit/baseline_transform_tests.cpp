#include "../test_support.hpp"

#include <binobf/formats/object_writer.hpp>
#include <binobf/transforms/baseline.hpp>
#include <binobf/transforms/pass_manager.hpp>

#include <algorithm>
#include <cstddef>
#include <memory>
#include <string_view>

namespace {

auto make_coff_symbols() -> binobf::BinaryImage {
    binobf::BinaryImage image;
    image.format = binobf::BinaryFormat::COFF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86_64;
    image.sections.push_back(binobf::Section{
        .id = binobf::EntityId{1}, .formatIndex = 1,
        .formatFlags = 0x60300020, .name = ".text",
        .kind = binobf::SectionKind::Code, .address = {},
        .logicalSize = 1, .alignment = 4, .readable = true,
        .executable = true, .contents = {std::byte{0x90}}, .lineage = {}});
    image.symbols = {
        binobf::Symbol{
            .id = binobf::EntityId{2}, .formatIndex = 0, .formatTableIndex = 0,
            .formatType = 0x20, .formatStorage = 3, .formatSectionIndex = 1,
            .auxiliaryData = {}, .name = "helper", .section = binobf::EntityId{1},
            .address = {}, .kind = binobf::SymbolKind::Function,
            .visibility = binobf::SymbolVisibility::Local, .defined = true, .lineage = {}},
        binobf::Symbol{
            .id = binobf::EntityId{3}, .formatIndex = 1, .formatTableIndex = 0,
            .formatType = 0x20, .formatStorage = 2, .formatSectionIndex = 1,
            .auxiliaryData = {}, .name = "public_api", .section = binobf::EntityId{1},
            .address = {}, .kind = binobf::SymbolKind::Function,
            .visibility = binobf::SymbolVisibility::External, .defined = true, .lineage = {}},
        binobf::Symbol{
            .id = binobf::EntityId{4}, .formatIndex = 2, .formatTableIndex = 0,
            .formatType = 0x20, .formatStorage = 2, .formatSectionIndex = 0,
            .auxiliaryData = {}, .name = "external_ref", .section = std::nullopt,
            .address = {}, .kind = binobf::SymbolKind::Function,
            .visibility = binobf::SymbolVisibility::External, .defined = false, .lineage = {}},
        binobf::Symbol{
            .id = binobf::EntityId{5}, .formatIndex = 3, .formatTableIndex = 0,
            .formatType = 0, .formatStorage = 3, .formatSectionIndex = 1,
            .auxiliaryData = std::vector<std::byte>(18), .name = ".text",
            .section = binobf::EntityId{1}, .address = {},
            .kind = binobf::SymbolKind::Section,
            .visibility = binobf::SymbolVisibility::Local, .defined = true, .lineage = {}},
        binobf::Symbol{
            .id = binobf::EntityId{6}, .formatIndex = 5, .formatTableIndex = 0,
            .formatType = 0, .formatStorage = 3, .formatSectionIndex = 1,
            .auxiliaryData = {}, .name = "keep_me", .section = binobf::EntityId{1},
            .address = {}, .kind = binobf::SymbolKind::Object,
            .visibility = binobf::SymbolVisibility::Local, .defined = true, .lineage = {}},
    };
    return image;
}

auto make_elf_symbols() -> binobf::BinaryImage {
    binobf::BinaryImage image;
    image.format = binobf::BinaryFormat::ELF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86_64;
    image.sections = {
        binobf::Section{
            .id = binobf::EntityId{1}, .formatIndex = 1, .formatType = 1,
            .formatFlags = 6, .name = ".text", .kind = binobf::SectionKind::Code,
            .address = {}, .logicalSize = 1, .alignment = 1, .readable = true,
            .executable = true, .contents = {std::byte{0x90}}, .lineage = {}},
        binobf::Section{
            .id = binobf::EntityId{2}, .formatIndex = 2, .formatType = 3,
            .name = ".strtab", .kind = binobf::SectionKind::StringTable,
            .address = {}, .alignment = 1, .contents = {}, .lineage = {}},
        binobf::Section{
            .id = binobf::EntityId{3}, .formatIndex = 3, .formatType = 2,
            .formatLink = 2, .formatInfo = 2, .formatEntrySize = 24,
            .name = ".symtab", .kind = binobf::SectionKind::SymbolTable,
            .address = {}, .alignment = 8, .contents = {}, .lineage = {}},
        binobf::Section{
            .id = binobf::EntityId{4}, .formatIndex = 4, .formatType = 3,
            .isSectionNameTable = true, .name = ".shstrtab",
            .kind = binobf::SectionKind::StringTable, .address = {}, .alignment = 1,
            .contents = {}, .lineage = {}},
    };
    image.symbols = {
        binobf::Symbol{
            .id = binobf::EntityId{5}, .formatIndex = 1, .formatTableIndex = 3,
            .formatType = 2, .formatStorage = 0, .formatSectionIndex = 1,
            .auxiliaryData = {}, .name = "elf_local", .section = binobf::EntityId{1},
            .address = {}, .size = 1, .kind = binobf::SymbolKind::Function,
            .visibility = binobf::SymbolVisibility::Local, .defined = true, .lineage = {}},
        binobf::Symbol{
            .id = binobf::EntityId{6}, .formatIndex = 2, .formatTableIndex = 3,
            .formatType = 2, .formatStorage = 1, .formatSectionIndex = 1,
            .auxiliaryData = {}, .name = "elf_public", .section = binobf::EntityId{1},
            .address = {}, .size = 1, .kind = binobf::SymbolKind::Function,
            .visibility = binobf::SymbolVisibility::External, .defined = true, .lineage = {}},
    };
    return image;
}

auto find_symbol(const binobf::BinaryImage& image, binobf::EntityId id)
    -> const binobf::Symbol& {
    const auto found = std::find_if(image.symbols.begin(), image.symbols.end(), [id](const auto& symbol) {
        return symbol.id == id;
    });
    if (found == image.symbols.end()) throw std::runtime_error("missing symbol");
    return *found;
}

auto rename(binobf::BinaryImage image, std::uint64_t seed, bool preserveKeep = false)
    -> binobf::TransformationOutcome {
    binobf::PassManager manager;
    const auto added = manager.add(binobf::make_rename_private_symbols_pass());
    if (!added.has_value()) throw std::runtime_error("could not add rename pass");
    binobf::TransformContext context{seed, false};
    if (preserveKeep) context.preserve_symbol("keep_me");
    auto outcome = manager.run(context, image);
    if (!outcome.has_value()) {
        throw std::runtime_error(outcome.error().code + ": " + outcome.error().message);
    }
    return std::move(outcome).value();
}

auto run_single(binobf::BinaryImage image, std::unique_ptr<binobf::TransformPass> pass)
    -> binobf::TransformationOutcome {
    binobf::PassManager manager;
    if (!manager.add(std::move(pass)).has_value()) throw std::runtime_error("add failed");
    binobf::TransformContext context{7, false};
    auto outcome = manager.run(context, image);
    if (!outcome.has_value()) {
        throw std::runtime_error(outcome.error().code + ": " + outcome.error().message);
    }
    return std::move(outcome).value();
}

} // namespace

TEST_CASE(rename_private_symbols_preserves_coff_abi_and_allowlisted_names) {
    const auto outcome = rename(make_coff_symbols(), 1337, true);
    const auto& helper = find_symbol(outcome.image, binobf::EntityId{2});
    REQUIRE(helper.name != "helper");
    REQUIRE_CONTAINS(helper.name, "__bo_");
    REQUIRE_EQ(find_symbol(outcome.image, binobf::EntityId{3}).name, "public_api");
    REQUIRE_EQ(find_symbol(outcome.image, binobf::EntityId{4}).name, "external_ref");
    REQUIRE_EQ(find_symbol(outcome.image, binobf::EntityId{5}).name, ".text");
    REQUIRE_EQ(find_symbol(outcome.image, binobf::EntityId{6}).name, "keep_me");
    REQUIRE_EQ(helper.lineage.parents.size(), std::size_t{1});
    REQUIRE_EQ(helper.lineage.parents.front().source, helper.id);
    REQUIRE_EQ(helper.lineage.parents.front().passName, "rename-private-symbols");
    REQUIRE_EQ(outcome.reports.front().statistics.examined, std::size_t{5});
    REQUIRE_EQ(outcome.reports.front().statistics.changed, std::size_t{1});
    REQUIRE_EQ(outcome.reports.front().statistics.skipped, std::size_t{4});
}

TEST_CASE(rename_private_symbols_preserves_coff_compiler_feature_markers) {
    auto image = make_coff_symbols();
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{7}, .formatIndex = 6, .formatTableIndex = 0,
        .formatType = 0, .formatStorage = 3, .formatSectionIndex = -1,
        .auxiliaryData = {}, .name = "@feat.00", .section = std::nullopt,
        .address = {}, .kind = binobf::SymbolKind::Object,
        .visibility = binobf::SymbolVisibility::Local, .defined = true, .lineage = {}});

    const auto outcome = rename(std::move(image), 1337);

    REQUIRE_EQ(find_symbol(outcome.image, binobf::EntityId{7}).name, "@feat.00");
}

TEST_CASE(rename_private_symbols_is_seeded_and_byte_deterministic) {
    const auto first = rename(make_coff_symbols(), 42);
    const auto second = rename(make_coff_symbols(), 42);
    const auto different = rename(make_coff_symbols(), 43);
    REQUIRE_EQ(find_symbol(first.image, binobf::EntityId{2}).name,
               find_symbol(second.image, binobf::EntityId{2}).name);
    REQUIRE(find_symbol(first.image, binobf::EntityId{2}).name
            != find_symbol(different.image, binobf::EntityId{2}).name);
    const auto firstBytes = binobf::write_object(first.image);
    const auto secondBytes = binobf::write_object(second.image);
    REQUIRE(firstBytes.has_value());
    REQUIRE(secondBytes.has_value());
    REQUIRE_EQ(firstBytes.value(), secondBytes.value());
    REQUIRE_EQ(find_symbol(first.image, binobf::EntityId{3}).name,
               find_symbol(different.image, binobf::EntityId{3}).name);
}

TEST_CASE(rename_private_symbols_supports_elf_local_bindings_only) {
    const auto outcome = rename(make_elf_symbols(), 99);
    REQUIRE(find_symbol(outcome.image, binobf::EntityId{5}).name != "elf_local");
    REQUIRE_EQ(find_symbol(outcome.image, binobf::EntityId{6}).name, "elf_public");
    REQUIRE_EQ(outcome.reports.front().statistics.changed, std::size_t{1});
}

TEST_CASE(strip_local_symbols_removes_only_unreferenced_unpreserved_private_entries) {
    auto image = make_coff_symbols();
    image.sections.front().logicalSize = 4;
    image.sections.front().contents = {
        std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90}};
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{7}, .formatIndex = 6, .formatTableIndex = 0,
        .formatType = 0, .formatStorage = 3, .formatSectionIndex = 1,
        .auxiliaryData = {}, .name = "unused_local", .section = binobf::EntityId{1},
        .address = {}, .kind = binobf::SymbolKind::Object,
        .visibility = binobf::SymbolVisibility::Local, .defined = true, .lineage = {}});
    image.symbols.push_back(binobf::Symbol{
        .id = binobf::EntityId{8}, .formatIndex = 7, .formatTableIndex = 0,
        .formatType = 0, .formatStorage = 103, .formatSectionIndex = -2,
        .auxiliaryData = {}, .name = "fixture.c", .section = std::nullopt,
        .address = {}, .kind = binobf::SymbolKind::File,
        .visibility = binobf::SymbolVisibility::Local, .defined = true, .lineage = {}});
    image.relocations.push_back(binobf::Relocation{
        .id = binobf::EntityId{20}, .formatIndex = 0, .formatTableIndex = 1,
        .section = binobf::EntityId{1}, .offset = 0,
        .kind = binobf::RelocationKind::PcRelative, .rawType = 4,
        .targetSymbol = binobf::EntityId{2}, .addend = 0, .lineage = {}});

    binobf::PassManager manager;
    REQUIRE(manager.add(binobf::make_strip_local_symbols_pass()).has_value());
    binobf::TransformContext context{7, false};
    context.preserve_symbol("keep_me");
    const auto result = manager.run(context, image);
    REQUIRE(result.has_value());
    const auto& outcome = result.value();

    REQUIRE(outcome.changed);
    REQUIRE(std::none_of(outcome.image.symbols.begin(), outcome.image.symbols.end(),
        [](const auto& symbol) {
            return symbol.id == binobf::EntityId{7} || symbol.id == binobf::EntityId{8};
        }));
    REQUIRE_EQ(find_symbol(outcome.image, binobf::EntityId{2}).name, "helper");
    REQUIRE_EQ(find_symbol(outcome.image, binobf::EntityId{3}).name, "public_api");
    REQUIRE_EQ(find_symbol(outcome.image, binobf::EntityId{5}).kind,
        binobf::SymbolKind::Section);
    REQUIRE_EQ(find_symbol(outcome.image, binobf::EntityId{6}).name, "keep_me");
    REQUIRE_EQ(outcome.image.relocations.front().targetSymbol,
        std::optional{binobf::EntityId{2}});
    REQUIRE_EQ(outcome.reports.front().statistics.changed, std::size_t{2});
    REQUIRE(binobf::write_object(outcome.image).has_value());
}

TEST_CASE(strip_local_symbols_supports_elf_and_refuses_raw_index_metadata) {
    const auto stripped = run_single(
        make_elf_symbols(), binobf::make_strip_local_symbols_pass());
    REQUIRE(stripped.changed);
    REQUIRE(std::none_of(stripped.image.symbols.begin(), stripped.image.symbols.end(),
        [](const auto& symbol) { return symbol.id == binobf::EntityId{5}; }));
    REQUIRE_EQ(find_symbol(stripped.image, binobf::EntityId{6}).formatIndex, 1U);
    REQUIRE(binobf::write_object(stripped.image).has_value());

    auto unsafe = make_elf_symbols();
    unsafe.sections.push_back(binobf::Section{
        .id = binobf::EntityId{30}, .formatIndex = 5, .formatType = 0x6fff4c03,
        .formatLink = 3, .name = ".llvm_addrsig", .kind = binobf::SectionKind::Metadata,
        .address = {}, .logicalSize = 1, .alignment = 1,
        .contents = {std::byte{1}}, .lineage = {}});
    binobf::PassManager manager;
    REQUIRE(manager.add(binobf::make_strip_local_symbols_pass()).has_value());
    binobf::TransformContext context{7, false};
    const auto refused = manager.run(context, unsafe);
    REQUIRE(!refused.has_value());
    REQUIRE_EQ(refused.error().code, std::string{"pass.unsafe_reference"});
}

TEST_CASE(strip_local_symbols_preserves_selected_function_identity) {
    auto image = make_elf_symbols();
    binobf::PassManager manager;
    REQUIRE(manager.add(binobf::make_strip_local_symbols_pass()).has_value());
    binobf::TransformContext context{7, false};
    binobf::FunctionSelectionPolicy policy;
    policy.includeNames = {"elf_local"};
    REQUIRE(context.set_function_selection(std::move(policy)).has_value());
    const auto result = manager.run(context, image);
    REQUIRE(result.has_value());
    REQUIRE_EQ(find_symbol(result.value().image, binobf::EntityId{5}).name, "elf_local");
}

TEST_CASE(metadata_cleanup_removes_elf_comment_and_repairs_raw_indices) {
    auto image = make_elf_symbols();
    for (auto& section : image.sections) {
        if (section.formatIndex >= 2) ++section.formatIndex;
        if (section.name == ".symtab") section.formatLink = 3;
    }
    for (auto& symbol : image.symbols) symbol.formatTableIndex = 4;
    image.sections.insert(image.sections.begin() + 1, binobf::Section{
        .id = binobf::EntityId{20}, .formatIndex = 2, .formatType = 1,
        .name = ".comment", .kind = binobf::SectionKind::Metadata,
        .address = {}, .logicalSize = 4, .alignment = 1,
        .contents = {std::byte{'x'}, std::byte{0}, std::byte{0}, std::byte{0}},
        .lineage = {}});
    const auto outcome = run_single(std::move(image), binobf::make_metadata_cleanup_pass());
    REQUIRE_EQ(outcome.image.sections.size(), std::size_t{4});
    REQUIRE(std::none_of(outcome.image.sections.begin(), outcome.image.sections.end(), [](const auto& section) {
        return section.name == ".comment";
    }));
    REQUIRE_EQ(find_symbol(outcome.image, binobf::EntityId{5}).formatTableIndex, 3U);
    const auto bytes = binobf::write_object(outcome.image);
    REQUIRE(bytes.has_value());
}

TEST_CASE(strip_debug_removes_coff_section_and_repairs_section_numbers) {
    auto image = make_coff_symbols();
    for (auto& section : image.sections) ++section.formatIndex;
    for (auto& symbol : image.symbols) {
        if (symbol.formatSectionIndex > 0) ++symbol.formatSectionIndex;
    }
    image.sections.insert(image.sections.begin(), binobf::Section{
        .id = binobf::EntityId{20}, .formatIndex = 1,
        .formatFlags = 0x42100040, .name = ".debug$S",
        .kind = binobf::SectionKind::Debug, .address = {},
        .logicalSize = 4, .alignment = 1, .readable = true,
        .contents = {std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}},
        .lineage = {}});
    const auto outcome = run_single(std::move(image), binobf::make_strip_debug_pass());
    REQUIRE_EQ(outcome.image.sections.size(), std::size_t{1});
    REQUIRE_EQ(outcome.image.sections.front().name, ".text");
    REQUIRE_EQ(outcome.image.sections.front().formatIndex, 1U);
    REQUIRE_EQ(find_symbol(outcome.image, binobf::EntityId{2}).formatSectionIndex, 1);
    REQUIRE(binobf::write_object(outcome.image).has_value());
}

TEST_CASE(strip_debug_closes_over_elf_relocations_symbols_and_addrsig) {
    auto image = make_elf_symbols();
    auto& symtab = *std::find_if(image.sections.begin(), image.sections.end(), [](const auto& section) {
        return section.name == ".symtab";
    });
    symtab.formatInfo = 3;
    image.symbols.at(1).formatIndex = 3;
    image.symbols.insert(image.symbols.begin() + 1, binobf::Symbol{
        .id = binobf::EntityId{20}, .formatIndex = 2, .formatTableIndex = 3,
        .formatType = 1, .formatStorage = 0, .formatSectionIndex = 5,
        .auxiliaryData = {}, .name = "debug_local", .section = binobf::EntityId{21},
        .address = {}, .size = 4, .kind = binobf::SymbolKind::Object,
        .visibility = binobf::SymbolVisibility::Local, .defined = true, .lineage = {}});
    image.sections.push_back(binobf::Section{
        .id = binobf::EntityId{21}, .formatIndex = 5, .formatType = 1,
        .name = ".debug_info", .kind = binobf::SectionKind::Debug,
        .address = {}, .logicalSize = 4, .alignment = 1,
        .contents = {std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}},
        .lineage = {}});
    image.sections.push_back(binobf::Section{
        .id = binobf::EntityId{22}, .formatIndex = 6, .formatType = 4,
        .formatLink = 3, .formatInfo = 5, .formatEntrySize = 24,
        .name = ".rela.debug_info", .kind = binobf::SectionKind::Relocation,
        .address = {}, .alignment = 8, .contents = {}, .lineage = {}});
    image.sections.push_back(binobf::Section{
        .id = binobf::EntityId{23}, .formatIndex = 7, .formatType = 0x6fff4c03,
        .formatLink = 3, .name = ".llvm_addrsig", .kind = binobf::SectionKind::Metadata,
        .address = {}, .logicalSize = 1, .alignment = 1,
        .contents = {std::byte{2}}, .lineage = {}});
    image.relocations.push_back(binobf::Relocation{
        .id = binobf::EntityId{24}, .formatIndex = 0, .formatTableIndex = 6,
        .section = binobf::EntityId{21}, .offset = 0,
        .kind = binobf::RelocationKind::Absolute, .rawType = 1,
        .targetSymbol = binobf::EntityId{20}, .addend = 0, .lineage = {}});

    REQUIRE(binobf::write_object(image).has_value());
    const auto outcome = run_single(std::move(image), binobf::make_strip_debug_pass());
    REQUIRE_EQ(outcome.image.sections.size(), std::size_t{4});
    REQUIRE_EQ(outcome.image.symbols.size(), std::size_t{2});
    REQUIRE(outcome.image.relocations.empty());
    REQUIRE(std::none_of(outcome.image.sections.begin(), outcome.image.sections.end(), [](const auto& section) {
        return section.name == ".debug_info" || section.name == ".rela.debug_info"
            || section.name == ".llvm_addrsig";
    }));
    REQUIRE_EQ(find_symbol(outcome.image, binobf::EntityId{6}).formatIndex, 2U);
    REQUIRE(binobf::write_object(outcome.image).has_value());
}

TEST_CASE(metadata_cleanup_reports_when_no_sections_are_eligible) {
    const auto outcome = run_single(make_coff_symbols(), binobf::make_metadata_cleanup_pass());
    REQUIRE(!outcome.changed);
    REQUIRE_EQ(outcome.reports.front().status, binobf::PassStatus::Unchanged);
    REQUIRE_EQ(outcome.reports.front().diagnostics.size(), std::size_t{1});
    REQUIRE_EQ(outcome.reports.front().diagnostics.front().code, "pass.no_matching_sections");
}

TEST_CASE(strip_debug_refuses_external_definitions_and_leaves_input_unchanged) {
    auto image = make_coff_symbols();
    for (auto& section : image.sections) ++section.formatIndex;
    for (auto& symbol : image.symbols) {
        if (symbol.formatSectionIndex > 0) ++symbol.formatSectionIndex;
    }
    image.sections.insert(image.sections.begin(), binobf::Section{
        .id = binobf::EntityId{20}, .formatIndex = 1,
        .formatFlags = 0x42100040, .name = ".debug$S",
        .kind = binobf::SectionKind::Debug, .address = {},
        .logicalSize = 1, .alignment = 1, .readable = true,
        .contents = {std::byte{0}}, .lineage = {}});
    image.symbols.at(1).section = binobf::EntityId{20};
    image.symbols.at(1).formatSectionIndex = 1;
    const auto original = image;
    binobf::PassManager manager;
    REQUIRE(manager.add(binobf::make_strip_debug_pass()).has_value());
    binobf::TransformContext context{0, false};
    const auto outcome = manager.run(context, image);
    REQUIRE(!outcome.has_value());
    REQUIRE_EQ(outcome.error().code, "pass.unsafe_reference");
    REQUIRE_EQ(image.sections.size(), original.sections.size());
    REQUIRE_EQ(image.symbols.at(1).name, "public_api");
    REQUIRE_EQ(image.symbols.at(1).section, std::optional{binobf::EntityId{20}});
}

TEST_CASE(metadata_cleanup_preserves_directives_unwind_resources_and_is_deterministic) {
    auto image = make_coff_symbols();
    const auto appendSection = [&image](std::uint64_t id, std::uint32_t index, std::string name) {
        image.sections.push_back(binobf::Section{
            .id = binobf::EntityId{id}, .formatIndex = index,
            .formatFlags = 0x40300040, .name = std::move(name),
            .kind = binobf::SectionKind::Metadata, .address = {},
            .logicalSize = 1, .alignment = 4, .readable = true,
            .contents = {std::byte{0}}, .lineage = {}});
    };
    appendSection(20, 2, ".drectve");
    appendSection(21, 3, ".pdata");
    appendSection(22, 4, ".rsrc");
    appendSection(23, 5, ".llvm_addrsig");
    const auto first = run_single(image, binobf::make_metadata_cleanup_pass());
    const auto second = run_single(std::move(image), binobf::make_metadata_cleanup_pass());
    REQUIRE(std::none_of(first.image.sections.begin(), first.image.sections.end(), [](const auto& section) {
        return section.name == ".llvm_addrsig";
    }));
    REQUIRE(std::any_of(first.image.sections.begin(), first.image.sections.end(), [](const auto& section) {
        return section.name == ".drectve";
    }));
    REQUIRE(std::any_of(first.image.sections.begin(), first.image.sections.end(), [](const auto& section) {
        return section.name == ".pdata";
    }));
    REQUIRE(std::any_of(first.image.sections.begin(), first.image.sections.end(), [](const auto& section) {
        return section.name == ".rsrc";
    }));
    const auto firstBytes = binobf::write_object(first.image);
    const auto secondBytes = binobf::write_object(second.image);
    REQUIRE(firstBytes.has_value());
    REQUIRE(secondBytes.has_value());
    REQUIRE_EQ(firstBytes.value(), secondBytes.value());
}

int main() {
    return binobf::test::run_all();
}

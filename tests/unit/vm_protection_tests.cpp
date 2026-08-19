#include "../test_support.hpp"

#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/vm/protection.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace {

auto make_function_object(binobf::BinaryFormat format) -> binobf::BinaryImage {
    binobf::BinaryImage image;
    image.format = format;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86_64;
    const bool elf = format == binobf::BinaryFormat::ELF;
    const bool systemV = format != binobf::BinaryFormat::COFF;
    image.sections.push_back(binobf::Section{
        .id = binobf::EntityId{1},
        .formatIndex = 1,
        .formatType = elf ? 1U : 0U,
        .formatFlags = elf ? 6U : 0x60500020U,
        .name = ".text",
        .kind = binobf::SectionKind::Code,
        .address = {},
        .logicalSize = 5,
        .alignment = 16,
        .readable = true,
        .executable = true,
        .contents = systemV ? std::vector<std::byte>{std::byte{0x89}, std::byte{0xf8}, std::byte{0x01},
                                                 std::byte{0xf0}, std::byte{0xc3}}
                        : std::vector<std::byte>{std::byte{0x89}, std::byte{0xc8}, std::byte{0x01},
                                                 std::byte{0xd0}, std::byte{0xc3}},
        .lineage = {}});
    if (elf) {
        image.sections.push_back(binobf::Section{.id = binobf::EntityId{2},
                                                 .formatIndex = 2,
                                                 .formatType = 3,
                                                 .name = ".strtab",
                                                 .kind = binobf::SectionKind::StringTable,
                                                 .address = {},
                                                 .alignment = 1,
                                                 .contents = {},
                                                 .lineage = {}});
        image.sections.push_back(binobf::Section{.id = binobf::EntityId{3},
                                                 .formatIndex = 3,
                                                 .formatType = 2,
                                                 .formatLink = 2,
                                                 .formatInfo = 1,
                                                 .formatEntrySize = 24,
                                                 .name = ".symtab",
                                                 .kind = binobf::SectionKind::SymbolTable,
                                                 .address = {},
                                                 .alignment = 8,
                                                 .contents = {},
                                                 .lineage = {}});
        image.sections.push_back(binobf::Section{.id = binobf::EntityId{4},
                                                 .formatIndex = 4,
                                                 .formatType = 3,
                                                 .isSectionNameTable = true,
                                                 .name = ".shstrtab",
                                                 .kind = binobf::SectionKind::StringTable,
                                                 .address = {},
                                                 .alignment = 1,
                                                 .contents = {},
                                                 .lineage = {}});
    }
    image.symbols.push_back(binobf::Symbol{.id = binobf::EntityId{5},
                                           .formatIndex = elf ? 1U : 0U,
                                           .formatTableIndex = elf ? 3U : 0U,
                                           .formatType = elf ? 2U : 0x20U,
                                           .formatStorage = elf ? std::uint8_t{1} : std::uint8_t{2},
                                           .formatSectionIndex = 1,
                                           .auxiliaryData = {},
                                           .name = "selected_add",
                                           .section = binobf::EntityId{1},
                                           .address = {},
                                           .size = 5,
                                           .kind = binobf::SymbolKind::Function,
                                           .visibility = binobf::SymbolVisibility::External,
                                           .defined = true,
                                           .definition = binobf::SymbolDefinitionKind::SectionRelative,
                                           .commonAlignment = 0,
                                           .tlsModel = binobf::TlsModel::None,
                                           .lineage = {}});
    return image;
}

auto find_symbol(const binobf::BinaryImage& image, std::string_view name) -> const binobf::Symbol* {
    const auto found = std::find_if(image.symbols.begin(), image.symbols.end(),
                                    [&](const auto& symbol) { return symbol.name == name; });
    return found == image.symbols.end() ? nullptr : &*found;
}

void require_embedded_magic(const binobf::vm::VmProtectionResult& result,
                            const binobf::Section& text) {
    REQUIRE(result.report.bytecodeSize > 4);
    const auto offset = static_cast<std::size_t>(result.report.bytecodeOffset);
    REQUIRE_EQ(text.contents.at(offset), std::byte{'B'});
    REQUIRE_EQ(text.contents.at(offset + 1), std::byte{'V'});
    REQUIRE_EQ(text.contents.at(offset + 2), std::byte{'M'});
    REQUIRE_EQ(text.contents.at(offset + 3), std::byte{'1'});
}

} // namespace

TEST_CASE(vm_protection_embeds_a_windows_adapter_bytecode_and_coff_relocation) {
    const auto result = binobf::vm::protect_function(
        make_function_object(binobf::BinaryFormat::COFF),
        binobf::vm::VmProtectionOptions{.function = "selected_add",
                                        .abi = binobf::ir::NativeAbi::WindowsX64,
                                        .argumentCount = 2,
                                        .seed = 16016});
    REQUIRE(result.has_value());
    REQUIRE_EQ(result.value().report.functionName, "selected_add");
    REQUIRE_EQ(result.value().report.originalAddress, UINT64_C(0));
    REQUIRE(result.value().report.protectedAddress >= 16);
    REQUIRE(result.value().report.wrapperSize > 0);
    REQUIRE_EQ(result.value().report.runtimeSymbol, binobf::vm::embeddedRuntimeSymbol);
    const auto* selected = find_symbol(result.value().image, "selected_add");
    const auto* runtime = find_symbol(result.value().image, binobf::vm::embeddedRuntimeSymbol);
    REQUIRE(selected != nullptr);
    REQUIRE(runtime != nullptr);
    REQUIRE_EQ(selected->address.value, result.value().report.protectedAddress);
    REQUIRE(!runtime->defined);
    REQUIRE(!runtime->section.has_value());
    REQUIRE_EQ(result.value().image.relocations.size(), std::size_t{1});
    REQUIRE_EQ(result.value().image.relocations.front().rawType, UINT64_C(4));
    REQUIRE_EQ(result.value().image.relocations.front().targetSymbol, std::optional{runtime->id});
    require_embedded_magic(result.value(), result.value().image.sections.front());
    const auto written = binobf::write_object(result.value().image);
    REQUIRE(written.has_value());
    REQUIRE(binobf::parse_object(written.value(), "protected.obj").has_value());
}

TEST_CASE(vm_protection_synthesizes_elf_runtime_symbol_and_rela_table) {
    const auto result = binobf::vm::protect_function(
        make_function_object(binobf::BinaryFormat::ELF),
        binobf::vm::VmProtectionOptions{.function = "selected_add",
                                        .abi = binobf::ir::NativeAbi::SystemVAMD64,
                                        .argumentCount = 2,
                                        .seed = 16016});
    REQUIRE(result.has_value());
    const auto relocationSection =
        std::find_if(result.value().image.sections.begin(), result.value().image.sections.end(),
                     [](const auto& section) { return section.name == ".rela.text"; });
    REQUIRE(relocationSection != result.value().image.sections.end());
    REQUIRE_EQ(relocationSection->formatType, UINT64_C(4));
    REQUIRE_EQ(relocationSection->formatInfo, 1U);
    REQUIRE_EQ(result.value().image.relocations.size(), std::size_t{1});
    REQUIRE_EQ(result.value().image.relocations.front().rawType, UINT64_C(4));
    REQUIRE_EQ(result.value().image.relocations.front().addend, INT64_C(-4));
    require_embedded_magic(result.value(), result.value().image.sections.front());
    const auto written = binobf::write_object(result.value().image);
    REQUIRE(written.has_value());
    REQUIRE(binobf::parse_object(written.value(), "protected.o").has_value());
}

TEST_CASE(vm_protection_embeds_a_systemv_adapter_and_macho_branch_relocation) {
    const auto result = binobf::vm::protect_function(
        make_function_object(binobf::BinaryFormat::MachO),
        binobf::vm::VmProtectionOptions{.function = "selected_add",
                                        .abi = binobf::ir::NativeAbi::SystemVAMD64,
                                        .argumentCount = 2,
                                        .seed = 16016});
    REQUIRE(result.has_value());
    REQUIRE_EQ(result.value().image.relocations.size(), std::size_t{1});
    REQUIRE_EQ(result.value().image.relocations.front().rawType, UINT64_C(2));
    REQUIRE_EQ(result.value().image.relocations.front().addend, INT64_C(0));
    require_embedded_magic(result.value(), result.value().image.sections.front());
    const auto written = binobf::write_object(result.value().image);
    REQUIRE(written.has_value());
    REQUIRE(binobf::parse_object(written.value(), "protected.macho.o").has_value());
}

TEST_CASE(vm_protection_is_deterministic_and_rejects_mismatched_or_unsupported_inputs) {
    const auto image = make_function_object(binobf::BinaryFormat::COFF);
    const binobf::vm::VmProtectionOptions options{.function = "selected_add",
                                                  .abi = binobf::ir::NativeAbi::WindowsX64,
                                                  .argumentCount = 2,
                                                  .seed = 99};
    const auto first = binobf::vm::protect_function(image, options);
    const auto repeated = binobf::vm::protect_function(image, options);
    REQUIRE(first.has_value());
    REQUIRE(repeated.has_value());
    REQUIRE_EQ(binobf::write_object(first.value().image).value(),
               binobf::write_object(repeated.value().image).value());

    auto mismatched = options;
    mismatched.abi = binobf::ir::NativeAbi::SystemVAMD64;
    const auto mismatch = binobf::vm::protect_function(image, mismatched);
    REQUIRE(!mismatch.has_value());
    REQUIRE_EQ(mismatch.error().code, "vm.protection_abi_format");

    auto unsupported = image;
    unsupported.architecture = binobf::Architecture::ARM64;
    const auto architecture = binobf::vm::protect_function(unsupported, options);
    REQUIRE(!architecture.has_value());
    REQUIRE_EQ(architecture.error().code, "vm.protection_architecture");
}

TEST_CASE(vm_protection_reuses_the_runtime_symbol_and_relocation_table) {
    auto image = make_function_object(binobf::BinaryFormat::COFF);
    auto& text = image.sections.front();
    const std::vector<std::byte> second{std::byte{0x89}, std::byte{0xc8}, std::byte{0x31},
                                        std::byte{0xd0}, std::byte{0xc3}};
    text.contents.insert(text.contents.end(), second.begin(), second.end());
    text.logicalSize = text.contents.size();
    image.symbols.push_back(
        binobf::Symbol{.id = binobf::EntityId{6},
                       .formatIndex = 1,
                       .formatTableIndex = 0,
                       .formatType = 0x20,
                       .formatStorage = 2,
                       .formatSectionIndex = 1,
                       .auxiliaryData = {},
                       .name = "selected_xor",
                       .section = binobf::EntityId{1},
                       .address = binobf::BinaryAddress{5, binobf::AddressKind::Virtual},
                       .size = 5,
                       .kind = binobf::SymbolKind::Function,
                       .visibility = binobf::SymbolVisibility::External,
                       .defined = true,
                       .definition = binobf::SymbolDefinitionKind::SectionRelative,
                       .commonAlignment = 0,
                       .tlsModel = binobf::TlsModel::None,
                       .lineage = {}});
    const auto first = binobf::vm::protect_function(
        image, binobf::vm::VmProtectionOptions{.function = "selected_add",
                                               .abi = binobf::ir::NativeAbi::WindowsX64,
                                               .argumentCount = 2,
                                               .seed = 1});
    REQUIRE(first.has_value());
    const auto serialized = binobf::write_object(first.value().image);
    REQUIRE(serialized.has_value());
    const auto reparsed = binobf::parse_object(serialized.value(), "once.obj");
    REQUIRE(reparsed.has_value());
    const auto secondResult = binobf::vm::protect_function(
        reparsed.value(), binobf::vm::VmProtectionOptions{.function = "selected_xor",
                                                          .abi = binobf::ir::NativeAbi::WindowsX64,
                                                          .argumentCount = 2,
                                                          .seed = 2});
    REQUIRE(secondResult.has_value());
    REQUIRE_EQ(std::count_if(secondResult.value().image.symbols.begin(),
                             secondResult.value().image.symbols.end(),
                             [](const auto& symbol) {
                                 return symbol.name == binobf::vm::embeddedRuntimeSymbol;
                             }),
               std::ptrdiff_t{1});
    REQUIRE_EQ(secondResult.value().image.relocations.size(), std::size_t{2});
    REQUIRE(binobf::write_object(secondResult.value().image).has_value());
}

TEST_CASE(vm_protection_rejects_fixed_internal_callers_and_selected_unwind_metadata) {
    auto directCaller = make_function_object(binobf::BinaryFormat::COFF);
    directCaller.sections.front().contents = {std::byte{0xe8}, std::byte{0x01}, std::byte{0x00},
                                              std::byte{0x00}, std::byte{0x00}, std::byte{0xc3},
                                              std::byte{0x89}, std::byte{0xc8}, std::byte{0x01},
                                              std::byte{0xd0}, std::byte{0xc3}};
    directCaller.sections.front().logicalSize = 11;
    directCaller.symbols.front().name = "fixed_caller";
    directCaller.symbols.front().size = 6;
    directCaller.symbols.push_back(
        binobf::Symbol{.id = binobf::EntityId{6},
                       .formatIndex = 1,
                       .formatTableIndex = 0,
                       .formatType = 0x20,
                       .formatStorage = 2,
                       .formatSectionIndex = 1,
                       .auxiliaryData = {},
                       .name = "selected_add",
                       .section = binobf::EntityId{1},
                       .address = binobf::BinaryAddress{6, binobf::AddressKind::Virtual},
                       .size = 5,
                       .kind = binobf::SymbolKind::Function,
                       .visibility = binobf::SymbolVisibility::External,
                       .defined = true,
                       .definition = binobf::SymbolDefinitionKind::SectionRelative,
                       .commonAlignment = 0,
                       .tlsModel = binobf::TlsModel::None,
                       .lineage = {}});
    const auto direct = binobf::vm::protect_function(
        directCaller, binobf::vm::VmProtectionOptions{.function = "selected_add",
                                                      .abi = binobf::ir::NativeAbi::WindowsX64,
                                                      .argumentCount = 2,
                                                      .seed = 1});
    REQUIRE(!direct.has_value());
    REQUIRE_EQ(direct.error().code, "vm.protection_direct_reference");

    auto unwind = make_function_object(binobf::BinaryFormat::COFF);
    unwind.unwindInfo.push_back(binobf::UnwindInfo{.id = binobf::EntityId{6},
                                                   .function = binobf::EntityId{7},
                                                   .encoded = {std::byte{0}},
                                                   .section = {},
                                                   .sectionOffset = 0,
                                                   .codeOffset = 0,
                                                   .codeSize = 0,
                                                   .format = binobf::UnwindFormat::Unknown,
                                                   .relocations = {},
                                                   .rewriteState = binobf::UnwindRewriteState::Opaque,
                                                   .lineage = {}});
    const auto rejected = binobf::vm::protect_function(
        unwind, binobf::vm::VmProtectionOptions{.function = "selected_add",
                                                .abi = binobf::ir::NativeAbi::WindowsX64,
                                                .argumentCount = 2,
                                                .seed = 1});
    REQUIRE(!rejected.has_value());
    REQUIRE_EQ(rejected.error().code, "vm.protection_unwind");
}

int main() { return binobf::test::run_all(); }

#include <binobf/architecture/backend.hpp>
#include <binobf/formats/object_writer.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

void write_file(const std::filesystem::path &path,
                const std::vector<std::byte> &bytes) {
  std::filesystem::create_directories(path.parent_path());
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream.write(reinterpret_cast<const char *>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  if (!stream)
    throw std::runtime_error("could not write ARM64 service artifact");
}

auto section(std::uint64_t id, std::uint32_t index, std::uint64_t type,
             std::string name, std::uint64_t flags = 0,
             std::uint64_t alignment = 1) -> binobf::Section {
  binobf::Section result{};
  result.id = binobf::EntityId{id};
  result.formatIndex = index;
  result.formatType = type;
  result.formatFlags = flags;
  result.name = std::move(name);
  result.kind = type == 3            ? binobf::SectionKind::StringTable
                : type == 2          ? binobf::SectionKind::SymbolTable
                : type == 4          ? binobf::SectionKind::Relocation
                : (flags & 4U) != 0U ? binobf::SectionKind::Code
                                     : binobf::SectionKind::Metadata;
  result.alignment = alignment;
  result.readable = (flags & 2U) != 0U;
  result.executable = (flags & 4U) != 0U;
  return result;
}

auto symbol(std::uint64_t id, std::uint32_t index, std::uint32_t table,
            std::string name, std::uint32_t type, std::uint8_t binding,
            std::int32_t rawSection, std::optional<binobf::EntityId> owner,
            std::uint64_t size = 0) -> binobf::Symbol {
  binobf::Symbol result{};
  result.id = binobf::EntityId{id};
  result.formatIndex = index;
  result.formatTableIndex = table;
  result.formatType = type;
  result.formatStorage = binding;
  result.formatSectionIndex = rawSection;
  result.name = std::move(name);
  result.section = owner;
  result.size = size;
  result.kind =
      type == 2U ? binobf::SymbolKind::Function : binobf::SymbolKind::Unknown;
  result.visibility = binding == 0U ? binobf::SymbolVisibility::Local
                                    : binobf::SymbolVisibility::External;
  result.defined = owner.has_value();
  result.definition =
      owner.has_value()
          ? std::optional{binobf::SymbolDefinitionKind::SectionRelative}
          : std::optional{binobf::SymbolDefinitionKind::Undefined};
  result.tlsModel = binobf::TlsModel::None;
  return result;
}

auto object_with_relocation(std::string sectionName,
                            std::vector<std::byte> contents,
                            std::string definedSymbol, std::string targetSymbol,
                            std::uint64_t relocationOffset,
                            std::uint64_t relocationType, std::int64_t addend,
                            binobf::SectionKind kind) -> binobf::BinaryImage {
  binobf::BinaryImage image{};
  image.format = binobf::BinaryFormat::ELF;
  image.type = binobf::BinaryType::RelocatableObject;
  image.architecture = binobf::Architecture::ARM64;
  auto payload = section(1, 1, 1, std::move(sectionName),
                         kind == binobf::SectionKind::Code ? 6 : 2,
                         kind == binobf::SectionKind::Code ? 4 : 8);
  payload.kind = kind;
  payload.contents = std::move(contents);
  payload.logicalSize = payload.contents.size();
  auto strings = section(2, 2, 3, ".strtab");
  auto symbols = section(3, 3, 2, ".symtab", 0, 8);
  symbols.formatLink = 2;
  symbols.formatInfo = 1;
  symbols.formatEntrySize = 24;
  auto sectionNames = section(4, 4, 3, ".shstrtab");
  sectionNames.isSectionNameTable = true;
  auto relocations = section(5, 5, 4, ".rela" + payload.name, 0, 8);
  relocations.formatLink = 3;
  relocations.formatInfo = 1;
  relocations.formatEntrySize = 24;
  image.sections = {std::move(payload), std::move(strings), std::move(symbols),
                    std::move(sectionNames), std::move(relocations)};
  image.symbols = {
      symbol(10, 1, 3, definedSymbol, 2, 1, 1, binobf::EntityId{1},
             image.sections.front().contents.size()),
      symbol(11, 2, 3, targetSymbol, 0, 1, 0, std::nullopt),
  };
  image.relocations.push_back(binobf::Relocation{
      .id = binobf::EntityId{12},
      .formatIndex = 0,
      .formatTableIndex = 5,
      .section = binobf::EntityId{1},
      .offset = relocationOffset,
      .kind = binobf::RelocationKind::PcRelative,
      .rawType = relocationType,
      .targetSymbol = binobf::EntityId{11},
      .addend = addend,
      .lineage = {},
  });
  return image;
}

auto register_binding(std::string name, std::uint16_t index)
    -> binobf::ir::IrStorageLocation {
  const auto type = binobf::ir::IrType{binobf::ir::IrWidth::U64};
  return binobf::ir::IrStorageLocation{binobf::ir::IrStorageKind::Register,
                                       type,
                                       std::move(name),
                                       0,
                                       8,
                                       8,
                                       index,
                                       false};
}

auto typed_register_binding(binobf::ir::IrType type, std::string name,
                            std::uint64_t size, std::uint32_t alignment,
                            std::uint16_t index)
    -> binobf::ir::IrStorageLocation {
  return binobf::ir::IrStorageLocation{binobf::ir::IrStorageKind::Register,
                                       type,
                                       std::move(name),
                                       0,
                                       size,
                                       alignment,
                                       index,
                                       false};
}

void write_adapter_object(const std::filesystem::path &path,
                          const binobf::AbiAdapterPlan &plan,
                          std::string adapterSymbol) {
  const auto &fixup = plan.emission.fixups.front();
  const auto image = object_with_relocation(
      ".text", plan.emission.bytes, std::move(adapterSymbol), fixup.symbol,
      fixup.offset, 0x11b, fixup.addend, binobf::SectionKind::Code);
  const auto bytes = binobf::write_object(image);
  if (!bytes.has_value())
    throw std::runtime_error(bytes.error().message);
  write_file(path, bytes.value());
}

void write_windows_unwind_object(const std::filesystem::path &path,
                                 const binobf::UnwindPlan &plan,
                                 const std::vector<std::byte> &code,
                                 const std::string &codeSymbol) {
  binobf::BinaryImage image{};
  image.format = binobf::BinaryFormat::COFF;
  image.type = binobf::BinaryType::RelocatableObject;
  image.architecture = binobf::Architecture::ARM64;
  binobf::Section text{};
  text.id = binobf::EntityId{1};
  text.formatIndex = 1;
  text.formatFlags = 0x60000020U;
  text.name = ".text";
  text.kind = binobf::SectionKind::Code;
  text.logicalSize = code.size();
  text.alignment = 4;
  text.readable = true;
  text.executable = true;
  text.contents = code;
  binobf::Section pdata{};
  pdata.id = binobf::EntityId{2};
  pdata.formatIndex = 2;
  pdata.formatFlags = 0x40000040U;
  pdata.name = ".pdata";
  pdata.kind = binobf::SectionKind::InitializedData;
  pdata.logicalSize = plan.encoded.size();
  pdata.alignment = 4;
  pdata.readable = true;
  pdata.contents = plan.encoded;
  image.sections = {std::move(text), std::move(pdata)};
  binobf::Symbol function{};
  function.id = binobf::EntityId{3};
  function.formatIndex = 0;
  function.formatType = 0x20;
  function.formatStorage = 2;
  function.formatSectionIndex = 1;
  function.name = codeSymbol;
  function.section = binobf::EntityId{1};
  function.size = code.size();
  function.kind = binobf::SymbolKind::Function;
  function.visibility = binobf::SymbolVisibility::External;
  function.defined = true;
  function.definition = binobf::SymbolDefinitionKind::SectionRelative;
  function.tlsModel = binobf::TlsModel::None;
  image.symbols.push_back(std::move(function));
  image.relocations.push_back(binobf::Relocation{
      .id = binobf::EntityId{4},
      .formatIndex = 0,
      .formatTableIndex = 2,
      .section = binobf::EntityId{2},
      .offset = plan.fixups.front().offset,
      .kind = binobf::RelocationKind::ImageRelative,
      .rawType = 0x0002,
      .targetSymbol = binobf::EntityId{3},
      .addend = plan.fixups.front().addend,
      .lineage = {},
  });
  const auto bytes = binobf::write_object(image);
  if (!bytes.has_value())
    throw std::runtime_error(bytes.error().message);
  write_file(path, bytes.value());
}

} // namespace

int main(int argc, char **argv) {
  try {
    if (argc != 3 && argc != 4)
      return 2;
    auto backend =
        binobf::make_architecture_backend(binobf::Architecture::ARM64);
    if (!backend.has_value())
      throw std::runtime_error(backend.error().message);

    binobf::AbiAdapterRequest adapter{};
    adapter.architecture = binobf::Architecture::ARM64;
    adapter.format = binobf::BinaryFormat::ELF;
    adapter.sourceAbi = binobf::ir::NativeAbi::AAPCS64;
    adapter.destinationAbi = binobf::ir::NativeAbi::AAPCS64;
    adapter.signature.parameterTypes.assign(
        9, binobf::ir::IrType{binobf::ir::IrWidth::U64});
    adapter.signature.parameterBindings = {
        register_binding("x1", 0),
        register_binding("x0", 1),
        register_binding("x2", 2),
        register_binding("x3", 3),
        register_binding("x4", 4),
        register_binding("x5", 5),
        register_binding("x6", 6),
        register_binding("x7", 7),
        binobf::ir::IrStorageLocation{
            binobf::ir::IrStorageKind::Stack,
            binobf::ir::IrType{binobf::ir::IrWidth::U64}, "sp", 0, 8, 8, 8,
            false},
    };
    adapter.signature.returnType = binobf::ir::IrType{binobf::ir::IrWidth::U64};
    adapter.symbol = "binobf_arm64_abi_target";
    adapter.stackAlignment = 16;
    const auto adapterPlan = backend.value()->build_abi_adapter(adapter);
    if (!adapterPlan.has_value())
      throw std::runtime_error(adapterPlan.error().message);
    write_adapter_object(argv[1], adapterPlan.value(),
                         "binobf_arm64_abi_adapter");

    binobf::AbiAdapterRequest mixed{};
    mixed.architecture = binobf::Architecture::ARM64;
    mixed.format = binobf::BinaryFormat::ELF;
    mixed.sourceAbi = binobf::ir::NativeAbi::WindowsARM64;
    mixed.destinationAbi = binobf::ir::NativeAbi::AAPCS64;
    const auto f64 =
        binobf::ir::IrType{binobf::ir::IrTypeKind::FloatingPoint, 64U};
    const auto v128 =
        binobf::ir::IrType{binobf::ir::IrTypeKind::Vector, 64U, 2U};
    const auto integer = binobf::ir::IrType{binobf::ir::IrWidth::U64};
    mixed.signature.parameterTypes = {f64, v128, integer};
    mixed.signature.parameterBindings = {
        typed_register_binding(f64, "v1", 8, 8, 0),
        typed_register_binding(v128, "v0", 16, 16, 1),
        typed_register_binding(integer, "x1", 8, 8, 2),
    };
    mixed.signature.returnType = integer;
    mixed.symbol = "binobf_arm64_mixed_target";
    mixed.stackAlignment = 16;
    const auto mixedPlan = backend.value()->build_abi_adapter(mixed);
    if (!mixedPlan.has_value())
      throw std::runtime_error(mixedPlan.error().message);
    write_adapter_object(std::filesystem::path{argv[1]}.parent_path() /
                             "mixed-adapter.o",
                         mixedPlan.value(), "binobf_arm64_mixed_adapter");

    binobf::AbiAdapterRequest indirect{};
    indirect.architecture = binobf::Architecture::ARM64;
    indirect.format = binobf::BinaryFormat::ELF;
    indirect.sourceAbi = binobf::ir::NativeAbi::AAPCS64;
    indirect.destinationAbi = binobf::ir::NativeAbi::AAPCS64;
    indirect.signature.returnType =
        binobf::ir::IrType{binobf::ir::IrTypeKind::Vector, 64U, 4U};
    indirect.signature.returnBinding =
        typed_register_binding(indirect.signature.returnType, "x8", 8, 8, 0);
    indirect.symbol = "binobf_arm64_indirect_target";
    indirect.stackAlignment = 16;
    const auto indirectPlan = backend.value()->build_abi_adapter(indirect);
    if (!indirectPlan.has_value())
      throw std::runtime_error(indirectPlan.error().message);
    write_adapter_object(std::filesystem::path{argv[1]}.parent_path() /
                             "indirect-adapter.o",
                         indirectPlan.value(), "binobf_arm64_indirect_adapter");

    auto unwindRequest = adapterPlan.value().unwind;
    unwindRequest.format = binobf::BinaryFormat::ELF;
    unwindRequest.codeStart = {0, binobf::AddressKind::RelativeVirtual};
    unwindRequest.codeSymbol = "binobf_arm64_unwind_target";
    const auto unwindPlan = backend.value()->build_unwind(unwindRequest);
    if (!unwindPlan.has_value())
      throw std::runtime_error(unwindPlan.error().message);
    const auto &unwindFixup = unwindPlan.value().fixups.front();
    const auto unwindImage = object_with_relocation(
        ".eh_frame", unwindPlan.value().encoded, "binobf_arm64_unwind_record",
        unwindFixup.symbol, unwindFixup.offset, 0x105, unwindFixup.addend,
        binobf::SectionKind::Metadata);
    const auto unwindBytes = binobf::write_object(unwindImage);
    if (!unwindBytes.has_value())
      throw std::runtime_error(unwindBytes.error().message);
    write_file(argv[2], unwindBytes.value());
    if (argc == 4) {
      auto windowsRequest = adapterPlan.value().unwind;
      windowsRequest.format = binobf::BinaryFormat::COFF;
      windowsRequest.codeStart = {0, binobf::AddressKind::RelativeVirtual};
      windowsRequest.codeSymbol = "binobf_arm64_windows_unwind_target";
      const auto windowsPlan = backend.value()->build_unwind(windowsRequest);
      if (!windowsPlan.has_value())
        throw std::runtime_error(windowsPlan.error().message);
      write_windows_unwind_object(argv[3], windowsPlan.value(),
                                  adapterPlan.value().emission.bytes,
                                  *windowsRequest.codeSymbol);
    }
    return 0;
  } catch (const std::exception &) {
    return 1;
  }
}

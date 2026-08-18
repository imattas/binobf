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

void write_file(const std::filesystem::path& path, const std::vector<std::byte>& bytes) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    if (!stream) throw std::runtime_error("could not write service evidence artifact");
}

auto section(
    std::uint64_t id,
    std::uint32_t index,
    std::uint64_t type,
    std::string name,
    std::uint64_t flags,
    std::vector<std::byte> contents = {}) -> binobf::Section {
    binobf::Section result{};
    result.id = binobf::EntityId{id};
    result.formatIndex = index;
    result.formatType = type;
    result.formatFlags = flags;
    result.name = std::move(name);
    result.kind = (flags & 4U) != 0U ? binobf::SectionKind::Code
        : type == 2U ? binobf::SectionKind::SymbolTable
        : type == 3U ? binobf::SectionKind::StringTable
        : type == 9U ? binobf::SectionKind::Relocation
                     : binobf::SectionKind::Metadata;
    result.logicalSize = contents.size();
    result.alignment = 4;
    result.readable = (flags & 2U) != 0U;
    result.executable = (flags & 4U) != 0U;
    result.contents = std::move(contents);
    return result;
}

auto symbol(
    std::uint64_t id,
    std::uint32_t index,
    std::uint32_t table,
    std::string name,
    std::uint32_t type,
    std::uint8_t storage,
    std::int32_t rawSection,
    std::optional<binobf::EntityId> owner,
    std::uint64_t size = 0) -> binobf::Symbol {
    binobf::Symbol result{};
    result.id = binobf::EntityId{id};
    result.formatIndex = index;
    result.formatTableIndex = table;
    result.formatType = type;
    result.formatStorage = storage;
    result.formatSectionIndex = rawSection;
    result.name = std::move(name);
    result.section = owner;
    result.size = size;
    result.kind = type == 2U ? binobf::SymbolKind::Function
                             : binobf::SymbolKind::Section;
    result.visibility = storage == 0U || storage == 3U
        ? binobf::SymbolVisibility::Local : binobf::SymbolVisibility::External;
    result.defined = owner.has_value();
    result.definition = owner.has_value()
        ? std::optional{binobf::SymbolDefinitionKind::SectionRelative}
        : std::optional{binobf::SymbolDefinitionKind::Undefined};
    result.tlsModel = binobf::TlsModel::None;
    return result;
}

auto adapter_object(const binobf::AbiAdapterPlan& plan) -> binobf::BinaryImage {
    binobf::BinaryImage image{};
    image.format = binobf::BinaryFormat::COFF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86;
    auto text = section(1, 1, 0, ".text", 0x60500020U, plan.emission.bytes);
    text.kind = binobf::SectionKind::Code;
    image.sections.push_back(std::move(text));
    image.symbols = {
        symbol(2, 0, 0, ".text", 0, 3, 1, binobf::EntityId{1}),
        symbol(3, 1, 0, "binobf_abi_adapter", 0x20, 2, 1,
               binobf::EntityId{1}, plan.emission.bytes.size()),
        symbol(4, 2, 0, "binobf_abi_target", 0x20, 2, 0, std::nullopt),
    };
    const auto& fixup = plan.emission.fixups.front();
    image.relocations.push_back(binobf::Relocation{
        .id = binobf::EntityId{5},
        .formatIndex = 0,
        .formatTableIndex = 1,
        .section = binobf::EntityId{1},
        .offset = fixup.offset,
        .kind = binobf::RelocationKind::PcRelative,
        .rawType = 0x14,
        .targetSymbol = binobf::EntityId{4},
        .addend = fixup.addend,
        .lineage = {},
    });
    return image;
}

auto unwind_object(const binobf::UnwindPlan& plan) -> binobf::BinaryImage {
    binobf::BinaryImage image{};
    image.format = binobf::BinaryFormat::ELF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86;
    std::vector<std::byte> code(16, std::byte{0x90});
    code.push_back(std::byte{0xc3});
    auto text = section(1, 1, 1, ".text", 6, std::move(code));
    auto strings = section(2, 2, 3, ".strtab", 0);
    auto symbols = section(3, 3, 2, ".symtab", 0);
    symbols.formatLink = 2;
    symbols.formatInfo = 2;
    symbols.formatEntrySize = 16;
    auto sectionNames = section(4, 4, 3, ".shstrtab", 0);
    sectionNames.isSectionNameTable = true;
    auto ehFrame = section(5, 5, 1, ".eh_frame", 2, plan.encoded);
    auto relocations = section(6, 6, 9, ".rel.eh_frame", 0);
    relocations.formatLink = 3;
    relocations.formatInfo = 5;
    relocations.formatEntrySize = 8;
    image.sections = {
        std::move(text), std::move(strings), std::move(symbols),
        std::move(sectionNames), std::move(ehFrame), std::move(relocations)};
    image.symbols = {
        symbol(10, 1, 3, ".text", 3, 0, 1, binobf::EntityId{1}),
        symbol(11, 2, 3, "owned_function", 2, 1, 1, binobf::EntityId{1}, 1),
    };
    image.symbols.back().address = {
        16, binobf::AddressKind::RelativeVirtual};
    const auto& fixup = plan.fixups.front();
    image.relocations.push_back(binobf::Relocation{
        .id = binobf::EntityId{12},
        .formatIndex = 0,
        .formatTableIndex = 6,
        .section = binobf::EntityId{5},
        .offset = fixup.offset,
        .kind = binobf::RelocationKind::PcRelative,
        .rawType = 2,
        .targetSymbol = binobf::EntityId{11},
        .addend = fixup.addend,
        .lineage = {},
    });
    return image;
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 3) return 2;
        auto backend = binobf::make_architecture_backend(binobf::Architecture::X86);
        if (!backend.has_value()) throw std::runtime_error(backend.error().message);

        binobf::AbiAdapterRequest adapter{};
        adapter.architecture = binobf::Architecture::X86;
        adapter.format = binobf::BinaryFormat::COFF;
        adapter.sourceAbi = binobf::ir::NativeAbi::WindowsI386Fastcall;
        adapter.destinationAbi = binobf::ir::NativeAbi::WindowsI386Fastcall;
        adapter.signature.parameterTypes = {
            binobf::ir::IrType{binobf::ir::IrWidth::U32},
            binobf::ir::IrType{binobf::ir::IrWidth::U32},
            binobf::ir::IrType{binobf::ir::IrWidth::U32}};
        adapter.signature.parameterBindings = {
            binobf::ir::IrStorageLocation{binobf::ir::IrStorageKind::Register,
                binobf::ir::IrType{binobf::ir::IrWidth::U32}, "edx", 0, 4, 4, 0},
            binobf::ir::IrStorageLocation{binobf::ir::IrStorageKind::Register,
                binobf::ir::IrType{binobf::ir::IrWidth::U32}, "ecx", 0, 4, 4, 1},
            binobf::ir::IrStorageLocation{binobf::ir::IrStorageKind::Register,
                binobf::ir::IrType{binobf::ir::IrWidth::U32}, "eax", 0, 4, 4, 2},
        };
        adapter.signature.returnType = binobf::ir::IrType{binobf::ir::IrWidth::U32};
        adapter.symbol = "binobf_abi_target";
        adapter.stackAlignment = 16;
        const auto adapterPlan = backend.value()->build_abi_adapter(adapter);
        if (!adapterPlan.has_value()) throw std::runtime_error(adapterPlan.error().message);
        const auto adapterBytes = binobf::write_object(adapter_object(adapterPlan.value()));
        if (!adapterBytes.has_value()) throw std::runtime_error(adapterBytes.error().message);
        write_file(argv[1], adapterBytes.value());

        binobf::UnwindRequest unwind{};
        unwind.architecture = binobf::Architecture::X86;
        unwind.format = binobf::BinaryFormat::ELF;
        unwind.codeStart = {16, binobf::AddressKind::RelativeVirtual};
        unwind.codeSize = 1;
        unwind.codeSymbol = "owned_function";
        unwind.actions = {
            {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "esp", 4, 0},
            {binobf::UnwindActionKind::SaveRegister, "eip", -4, 0},
        };
        const auto unwindPlan = backend.value()->build_unwind(unwind);
        if (!unwindPlan.has_value()) throw std::runtime_error(unwindPlan.error().message);
        const auto unwindBytes = binobf::write_object(unwind_object(unwindPlan.value()));
        if (!unwindBytes.has_value()) throw std::runtime_error(unwindBytes.error().message);
        write_file(argv[2], unwindBytes.value());
        return 0;
    } catch (const std::exception&) {
        return 1;
    }
}

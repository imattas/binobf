#include <binobf/vm/protection.hpp>

#include <binobf/analysis/object_analyzer.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/vm/bytecode.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace binobf::vm {
namespace {

struct NativeAdapter {
    std::vector<std::byte> bytes;
    std::size_t bytecodeDisplacement{0};
    std::size_t runtimeDisplacement{0};
};

auto failure(std::string code, std::string message) -> Result<VmProtectionResult, Diagnostic> {
    return Result<VmProtectionResult, Diagnostic>::failure(
        Diagnostic{DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

void append_byte(std::vector<std::byte>& bytes, std::uint8_t value) {
    bytes.push_back(static_cast<std::byte>(value));
}

void append_u32(std::vector<std::byte>& bytes, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        append_byte(bytes, static_cast<std::uint8_t>(
                               (value >> static_cast<unsigned int>(index * 8U)) & 0xffU));
    }
}

void put_u16(std::vector<std::byte>& bytes, std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<std::byte>(value & 0xffU);
    bytes[offset + 1] = static_cast<std::byte>((value >> 8U) & 0xffU);
}

void put_u32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        bytes[offset + index] =
            static_cast<std::byte>((value >> static_cast<unsigned int>(index * 8U)) & 0xffU);
    }
}

void put_i32(std::vector<std::byte>& bytes, std::size_t offset, std::int32_t value) {
    put_u32(bytes, offset, std::bit_cast<std::uint32_t>(value));
}

auto align_16(std::size_t value) -> std::optional<std::size_t> {
    if (value > std::numeric_limits<std::size_t>::max() - 15U) {
        return std::nullopt;
    }
    return (value + 15U) & ~std::size_t{15};
}

auto build_adapter(ir::NativeAbi abi, std::uint32_t bytecodeSize, std::uint32_t argumentCount)
    -> NativeAdapter {
    NativeAdapter adapter;
    auto& bytes = adapter.bytes;
    const auto count = static_cast<std::size_t>(argumentCount);
    const auto windows = abi == ir::NativeAbi::WindowsX64;
    const auto reserve = windows ? (count > 4U ? 72U : 56U) : (count > 4U ? 40U : 24U);
    append_byte(bytes, 0x48);
    append_byte(bytes, 0x83);
    append_byte(bytes, 0xec);
    append_byte(bytes, static_cast<std::uint8_t>(reserve));

    const auto store_register = [&](std::uint8_t registerCode, std::size_t offset) {
        append_byte(bytes, registerCode >= 8U ? 0x44U : 0x40U);
        append_byte(bytes, 0x89U);
        append_byte(bytes, static_cast<std::uint8_t>(0x44U | ((registerCode & 7U) << 3U)));
        append_byte(bytes, 0x24U);
        append_byte(bytes, static_cast<std::uint8_t>(offset));
    };
    const auto store_r11 = [&](std::size_t offset) { store_register(11U, offset); };
    const auto load_r11 = [&](std::size_t offset) {
        append_byte(bytes, 0x44U);
        append_byte(bytes, 0x8bU);
        append_byte(bytes, 0x5cU);
        append_byte(bytes, 0x24U);
        append_byte(bytes, static_cast<std::uint8_t>(offset));
    };
    if (windows) {
        constexpr std::array<std::uint8_t, 4> registers{1U, 2U, 8U, 9U};
        for (std::size_t index = 0; index < std::min(count, std::size_t{4}); ++index)
            store_register(registers[index], 32U + index * 4U);
        for (std::size_t index = 4; index < count; ++index) {
            load_r11(reserve + 40U + (index - 4U) * 8U);
            store_r11(32U + index * 4U);
        }
        // Windows x64 runtime ABI: RCX=bytecode, RDX=bytecode size,
        // R8=argument array, and R9=argument count.
        const std::uint8_t argumentsAddress[] = {0x4c, 0x8d, 0x44, 0x24, 0x20};
        for (const auto value : argumentsAddress) append_byte(bytes, value);
        append_byte(bytes, 0x48);
        append_byte(bytes, 0x8d);
        append_byte(bytes, 0x0d);
        adapter.bytecodeDisplacement = bytes.size();
        append_u32(bytes, 0);
        append_byte(bytes, 0xba);
        append_u32(bytes, bytecodeSize);
        append_byte(bytes, 0x41);
        append_byte(bytes, 0xb9);
        append_u32(bytes, argumentCount);
    } else {
        constexpr std::array<std::uint8_t, 4> registers{7U, 6U, 2U, 1U};
        for (std::size_t index = 0; index < std::min(count, std::size_t{4}); ++index)
            store_register(registers[index], index * 4U);
        for (std::size_t index = 4; index < count; ++index) {
            load_r11(reserve + 8U + (index - 4U) * 8U);
            store_r11(index * 4U);
        }
        const std::uint8_t argumentsAddress[] = {0x48, 0x8d, 0x14, 0x24};
        for (const auto value : argumentsAddress) append_byte(bytes, value);
        append_byte(bytes, 0x48);
        append_byte(bytes, 0x8d);
        append_byte(bytes, 0x3d);
        adapter.bytecodeDisplacement = bytes.size();
        append_u32(bytes, 0);
        append_byte(bytes, 0xbe);
        append_u32(bytes, bytecodeSize);
        append_byte(bytes, 0xb9);
        append_u32(bytes, argumentCount);
    }
    append_byte(bytes, 0xe8);
    adapter.runtimeDisplacement = bytes.size();
    append_u32(bytes, 0);
    const std::uint8_t suffix[] = {
        0x48, 0x83,
        0xc4, static_cast<std::uint8_t>(reserve),
        0xc3,
    };
    for (const auto value : suffix)
        append_byte(bytes, value);
    return adapter;
}

void include_id(std::uint64_t& maximum, EntityId id) { maximum = std::max(maximum, id.value()); }

auto next_entity_id(const BinaryImage& image) -> std::optional<std::uint64_t> {
    std::uint64_t maximum = 0;
    for (const auto& value : image.sections)
        include_id(maximum, value.id);
    for (const auto& value : image.segments)
        include_id(maximum, value.id);
    for (const auto& value : image.symbols)
        include_id(maximum, value.id);
    for (const auto& value : image.imports)
        include_id(maximum, value.id);
    for (const auto& value : image.exports)
        include_id(maximum, value.id);
    for (const auto& value : image.relocations)
        include_id(maximum, value.id);
    for (const auto& value : image.instructions)
        include_id(maximum, value.id);
    for (const auto& value : image.basicBlocks)
        include_id(maximum, value.id);
    for (const auto& value : image.functions)
        include_id(maximum, value.id);
    for (const auto& value : image.dataObjects)
        include_id(maximum, value.id);
    for (const auto& value : image.unwindInfo)
        include_id(maximum, value.id);
    for (const auto& value : image.debugInfo)
        include_id(maximum, value.id);
    for (const auto& value : image.resources)
        include_id(maximum, value.id);
    if (maximum == std::numeric_limits<std::uint64_t>::max())
        return std::nullopt;
    return maximum + 1U;
}

auto find_section(BinaryImage& image, EntityId id) -> Section* {
    const auto found = std::find_if(image.sections.begin(), image.sections.end(),
                                    [&](const auto& section) { return section.id == id; });
    return found == image.sections.end() ? nullptr : &*found;
}

auto find_symbol(BinaryImage& image, EntityId id) -> Symbol* {
    const auto found = std::find_if(image.symbols.begin(), image.symbols.end(),
                                    [&](const auto& symbol) { return symbol.id == id; });
    return found == image.symbols.end() ? nullptr : &*found;
}

auto raw_coff_symbol_count(const BinaryImage& image) -> std::optional<std::uint32_t> {
    std::uint64_t maximum = 0;
    for (const auto& symbol : image.symbols) {
        const auto count = UINT64_C(1) + symbol.auxiliaryData.size() / 18U;
        maximum = std::max(maximum, static_cast<std::uint64_t>(symbol.formatIndex) + count);
    }
    if (maximum > std::numeric_limits<std::uint32_t>::max())
        return std::nullopt;
    return static_cast<std::uint32_t>(maximum);
}

auto next_symbol_index(const BinaryImage& image, std::uint32_t table)
    -> std::optional<std::uint32_t> {
    std::uint32_t maximum = 0;
    bool foundAny = false;
    for (const auto& symbol : image.symbols) {
        if (symbol.formatTableIndex != table)
            continue;
        maximum = std::max(maximum, symbol.formatIndex);
        foundAny = true;
    }
    if (!foundAny)
        return std::uint32_t{1};
    if (maximum == std::numeric_limits<std::uint32_t>::max())
        return std::nullopt;
    return maximum + 1U;
}

auto next_relocation_index(const BinaryImage& image, std::uint32_t table)
    -> std::optional<std::uint32_t> {
    std::uint32_t maximum = 0;
    bool foundAny = false;
    for (const auto& relocation : image.relocations) {
        if (relocation.formatTableIndex != table)
            continue;
        maximum = std::max(maximum, relocation.formatIndex);
        foundAny = true;
    }
    if (!foundAny)
        return std::uint32_t{0};
    if (maximum == std::numeric_limits<std::uint32_t>::max())
        return std::nullopt;
    return maximum + 1U;
}

auto has_relocation_reference(const Instruction& instruction) -> bool {
    return std::any_of(instruction.references.begin(), instruction.references.end(),
                       [](const auto& reference) { return reference.relocation.has_value(); });
}

auto has_unsafe_direct_caller(const BinaryImage& analyzed, const Function& selected) -> bool {
    for (const auto& function : analyzed.functions) {
        if (function.id == selected.id)
            continue;
        for (const auto instructionId : function.instructions) {
            const auto found = std::find_if(
                analyzed.instructions.begin(), analyzed.instructions.end(),
                [&](const auto& instruction) { return instruction.id == instructionId; });
            if (found == analyzed.instructions.end() || !found->directTarget.has_value())
                continue;
            const bool transfers = found->kind == InstructionKind::DirectCall ||
                                   found->kind == InstructionKind::DirectBranch;
            if (transfers && *found->directTarget == selected.address &&
                !has_relocation_reference(*found)) {
                return true;
            }
        }
    }
    return false;
}

void repair_coff_section_symbol(BinaryImage& image, const Section& section) {
    const auto relocationCount = static_cast<std::uint16_t>(std::count_if(
        image.relocations.begin(), image.relocations.end(), [&](const auto& relocation) {
            return relocation.formatTableIndex == section.formatIndex;
        }));
    for (auto& symbol : image.symbols) {
        if (symbol.section != std::optional{section.id} || symbol.kind != SymbolKind::Section ||
            symbol.auxiliaryData.size() < 18) {
            continue;
        }
        put_u32(symbol.auxiliaryData, 0, static_cast<std::uint32_t>(section.contents.size()));
        put_u16(symbol.auxiliaryData, 4, relocationCount);
    }
}

} // namespace

auto protect_function(const BinaryImage& image, const VmProtectionOptions& options)
    -> Result<VmProtectionResult, Diagnostic> {
    if (image.type != BinaryType::RelocatableObject ||
        (image.format != BinaryFormat::COFF && image.format != BinaryFormat::ELF &&
         image.format != BinaryFormat::MachO)) {
        return failure("vm.protection_format",
                       "VM protection requires a relocatable COFF, ELF, or Mach-O object");
    }
    if (image.architecture != Architecture::X86_64) {
        return failure("vm.protection_architecture",
                       "VM protection currently requires x86-64 object code");
    }
    if ((image.format == BinaryFormat::COFF && options.abi != ir::NativeAbi::WindowsX64) ||
        ((image.format == BinaryFormat::ELF || image.format == BinaryFormat::MachO) &&
         options.abi != ir::NativeAbi::SystemVAMD64)) {
        return failure("vm.protection_abi_format",
                       "the selected ABI does not match the object format");
    }
    if (options.function.empty()) {
        return failure("vm.protection_function", "selected function name is empty");
    }
    if (options.argumentCount > 8) {
        return failure("vm.protection_arguments",
                       "VM protection accepts zero through eight u32 arguments");
    }

    const auto analyzed = analyze_object(image);
    if (!analyzed.has_value()) {
        return Result<VmProtectionResult, Diagnostic>::failure(analyzed.error());
    }
    const auto selected = std::find_if(
        analyzed.value().image.functions.begin(), analyzed.value().image.functions.end(),
        [&](const auto& function) { return function.name == options.function; });
    if (selected == analyzed.value().image.functions.end()) {
        return failure("vm.protection_function_not_found",
                       "selected function was not recovered: " + options.function);
    }
    if (!selected->complete || !selected->symbol.has_value()) {
        return failure("vm.protection_incomplete_function",
                       "selected function is incomplete or lacks a defining symbol");
    }
    if (has_unsafe_direct_caller(analyzed.value().image, *selected)) {
        return failure("vm.protection_direct_reference",
                       "selected function has a relocation-free direct caller in "
                       "the same object");
    }
    if (std::any_of(analyzed.value().image.unwindInfo.begin(),
                    analyzed.value().image.unwindInfo.end(),
                    [&](const auto& unwind) { return unwind.function == selected->id; })) {
        return failure("vm.protection_unwind",
                       "selected function has unwind metadata that cannot describe "
                       "the adapter");
    }

    ir::NativeFunctionSignature signature;
    signature.abi = options.abi;
    signature.arguments.assign(options.argumentCount, ir::IrType{ir::IrWidth::U32});
    signature.returnType = ir::IrType{ir::IrWidth::U32};
    const auto lifted = ir::lift_function(analyzed.value().image, selected->id, signature);
    if (!lifted.has_value()) {
        return Result<VmProtectionResult, Diagnostic>::failure(lifted.error());
    }
    if (!lifted.value().complete) {
        const auto message =
            lifted.value().diagnostics.empty()
                ? std::string{"selected function is outside the VM lowering subset"}
                : lifted.value().diagnostics.front().message;
        return failure("vm.protection_not_lowerable", message);
    }
    const auto lowered = ir::lower_to_vm(lifted.value().function);
    if (!lowered.has_value()) {
        return Result<VmProtectionResult, Diagnostic>::failure(lowered.error());
    }
    const auto assembled =
        assemble_program(lowered.value().program, VmAssemblyOptions{options.seed});
    if (!assembled.has_value()) {
        return Result<VmProtectionResult, Diagnostic>::failure(assembled.error());
    }
    if (assembled.value().size() > std::numeric_limits<std::uint32_t>::max()) {
        return failure("vm.protection_size", "embedded bytecode exceeds adapter limits");
    }

    BinaryImage output = image;
    auto nextId = next_entity_id(output);
    if (!nextId.has_value()) {
        return failure("vm.protection_id_exhausted", "no entity IDs remain for VM protection");
    }
    auto* section = find_section(output, selected->section);
    auto* selectedSymbol = find_symbol(output, *selected->symbol);
    if (section == nullptr || selectedSymbol == nullptr) {
        return failure("vm.protection_model",
                       "selected function references unavailable object entities");
    }
    const auto wrapperOffset = align_16(section->contents.size());
    if (!wrapperOffset.has_value()) {
        return failure("vm.protection_size", "adapter layout overflows host limits");
    }
    auto adapter = build_adapter(options.abi, static_cast<std::uint32_t>(assembled.value().size()),
                                 static_cast<std::uint32_t>(options.argumentCount));
    const auto unalignedBytecode = *wrapperOffset + adapter.bytes.size();
    const auto bytecodeOffset = align_16(unalignedBytecode);
    if (!bytecodeOffset.has_value() ||
        *bytecodeOffset > static_cast<std::size_t>(std::numeric_limits<std::int64_t>::max())) {
        return failure("vm.protection_size", "bytecode layout exceeds adapter limits");
    }
    const auto leaNext = *wrapperOffset + adapter.bytecodeDisplacement + 4U;
    const auto displacement =
        static_cast<std::int64_t>(*bytecodeOffset) - static_cast<std::int64_t>(leaNext);
    if (displacement < std::numeric_limits<std::int32_t>::min() ||
        displacement > std::numeric_limits<std::int32_t>::max()) {
        return failure("vm.protection_size", "embedded bytecode is outside RIP-relative range");
    }
    put_i32(adapter.bytes, adapter.bytecodeDisplacement, static_cast<std::int32_t>(displacement));
    section->contents.resize(*wrapperOffset, std::byte{0x90});
    section->contents.insert(section->contents.end(), adapter.bytes.begin(), adapter.bytes.end());
    section->contents.resize(*bytecodeOffset, std::byte{0x90});
    section->contents.insert(section->contents.end(), assembled.value().begin(),
                             assembled.value().end());
    section->logicalSize = section->contents.size();

    const auto originalAddress = selectedSymbol->address.value;
    if (section->address.value > std::numeric_limits<std::uint64_t>::max() - *wrapperOffset) {
        return failure("vm.protection_size", "protected symbol address overflows");
    }
    selectedSymbol->address.value = section->address.value + *wrapperOffset;
    selectedSymbol->size = adapter.bytes.size();
    const auto protectedAddress = selectedSymbol->address.value;
    const auto selectedSymbolTable = selectedSymbol->formatTableIndex;
    const auto selectedSectionId = section->id;
    const auto selectedSectionIndex = section->formatIndex;
    const auto selectedSectionName = section->name;

    Symbol* runtimeSymbol = nullptr;
    const auto existingRuntime =
        std::find_if(output.symbols.begin(), output.symbols.end(),
                     [](const auto& symbol) { return symbol.name == embeddedRuntimeSymbol; });
    if (existingRuntime != output.symbols.end()) {
        if (existingRuntime->defined || existingRuntime->section.has_value() ||
            existingRuntime->visibility != SymbolVisibility::External) {
            return failure("vm.protection_runtime_symbol",
                           "object defines an incompatible embedded VM runtime symbol");
        }
        runtimeSymbol = &*existingRuntime;
    } else {
        const auto symbolId = EntityId{(*nextId)++};
        if (output.format == BinaryFormat::COFF) {
            const auto rawIndex = raw_coff_symbol_count(output);
            if (!rawIndex.has_value()) {
                return failure("vm.protection_size", "COFF symbol table is full");
            }
            output.symbols.push_back(Symbol{.id = symbolId,
                                            .formatIndex = *rawIndex,
                                            .formatTableIndex = 0,
                                            .formatType = 0x20,
                                            .formatStorage = 2,
                                            .formatSectionIndex = 0,
                                            .auxiliaryData = {},
                                            .name = std::string{embeddedRuntimeSymbol},
                                            .section = std::nullopt,
                                            .address = {},
                                            .size = 0,
                                            .kind = SymbolKind::Function,
                                            .visibility = SymbolVisibility::External,
                                            .defined = false,
                                            .definition = SymbolDefinitionKind::Undefined,
                                            .commonAlignment = 0,
                                            .tlsModel = TlsModel::None,
                                            .lineage = {}});
        } else {
            const auto table = selectedSymbolTable;
            const auto index = next_symbol_index(output, table);
            if (!index.has_value()) {
                return failure("vm.protection_size", "ELF symbol table is full");
            }
            output.symbols.push_back(Symbol{.id = symbolId,
                                            .formatIndex = *index,
                                            .formatTableIndex = table,
                                            .formatType = 2,
                                            .formatStorage = 1,
                                            .formatSectionIndex = 0,
                                            .auxiliaryData = {},
                                            .name = std::string{embeddedRuntimeSymbol},
                                            .section = std::nullopt,
                                            .address = {},
                                            .size = 0,
                                            .kind = SymbolKind::Function,
                                            .visibility = SymbolVisibility::External,
                                            .defined = false,
                                            .definition = SymbolDefinitionKind::Undefined,
                                            .commonAlignment = 0,
                                            .tlsModel = TlsModel::None,
                                            .lineage = {}});
        }
        runtimeSymbol = &output.symbols.back();
    }

    std::uint32_t relocationTable = selectedSectionIndex;
    if (output.format == BinaryFormat::ELF) {
        const auto symbolTable = runtimeSymbol->formatTableIndex;
        auto relocationSection = std::find_if(
            output.sections.begin(), output.sections.end(), [&](const auto& candidate) {
                return candidate.formatType == 4 && candidate.formatInfo == selectedSectionIndex &&
                       candidate.formatLink == symbolTable;
            });
        if (relocationSection == output.sections.end()) {
            const auto formatIndex = output.sections.size() + 1U;
            if (formatIndex > std::numeric_limits<std::uint32_t>::max()) {
                return failure("vm.protection_size", "ELF section table is full");
            }
            const auto name = ".rela" + selectedSectionName;
            if (std::any_of(output.sections.begin(), output.sections.end(),
                            [&](const auto& candidate) { return candidate.name == name; })) {
                return failure("vm.protection_relocation_table",
                               "ELF relocation section name is already used incompatibly");
            }
            output.sections.push_back(
                Section{.id = EntityId{(*nextId)++},
                        .formatIndex = static_cast<std::uint32_t>(formatIndex),
                        .formatType = 4,
                        .formatFlags = 0,
                        .formatLink = symbolTable,
                        .formatInfo = selectedSectionIndex,
                        .formatEntrySize = 24,
                        .isSectionNameTable = false,
                        .name = name,
                        .kind = SectionKind::Relocation,
                        .address = {},
                        .logicalSize = 0,
                        .alignment = 8,
                        .readable = false,
                        .writable = false,
                        .executable = false,
                        .contents = {},
                        .lineage = {}});
            relocationTable = output.sections.back().formatIndex;
        } else {
            relocationTable = relocationSection->formatIndex;
        }
    }
    const auto relocationIndex = next_relocation_index(output, relocationTable);
    if (!relocationIndex.has_value()) {
        return failure("vm.protection_size", "relocation table is full");
    }
    const auto runtimeRelocationOffset = *wrapperOffset + adapter.runtimeDisplacement;
    output.relocations.push_back(
        Relocation{.id = EntityId{(*nextId)++},
                   .formatIndex = *relocationIndex,
                   .formatTableIndex = relocationTable,
                   .section = selectedSectionId,
                   .offset = runtimeRelocationOffset,
                   .kind = RelocationKind::PcRelative,
                   .rawType = output.format == BinaryFormat::MachO ? 2U : 4U,
                   .targetSymbol = runtimeSymbol->id,
                   .addend = output.format == BinaryFormat::MachO
                       ? INT64_C(0) : INT64_C(-4),
                   .lineage = {}});
    if (output.format == BinaryFormat::COFF) {
        if (output.relocations.size() > std::numeric_limits<std::uint16_t>::max()) {
            return failure("vm.protection_size", "COFF relocation count exceeds limits");
        }
        const auto* repairedSection = find_section(output, selectedSectionId);
        if (repairedSection == nullptr) {
            return failure("vm.protection_model", "protected code section disappeared");
        }
        repair_coff_section_symbol(output, *repairedSection);
    }

    const auto validated = write_object(output);
    if (!validated.has_value()) {
        return Result<VmProtectionResult, Diagnostic>::failure(validated.error());
    }
    VmProtectionReport report{
        .functionName = options.function,
        .sectionName = selectedSectionName,
        .runtimeSymbol = std::string{embeddedRuntimeSymbol},
        .abi = options.abi,
        .argumentCount = options.argumentCount,
        .seed = options.seed,
        .originalAddress = originalAddress,
        .protectedAddress = protectedAddress,
        .wrapperOffset = *wrapperOffset,
        .wrapperSize = adapter.bytes.size(),
        .bytecodeOffset = *bytecodeOffset,
        .bytecodeSize = assembled.value().size(),
        .runtimeRelocationOffset = runtimeRelocationOffset,
        .instructionLineage = lowered.value().lineage,
    };
    return Result<VmProtectionResult, Diagnostic>::success(VmProtectionResult{
        .image = std::move(output),
        .bytecode = assembled.value(),
        .report = std::move(report),
    });
}

} // namespace binobf::vm

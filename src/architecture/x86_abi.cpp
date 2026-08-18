#include "x86_abi.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace binobf::detail {
namespace {

template <typename T>
auto failure(std::string code, std::string message) -> Result<T, Diagnostic> {
    return Result<T, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

auto is_i386_abi(ir::NativeAbi abi) -> bool {
    return abi == ir::NativeAbi::WindowsI386Cdecl
        || abi == ir::NativeAbi::WindowsI386Stdcall
        || abi == ir::NativeAbi::WindowsI386Fastcall
        || abi == ir::NativeAbi::WindowsI386Thiscall
        || abi == ir::NativeAbi::SystemVI386;
}

auto caller_cleans(ir::NativeAbi abi) -> bool {
    return abi == ir::NativeAbi::WindowsI386Cdecl || abi == ir::NativeAbi::SystemVI386;
}

auto slot_size(const ir::IrType& type) -> std::optional<std::uint64_t> {
    if (type.byteOrder != ir::IrByteOrder::Little || type.addressSpace != 0U) {
        return std::nullopt;
    }
    if (type.kind == ir::IrTypeKind::Integer
        && type.lanes == 1U
        && (type.bits == 8U || type.bits == 16U || type.bits == 32U || type.bits == 64U)) {
        return std::max<std::uint64_t>(4U, (type.bits + 7U) / 8U);
    }
    if (type.kind == ir::IrTypeKind::Pointer && type.bits == 32U && type.lanes == 1U) return 4U;
    if (type.kind == ir::IrTypeKind::FloatingPoint
        && type.lanes == 1U
        && (type.bits == 32U || type.bits == 64U)) {
        return type.bits / 8U;
    }
    if (type.kind == ir::IrTypeKind::Vector && type.bits != 0U && type.lanes != 0U) {
        const auto totalBits = static_cast<std::uint64_t>(type.bits) * type.lanes;
        if ((totalBits == 64U || totalBits == 128U) && totalBits % 32U == 0U) {
            return totalBits / 8U;
        }
    }
    return std::nullopt;
}

auto register_eligible(const ir::IrType& type) -> bool {
    return (type.kind == ir::IrTypeKind::Integer && type.bits <= 32U)
        || (type.kind == ir::IrTypeKind::Pointer && type.bits == 32U);
}

auto register_location(
    const ir::IrType& type,
    std::string name,
    std::uint16_t index) -> ir::IrStorageLocation {
    return ir::IrStorageLocation{
        .kind = ir::IrStorageKind::Register,
        .type = type,
        .name = std::move(name),
        .size = 4U,
        .alignment = 4U,
        .index = index,
    };
}

auto stack_location(
    const ir::IrType& type,
    std::int64_t offset,
    std::uint64_t size,
    std::uint16_t index) -> ir::IrStorageLocation {
    return ir::IrStorageLocation{
        .kind = ir::IrStorageKind::Stack,
        .type = type,
        .name = "esp",
        .offset = offset,
        .size = size,
        .alignment = 4U,
        .index = index,
    };
}

auto derive_bindings(
    ir::NativeAbi abi,
    const std::vector<ir::IrType>& types,
    const std::vector<std::uint64_t>& sizes) -> std::vector<ir::IrStorageLocation> {
    std::vector<ir::IrStorageLocation> result;
    result.reserve(types.size());
    std::int64_t stackOffset = 4;
    std::size_t registerOrdinal = 0;
    for (std::size_t index = 0; index < types.size(); ++index) {
        const auto size = sizes[index];
        std::optional<std::string> registerName;
        if (abi == ir::NativeAbi::WindowsI386Fastcall
            && register_eligible(types[index]) && registerOrdinal < 2U) {
            registerName = registerOrdinal == 0U ? "ecx" : "edx";
            ++registerOrdinal;
        } else if (abi == ir::NativeAbi::WindowsI386Thiscall
                   && index == 0U && register_eligible(types[index])) {
            registerName = "ecx";
        }
        if (registerName.has_value()) {
            result.push_back(register_location(
                types[index], std::move(*registerName), static_cast<std::uint16_t>(index)));
        } else {
            result.push_back(stack_location(
                types[index], stackOffset, size, static_cast<std::uint16_t>(index)));
            stackOffset += static_cast<std::int64_t>(size);
        }
    }
    return result;
}

auto stack_bytes(const std::vector<ir::IrStorageLocation>& bindings) -> std::uint64_t {
    std::uint64_t result = 0;
    for (const auto& binding : bindings) {
        if (binding.kind == ir::IrStorageKind::Stack) result += binding.size;
    }
    return result;
}

auto validate_return(const ir::IrFunctionSignature& signature) -> bool {
    const auto& type = signature.returnType;
    if (type.kind == ir::IrTypeKind::Void) return !signature.returnBinding.has_value();
    std::string expected;
    if (type.kind == ir::IrTypeKind::Integer && type.bits <= 32U) expected = "eax";
    else if (type.kind == ir::IrTypeKind::Pointer && type.bits == 32U) expected = "eax";
    else if (type.kind == ir::IrTypeKind::Integer && type.bits == 64U) expected = "edx:eax";
    else if (type.kind == ir::IrTypeKind::FloatingPoint
             && (type.bits == 32U || type.bits == 64U)) expected = "st0";
    else if (type.kind == ir::IrTypeKind::Vector
             && type.bits != 0U && type.lanes != 0U
             && static_cast<std::uint32_t>(type.bits) * type.lanes <= 128U) expected = "xmm0";
    else return false;
    return !signature.returnBinding.has_value()
        || (signature.returnBinding->kind == ir::IrStorageKind::Register
            && signature.returnBinding->name == expected
            && signature.returnBinding->type == type
            && signature.returnBinding->size
                == (static_cast<std::uint64_t>(type.bits) * type.lanes + 7U) / 8U
            && signature.returnBinding->offset == 0
            && signature.returnBinding->alignment == 4U
            && signature.returnBinding->index == 0U
            && !signature.returnBinding->readonly);
}

auto append_instruction(std::string& assembly, std::size_t& count, std::string line) -> void {
    assembly += std::move(line);
    assembly += '\n';
    ++count;
}

auto valid_source_binding(
    const ir::IrStorageLocation& binding,
    const ir::IrType& type,
    std::uint16_t index,
    std::uint64_t size) -> bool {
    if (binding.type != type || binding.index != index || binding.size != size
        || binding.alignment != 4U || binding.readonly) {
        return false;
    }
    if (binding.kind == ir::IrStorageKind::Register) {
        return size == 4U && binding.offset == 0
            && (binding.name == "eax" || binding.name == "ecx" || binding.name == "edx");
    }
    return binding.kind == ir::IrStorageKind::Stack && binding.name == "esp"
        && binding.offset >= 4 && binding.offset % 4 == 0
        && binding.offset <= std::numeric_limits<std::int64_t>::max()
            - 4 - static_cast<std::int64_t>(size);
}

auto source_operand(
    const ir::IrStorageLocation& source,
    std::optional<std::uint64_t> spillDistance)
    -> std::string {
    if (source.kind == ir::IrStorageKind::Register) {
        return "dword ptr [ebp - " + std::to_string(*spillDistance) + "]";
    }
    return "dword ptr [ebp + " + std::to_string(source.offset + 4) + "]";
}

} // namespace

auto build_x86_abi_adapter(
    const AbiAdapterRequest& request,
    const CodegenProvider& codegen) -> Result<AbiAdapterPlan, Diagnostic> {
    if (request.architecture != Architecture::X86) {
        return failure<AbiAdapterPlan>(
            "architecture.request_mismatch", "x86 ABI adapter request has the wrong architecture");
    }
    if (request.format != BinaryFormat::COFF && request.format != BinaryFormat::ELF) {
        return failure<AbiAdapterPlan>(
            "architecture.unsupported_format", "i386 ABI adapters require COFF or ELF");
    }
    if (!is_i386_abi(request.sourceAbi) || !is_i386_abi(request.destinationAbi)
        || request.symbol.empty() || request.stackAlignment != 16U) {
        return failure<AbiAdapterPlan>(
            "architecture.incompatible_abi", "i386 ABI adapter request is incomplete or incompatible");
    }
    if (request.tailCall) {
        return failure<AbiAdapterPlan>(
            "architecture.incompatible_abi", "bounded i386 ABI adapters do not emit tail calls");
    }
    if (request.signature.variadic && !caller_cleans(request.destinationAbi)) {
        return failure<AbiAdapterPlan>(
            "architecture.unsupported_variadic_abi",
            "variadic i386 destinations must use cdecl or System V cleanup");
    }
    std::vector<std::uint64_t> parameterSizes;
    parameterSizes.reserve(request.signature.parameterTypes.size());
    for (const auto& type : request.signature.parameterTypes) {
        const auto size = slot_size(type);
        if (!size.has_value()) {
            return failure<AbiAdapterPlan>(
                "architecture.incompatible_abi", "parameter layout is not representable by an i386 ABI adapter");
        }
        parameterSizes.push_back(*size);
    }
    if (!validate_return(request.signature)) {
        return failure<AbiAdapterPlan>(
            "architecture.incompatible_abi", "return layout is not representable by the i386 ABI");
    }

    auto sourceBindings = request.signature.parameterBindings.empty()
        ? derive_bindings(request.sourceAbi, request.signature.parameterTypes, parameterSizes)
        : request.signature.parameterBindings;
    if (sourceBindings.size() != request.signature.parameterTypes.size()) {
        return failure<AbiAdapterPlan>(
            "architecture.incompatible_abi", "source parameter binding count does not match the signature");
    }
    const auto destinationBindings = derive_bindings(
        request.destinationAbi, request.signature.parameterTypes, parameterSizes);
    std::vector<AbiArgumentMove> argumentMoves;
    std::vector<std::pair<std::int64_t, std::int64_t>> stackRanges;
    std::vector<std::string> sourceRegisters;
    for (std::size_t index = 0; index < sourceBindings.size(); ++index) {
        const auto size = parameterSizes[index];
        if (!valid_source_binding(
                sourceBindings[index], request.signature.parameterTypes[index],
                static_cast<std::uint16_t>(index), size)) {
            return failure<AbiAdapterPlan>(
                "architecture.incompatible_abi", "source binding is not an i386 register or stack slot");
        }
        if (sourceBindings[index].kind == ir::IrStorageKind::Register) {
            if (std::ranges::find(sourceRegisters, sourceBindings[index].name)
                != sourceRegisters.end()) {
                return failure<AbiAdapterPlan>(
                    "architecture.incompatible_abi", "source register bindings overlap");
            }
            sourceRegisters.push_back(sourceBindings[index].name);
        } else {
            const auto begin = sourceBindings[index].offset;
            const auto end = begin + static_cast<std::int64_t>(size);
            if (std::ranges::any_of(stackRanges, [&](const auto& range) {
                    return begin < range.second && range.first < end;
                })) {
                return failure<AbiAdapterPlan>(
                    "architecture.incompatible_abi", "source stack bindings overlap");
            }
            stackRanges.emplace_back(begin, end);
        }
        if (sourceBindings[index] != destinationBindings[index]) {
            argumentMoves.push_back(AbiArgumentMove{sourceBindings[index], destinationBindings[index]});
        }
    }
    std::ranges::sort(stackRanges);
    std::int64_t expectedStackOffset = 4;
    for (const auto& range : stackRanges) {
        if (range.first != expectedStackOffset) {
            return failure<AbiAdapterPlan>(
                "architecture.incompatible_abi", "source stack bindings are not contiguous");
        }
        expectedStackOffset = range.second;
    }

    std::string assembly;
    std::size_t instructionCount = 0;
    append_instruction(assembly, instructionCount, "push ebp");
    append_instruction(assembly, instructionCount, "mov ebp, esp");
    std::vector<std::optional<std::uint64_t>> spillDistances(sourceBindings.size());
    std::uint64_t spillBytes = 0;
    for (std::size_t index = 0; index < sourceBindings.size(); ++index) {
        if (sourceBindings[index].kind == ir::IrStorageKind::Register) {
            spillBytes += 4U;
            spillDistances[index] = spillBytes;
            append_instruction(
                assembly, instructionCount, "push " + sourceBindings[index].name);
        }
    }
    append_instruction(assembly, instructionCount, "and esp, -16");

    const auto destinationStackBytes = stack_bytes(destinationBindings);
    const auto padding = (16U - destinationStackBytes % 16U) % 16U;
    if (padding != 0U) {
        append_instruction(assembly, instructionCount, "sub esp, " + std::to_string(padding));
    }
    for (std::size_t reverse = destinationBindings.size(); reverse != 0U; --reverse) {
        const auto index = reverse - 1U;
        if (destinationBindings[index].kind != ir::IrStorageKind::Stack) continue;
        const auto& source = sourceBindings[index];
        const auto words = destinationBindings[index].size / 4U;
        if (source.kind == ir::IrStorageKind::Register && words != 1U) {
            return failure<AbiAdapterPlan>(
                "architecture.incompatible_abi", "multiword source values require stack storage");
        }
        for (std::uint64_t word = words; word != 0U; --word) {
            if (source.kind == ir::IrStorageKind::Register) {
                append_instruction(
                    assembly, instructionCount,
                    "push " + source_operand(source, spillDistances[index]));
            } else {
                auto wordSource = source;
                wordSource.offset += static_cast<std::int64_t>((word - 1U) * 4U);
                append_instruction(
                    assembly, instructionCount,
                    "push " + source_operand(wordSource, std::nullopt));
            }
        }
    }
    for (std::size_t index = 0; index < sourceBindings.size(); ++index) {
        const auto& destination = destinationBindings[index];
        if (destination.kind != ir::IrStorageKind::Register) continue;
        append_instruction(
            assembly, instructionCount,
            "mov " + destination.name + ", " + source_operand(
                sourceBindings[index], spillDistances[index]));
    }
    append_instruction(assembly, instructionCount, "call " + request.symbol);
    append_instruction(assembly, instructionCount, "mov esp, ebp");
    append_instruction(assembly, instructionCount, "pop ebp");
    const auto sourceStackBytes = stack_bytes(sourceBindings);
    if (caller_cleans(request.sourceAbi) || sourceStackBytes == 0U) {
        append_instruction(assembly, instructionCount, "ret");
    } else {
        if (sourceStackBytes > std::numeric_limits<std::uint16_t>::max()) {
            return failure<AbiAdapterPlan>(
                "architecture.incompatible_abi", "callee cleanup exceeds the i386 ret immediate");
        }
        append_instruction(
            assembly, instructionCount, "ret " + std::to_string(sourceStackBytes));
    }

    MachineAssemblyRequest assemblyRequest{};
    assemblyRequest.architecture = Architecture::X86;
    assemblyRequest.format = request.format;
    assemblyRequest.triple = request.format == BinaryFormat::COFF
        ? "i686-pc-windows-msvc" : "i386-unknown-linux-gnu";
    assemblyRequest.syntax = MachineSyntax::Intel;
    assemblyRequest.assembly = std::move(assembly);
    assemblyRequest.limits = request.limits;
    assemblyRequest.expectedInstructionCount = instructionCount;
    auto emission = codegen.emit(assemblyRequest);
    if (!emission.has_value()) {
        return failure<AbiAdapterPlan>(emission.error().code, emission.error().message);
    }
    if (emission.value().fixups.size() != 1U
        || emission.value().fixups.front().kind != MachineFixupKind::PcRelative32
        || emission.value().fixups.front().symbol != request.symbol) {
        return failure<AbiAdapterPlan>(
            "architecture.invalid_fixup", "i386 ABI adapter must contain one external call fixup");
    }
    const auto& emittedBytes = emission.value().bytes;
    if (emittedBytes.size() < 6U || emittedBytes[0] != std::byte{0x55}
        || emittedBytes[1] != std::byte{0x89} || emittedBytes[2] != std::byte{0xe5}) {
        return failure<AbiAdapterPlan>(
            "architecture.invalid_emission", "i386 ABI adapter prologue is not canonical");
    }
    std::optional<std::size_t> epilogueOffset;
    for (std::size_t index = 3; index + 2U < emittedBytes.size(); ++index) {
        if (emittedBytes[index] == std::byte{0x89}
            && emittedBytes[index + 1U] == std::byte{0xec}
            && emittedBytes[index + 2U] == std::byte{0x5d}) {
            epilogueOffset = index;
        }
    }
    if (!epilogueOffset.has_value()) {
        return failure<AbiAdapterPlan>(
            "architecture.invalid_emission", "i386 ABI adapter epilogue is not canonical");
    }
    const auto epilogueStackRestored = static_cast<std::uint64_t>(*epilogueOffset + 2U);
    const auto epilogueFrameRestored = static_cast<std::uint64_t>(*epilogueOffset + 3U);
    std::vector<UnwindAction> unwindActions{
        {UnwindActionKind::DefineCanonicalFrameAddress, "esp", 4, 0},
        {UnwindActionKind::SaveRegister, "eip", -4, 0},
        {UnwindActionKind::SaveRegister, "ebp", -8, 1},
        {UnwindActionKind::DefineCanonicalFrameAddress, "esp", 8, 1},
        {UnwindActionKind::DefineCanonicalFrameAddress, "ebp", 8, 3},
        {UnwindActionKind::DefineCanonicalFrameAddress, "esp", 8, epilogueStackRestored},
        {UnwindActionKind::RestoreRegister, "ebp", 0, epilogueFrameRestored},
        {UnwindActionKind::DefineCanonicalFrameAddress, "esp", 4, epilogueFrameRestored},
    };
    const std::vector<std::string> clobbered{"eax", "ecx", "edx"};
    emission.value().clobberedRegisters = clobbered;
    const auto emittedSize = emission.value().bytes.size();
    return Result<AbiAdapterPlan, Diagnostic>::success(AbiAdapterPlan{
        .emission = std::move(emission).value(),
        .argumentMoves = std::move(argumentMoves),
        .stackArgumentBytes = destinationStackBytes,
        .stackDelta = 0,
        .callerCleansStack = caller_cleans(request.destinationAbi),
        .clobbers = ir::IrCallClobbers{clobbered, true, true},
        .unwind = UnwindRequest{
            .architecture = Architecture::X86,
            .format = request.format,
            .codeStart = BinaryAddress{0U, AddressKind::Virtual},
            .codeSize = emittedSize,
            .actions = std::move(unwindActions),
            .codeSymbol = std::nullopt,
            .handlerSymbol = std::nullopt,
            .limits = request.limits,
            .handlerOwned = false,
        },
    });
}

} // namespace binobf::detail

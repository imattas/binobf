#include "x86_64_abi.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace binobf::detail {
namespace {

template <typename T>
auto failure(std::string code, std::string message) -> Result<T, Diagnostic> {
    return Result<T, Diagnostic>::failure(
        Diagnostic{DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

auto append(std::string& assembly, std::size_t& count, std::string line) -> void {
    assembly += line;
    assembly.push_back('\n');
    ++count;
}

auto type_bytes(const ir::IrType& type) -> std::uint64_t {
    if (type.kind == ir::IrTypeKind::Vector) {
        return static_cast<std::uint64_t>(type.bits / 8U) * type.lanes;
    }
    return type.bits / 8U;
}

auto source_registers(ir::NativeAbi abi) -> std::array<std::string_view, 4> {
    return abi == ir::NativeAbi::WindowsX64
        ? std::array<std::string_view, 4>{"ecx", "edx", "r8d", "r9d"}
        : std::array<std::string_view, 4>{"edi", "esi", "edx", "ecx"};
}

auto destination_registers(ir::NativeAbi abi) -> std::array<std::string_view, 4> {
    return source_registers(abi);
}

} // namespace

auto build_x86_64_abi_adapter(const AbiAdapterRequest& request,
                              const CodegenProvider& codegen)
    -> Result<AbiAdapterPlan, Diagnostic> {
    if (request.architecture != Architecture::X86_64) {
        return failure<AbiAdapterPlan>(
            "architecture.request_mismatch", "x86-64 ABI request has the wrong architecture");
    }
    if (request.format != BinaryFormat::COFF && request.format != BinaryFormat::ELF &&
        request.format != BinaryFormat::MachO) {
        return failure<AbiAdapterPlan>(
            "architecture.unsupported_format", "x86-64 ABI adapters require COFF, ELF, or Mach-O");
    }
    if ((request.sourceAbi != ir::NativeAbi::WindowsX64 &&
         request.sourceAbi != ir::NativeAbi::SystemVAMD64) ||
        (request.destinationAbi != ir::NativeAbi::WindowsX64 &&
         request.destinationAbi != ir::NativeAbi::SystemVAMD64)) {
        return failure<AbiAdapterPlan>(
            "architecture.unsupported_abi", "x86-64 adapters support Windows x64 and System V AMD64");
    }
    if (request.signature.variadic || request.signature.parameterTypes.size() > 4U ||
        request.signature.returnType.kind != ir::IrTypeKind::Integer ||
        type_bytes(request.signature.returnType) > 8U) {
        return failure<AbiAdapterPlan>(
            "architecture.incompatible_abi", "x86-64 adapter supports at most four integer arguments");
    }
    for (const auto& type : request.signature.parameterTypes) {
        if (type.kind != ir::IrTypeKind::Integer || type_bytes(type) > 8U) {
            return failure<AbiAdapterPlan>(
                "architecture.incompatible_abi", "x86-64 adapter arguments must be integer values");
        }
    }
    if (request.symbol.empty() || request.limits.maxInstructions < 4U) {
        return failure<AbiAdapterPlan>(
            "architecture.invalid_request", "x86-64 adapter request is incomplete");
    }

    const auto source = source_registers(request.sourceAbi);
    const auto destination = destination_registers(request.destinationAbi);
    std::string assembly;
    std::size_t instructionCount = 0;
    // Reserve Windows shadow space plus aligned spill slots for all arguments.
    append(assembly, instructionCount, "sub rsp, 96");
    for (std::size_t index = 0; index < request.signature.parameterTypes.size(); ++index) {
        append(assembly, instructionCount,
               "mov dword ptr [rsp + " + std::to_string(64U + index * 8U) + "], " +
                   std::string{source[index]});
    }
    for (std::size_t index = 0; index < request.signature.parameterTypes.size(); ++index) {
        append(assembly, instructionCount,
               "mov " + std::string{destination[index]} + ", dword ptr [rsp + " +
                   std::to_string(64U + index * 8U) + "]");
    }
    append(assembly, instructionCount, "call " + request.symbol);
    append(assembly, instructionCount, "add rsp, 96");
    append(assembly, instructionCount, "ret");

    MachineAssemblyRequest assemblyRequest{};
    assemblyRequest.architecture = Architecture::X86_64;
    assemblyRequest.format = request.format;
    assemblyRequest.triple = request.format == BinaryFormat::COFF
        ? "x86_64-pc-windows-msvc"
        : request.format == BinaryFormat::MachO ? "x86_64-apple-darwin"
                                                 : "x86_64-unknown-linux-gnu";
    assemblyRequest.syntax = MachineSyntax::Intel;
    assemblyRequest.assembly = std::move(assembly);
    assemblyRequest.limits = request.limits;
    assemblyRequest.expectedInstructionCount = instructionCount;
    const auto emitted = codegen.emit(assemblyRequest);
    if (!emitted.has_value()) {
        return failure<AbiAdapterPlan>(emitted.error().code, emitted.error().message);
    }
    if (emitted.value().fixups.size() != 1U ||
        emitted.value().fixups.front().kind != MachineFixupKind::PcRelative32 ||
        emitted.value().fixups.front().symbol != request.symbol) {
        return failure<AbiAdapterPlan>(
            "architecture.invalid_fixup", "x86-64 adapter must contain one external call fixup");
    }
    auto emission = std::move(emitted).value();
    const auto emissionSize = emission.bytes.size();
    ir::IrCallClobbers clobbers;
    clobbers.flags = true;
    clobbers.memory = true;
    clobbers.registers = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"};
    return Result<AbiAdapterPlan, Diagnostic>::success(AbiAdapterPlan{
        .emission = std::move(emission),
        .argumentMoves = {},
        .stackArgumentBytes = 0,
        .stackDelta = 0,
        .callerCleansStack = true,
        .clobbers = std::move(clobbers),
        .unwind = UnwindRequest{.architecture = Architecture::X86_64,
                                .format = request.format,
                                .codeStart = {},
                                .codeSize = emissionSize,
                                .actions = {},
                                .codeSymbol = std::nullopt,
                                .handlerSymbol = std::nullopt,
                                .limits = request.limits,
                                .handlerOwned = false},
    });
}

} // namespace binobf::detail

#include "x86_templates.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
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

auto nops(std::size_t size, bool singleByteOnly) -> std::vector<std::byte> {
    std::vector<std::byte> bytes;
    bytes.reserve(size);
    if (singleByteOnly) {
        bytes.assign(size, std::byte{0x90});
        return bytes;
    }
    bytes.assign(size - 1U, std::byte{0x66});
    bytes.push_back(std::byte{0x90});
    return bytes;
}

auto append_u32(std::vector<std::byte>& bytes, std::uint32_t value) -> void {
    for (unsigned shift = 0; shift < 32U; shift += 8U) {
        bytes.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
    }
}

auto byte_assembly(std::span<const std::byte> bytes) -> std::string {
    constexpr char digits[] = "0123456789abcdef";
    std::string result{".byte "};
    result.reserve(6U + bytes.size() * 6U);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index != 0U) result += ", ";
        const auto value = std::to_integer<unsigned>(bytes[index]);
        result += "0x";
        result += digits[(value >> 4U) & 0xfU];
        result += digits[value & 0xfU];
    }
    result += '\n';
    return result;
}

auto checked_displacement(
    const MachineTransformRequest& request,
    std::size_t size,
    std::int64_t minimum,
    std::int64_t maximum) -> Result<std::int64_t, Diagnostic> {
    if (!request.source.has_value() || !request.targetAddress.has_value()) {
        return failure<std::int64_t>(
            "architecture.invalid_template", "direct control flow requires source and target");
    }
    const auto source = request.source->address.value;
    const auto target = *request.targetAddress;
    if (source > std::numeric_limits<std::uint32_t>::max()
        || target > std::numeric_limits<std::uint32_t>::max()
        || source > std::numeric_limits<std::uint32_t>::max() - size) {
        return failure<std::int64_t>(
            "architecture.target_out_of_range", "i386 branch target is outside 32-bit range");
    }
    const auto displacement = static_cast<std::int64_t>(target)
        - static_cast<std::int64_t>(source + size);
    if (displacement < minimum || displacement > maximum) {
        return failure<std::int64_t>(
            "architecture.target_out_of_range", "i386 branch displacement is out of range");
    }
    return Result<std::int64_t, Diagnostic>::success(displacement);
}

auto condition_opcode(std::string_view condition, bool near) -> std::optional<std::uint8_t> {
    if (condition == "equal" || condition == "zero") return near ? 0x85U : 0x75U;
    if (condition == "not-equal" || condition == "nonzero") return near ? 0x84U : 0x74U;
    if (condition == "unsigned-below") return near ? 0x83U : 0x73U;
    if (condition == "unsigned-above-or-equal") return near ? 0x82U : 0x72U;
    if (condition == "signed-less") return near ? 0x8dU : 0x7dU;
    if (condition == "signed-greater-or-equal") return near ? 0x8cU : 0x7cU;
    return std::nullopt;
}

auto emit_bytes(
    const MachineTransformRequest& request,
    const CodegenProvider& codegen,
    std::vector<std::byte> bytes,
    std::size_t instructionCount,
    MachineControlFlow controlFlow,
    bool readsFlags,
    std::vector<std::string> clobbers = {}) -> Result<MachineTransformEmission, Diagnostic> {
    const auto assembly = byte_assembly(bytes);
    if (bytes.size() > request.limits.maxEmittedBytes
        || instructionCount > request.limits.maxInstructions
        || request.limits.maxLines == 0U
        || assembly.size() > request.limits.maxAssemblyBytes) {
        return failure<MachineTransformEmission>(
            "architecture.resource_limit", "x86 template exceeds the request limits");
    }
    MachineAssemblyRequest assemblyRequest{};
    assemblyRequest.architecture = Architecture::X86;
    assemblyRequest.format = request.format;
    assemblyRequest.triple = request.format == BinaryFormat::COFF
        ? "i686-pc-windows-msvc" : "i386-unknown-linux-gnu";
    assemblyRequest.syntax = MachineSyntax::Intel;
    assemblyRequest.baseAddress = request.source.has_value()
        ? request.source->address : BinaryAddress{};
    assemblyRequest.limits = request.limits;
    assemblyRequest.expectedInstructionCount = instructionCount;
    assemblyRequest.assembly = assembly;
    auto emission = codegen.emit(assemblyRequest);
    if (!emission.has_value()) {
        return failure<MachineTransformEmission>(
            emission.error().code, emission.error().message);
    }
    if (emission.value().bytes != bytes) {
        return failure<MachineTransformEmission>(
            "architecture.exact_size_unavailable", "assembler changed the exact x86 template");
    }
    emission.value().clobberedRegisters = std::move(clobbers);
    return Result<MachineTransformEmission, Diagnostic>::success(MachineTransformEmission{
        .emission = std::move(emission).value(),
        .instructionCount = instructionCount,
        .controlFlow = controlFlow,
        .stackDelta = 0,
        .readsFlags = readsFlags,
        .writesFlags = false,
    });
}

} // namespace

auto emit_x86_transform(
    const MachineTransformRequest& request,
    const CodegenProvider& codegen) -> Result<MachineTransformEmission, Diagnostic> {
    if (request.architecture != Architecture::X86) {
        return failure<MachineTransformEmission>(
            "architecture.request_mismatch", "x86 template request has the wrong architecture");
    }
    if (request.format != BinaryFormat::COFF && request.format != BinaryFormat::ELF) {
        return failure<MachineTransformEmission>(
            "architecture.unsupported_format", "x86 templates require COFF or ELF");
    }
    if (request.kind == MachineTransformKind::DeadCodeFill) {
        if (request.exactSize == 0U || request.exactSize > 15U) {
            return failure<MachineTransformEmission>(
                "architecture.exact_size_unavailable", "x86 dead-code fill supports 1 to 15 bytes");
        }
        return emit_bytes(
            request, codegen, nops(request.exactSize, true), request.exactSize,
            MachineControlFlow::Fallthrough, false);
    }
    if (request.kind == MachineTransformKind::InstructionEquivalent) {
        if (!request.source.has_value() || request.source->mnemonic != "nop") {
            return failure<MachineTransformEmission>(
                "architecture.invalid_template", "only effectless x86 NOP substitution is supported");
        }
        if (request.exactSize == 0U || request.exactSize > 15U) {
            return failure<MachineTransformEmission>(
                "architecture.exact_size_unavailable", "x86 NOP substitution supports 1 to 15 bytes");
        }
        return emit_bytes(
            request, codegen, nops(request.exactSize, false), 1U,
            MachineControlFlow::Fallthrough, false);
    }
    if (request.kind == MachineTransformKind::ConstantMaterialization) {
        if (request.exactSize != 5U) {
            return failure<MachineTransformEmission>(
                "architecture.exact_size_unavailable", "i386 immediate materialization is exactly 5 bytes");
        }
        if (!request.constantBits.has_value()
            || *request.constantBits > std::numeric_limits<std::uint32_t>::max()
            || (request.condition != "eax" && request.condition != "ecx")) {
            return failure<MachineTransformEmission>(
                "architecture.invalid_template", "i386 constant template requires eax or ecx and a 32-bit value");
        }
        std::vector<std::byte> bytes{
            request.condition == "eax" ? std::byte{0xb8} : std::byte{0xb9}};
        append_u32(bytes, static_cast<std::uint32_t>(*request.constantBits));
        return emit_bytes(
            request, codegen, std::move(bytes), 1U,
            MachineControlFlow::Fallthrough, false, {request.condition});
    }
    if (request.kind == MachineTransformKind::ConditionalInversion) {
        if (request.exactSize != 2U && request.exactSize != 6U) {
            return failure<MachineTransformEmission>(
                "architecture.exact_size_unavailable", "i386 conditional branch is exactly 2 or 6 bytes");
        }
        const bool near = request.exactSize == 6U;
        const auto opcode = condition_opcode(request.condition, near);
        if (!opcode.has_value()) {
            return failure<MachineTransformEmission>(
                "architecture.invalid_condition", "condition is not a normalized invertible i386 condition");
        }
        const auto displacement = checked_displacement(
            request, request.exactSize,
            near ? std::numeric_limits<std::int32_t>::min() : std::numeric_limits<std::int8_t>::min(),
            near ? std::numeric_limits<std::int32_t>::max() : std::numeric_limits<std::int8_t>::max());
        if (!displacement.has_value()) return failure<MachineTransformEmission>(
            displacement.error().code, displacement.error().message);
        std::vector<std::byte> bytes;
        if (near) {
            bytes = {std::byte{0x0f}, static_cast<std::byte>(*opcode)};
            append_u32(bytes, static_cast<std::uint32_t>(displacement.value()));
        } else {
            bytes = {static_cast<std::byte>(*opcode),
                     static_cast<std::byte>(static_cast<std::uint8_t>(displacement.value()))};
        }
        return emit_bytes(
            request, codegen, std::move(bytes), 1U,
            MachineControlFlow::Conditional, true);
    }
    if (request.kind == MachineTransformKind::DirectJump) {
        std::size_t size = request.exactSize;
        if (size == 0U) {
            const auto shortDisplacement = checked_displacement(
                request, 2U, std::numeric_limits<std::int8_t>::min(),
                std::numeric_limits<std::int8_t>::max());
            size = shortDisplacement.has_value() ? 2U : 5U;
        }
        if (size != 2U && size != 5U) {
            return failure<MachineTransformEmission>(
                "architecture.exact_size_unavailable", "i386 direct jump is exactly 2 or 5 bytes");
        }
        const auto displacement = checked_displacement(
            request, size,
            size == 2U ? std::numeric_limits<std::int8_t>::min()
                       : std::numeric_limits<std::int32_t>::min(),
            size == 2U ? std::numeric_limits<std::int8_t>::max()
                       : std::numeric_limits<std::int32_t>::max());
        if (!displacement.has_value()) return failure<MachineTransformEmission>(
            displacement.error().code, displacement.error().message);
        std::vector<std::byte> bytes{size == 2U ? std::byte{0xeb} : std::byte{0xe9}};
        if (size == 2U) {
            bytes.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(displacement.value())));
        } else {
            append_u32(bytes, static_cast<std::uint32_t>(displacement.value()));
        }
        return emit_bytes(
            request, codegen, std::move(bytes), 1U,
            MachineControlFlow::Direct, false);
    }
    return failure<MachineTransformEmission>(
        "architecture.service_unsupported", "x86 template kind is not implemented");
}

} // namespace binobf::detail

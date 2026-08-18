#include "x86_unwind.hpp"

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

auto append_u32(std::vector<std::byte>& output, std::uint32_t value) -> void {
    for (unsigned shift = 0; shift < 32U; shift += 8U) {
        output.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
    }
}

auto patch_u32(std::vector<std::byte>& output, std::size_t offset, std::uint32_t value) -> void {
    for (unsigned shift = 0; shift < 32U; shift += 8U) {
        output[offset + shift / 8U] = static_cast<std::byte>((value >> shift) & 0xffU);
    }
}

auto append_uleb(std::vector<std::byte>& output, std::uint64_t value) -> void {
    do {
        auto byte = static_cast<std::uint8_t>(value & 0x7fU);
        value >>= 7U;
        if (value != 0U) byte |= 0x80U;
        output.push_back(static_cast<std::byte>(byte));
    } while (value != 0U);
}

auto append_sleb(std::vector<std::byte>& output, std::int64_t value) -> void {
    bool more = true;
    while (more) {
        auto byte = static_cast<std::uint8_t>(value & 0x7f);
        const bool sign = (byte & 0x40U) != 0U;
        value >>= 7;
        more = !((value == 0 && !sign) || (value == -1 && sign));
        if (more) byte |= 0x80U;
        output.push_back(static_cast<std::byte>(byte));
    }
}

auto dwarf_register(std::string_view name) -> std::optional<std::uint8_t> {
    if (name == "eax") return 0U;
    if (name == "ecx") return 1U;
    if (name == "edx") return 2U;
    if (name == "ebx") return 3U;
    if (name == "esp") return 4U;
    if (name == "ebp") return 5U;
    if (name == "esi") return 6U;
    if (name == "edi") return 7U;
    if (name == "eip") return 8U;
    return std::nullopt;
}

auto append_action(std::vector<std::byte>& output, const UnwindAction& action)
    -> Result<bool, Diagnostic> {
    const auto registerNumber = dwarf_register(action.registerName);
    if (!registerNumber.has_value()) {
        return failure<bool>(
            "architecture.unwind_action", "DWARF CFI action names an unknown i386 register");
    }
    switch (action.kind) {
    case UnwindActionKind::DefineCanonicalFrameAddress:
        if (action.offset < 0) {
            return failure<bool>(
                "architecture.unwind_action", "canonical frame offset must be nonnegative");
        }
        output.push_back(std::byte{0x0c});
        append_uleb(output, *registerNumber);
        append_uleb(output, static_cast<std::uint64_t>(action.offset));
        break;
    case UnwindActionKind::SaveRegister:
        if (action.offset >= 0 || action.offset % 4 != 0 || *registerNumber > 0x3fU) {
            return failure<bool>(
                "architecture.unwind_action", "saved i386 registers require a negative 4-byte offset");
        }
        output.push_back(static_cast<std::byte>(0x80U | *registerNumber));
        append_uleb(output, static_cast<std::uint64_t>(-action.offset / 4));
        break;
    case UnwindActionKind::RestoreRegister:
        if (*registerNumber > 0x3fU) {
            return failure<bool>(
                "architecture.unwind_action", "restored i386 register is not encodable");
        }
        output.push_back(static_cast<std::byte>(0xc0U | *registerNumber));
        break;
    }
    return Result<bool, Diagnostic>::success(true);
}

} // namespace

auto build_x86_unwind_plan(const UnwindRequest& request)
    -> Result<UnwindPlan, Diagnostic> {
    if (request.architecture != Architecture::X86) {
        return failure<UnwindPlan>(
            "architecture.request_mismatch", "x86 unwind request has the wrong architecture");
    }
    if (request.codeSize == 0U
        || request.codeStart.value > std::numeric_limits<std::uint32_t>::max()
        || request.codeSize > std::numeric_limits<std::uint32_t>::max()
        || request.codeStart.value
            > std::numeric_limits<std::uint32_t>::max() - request.codeSize) {
        return failure<UnwindPlan>(
            "architecture.unwind_range", "i386 unwind code range must fit in 32 bits");
    }
    if (request.actions.size() > request.limits.maxInstructions) {
        return failure<UnwindPlan>(
            "architecture.resource_limit", "unwind action count exceeds the request limit");
    }
    if (request.format == BinaryFormat::COFF) {
        if (request.handlerSymbol.has_value() && !request.handlerOwned) {
            return failure<UnwindPlan>(
                "architecture.unwind_unowned",
                "i386 SafeSEH handler metadata may only be preserved for owned handlers");
        }
        return Result<UnwindPlan, Diagnostic>::success(UnwindPlan{
            .disposition = request.handlerSymbol.has_value()
                ? UnwindDisposition::Preserve : UnwindDisposition::NotRequired,
            .encoding = UnwindEncoding::WindowsI386,
            .codeStart = request.codeStart,
            .codeSize = request.codeSize,
            .actions = request.actions,
            .encoded = {},
            .fixups = {},
        });
    }
    if (request.format != BinaryFormat::ELF) {
        return failure<UnwindPlan>(
            "architecture.unsupported_format", "i386 unwind generation requires COFF or ELF");
    }
    if (request.handlerSymbol.has_value()) {
        return failure<UnwindPlan>(
            "architecture.unwind_unowned", "ELF personality handlers are not owned by this request");
    }

    std::vector<std::byte> encoded;
    encoded.reserve(64U + request.actions.size() * 3U);
    const auto cieLengthOffset = encoded.size();
    append_u32(encoded, 0U);
    const auto cieStart = encoded.size();
    append_u32(encoded, 0U);
    encoded.push_back(std::byte{1});
    encoded.push_back(std::byte{0});
    append_uleb(encoded, 1U);
    append_sleb(encoded, -4);
    append_uleb(encoded, 8U);
    encoded.push_back(std::byte{0x0c});
    append_uleb(encoded, 4U);
    append_uleb(encoded, 4U);
    patch_u32(encoded, cieLengthOffset, static_cast<std::uint32_t>(encoded.size() - cieStart));

    const auto fdeLengthOffset = encoded.size();
    append_u32(encoded, 0U);
    const auto fdeStart = encoded.size();
    append_u32(encoded, 0U);
    append_u32(encoded, static_cast<std::uint32_t>(request.codeStart.value));
    append_u32(encoded, static_cast<std::uint32_t>(request.codeSize));
    for (const auto& action : request.actions) {
        const auto appended = append_action(encoded, action);
        if (!appended.has_value()) {
            return failure<UnwindPlan>(appended.error().code, appended.error().message);
        }
    }
    patch_u32(encoded, fdeLengthOffset, static_cast<std::uint32_t>(encoded.size() - fdeStart));
    if (encoded.size() > request.limits.maxEmittedBytes) {
        return failure<UnwindPlan>(
            "architecture.resource_limit", "DWARF CFI exceeds the emitted-byte limit");
    }
    return Result<UnwindPlan, Diagnostic>::success(UnwindPlan{
        .disposition = UnwindDisposition::Emit,
        .encoding = UnwindEncoding::DwarfCfi32,
        .codeStart = request.codeStart,
        .codeSize = request.codeSize,
        .actions = request.actions,
        .encoded = std::move(encoded),
        .fixups = {},
    });
}

} // namespace binobf::detail

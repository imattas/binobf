#include "x86_64_unwind.hpp"

#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <array>
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
    return Result<T, Diagnostic>::failure(
        Diagnostic{DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

void append_u32(std::vector<std::byte>& output, std::uint32_t value) {
    for (unsigned shift = 0; shift < 32U; shift += 8U) {
        output.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
    }
}

void patch_u32(std::vector<std::byte>& output, std::size_t offset, std::uint32_t value) {
    for (unsigned shift = 0; shift < 32U; shift += 8U) {
        output[offset + shift / 8U] = static_cast<std::byte>((value >> shift) & 0xffU);
    }
}

void append_uleb(std::vector<std::byte>& output, std::uint64_t value) {
    do {
        auto byte = static_cast<std::uint8_t>(value & 0x7fU);
        value >>= 7U;
        if (value != 0U) byte |= 0x80U;
        output.push_back(static_cast<std::byte>(byte));
    } while (value != 0U);
}

void append_sleb(std::vector<std::byte>& output, std::int64_t value) {
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

auto register_number(std::string_view name) -> std::optional<std::uint8_t> {
    constexpr std::array<std::string_view, 17> names{
        "rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"};
    for (std::uint8_t index = 0; index < names.size(); ++index) {
        if (names[index] == name) return index;
    }
    return std::nullopt;
}

void append_advance(std::vector<std::byte>& output, std::uint64_t delta) {
    while (delta != 0U) {
        const auto step = std::min<std::uint64_t>(delta, 0x3fU);
        output.push_back(static_cast<std::byte>(0x40U | step));
        delta -= step;
    }
}

void pad_to_four(std::vector<std::byte>& output) {
    while (output.size() % 4U != 0U) output.push_back(std::byte{0});
}

auto append_action(std::vector<std::byte>& output, const UnwindAction& action)
    -> Result<bool, Diagnostic> {
    if (action.kind == UnwindActionKind::DefineCanonicalFrameAddress) {
        const auto reg = register_number(action.registerName);
        if (!reg.has_value() || action.offset < 0 || action.offset % 8 != 0) {
            return failure<bool>("architecture.unwind_action", "invalid x86-64 CFA action");
        }
        output.push_back(std::byte{0x0c});
        append_uleb(output, *reg);
        append_uleb(output, static_cast<std::uint64_t>(action.offset / 8));
    } else {
        const auto reg = register_number(action.registerName);
        if (!reg.has_value() || *reg > 63U) {
            return failure<bool>("architecture.unwind_action", "invalid x86-64 unwind register");
        }
        if (action.kind == UnwindActionKind::SaveRegister) {
            if (action.offset >= 0 || action.offset == std::numeric_limits<std::int64_t>::min() ||
                action.offset % 8 != 0) {
                return failure<bool>("architecture.unwind_action",
                                     "saved x86-64 registers require a negative 8-byte offset");
            }
            output.push_back(static_cast<std::byte>(0x80U | *reg));
            append_uleb(output, static_cast<std::uint64_t>(-action.offset / 8));
        } else {
            output.push_back(static_cast<std::byte>(0xc0U | *reg));
        }
    }
    return Result<bool, Diagnostic>::success(true);
}

} // namespace

auto build_x86_64_unwind_plan(const UnwindRequest& request)
    -> Result<UnwindPlan, Diagnostic> {
    if (request.architecture != Architecture::X86_64 || request.codeSize == 0U ||
        request.codeSize > std::numeric_limits<std::uint32_t>::max()) {
        return failure<UnwindPlan>("architecture.unwind_range",
                                   "x86-64 unwind code range is invalid");
    }
    if (request.actions.size() > request.limits.maxInstructions) {
        return failure<UnwindPlan>("architecture.resource_limit",
                                   "unwind action count exceeds the request limit");
    }
    if (request.format == BinaryFormat::COFF) {
        if (request.handlerSymbol.has_value() && !request.handlerOwned) {
            return failure<UnwindPlan>("architecture.unwind_unowned",
                                       "Windows x64 handlers may only be preserved when owned");
        }
        return Result<UnwindPlan, Diagnostic>::success(UnwindPlan{
            .disposition = request.handlerSymbol.has_value()
                ? UnwindDisposition::Preserve : UnwindDisposition::NotRequired,
            .encoding = UnwindEncoding::WindowsX64,
            .codeStart = request.codeStart,
            .codeSize = request.codeSize,
            .actions = request.actions,
            .encoded = {},
            .fixups = {},
        });
    }
    if (request.format != BinaryFormat::ELF && request.format != BinaryFormat::MachO) {
        return failure<UnwindPlan>("architecture.unsupported_format",
                                   "x86-64 unwind generation requires COFF, ELF, or Mach-O");
    }
    if (request.handlerSymbol.has_value() || !request.codeSymbol.has_value() ||
        request.codeSymbol->empty()) {
        return failure<UnwindPlan>("architecture.unwind_unowned",
                                   "x86-64 DWARF CFI requires an owned code symbol");
    }
    std::vector<std::byte> encoded;
    append_u32(encoded, 0U);
    const auto cieStart = encoded.size();
    append_u32(encoded, 0U);
    encoded.push_back(std::byte{1});
    encoded.push_back(std::byte{'z'});
    encoded.push_back(std::byte{'R'});
    encoded.push_back(std::byte{0});
    append_uleb(encoded, 1U);
    append_sleb(encoded, -8);
    append_uleb(encoded, 16U);
    append_uleb(encoded, 1U);
    encoded.push_back(std::byte{0x1b});
    encoded.push_back(std::byte{0x0c});
    append_uleb(encoded, 7U);
    append_uleb(encoded, 8U);
    pad_to_four(encoded);
    patch_u32(encoded, 0, static_cast<std::uint32_t>(encoded.size() - cieStart));

    const auto fdeLengthOffset = encoded.size();
    append_u32(encoded, 0U);
    const auto fdeStart = encoded.size();
    append_u32(encoded, static_cast<std::uint32_t>(fdeStart - 4U));
    const auto initialLocationOffset = encoded.size();
    append_u32(encoded, 0U);
    append_u32(encoded, static_cast<std::uint32_t>(request.codeSize));
    append_uleb(encoded, 0U);
    std::uint64_t currentOffset = 0;
    for (const auto& action : request.actions) {
        if (action.codeOffset < currentOffset || action.codeOffset > request.codeSize) {
            return failure<UnwindPlan>("architecture.unwind_action",
                                       "x86-64 CFI action offset is outside the code range");
        }
        append_advance(encoded, action.codeOffset - currentOffset);
        currentOffset = action.codeOffset;
        const auto result = append_action(encoded, action);
        if (!result.has_value()) return failure<UnwindPlan>(result.error().code, result.error().message);
    }
    pad_to_four(encoded);
    patch_u32(encoded, fdeLengthOffset,
              static_cast<std::uint32_t>(encoded.size() - fdeStart));
    if (encoded.size() > request.limits.maxEmittedBytes || request.limits.maxFixups == 0U) {
        return failure<UnwindPlan>("architecture.resource_limit", "x86-64 CFI exceeds limits");
    }
    return Result<UnwindPlan, Diagnostic>::success(UnwindPlan{
        .disposition = UnwindDisposition::Emit,
        .encoding = UnwindEncoding::DwarfCfi64,
        .codeStart = request.codeStart,
        .codeSize = request.codeSize,
        .actions = request.actions,
        .encoded = std::move(encoded),
        .fixups = {MachineFixup{.offset = initialLocationOffset,
                                .bitWidth = 32,
                                .isSigned = true,
                                .pcRelative = true,
                                .addend = 0,
                                .symbol = *request.codeSymbol,
                                .kind = MachineFixupKind::PcRelative32}},
    });
}

} // namespace binobf::detail

#include "arm64_unwind.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <set>
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

auto parse_numbered_register(std::string_view name, char prefix,
                             unsigned maximum) -> std::optional<unsigned> {
  if (name.size() < 2U || name.front() != prefix)
    return std::nullopt;
  unsigned value = 0;
  for (const char character : name.substr(1U)) {
    if (std::isdigit(static_cast<unsigned char>(character)) == 0)
      return std::nullopt;
    value = value * 10U + static_cast<unsigned>(character - '0');
    if (value > maximum)
      return std::nullopt;
  }
  if (name.size() > 2U && name[1] == '0')
    return std::nullopt;
  return value;
}

auto append_u32(std::vector<std::byte> &output, std::uint32_t value) -> void {
  for (unsigned shift = 0; shift < 32U; shift += 8U)
    output.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
}

auto patch_u32(std::vector<std::byte> &output, std::size_t offset,
               std::uint32_t value) -> void {
  for (unsigned shift = 0; shift < 32U; shift += 8U)
    output[offset + shift / 8U] =
        static_cast<std::byte>((value >> shift) & 0xffU);
}

auto append_uleb(std::vector<std::byte> &output, std::uint64_t value) -> void {
  do {
    auto byte = static_cast<std::uint8_t>(value & 0x7fU);
    value >>= 7U;
    if (value != 0U)
      byte |= 0x80U;
    output.push_back(static_cast<std::byte>(byte));
  } while (value != 0U);
}

auto append_sleb(std::vector<std::byte> &output, std::int64_t value) -> void {
  bool more = true;
  while (more) {
    auto byte = static_cast<std::uint8_t>(value & 0x7f);
    const bool sign = (byte & 0x40U) != 0U;
    value >>= 7;
    more = !((value == 0 && !sign) || (value == -1 && sign));
    if (more)
      byte |= 0x80U;
    output.push_back(static_cast<std::byte>(byte));
  }
}

auto dwarf_register(std::string_view name) -> std::optional<std::uint64_t> {
  if (name == "sp")
    return 31U;
  if (const auto integer = parse_numbered_register(name, 'x', 30U))
    return *integer;
  if (const auto vector = parse_numbered_register(name, 'v', 31U))
    return 64U + *vector;
  return std::nullopt;
}

auto append_advance(std::vector<std::byte> &output, std::uint64_t delta)
    -> void {
  if (delta == 0U)
    return;
  if (delta <= 0x3fU) {
    output.push_back(static_cast<std::byte>(0x40U | delta));
  } else if (delta <= std::numeric_limits<std::uint8_t>::max()) {
    output.push_back(std::byte{0x02});
    output.push_back(static_cast<std::byte>(delta));
  } else if (delta <= std::numeric_limits<std::uint16_t>::max()) {
    output.push_back(std::byte{0x03});
    output.push_back(static_cast<std::byte>(delta & 0xffU));
    output.push_back(static_cast<std::byte>((delta >> 8U) & 0xffU));
  } else {
    output.push_back(std::byte{0x04});
    append_u32(output, static_cast<std::uint32_t>(delta));
  }
}

auto append_dwarf_action(std::vector<std::byte> &output,
                         const UnwindAction &action)
    -> Result<bool, Diagnostic> {
  const auto reg = dwarf_register(action.registerName);
  if (!reg.has_value()) {
    return failure<bool>("architecture.unwind_action",
                         "DWARF CFI action names an unknown ARM64 register");
  }
  switch (action.kind) {
  case UnwindActionKind::DefineCanonicalFrameAddress:
    if (action.offset < 0) {
      return failure<bool>("architecture.unwind_action",
                           "canonical frame offset must be nonnegative");
    }
    output.push_back(std::byte{0x0c});
    append_uleb(output, *reg);
    append_uleb(output, static_cast<std::uint64_t>(action.offset));
    break;
  case UnwindActionKind::SaveRegister:
    if (action.offset >= 0 ||
        action.offset == std::numeric_limits<std::int64_t>::min() ||
        action.offset % 8 != 0) {
      return failure<bool>(
          "architecture.unwind_action",
          "saved ARM64 registers require a negative 8-byte offset");
    }
    if (*reg <= 0x3fU) {
      output.push_back(static_cast<std::byte>(0x80U | *reg));
    } else {
      output.push_back(std::byte{0x05});
      append_uleb(output, *reg);
    }
    append_uleb(output, static_cast<std::uint64_t>(-action.offset / 8));
    break;
  case UnwindActionKind::RestoreRegister:
    if (action.offset != 0) {
      return failure<bool>("architecture.unwind_action",
                           "restored ARM64 registers require a zero offset");
    }
    if (*reg <= 0x3fU) {
      output.push_back(static_cast<std::byte>(0xc0U | *reg));
    } else {
      output.push_back(std::byte{0x06});
      append_uleb(output, *reg);
    }
    break;
  }
  return Result<bool, Diagnostic>::success(true);
}

auto pad_to_four(std::vector<std::byte> &output) -> void {
  while (output.size() % 4U != 0U)
    output.push_back(std::byte{0});
}

auto validate_unwind_request(const UnwindRequest &request)
    -> Result<bool, Diagnostic> {
  if (request.architecture != Architecture::ARM64) {
    return failure<bool>("architecture.request_mismatch",
                         "ARM64 unwind request has the wrong architecture");
  }
  if (request.codeSize == 0U || (request.codeStart.value & 3U) != 0U ||
      (request.codeSize & 3U) != 0U ||
      request.codeSize > std::numeric_limits<std::uint32_t>::max() ||
      request.codeStart.value >
          std::numeric_limits<std::uint64_t>::max() - request.codeSize) {
    return failure<bool>("architecture.unwind_range",
                         "ARM64 unwind code range must be aligned and bounded");
  }
  if (request.actions.size() > request.limits.maxInstructions ||
      request.actions.size() >
          (std::numeric_limits<std::size_t>::max() - 64U) / 4U) {
    return failure<bool>("architecture.resource_limit",
                         "unwind action count exceeds the request limit");
  }
  std::uint64_t previous = 0;
  for (const auto &action : request.actions) {
    if (action.codeOffset < previous || action.codeOffset > request.codeSize ||
        (action.codeOffset & 3U) != 0U) {
      return failure<bool>(
          "architecture.unwind_action",
          "ARM64 unwind actions must be ordered on instruction boundaries");
    }
    previous = action.codeOffset;
    std::vector<std::byte> sink;
    const auto valid = append_dwarf_action(sink, action);
    if (!valid.has_value())
      return valid;
  }
  return Result<bool, Diagnostic>::success(true);
}

struct PackedFrame {
  std::uint32_t integerRegisters{0};
  std::uint32_t vectorRegisters{0};
  std::uint32_t frameUnits{0};
};

auto analyze_packed_frame(const UnwindRequest &request)
    -> Result<std::optional<PackedFrame>, Diagnostic> {
  std::set<std::string> saves;
  std::set<std::string> restores;
  std::uint64_t maximumCfa = 0;
  bool framePointer = false;
  bool initialCfa = false;
  bool finalCfa = false;
  std::optional<std::uint64_t> saveBoundary;
  std::optional<std::uint64_t> restoreBoundary;
  std::optional<std::uint64_t> frameBoundary;
  for (const auto &action : request.actions) {
    if (action.kind == UnwindActionKind::DefineCanonicalFrameAddress) {
      if (action.registerName == "sp") {
        maximumCfa =
            std::max(maximumCfa, static_cast<std::uint64_t>(action.offset));
        initialCfa =
            initialCfa || (action.offset == 0 && action.codeOffset == 0);
        finalCfa =
            finalCfa || (action.offset == 0 && restoreBoundary.has_value() &&
                         action.codeOffset >= *restoreBoundary);
      } else if (action.registerName == "x29" && action.offset == 16) {
        framePointer = true;
        if (frameBoundary.has_value())
          return failure<std::optional<PackedFrame>>(
              "architecture.unwind_action",
              "Windows ARM64 packed unwind has multiple frame-chain actions");
        frameBoundary = action.codeOffset;
      } else {
        return failure<std::optional<PackedFrame>>(
            "architecture.unwind_action",
            "Windows ARM64 packed unwind requires canonical SP or x29 CFA "
            "actions");
      }
      continue;
    }
    auto &registers =
        action.kind == UnwindActionKind::SaveRegister ? saves : restores;
    if (!registers.insert(action.registerName).second) {
      return failure<std::optional<PackedFrame>>(
          "architecture.unwind_action",
          "Windows ARM64 packed unwind contains a duplicate register action");
    }
    auto &boundary = action.kind == UnwindActionKind::SaveRegister
                         ? saveBoundary
                         : restoreBoundary;
    if (boundary.has_value() && *boundary != action.codeOffset) {
      return failure<std::optional<PackedFrame>>(
          "architecture.unwind_action", "Windows ARM64 packed unwind register "
                                        "actions cross phase boundaries");
    }
    boundary = action.codeOffset;
  }
  if (saves.empty() && restores.empty() && maximumCfa == 0U && !framePointer)
    return Result<std::optional<PackedFrame>, Diagnostic>::success(
        std::nullopt);
  if (!request.codeSymbol.has_value() || request.codeSymbol->empty()) {
    return failure<std::optional<PackedFrame>>(
        "architecture.unwind_unowned",
        "Windows ARM64 packed unwind requires an owned code symbol");
  }
  if (!saves.contains("x29") || !saves.contains("x30") ||
      !restores.contains("x29") || !restores.contains("x30") || !framePointer ||
      saves != restores || !initialCfa || !finalCfa ||
      !saveBoundary.has_value() || !restoreBoundary.has_value() ||
      !frameBoundary.has_value() || *saveBoundary >= *frameBoundary ||
      *frameBoundary >= *restoreBoundary) {
    return failure<std::optional<PackedFrame>>(
        "architecture.unwind_action",
        "Windows ARM64 packed unwind requires a symmetric x29/x30 frame chain");
  }
  std::uint32_t integerCount = 0;
  for (unsigned reg = 19; reg <= 28; ++reg) {
    const auto name = "x" + std::to_string(reg);
    if (!saves.contains(name))
      break;
    ++integerCount;
  }
  std::uint32_t vectorCount = 0;
  for (unsigned reg = 8; reg <= 15; ++reg) {
    const auto name = "v" + std::to_string(reg);
    if (!saves.contains(name))
      break;
    ++vectorCount;
  }
  if (vectorCount == 1U || saves.size() != 2U + integerCount + vectorCount) {
    return failure<std::optional<PackedFrame>>(
        "architecture.unwind_action", "Windows ARM64 packed unwind requires "
                                      "contiguous x19-x28 and v8-v15 saves");
  }
  for (const auto &action : request.actions) {
    if (action.kind != UnwindActionKind::SaveRegister)
      continue;
    std::int64_t expected = 0;
    if (action.registerName == "x29")
      expected = -16;
    else if (action.registerName == "x30")
      expected = -8;
    else if (const auto integerReg =
                 parse_numbered_register(action.registerName, 'x', 28U))
      expected = -24 - 8 * static_cast<std::int64_t>(*integerReg - 19U);
    else if (const auto vectorReg =
                 parse_numbered_register(action.registerName, 'v', 15U))
      expected = -24 - 8 * static_cast<std::int64_t>(integerCount) -
                 8 * static_cast<std::int64_t>(*vectorReg - 8U);
    if (expected == 0 || action.offset != expected) {
      return failure<std::optional<PackedFrame>>(
          "architecture.unwind_action",
          "Windows ARM64 packed unwind register offsets are noncanonical");
    }
  }
  if (maximumCfa == 0U)
    maximumCfa = 16U;
  if ((maximumCfa & 15U) != 0U || maximumCfa / 16U > 0x1ffU ||
      maximumCfa < 16U + 8U * (integerCount + vectorCount)) {
    return failure<std::optional<PackedFrame>>(
        "architecture.unwind_range",
        "Windows ARM64 packed unwind frame size is not representable");
  }
  return Result<std::optional<PackedFrame>, Diagnostic>::success(PackedFrame{
      integerCount, vectorCount, static_cast<std::uint32_t>(maximumCfa / 16U)});
}

auto emit_windows_packed(const UnwindRequest &request)
    -> Result<UnwindPlan, Diagnostic> {
  if (request.codeSize / 4U > 0x7ffU) {
    return failure<UnwindPlan>(
        "architecture.unwind_range",
        "Windows ARM64 packed unwind function length exceeds 11 bits");
  }
  const auto frame = analyze_packed_frame(request);
  if (!frame.has_value())
    return failure<UnwindPlan>(frame.error().code, frame.error().message);
  if (!frame.value().has_value()) {
    return Result<UnwindPlan, Diagnostic>::success(UnwindPlan{
        .disposition = UnwindDisposition::NotRequired,
        .encoding = UnwindEncoding::WindowsARM64,
        .codeStart = request.codeStart,
        .codeSize = request.codeSize,
        .actions = request.actions,
        .encoded = {},
        .fixups = {},
    });
  }
  const auto &packed = *frame.value();
  std::uint32_t word = 1U;
  word |= static_cast<std::uint32_t>(request.codeSize / 4U) << 2U;
  const auto encodedRegF =
      packed.vectorRegisters == 0U ? 0U : packed.vectorRegisters - 1U;
  word |= encodedRegF << 13U;
  word |= packed.integerRegisters << 16U;
  word |= 3U << 21U;
  word |= packed.frameUnits << 23U;
  std::vector<std::byte> encoded(4U, std::byte{0});
  append_u32(encoded, word);
  if (encoded.size() > request.limits.maxEmittedBytes ||
      request.limits.maxFixups == 0U) {
    return failure<UnwindPlan>(
        "architecture.resource_limit",
        "Windows ARM64 packed unwind exceeds request limits");
  }
  return Result<UnwindPlan, Diagnostic>::success(UnwindPlan{
      .disposition = UnwindDisposition::Emit,
      .encoding = UnwindEncoding::WindowsARM64,
      .codeStart = request.codeStart,
      .codeSize = request.codeSize,
      .actions = request.actions,
      .encoded = std::move(encoded),
      .fixups = {MachineFixup{
          .offset = 0,
          .bitWidth = 32,
          .isSigned = false,
          .pcRelative = false,
          .addend = 0,
          .symbol = *request.codeSymbol,
          .kind = MachineFixupKind::ImageRelative32,
      }},
  });
}

auto emit_dwarf_cfi(const UnwindRequest &request)
    -> Result<UnwindPlan, Diagnostic> {
  if (!request.codeSymbol.has_value() || request.codeSymbol->empty()) {
    return failure<UnwindPlan>(
        "architecture.unwind_unowned",
        "ELF ARM64 unwind emission requires an owned code symbol");
  }
  std::vector<std::byte> encoded;
  encoded.reserve(64U + request.actions.size() * 4U);
  const auto cieLengthOffset = encoded.size();
  append_u32(encoded, 0U);
  const auto cieStart = encoded.size();
  append_u32(encoded, 0U);
  encoded.push_back(std::byte{1});
  encoded.push_back(std::byte{'z'});
  encoded.push_back(std::byte{'R'});
  encoded.push_back(std::byte{0});
  append_uleb(encoded, 1U);
  append_sleb(encoded, -8);
  append_uleb(encoded, 30U);
  append_uleb(encoded, 1U);
  encoded.push_back(std::byte{0x1b});
  encoded.push_back(std::byte{0x0c});
  append_uleb(encoded, 31U);
  append_uleb(encoded, 0U);
  pad_to_four(encoded);
  patch_u32(encoded, cieLengthOffset,
            static_cast<std::uint32_t>(encoded.size() - cieStart));

  const auto fdeLengthOffset = encoded.size();
  append_u32(encoded, 0U);
  const auto fdeStart = encoded.size();
  append_u32(encoded, static_cast<std::uint32_t>(fdeStart - cieLengthOffset));
  const auto initialLocationOffset = encoded.size();
  append_u32(encoded, 0U);
  append_u32(encoded, static_cast<std::uint32_t>(request.codeSize));
  append_uleb(encoded, 0U);
  std::uint64_t currentOffset = 0;
  for (const auto &action : request.actions) {
    append_advance(encoded, action.codeOffset - currentOffset);
    currentOffset = action.codeOffset;
    const auto appended = append_dwarf_action(encoded, action);
    if (!appended.has_value())
      return failure<UnwindPlan>(appended.error().code,
                                 appended.error().message);
  }
  pad_to_four(encoded);
  const auto fdeLength = encoded.size() - fdeStart;
  if (fdeLength > std::numeric_limits<std::uint32_t>::max() ||
      encoded.size() > request.limits.maxEmittedBytes ||
      request.limits.maxFixups == 0U) {
    return failure<UnwindPlan>("architecture.resource_limit",
                               "ARM64 DWARF CFI exceeds request limits");
  }
  patch_u32(encoded, fdeLengthOffset, static_cast<std::uint32_t>(fdeLength));
  return Result<UnwindPlan, Diagnostic>::success(UnwindPlan{
      .disposition = UnwindDisposition::Emit,
      .encoding = UnwindEncoding::DwarfCfi64,
      .codeStart = request.codeStart,
      .codeSize = request.codeSize,
      .actions = request.actions,
      .encoded = std::move(encoded),
      .fixups = {MachineFixup{
          .offset = initialLocationOffset,
          .bitWidth = 32,
          .isSigned = true,
          .pcRelative = true,
          .addend = 0,
          .symbol = *request.codeSymbol,
          .kind = MachineFixupKind::PcRelative32,
      }},
  });
}

} // namespace

auto build_arm64_unwind_plan(const UnwindRequest &request)
    -> Result<UnwindPlan, Diagnostic> {
  const auto valid = validate_unwind_request(request);
  if (!valid.has_value())
    return failure<UnwindPlan>(valid.error().code, valid.error().message);
  if (request.handlerSymbol.has_value() || request.handlerOwned) {
    return failure<UnwindPlan>("architecture.unwind_unowned",
                               "ARM64 personality handlers require an xdata "
                               "record and are not emitted");
  }
  if (request.format == BinaryFormat::COFF)
    return emit_windows_packed(request);
  if (request.format == BinaryFormat::ELF)
    return emit_dwarf_cfi(request);
  return failure<UnwindPlan>("architecture.unsupported_format",
                             "ARM64 unwind generation requires COFF or ELF");
}

} // namespace binobf::detail

#include "arm64_abi.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace binobf::detail {
namespace {

enum class RegisterClass : std::uint8_t { Integer, Vector };

struct TypeLayout {
  std::uint64_t size{0};
  std::uint32_t alignment{1};
  RegisterClass registerClass{RegisterClass::Integer};
};

template <typename T>
auto failure(std::string code, std::string message) -> Result<T, Diagnostic> {
  return Result<T, Diagnostic>::failure(Diagnostic{
      DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

auto is_arm64_abi(ir::NativeAbi abi) noexcept -> bool {
  return abi == ir::NativeAbi::WindowsARM64 || abi == ir::NativeAbi::AAPCS64;
}

auto align_up(std::uint64_t value, std::uint64_t alignment)
    -> std::optional<std::uint64_t> {
  if (alignment == 0U || (alignment & (alignment - 1U)) != 0U)
    return std::nullopt;
  const auto mask = alignment - 1U;
  if (value > std::numeric_limits<std::uint64_t>::max() - mask)
    return std::nullopt;
  return (value + mask) & ~mask;
}

auto type_layout(const ir::IrType &type) -> std::optional<TypeLayout> {
  if (type.byteOrder != ir::IrByteOrder::Little || type.addressSpace != 0U ||
      type.lanes == 0U || type.bits == 0U) {
    return std::nullopt;
  }
  if (type.kind == ir::IrTypeKind::Integer && type.lanes == 1U &&
      (type.bits == 8U || type.bits == 16U || type.bits == 32U ||
       type.bits == 64U)) {
    const auto size = static_cast<std::uint64_t>((type.bits + 7U) / 8U);
    return TypeLayout{
        size, static_cast<std::uint32_t>(std::min<std::uint64_t>(size, 8U)),
        RegisterClass::Integer};
  }
  if (type.kind == ir::IrTypeKind::Pointer && type.bits == 64U &&
      type.lanes == 1U) {
    return TypeLayout{8U, 8U, RegisterClass::Integer};
  }
  if (type.kind == ir::IrTypeKind::FloatingPoint && type.lanes == 1U &&
      (type.bits == 32U || type.bits == 64U)) {
    return TypeLayout{type.bits / 8U, type.bits / 8U, RegisterClass::Vector};
  }
  if (type.kind == ir::IrTypeKind::Vector) {
    const auto totalBits = static_cast<std::uint64_t>(type.bits) * type.lanes;
    if (totalBits == 64U || totalBits == 128U) {
      return TypeLayout{totalBits / 8U,
                        static_cast<std::uint32_t>(totalBits / 8U),
                        RegisterClass::Vector};
    }
  }
  return std::nullopt;
}

auto register_location(const ir::IrType &type, const TypeLayout &layout,
                       RegisterClass registerClass, std::size_t ordinal,
                       std::uint16_t index) -> ir::IrStorageLocation {
  return ir::IrStorageLocation{
      .kind = ir::IrStorageKind::Register,
      .type = type,
      .name = std::string{registerClass == RegisterClass::Integer ? "x" : "v"} +
              std::to_string(ordinal),
      .offset = 0,
      .size = layout.size,
      .alignment = layout.alignment,
      .index = index,
      .readonly = false,
  };
}

auto stack_location(const ir::IrType &type, const TypeLayout &layout,
                    std::uint64_t offset, std::uint16_t index)
    -> ir::IrStorageLocation {
  return ir::IrStorageLocation{
      .kind = ir::IrStorageKind::Stack,
      .type = type,
      .name = "sp",
      .offset = static_cast<std::int64_t>(offset),
      .size = layout.size,
      .alignment = std::max<std::uint32_t>(layout.alignment, 8U),
      .index = index,
      .readonly = false,
  };
}

auto derive_bindings(const std::vector<ir::IrType> &types,
                     const std::vector<TypeLayout> &layouts)
    -> std::optional<std::vector<ir::IrStorageLocation>> {
  std::vector<ir::IrStorageLocation> result;
  result.reserve(types.size());
  std::size_t integerOrdinal = 0;
  std::size_t vectorOrdinal = 0;
  std::uint64_t stackOffset = 0;
  for (std::size_t index = 0; index < types.size(); ++index) {
    auto &ordinal = layouts[index].registerClass == RegisterClass::Integer
                        ? integerOrdinal
                        : vectorOrdinal;
    if (ordinal < 8U) {
      result.push_back(register_location(
          types[index], layouts[index], layouts[index].registerClass, ordinal++,
          static_cast<std::uint16_t>(index)));
      continue;
    }
    const auto stackAlignment =
        std::max<std::uint32_t>(layouts[index].alignment, 8U);
    const auto aligned = align_up(stackOffset, stackAlignment);
    if (!aligned.has_value() ||
        *aligned > std::numeric_limits<std::int64_t>::max()) {
      return std::nullopt;
    }
    result.push_back(stack_location(types[index], layouts[index], *aligned,
                                    static_cast<std::uint16_t>(index)));
    const auto slotSize = align_up(layouts[index].size, 8U);
    if (!slotSize.has_value() ||
        *aligned > std::numeric_limits<std::uint64_t>::max() - *slotSize) {
      return std::nullopt;
    }
    stackOffset = *aligned + *slotSize;
  }
  return result;
}

auto stack_bytes(const std::vector<ir::IrStorageLocation> &bindings)
    -> std::optional<std::uint64_t> {
  std::uint64_t end = 0;
  for (const auto &binding : bindings) {
    if (binding.kind != ir::IrStorageKind::Stack)
      continue;
    if (binding.offset < 0)
      return std::nullopt;
    const auto begin = static_cast<std::uint64_t>(binding.offset);
    if (begin > std::numeric_limits<std::uint64_t>::max() - binding.size) {
      return std::nullopt;
    }
    end = std::max(end, begin + binding.size);
  }
  return align_up(end, 16U);
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

auto valid_source_binding(const ir::IrStorageLocation &binding,
                          const ir::IrType &type, const TypeLayout &layout,
                          std::uint16_t index) -> bool {
  const auto expectedAlignment =
      binding.kind == ir::IrStorageKind::Stack
          ? std::max<std::uint32_t>(layout.alignment, 8U)
          : layout.alignment;
  if (binding.type != type || binding.index != index ||
      binding.size != layout.size || binding.readonly ||
      binding.alignment != expectedAlignment) {
    return false;
  }
  if (binding.kind == ir::IrStorageKind::Register) {
    if (binding.offset != 0)
      return false;
    const auto registerIndex = parse_numbered_register(
        binding.name,
        layout.registerClass == RegisterClass::Integer ? 'x' : 'v', 7U);
    return registerIndex.has_value();
  }
  if (binding.kind != ir::IrStorageKind::Stack || binding.name != "sp" ||
      binding.offset < 0 || binding.offset % binding.alignment != 0) {
    return false;
  }
  constexpr auto maximumAddressableOffset = INT64_C(4080);
  return binding.offset <= maximumAddressableOffset &&
         binding.size <= static_cast<std::uint64_t>(maximumAddressableOffset -
                                                    binding.offset);
}

auto validate_return(const ir::IrFunctionSignature &signature) -> bool {
  const auto &type = signature.returnType;
  if (type.kind == ir::IrTypeKind::Void)
    return !signature.returnBinding.has_value();
  std::string expectedName;
  std::uint64_t expectedSize = 0;
  std::uint32_t expectedAlignment = 0;
  if (type.kind == ir::IrTypeKind::Integer && type.lanes == 1U &&
      type.bits > 0U && type.bits <= 64U) {
    expectedName = "x0";
    expectedSize = (type.bits + 7U) / 8U;
    expectedAlignment =
        static_cast<std::uint32_t>(std::min<std::uint64_t>(expectedSize, 8U));
  } else if (type.kind == ir::IrTypeKind::Pointer && type.bits == 64U &&
             type.lanes == 1U) {
    expectedName = "x0";
    expectedSize = 8;
    expectedAlignment = 8;
  } else if (type.kind == ir::IrTypeKind::Integer && type.bits == 128U &&
             type.lanes == 1U) {
    expectedName = "x0:x1";
    expectedSize = 16;
    expectedAlignment = 16;
  } else if (type.kind == ir::IrTypeKind::FloatingPoint &&
             (type.bits == 32U || type.bits == 64U) && type.lanes == 1U) {
    expectedName = "v0";
    expectedSize = type.bits / 8U;
    expectedAlignment = static_cast<std::uint32_t>(expectedSize);
  } else if (type.kind == ir::IrTypeKind::Vector && type.bits != 0U) {
    const auto totalBits = static_cast<std::uint64_t>(type.bits) * type.lanes;
    if (totalBits == 64U || totalBits == 128U) {
      expectedName = "v0";
      expectedSize = totalBits / 8U;
      expectedAlignment = static_cast<std::uint32_t>(expectedSize);
    } else if (totalBits > 128U && totalBits <= 256U) {
      expectedName = "x8";
      expectedSize = 8;
      expectedAlignment = 8;
    } else {
      return false;
    }
  } else {
    return false;
  }
  if (!signature.returnBinding.has_value())
    return true;
  const auto &binding = *signature.returnBinding;
  return binding.kind == ir::IrStorageKind::Register && binding.type == type &&
         binding.name == expectedName && binding.offset == 0 &&
         binding.size == expectedSize &&
         binding.alignment == expectedAlignment && binding.index == 0U &&
         !binding.readonly;
}

auto scalar_register_name(const ir::IrStorageLocation &location)
    -> std::string {
  if (location.type.kind == ir::IrTypeKind::FloatingPoint ||
      location.type.kind == ir::IrTypeKind::Vector) {
    const char prefix = location.size == 4U   ? 's'
                        : location.size == 8U ? 'd'
                                              : 'q';
    return std::string{prefix} + location.name.substr(1U);
  }
  const char prefix = location.size <= 4U ? 'w' : 'x';
  return std::string{prefix} + location.name.substr(1U);
}

auto scratch_register(const TypeLayout &layout) -> std::string {
  if (layout.registerClass == RegisterClass::Vector) {
    const char prefix = layout.size == 4U ? 's' : layout.size == 8U ? 'd' : 'q';
    return std::string{prefix} + "16";
  }
  return layout.size <= 4U ? "w16" : "x16";
}

auto append_instruction(std::string &assembly, std::size_t &count,
                        std::string line) -> void {
  assembly += std::move(line);
  assembly += '\n';
  ++count;
}

auto memory_operand(std::string_view base, std::uint64_t offset)
    -> std::string {
  return "[" + std::string{base} + ", #" + std::to_string(offset) + "]";
}

auto append_u32(std::vector<std::byte> &output, std::uint32_t value) -> void {
  for (unsigned shift = 0; shift < 32U; shift += 8U) {
    output.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
  }
}

auto patch_u32(std::vector<std::byte> &output, std::size_t offset,
               std::uint32_t value) -> void {
  for (unsigned shift = 0; shift < 32U; shift += 8U) {
    output[offset + shift / 8U] =
        static_cast<std::byte>((value >> shift) & 0xffU);
  }
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

auto pad_to_four(std::vector<std::byte> &output, std::byte fill = std::byte{0})
    -> void {
  while (output.size() % 4U != 0U)
    output.push_back(fill);
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
  if (request.actions.size() > request.limits.maxInstructions) {
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

} // namespace

auto build_arm64_abi_adapter(const AbiAdapterRequest &request,
                             const CodegenProvider &codegen)
    -> Result<AbiAdapterPlan, Diagnostic> {
  if (request.architecture != Architecture::ARM64) {
    return failure<AbiAdapterPlan>(
        "architecture.request_mismatch",
        "ARM64 ABI adapter request has the wrong architecture");
  }
  if (request.format != BinaryFormat::COFF &&
      request.format != BinaryFormat::ELF) {
    return failure<AbiAdapterPlan>("architecture.unsupported_format",
                                   "ARM64 ABI adapters require COFF or ELF");
  }
  if (!is_arm64_abi(request.sourceAbi) ||
      !is_arm64_abi(request.destinationAbi) || request.symbol.empty() ||
      request.stackAlignment != 16U) {
    return failure<AbiAdapterPlan>(
        "architecture.incompatible_abi",
        "ARM64 ABI adapter request is incomplete or incompatible");
  }
  if (request.tailCall) {
    return failure<AbiAdapterPlan>(
        "architecture.incompatible_abi",
        "bounded ARM64 ABI adapters do not emit tail calls");
  }
  if (request.signature.variadic) {
    return failure<AbiAdapterPlan>(
        "architecture.unsupported_variadic_abi",
        "ARM64 variadic adapters require ABI-specific register save areas");
  }

  std::vector<TypeLayout> layouts;
  layouts.reserve(request.signature.parameterTypes.size());
  for (const auto &type : request.signature.parameterTypes) {
    const auto layout = type_layout(type);
    if (!layout.has_value()) {
      return failure<AbiAdapterPlan>(
          "architecture.incompatible_abi",
          "parameter layout is not representable by an ARM64 ABI adapter");
    }
    layouts.push_back(*layout);
  }
  if (!validate_return(request.signature)) {
    return failure<AbiAdapterPlan>(
        "architecture.incompatible_abi",
        "return layout is not representable by the ARM64 ABI");
  }
  const auto derivedSource =
      derive_bindings(request.signature.parameterTypes, layouts);
  const auto derivedDestination =
      derive_bindings(request.signature.parameterTypes, layouts);
  if (!derivedSource.has_value() || !derivedDestination.has_value()) {
    return failure<AbiAdapterPlan>("architecture.incompatible_abi",
                                   "ARM64 ABI parameter layout overflowed");
  }
  auto sourceBindings = request.signature.parameterBindings.empty()
                            ? *derivedSource
                            : request.signature.parameterBindings;
  if (sourceBindings.size() != layouts.size()) {
    return failure<AbiAdapterPlan>(
        "architecture.incompatible_abi",
        "source parameter binding count does not match the signature");
  }

  std::vector<std::string> usedRegisters;
  std::vector<std::pair<std::int64_t, std::int64_t>> stackRanges;
  std::vector<AbiArgumentMove> moves;
  for (std::size_t index = 0; index < sourceBindings.size(); ++index) {
    if (!valid_source_binding(
            sourceBindings[index], request.signature.parameterTypes[index],
            layouts[index], static_cast<std::uint16_t>(index))) {
      return failure<AbiAdapterPlan>(
          "architecture.incompatible_abi",
          "source binding is not a canonical ARM64 register or stack slot");
    }
    if (sourceBindings[index].kind == ir::IrStorageKind::Register) {
      if (std::ranges::find(usedRegisters, sourceBindings[index].name) !=
          usedRegisters.end()) {
        return failure<AbiAdapterPlan>("architecture.incompatible_abi",
                                       "source register bindings overlap");
      }
      usedRegisters.push_back(sourceBindings[index].name);
    } else {
      const auto begin = sourceBindings[index].offset;
      const auto end =
          begin + static_cast<std::int64_t>(sourceBindings[index].size);
      if (std::ranges::any_of(stackRanges, [&](const auto &range) {
            return begin < range.second && range.first < end;
          })) {
        return failure<AbiAdapterPlan>("architecture.incompatible_abi",
                                       "source stack bindings overlap");
      }
      stackRanges.emplace_back(begin, end);
    }
    if (sourceBindings[index] != (*derivedDestination)[index]) {
      moves.push_back(
          AbiArgumentMove{sourceBindings[index], (*derivedDestination)[index]});
    }
  }

  const auto destinationStackBytes = stack_bytes(*derivedDestination);
  if (!destinationStackBytes.has_value()) {
    return failure<AbiAdapterPlan>("architecture.incompatible_abi",
                                   "destination stack layout overflowed");
  }
  std::vector<std::optional<std::uint64_t>> spillOffsets(sourceBindings.size());
  std::uint64_t frameBytes = *destinationStackBytes;
  for (std::size_t index = 0; index < sourceBindings.size(); ++index) {
    if (sourceBindings[index].kind != ir::IrStorageKind::Register)
      continue;
    const auto aligned = align_up(
        frameBytes, std::max<std::uint32_t>(layouts[index].alignment, 8U));
    if (!aligned.has_value() ||
        *aligned >
            std::numeric_limits<std::uint64_t>::max() - layouts[index].size) {
      return failure<AbiAdapterPlan>("architecture.incompatible_abi",
                                     "ARM64 register spill layout overflowed");
    }
    spillOffsets[index] = *aligned;
    frameBytes = *aligned + layouts[index].size;
  }
  const auto alignedFrame =
      align_up(std::max<std::uint64_t>(frameBytes, 16U), 16U);
  if (!alignedFrame.has_value() || *alignedFrame > 4080U) {
    return failure<AbiAdapterPlan>(
        "architecture.incompatible_abi",
        "ARM64 adapter frame is not representable by bounded immediates");
  }

  std::string assembly;
  std::size_t instructionCount = 0;
  append_instruction(assembly, instructionCount, "stp x29, x30, [sp, #-16]!");
  append_instruction(assembly, instructionCount, "mov x29, sp");
  append_instruction(assembly, instructionCount,
                     "sub sp, sp, #" + std::to_string(*alignedFrame));
  for (std::size_t index = 0; index < sourceBindings.size(); ++index) {
    if (!spillOffsets[index].has_value())
      continue;
    append_instruction(assembly, instructionCount,
                       "str " + scalar_register_name(sourceBindings[index]) +
                           ", " + memory_operand("sp", *spillOffsets[index]));
  }
  for (std::size_t index = 0; index < sourceBindings.size(); ++index) {
    const auto &source = sourceBindings[index];
    const auto &destination = (*derivedDestination)[index];
    const auto base = source.kind == ir::IrStorageKind::Register ? "sp" : "x29";
    const auto sourceOffset =
        source.kind == ir::IrStorageKind::Register
            ? *spillOffsets[index]
            : static_cast<std::uint64_t>(source.offset) + 16U;
    if (destination.kind == ir::IrStorageKind::Register) {
      append_instruction(assembly, instructionCount,
                         "ldr " + scalar_register_name(destination) + ", " +
                             memory_operand(base, sourceOffset));
    } else {
      const auto scratch = scratch_register(layouts[index]);
      append_instruction(assembly, instructionCount,
                         "ldr " + scratch + ", " +
                             memory_operand(base, sourceOffset));
      append_instruction(assembly, instructionCount,
                         "str " + scratch + ", " +
                             memory_operand("sp", static_cast<std::uint64_t>(
                                                      destination.offset)));
    }
  }
  append_instruction(assembly, instructionCount, "bl " + request.symbol);
  const auto epilogueOffset = static_cast<std::uint64_t>(instructionCount * 4U);
  append_instruction(assembly, instructionCount, "mov sp, x29");
  append_instruction(assembly, instructionCount, "ldp x29, x30, [sp], #16");
  append_instruction(assembly, instructionCount, "ret");

  MachineAssemblyRequest assemblyRequest{};
  assemblyRequest.architecture = Architecture::ARM64;
  assemblyRequest.format = request.format;
  assemblyRequest.triple = request.format == BinaryFormat::COFF
                               ? "aarch64-pc-windows-msvc"
                               : "aarch64-unknown-linux-gnu";
  assemblyRequest.syntax = MachineSyntax::GNU;
  assemblyRequest.assembly = std::move(assembly);
  assemblyRequest.limits = request.limits;
  assemblyRequest.expectedInstructionCount = instructionCount;
  auto emission = codegen.emit(assemblyRequest);
  if (!emission.has_value()) {
    return failure<AbiAdapterPlan>(emission.error().code,
                                   emission.error().message);
  }
  if (emission.value().bytes.size() != instructionCount * 4U ||
      emission.value().fixups.size() != 1U ||
      emission.value().fixups.front().kind != MachineFixupKind::AArch64Call26 ||
      emission.value().fixups.front().symbol != request.symbol) {
    return failure<AbiAdapterPlan>(
        "architecture.invalid_fixup",
        "ARM64 ABI adapter must contain one aligned external CALL26 fixup");
  }

  std::vector<std::string> clobbered;
  for (unsigned index = 0; index <= 17U; ++index)
    clobbered.push_back("x" + std::to_string(index));
  for (unsigned index = 0; index <= 7U; ++index)
    clobbered.push_back("v" + std::to_string(index));
  for (unsigned index = 16; index <= 31U; ++index)
    clobbered.push_back("v" + std::to_string(index));
  clobbered.push_back("x30");
  emission.value().clobberedRegisters = clobbered;
  const auto emittedSize = emission.value().bytes.size();
  std::vector<UnwindAction> unwindActions{
      {UnwindActionKind::DefineCanonicalFrameAddress, "sp", 0, 0},
      {UnwindActionKind::DefineCanonicalFrameAddress, "sp", 16, 4},
      {UnwindActionKind::SaveRegister, "x29", -16, 4},
      {UnwindActionKind::SaveRegister, "x30", -8, 4},
      {UnwindActionKind::DefineCanonicalFrameAddress, "x29", 16, 8},
      {UnwindActionKind::DefineCanonicalFrameAddress, "sp",
       static_cast<std::int64_t>(*alignedFrame + 16U), 12},
      {UnwindActionKind::DefineCanonicalFrameAddress, "sp", 16,
       epilogueOffset + 4U},
      {UnwindActionKind::RestoreRegister, "x29", 0, epilogueOffset + 8U},
      {UnwindActionKind::RestoreRegister, "x30", 0, epilogueOffset + 8U},
      {UnwindActionKind::DefineCanonicalFrameAddress, "sp", 0,
       epilogueOffset + 8U},
  };
  return Result<AbiAdapterPlan, Diagnostic>::success(AbiAdapterPlan{
      .emission = std::move(emission).value(),
      .argumentMoves = std::move(moves),
      .stackArgumentBytes = *destinationStackBytes,
      .stackDelta = 0,
      .callerCleansStack = true,
      .clobbers = ir::IrCallClobbers{clobbered, true, true},
      .unwind =
          UnwindRequest{
              .architecture = Architecture::ARM64,
              .format = request.format,
              .codeStart = {0U, AddressKind::Virtual},
              .codeSize = emittedSize,
              .actions = std::move(unwindActions),
              .codeSymbol = std::nullopt,
              .handlerSymbol = std::nullopt,
              .limits = request.limits,
              .handlerOwned = false,
          },
  });
}

auto build_arm64_unwind_plan(const UnwindRequest &request)
    -> Result<UnwindPlan, Diagnostic> {
  const auto valid = validate_unwind_request(request);
  if (!valid.has_value())
    return failure<UnwindPlan>(valid.error().code, valid.error().message);
  if (request.handlerSymbol.has_value()) {
    return failure<UnwindPlan>("architecture.unwind_unowned",
                               "ARM64 personality handlers are not emitted "
                               "without an owned handler record");
  }
  if (request.format == BinaryFormat::COFF) {
    if (request.codeSize / 4U > 0x3ffffU) {
      return failure<UnwindPlan>(
          "architecture.unwind_range",
          "Windows ARM64 unwind function length exceeds one xdata record");
    }
    std::uint64_t maximumCfaOffset = 0;
    bool savesFrameLink = false;
    bool setsFrame = false;
    std::optional<std::uint64_t> firstRestoreOffset;
    for (const auto &action : request.actions) {
      if (action.kind == UnwindActionKind::SaveRegister) {
        savesFrameLink = savesFrameLink || action.registerName == "x29" ||
                         action.registerName == "x30";
      }
      if (action.kind == UnwindActionKind::DefineCanonicalFrameAddress &&
          action.registerName == "sp" && action.offset > 0) {
        maximumCfaOffset = std::max(maximumCfaOffset,
                                    static_cast<std::uint64_t>(action.offset));
      }
      setsFrame =
          setsFrame ||
          (action.kind == UnwindActionKind::DefineCanonicalFrameAddress &&
           action.registerName == "x29");
      if (action.kind == UnwindActionKind::RestoreRegister &&
          !firstRestoreOffset.has_value()) {
        firstRestoreOffset = action.codeOffset;
      }
    }
    const auto frameBodyBytes =
        maximumCfaOffset > 16U ? maximumCfaOffset - 16U : 0U;
    if (frameBodyBytes > 32752U || frameBodyBytes % 16U != 0U) {
      return failure<UnwindPlan>(
          "architecture.unwind_action",
          "bounded Windows ARM64 xdata only supports canonical medium frames");
    }
    std::vector<std::byte> opcodes;
    if (frameBodyBytes != 0U) {
      const auto units = frameBodyBytes / 16U;
      if (frameBodyBytes < 512U) {
        opcodes.push_back(static_cast<std::byte>(units));
      } else {
        opcodes.push_back(static_cast<std::byte>(0xc0U | (units >> 8U)));
        opcodes.push_back(static_cast<std::byte>(units & 0xffU));
      }
    }
    if (setsFrame)
      opcodes.push_back(std::byte{0xe1});
    if (savesFrameLink)
      opcodes.push_back(std::byte{0x81});
    opcodes.push_back(std::byte{0xe4});
    const auto codeWords =
        static_cast<std::uint32_t>((opcodes.size() + 3U) / 4U);
    std::uint32_t header = static_cast<std::uint32_t>(request.codeSize / 4U);
    const bool hasEpilogue =
        firstRestoreOffset.has_value() && *firstRestoreOffset >= 4U;
    if (hasEpilogue) {
      header |= 1U << 22U;
    } else {
      header |= 1U << 21U;
      header |= static_cast<std::uint32_t>(opcodes.size() - 1U) << 22U;
    }
    header |= codeWords << 27U;
    std::vector<std::byte> encoded;
    append_u32(encoded, header);
    if (hasEpilogue) {
      const auto scopeOffset = (*firstRestoreOffset - 4U) / 4U;
      const auto epilogueIndex = frameBodyBytes == 0U    ? 0U
                                 : frameBodyBytes < 512U ? 1U
                                                         : 2U;
      const auto scope = static_cast<std::uint32_t>(scopeOffset) |
                         static_cast<std::uint32_t>(epilogueIndex << 22U);
      append_u32(encoded, scope);
    }
    encoded.insert(encoded.end(), opcodes.begin(), opcodes.end());
    pad_to_four(encoded, std::byte{0xe3});
    if (encoded.size() > request.limits.maxEmittedBytes) {
      return failure<UnwindPlan>(
          "architecture.resource_limit",
          "Windows ARM64 xdata exceeds the emitted-byte limit");
    }
    return Result<UnwindPlan, Diagnostic>::success(UnwindPlan{
        .disposition = UnwindDisposition::Emit,
        .encoding = UnwindEncoding::WindowsARM64,
        .codeStart = request.codeStart,
        .codeSize = request.codeSize,
        .actions = request.actions,
        .encoded = std::move(encoded),
        .fixups = {},
    });
  }
  if (request.format != BinaryFormat::ELF) {
    return failure<UnwindPlan>("architecture.unsupported_format",
                               "ARM64 unwind generation requires COFF or ELF");
  }
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
    if (!appended.has_value()) {
      return failure<UnwindPlan>(appended.error().code,
                                 appended.error().message);
    }
  }
  pad_to_four(encoded);
  patch_u32(encoded, fdeLengthOffset,
            static_cast<std::uint32_t>(encoded.size() - fdeStart));
  if (encoded.size() > request.limits.maxEmittedBytes) {
    return failure<UnwindPlan>(
        "architecture.resource_limit",
        "ARM64 DWARF CFI exceeds the emitted-byte limit");
  }
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

} // namespace binobf::detail

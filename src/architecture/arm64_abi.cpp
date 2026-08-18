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
              .codeSymbol = request.symbol,
              .handlerSymbol = std::nullopt,
              .limits = request.limits,
              .handlerOwned = false,
          },
  });
}

} // namespace binobf::detail

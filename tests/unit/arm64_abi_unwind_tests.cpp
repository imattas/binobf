#include "../test_support.hpp"

#include <binobf/architecture/backend.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

auto backend() -> std::unique_ptr<binobf::ArchitectureBackend> {
  auto result = binobf::make_architecture_backend(binobf::Architecture::ARM64);
  if (!result.has_value())
    throw std::runtime_error(result.error().message);
  return std::move(result).value();
}

auto u64() -> binobf::ir::IrType {
  return binobf::ir::IrType{binobf::ir::IrWidth::U64};
}

auto request(binobf::ir::NativeAbi source = binobf::ir::NativeAbi::WindowsARM64,
             binobf::ir::NativeAbi destination = binobf::ir::NativeAbi::AAPCS64,
             binobf::BinaryFormat format = binobf::BinaryFormat::ELF)
    -> binobf::AbiAdapterRequest {
  binobf::AbiAdapterRequest result{};
  result.architecture = binobf::Architecture::ARM64;
  result.format = format;
  result.sourceAbi = source;
  result.destinationAbi = destination;
  result.signature.returnType = u64();
  result.symbol = "external_target";
  result.stackAlignment = 16;
  return result;
}

auto binding(binobf::ir::IrType type, std::string name, std::uint16_t index,
             std::uint64_t size = 8, std::uint32_t alignment = 8)
    -> binobf::ir::IrStorageLocation {
  return binobf::ir::IrStorageLocation{binobf::ir::IrStorageKind::Register,
                                       type,
                                       std::move(name),
                                       0,
                                       size,
                                       alignment,
                                       index,
                                       false};
}

auto return_binding(binobf::ir::IrType type, std::string name,
                    std::uint64_t size, std::uint32_t alignment)
    -> binobf::ir::IrStorageLocation {
  return binobf::ir::IrStorageLocation{binobf::ir::IrStorageKind::Register,
                                       type,
                                       std::move(name),
                                       0,
                                       size,
                                       alignment,
                                       0,
                                       false};
}

} // namespace

TEST_CASE(arm64_adapter_places_ninth_integer_on_an_aligned_stack) {
  auto fixed = backend();
  auto value = request();
  value.signature.parameterTypes.assign(9, u64());
  const auto plan = fixed->build_abi_adapter(value);
  REQUIRE(plan.has_value());
  REQUIRE_EQ(plan.value().stackArgumentBytes, UINT64_C(16));
  REQUIRE_EQ(plan.value().stackDelta, INT64_C(0));
  REQUIRE(plan.value().callerCleansStack);
  REQUIRE_EQ(plan.value().emission.bytes.size() % 4U, std::size_t{0});
  REQUIRE_EQ(plan.value().emission.fixups.size(), std::size_t{1});
  REQUIRE_EQ(plan.value().emission.fixups.front().kind,
             binobf::MachineFixupKind::AArch64Call26);
  REQUIRE_EQ(plan.value().emission.fixups.front().symbol, "external_target");
}

TEST_CASE(arm64_adapter_allocates_integer_and_vector_registers_independently) {
  auto fixed = backend();
  auto value = request();
  const auto f64 =
      binobf::ir::IrType{binobf::ir::IrTypeKind::FloatingPoint, 64U};
  const auto v128 = binobf::ir::IrType{binobf::ir::IrTypeKind::Vector, 32U, 4U};
  value.signature.parameterTypes = {u64(), f64, u64(), v128, f64};
  value.signature.parameterBindings = {
      binding(u64(), "x1", 0), binding(f64, "v1", 1), binding(u64(), "x0", 2),
      binding(v128, "v0", 3, 16, 16), binding(f64, "v2", 4)};
  const auto plan = fixed->build_abi_adapter(value);
  REQUIRE(plan.has_value());
  REQUIRE_EQ(plan.value().argumentMoves.size(), std::size_t{4});
  REQUIRE(std::ranges::any_of(plan.value().argumentMoves, [](const auto &move) {
    return move.destination.name == "x0";
  }));
  REQUIRE(std::ranges::any_of(plan.value().argumentMoves, [](const auto &move) {
    return move.destination.name == "v0";
  }));
}

TEST_CASE(arm64_adapter_preserves_parallel_register_cycle_sources) {
  auto fixed = backend();
  auto value =
      request(binobf::ir::NativeAbi::AAPCS64, binobf::ir::NativeAbi::AAPCS64);
  value.signature.parameterTypes = {u64(), u64()};
  value.signature.parameterBindings = {binding(u64(), "x1", 0),
                                       binding(u64(), "x0", 1)};
  const auto plan = fixed->build_abi_adapter(value);
  REQUIRE(plan.has_value());
  REQUIRE_EQ(plan.value().argumentMoves.size(), std::size_t{2});
  REQUIRE(std::ranges::find(plan.value().clobbers.registers, "x16") !=
          plan.value().clobbers.registers.end());
  REQUIRE_EQ(plan.value().unwind.actions.front().registerName, "sp");
  REQUIRE_EQ(plan.value().unwind.actions.back().offset, INT64_C(0));
}

TEST_CASE(arm64_adapter_accepts_canonical_direct_and_indirect_returns) {
  auto fixed = backend();
  struct ReturnCase {
    binobf::ir::IrType type;
    const char *name;
    std::uint64_t size;
    std::uint32_t alignment;
  };
  const std::array cases{
      ReturnCase{u64(), "x0", 8, 8},
      ReturnCase{binobf::ir::IrType{binobf::ir::IrTypeKind::Integer, 128U},
                 "x0:x1", 16, 16},
      ReturnCase{binobf::ir::IrType{binobf::ir::IrTypeKind::FloatingPoint, 64U},
                 "v0", 8, 8},
      ReturnCase{binobf::ir::IrType{binobf::ir::IrTypeKind::Vector, 32U, 8U},
                 "x8", 8, 8},
  };
  for (const auto &item : cases) {
    auto value = request();
    value.signature.returnType = item.type;
    value.signature.returnBinding =
        return_binding(item.type, item.name, item.size, item.alignment);
    REQUIRE(fixed->build_abi_adapter(value).has_value());
  }
}

TEST_CASE(arm64_adapter_rejects_variadics_tail_calls_and_bad_types) {
  auto fixed = backend();
  auto value = request();
  value.signature.variadic = true;
  auto plan = fixed->build_abi_adapter(value);
  REQUIRE(!plan.has_value());
  REQUIRE_EQ(plan.error().code, "architecture.unsupported_variadic_abi");

  value.signature.variadic = false;
  value.tailCall = true;
  REQUIRE(!fixed->build_abi_adapter(value).has_value());
  value.tailCall = false;
  value.signature.parameterTypes = {
      binobf::ir::IrType{binobf::ir::IrTypeKind::Pointer, 32U}};
  REQUIRE(!fixed->build_abi_adapter(value).has_value());
  value.signature.parameterTypes = {
      binobf::ir::IrType{binobf::ir::IrTypeKind::Vector, 32U, 8U}};
  REQUIRE(!fixed->build_abi_adapter(value).has_value());
}

TEST_CASE(arm64_adapter_rejects_overlapping_and_huge_explicit_bindings) {
  auto fixed = backend();
  auto value = request();
  value.signature.parameterTypes = {u64(), u64()};
  value.signature.parameterBindings = {binding(u64(), "x0", 0),
                                       binding(u64(), "x0", 1)};
  REQUIRE(!fixed->build_abi_adapter(value).has_value());

  value.signature.parameterBindings = {
      binobf::ir::IrStorageLocation{
          binobf::ir::IrStorageKind::Stack, u64(), "sp",
          std::numeric_limits<std::int64_t>::max() - 7, 8, 8, 0, false},
      binobf::ir::IrStorageLocation{binobf::ir::IrStorageKind::Stack, u64(),
                                    "sp", 0, 8, 8, 1, false}};
  REQUIRE(!fixed->build_abi_adapter(value).has_value());
}

TEST_CASE(arm64_adapter_rejects_binding_shape_mismatches_and_oversized_frames) {
  auto fixed = backend();
  auto value = request();
  value.signature.parameterTypes = {u64()};
  value.signature.parameterBindings = {binding(u64(), "v0", 0)};
  REQUIRE(!fixed->build_abi_adapter(value).has_value());
  value.signature.parameterBindings = {binding(u64(), "x0", 1)};
  REQUIRE(!fixed->build_abi_adapter(value).has_value());
  value.signature.parameterBindings = {binding(u64(), "x0", 0, 4, 8)};
  REQUIRE(!fixed->build_abi_adapter(value).has_value());
  value.signature.parameterBindings = {binding(u64(), "x0", 0, 8, 16)};
  REQUIRE(!fixed->build_abi_adapter(value).has_value());

  value.signature.parameterBindings.clear();
  value.signature.parameterTypes.assign(600, u64());
  const auto oversized = fixed->build_abi_adapter(value);
  REQUIRE(!oversized.has_value());
  REQUIRE_EQ(oversized.error().code, "architecture.incompatible_abi");
}

TEST_CASE(
    arm64_adapter_handles_narrow_integer_stack_exhaustion_and_rejects_bad_return) {
  auto fixed = backend();
  auto value = request();
  value.signature.parameterTypes.assign(
      9, binobf::ir::IrType{binobf::ir::IrWidth::U32});
  REQUIRE(fixed->build_abi_adapter(value).has_value());

  value.signature.parameterTypes.clear();
  value.signature.returnType = u64();
  value.signature.returnBinding = return_binding(u64(), "x1", 8, 8);
  REQUIRE(!fixed->build_abi_adapter(value).has_value());
  value.signature.returnBinding = return_binding(u64(), "x0", 8, 8);
  value.signature.returnBinding->readonly = true;
  REQUIRE(!fixed->build_abi_adapter(value).has_value());
}

TEST_CASE(arm64_unwind_emits_windows_and_dwarf64_records) {
  auto fixed = backend();
  binobf::UnwindRequest value{};
  value.architecture = binobf::Architecture::ARM64;
  value.codeStart = {0x1000, binobf::AddressKind::Virtual};
  value.codeSize = 32;
  value.codeSymbol = "owned_function";
  value.actions = {
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "sp", 0, 0},
      {binobf::UnwindActionKind::SaveRegister, "x29", -16, 4},
      {binobf::UnwindActionKind::SaveRegister, "x30", -8, 4},
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "x29", 16, 8},
      {binobf::UnwindActionKind::RestoreRegister, "x29", 0, 24},
      {binobf::UnwindActionKind::RestoreRegister, "x30", 0, 24},
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "sp", 0, 28},
  };
  value.format = binobf::BinaryFormat::COFF;
  auto plan = fixed->build_unwind(value);
  REQUIRE(plan.has_value());
  REQUIRE_EQ(plan.value().disposition, binobf::UnwindDisposition::Emit);
  REQUIRE_EQ(plan.value().encoding, binobf::UnwindEncoding::WindowsARM64);
  REQUIRE(!plan.value().encoded.empty());

  value.format = binobf::BinaryFormat::ELF;
  plan = fixed->build_unwind(value);
  REQUIRE(plan.has_value());
  REQUIRE_EQ(plan.value().encoding, binobf::UnwindEncoding::DwarfCfi64);
  REQUIRE_EQ(plan.value().fixups.size(), std::size_t{1});
  REQUIRE_EQ(plan.value().fixups.front().kind,
             binobf::MachineFixupKind::PcRelative32);
}

TEST_CASE(arm64_unwind_rejects_unowned_handlers_and_invalid_actions) {
  auto fixed = backend();
  binobf::UnwindRequest value{};
  value.architecture = binobf::Architecture::ARM64;
  value.format = binobf::BinaryFormat::ELF;
  value.codeSize = 16;
  value.codeSymbol = "owned_function";
  value.handlerSymbol = "personality";
  auto plan = fixed->build_unwind(value);
  REQUIRE(!plan.has_value());
  REQUIRE_EQ(plan.error().code, "architecture.unwind_unowned");

  value.handlerSymbol.reset();
  value.actions = {
      {binobf::UnwindActionKind::SaveRegister, "x29",
       std::numeric_limits<std::int64_t>::min(), 12},
      {binobf::UnwindActionKind::RestoreRegister, "x29", 0, 4},
  };
  plan = fixed->build_unwind(value);
  REQUIRE(!plan.has_value());
  REQUIRE_EQ(plan.error().code, "architecture.unwind_action");
}

TEST_CASE(arm64_windows_unwind_matches_the_llvm_canonical_frame_record) {
  auto fixed = backend();
  binobf::UnwindRequest value{};
  value.architecture = binobf::Architecture::ARM64;
  value.format = binobf::BinaryFormat::COFF;
  value.codeSize = 24;
  value.actions = {
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "sp", 0, 0},
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "sp", 16, 4},
      {binobf::UnwindActionKind::SaveRegister, "x29", -16, 4},
      {binobf::UnwindActionKind::SaveRegister, "x30", -8, 4},
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "x29", 16, 8},
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "sp", 96, 12},
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "sp", 16, 16},
      {binobf::UnwindActionKind::RestoreRegister, "x29", 0, 20},
      {binobf::UnwindActionKind::RestoreRegister, "x30", 0, 20},
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "sp", 0, 20},
  };
  const auto plan = fixed->build_unwind(value);
  REQUIRE(plan.has_value());
  const std::vector<std::byte> expected{
      std::byte{0x06}, std::byte{0x00}, std::byte{0x40}, std::byte{0x08},
      std::byte{0x04}, std::byte{0x00}, std::byte{0x40}, std::byte{0x00},
      std::byte{0x05}, std::byte{0xe1}, std::byte{0x81}, std::byte{0xe4},
  };
  REQUIRE_EQ(plan.value().encoded, expected);

  value.actions[5].offset = 528;
  const auto medium = fixed->build_unwind(value);
  REQUIRE(medium.has_value());
  REQUIRE_EQ(medium.value().encoded[8], std::byte{0xc0});
  REQUIRE_EQ(medium.value().encoded[9], std::byte{0x20});
}

int main() { return binobf::test::run_all(); }

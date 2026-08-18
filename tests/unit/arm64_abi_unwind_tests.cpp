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

auto u32(const std::vector<std::byte> &bytes, std::size_t offset)
    -> std::uint32_t {
  return std::to_integer<std::uint32_t>(bytes.at(offset)) |
         std::to_integer<std::uint32_t>(bytes.at(offset + 1U)) << 8U |
         std::to_integer<std::uint32_t>(bytes.at(offset + 2U)) << 16U |
         std::to_integer<std::uint32_t>(bytes.at(offset + 3U)) << 24U;
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
  REQUIRE_EQ(plan.value().encoded.size(), std::size_t{8});
  REQUIRE_EQ(plan.value().fixups.size(), std::size_t{1});
  REQUIRE_EQ(plan.value().fixups.front().kind,
             binobf::MachineFixupKind::ImageRelative32);

  value.format = binobf::BinaryFormat::ELF;
  plan = fixed->build_unwind(value);
  REQUIRE(plan.has_value());
  REQUIRE_EQ(plan.value().encoding, binobf::UnwindEncoding::DwarfCfi64);
  REQUIRE_EQ(plan.value().fixups.size(), std::size_t{1});
  REQUIRE_EQ(plan.value().fixups.front().kind,
             binobf::MachineFixupKind::PcRelative32);
  const auto &dwarf = plan.value().encoded;
  REQUIRE_EQ(u32(dwarf, 0), std::uint32_t{16});
  REQUIRE_EQ(dwarf[8], std::byte{1});
  REQUIRE_EQ(dwarf[9], std::byte{'z'});
  REQUIRE_EQ(dwarf[10], std::byte{'R'});
  REQUIRE_EQ(dwarf[12], std::byte{1});
  REQUIRE_EQ(dwarf[13], std::byte{0x78});
  REQUIRE_EQ(dwarf[14], std::byte{30});
  REQUIRE_EQ(dwarf[16], std::byte{0x1b});
  REQUIRE_EQ(u32(dwarf, 24), std::uint32_t{24});
  REQUIRE_EQ(plan.value().fixups.front().offset, std::uint64_t{28});
  REQUIRE_EQ(dwarf.size() % 4U, std::size_t{0});
  REQUIRE(std::ranges::find(dwarf, std::byte{0x9d}) != dwarf.end());
  REQUIRE(std::ranges::find(dwarf, std::byte{0x9e}) != dwarf.end());
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
  value.handlerOwned = true;
  plan = fixed->build_unwind(value);
  REQUIRE(!plan.has_value());
  REQUIRE_EQ(plan.error().code, "architecture.unwind_unowned");

  value.handlerOwned = false;
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
  value.codeSymbol = "owned_function";
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
      std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
      std::byte{0x19}, std::byte{0x00}, std::byte{0x60}, std::byte{0x03},
  };
  REQUIRE_EQ(plan.value().encoded, expected);
  REQUIRE_EQ(plan.value().fixups.size(), std::size_t{1});
  REQUIRE_EQ(plan.value().fixups.front().offset, std::uint64_t{0});
  REQUIRE_EQ(plan.value().fixups.front().symbol, "owned_function");

  value.actions[5].offset = 528;
  const auto medium = fixed->build_unwind(value);
  REQUIRE(medium.has_value());
  REQUIRE_EQ(medium.value().encoded.size(), std::size_t{8});
}

TEST_CASE(arm64_windows_unwind_omits_leaf_records) {
  auto fixed = backend();
  binobf::UnwindRequest value{};
  value.architecture = binobf::Architecture::ARM64;
  value.format = binobf::BinaryFormat::COFF;
  value.codeSize = 4;
  value.actions = {
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "sp", 0, 0}};
  const auto plan = fixed->build_unwind(value);
  REQUIRE(plan.has_value());
  REQUIRE_EQ(plan.value().disposition, binobf::UnwindDisposition::NotRequired);
  REQUIRE(plan.value().encoded.empty());
  REQUIRE(plan.value().fixups.empty());
}

TEST_CASE(arm64_windows_packed_unwind_encodes_integer_and_vector_saves) {
  auto fixed = backend();
  binobf::UnwindRequest value{};
  value.architecture = binobf::Architecture::ARM64;
  value.format = binobf::BinaryFormat::COFF;
  value.codeSize = 40;
  value.codeSymbol = "saved_register_function";
  value.actions = {
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "sp", 0, 0},
      {binobf::UnwindActionKind::SaveRegister, "x29", -16, 4},
      {binobf::UnwindActionKind::SaveRegister, "x30", -8, 4},
      {binobf::UnwindActionKind::SaveRegister, "x19", -24, 4},
      {binobf::UnwindActionKind::SaveRegister, "x20", -32, 4},
      {binobf::UnwindActionKind::SaveRegister, "v8", -40, 4},
      {binobf::UnwindActionKind::SaveRegister, "v9", -48, 4},
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "x29", 16, 8},
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "sp", 80, 12},
      {binobf::UnwindActionKind::RestoreRegister, "x29", 0, 32},
      {binobf::UnwindActionKind::RestoreRegister, "x30", 0, 32},
      {binobf::UnwindActionKind::RestoreRegister, "x19", 0, 32},
      {binobf::UnwindActionKind::RestoreRegister, "x20", 0, 32},
      {binobf::UnwindActionKind::RestoreRegister, "v8", 0, 32},
      {binobf::UnwindActionKind::RestoreRegister, "v9", 0, 32},
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "sp", 0, 36},
  };
  const auto plan = fixed->build_unwind(value);
  REQUIRE(plan.has_value());
  const auto &bytes = plan.value().encoded;
  const auto word = std::to_integer<std::uint32_t>(bytes[4]) |
                    std::to_integer<std::uint32_t>(bytes[5]) << 8U |
                    std::to_integer<std::uint32_t>(bytes[6]) << 16U |
                    std::to_integer<std::uint32_t>(bytes[7]) << 24U;
  REQUIRE_EQ((word >> 2U) & 0x7ffU, std::uint32_t{10});
  REQUIRE_EQ((word >> 13U) & 0x7U, std::uint32_t{1});
  REQUIRE_EQ((word >> 16U) & 0xfU, std::uint32_t{2});
  REQUIRE_EQ((word >> 21U) & 0x3U, std::uint32_t{3});
  REQUIRE_EQ((word >> 23U) & 0x1ffU, std::uint32_t{5});
}

TEST_CASE(arm64_windows_packed_unwind_accepts_register_field_boundaries) {
  auto fixed = backend();
  binobf::UnwindRequest value{};
  value.architecture = binobf::Architecture::ARM64;
  value.format = binobf::BinaryFormat::COFF;
  value.codeSize = 48;
  value.codeSymbol = "maximum_saved_registers";
  value.actions = {
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "sp", 0, 0},
      {binobf::UnwindActionKind::SaveRegister, "x29", -16, 4},
      {binobf::UnwindActionKind::SaveRegister, "x30", -8, 4},
  };
  std::int64_t offset = -24;
  for (unsigned reg = 19; reg <= 28; ++reg, offset -= 8)
    value.actions.push_back({binobf::UnwindActionKind::SaveRegister,
                             "x" + std::to_string(reg), offset, 4});
  for (unsigned reg = 8; reg <= 15; ++reg, offset -= 8)
    value.actions.push_back({binobf::UnwindActionKind::SaveRegister,
                             "v" + std::to_string(reg), offset, 4});
  value.actions.push_back(
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "x29", 16, 8});
  value.actions.push_back(
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "sp", 160, 12});
  value.actions.push_back(
      {binobf::UnwindActionKind::RestoreRegister, "x29", 0, 40});
  value.actions.push_back(
      {binobf::UnwindActionKind::RestoreRegister, "x30", 0, 40});
  for (unsigned reg = 19; reg <= 28; ++reg)
    value.actions.push_back({binobf::UnwindActionKind::RestoreRegister,
                             "x" + std::to_string(reg), 0, 40});
  for (unsigned reg = 8; reg <= 15; ++reg)
    value.actions.push_back({binobf::UnwindActionKind::RestoreRegister,
                             "v" + std::to_string(reg), 0, 40});
  value.actions.push_back(
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "sp", 0, 44});
  const auto plan = fixed->build_unwind(value);
  REQUIRE(plan.has_value());
  const auto word = u32(plan.value().encoded, 4);
  REQUIRE_EQ((word >> 13U) & 0x7U, std::uint32_t{7});
  REQUIRE_EQ((word >> 16U) & 0xfU, std::uint32_t{10});

  value.actions[4].registerName = "x22";
  REQUIRE(!fixed->build_unwind(value).has_value());
}

TEST_CASE(arm64_windows_packed_unwind_refuses_unrepresentable_boundaries) {
  auto fixed = backend();
  binobf::UnwindRequest value{};
  value.architecture = binobf::Architecture::ARM64;
  value.format = binobf::BinaryFormat::COFF;
  value.codeSize = 8192;
  value.codeSymbol = "too_large";
  REQUIRE(!fixed->build_unwind(value).has_value());

  value.codeSize = 8188;
  value.actions = {
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "sp", 0, 0},
      {binobf::UnwindActionKind::SaveRegister, "x29", -16, 4},
      {binobf::UnwindActionKind::SaveRegister, "x30", -8, 4},
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "x29", 16, 8},
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "sp", 8176, 12},
      {binobf::UnwindActionKind::RestoreRegister, "x29", 0, 8180},
      {binobf::UnwindActionKind::RestoreRegister, "x30", 0, 8180},
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "sp", 0, 8184},
  };
  const auto boundary = fixed->build_unwind(value);
  REQUIRE(boundary.has_value());
  REQUIRE_EQ((u32(boundary.value().encoded, 4) >> 2U) & 0x7ffU,
             std::uint32_t{0x7ff});
  REQUIRE_EQ((u32(boundary.value().encoded, 4) >> 23U) & 0x1ffU,
             std::uint32_t{0x1ff});

  value.codeSize = 32;
  value.actions = {
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "sp", 0, 0},
      {binobf::UnwindActionKind::SaveRegister, "x29", -16, 4},
      {binobf::UnwindActionKind::SaveRegister, "x30", -8, 4},
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "x29", 16, 8},
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "sp", 8192, 12},
      {binobf::UnwindActionKind::RestoreRegister, "x29", 0, 24},
      {binobf::UnwindActionKind::RestoreRegister, "x30", 0, 24},
      {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "sp", 0, 28},
  };
  REQUIRE(!fixed->build_unwind(value).has_value());
}

int main() { return binobf::test::run_all(); }

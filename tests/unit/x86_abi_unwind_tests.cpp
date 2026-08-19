#include <binobf/architecture/backend.hpp>

#include "../test_support.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <limits>
#include <memory>

namespace {

auto backend() -> std::unique_ptr<binobf::ArchitectureBackend> {
    auto result = binobf::make_architecture_backend(binobf::Architecture::X86);
    if (!result.has_value()) throw std::runtime_error(result.error().message);
    return std::move(result).value();
}

auto backend_x64() -> std::unique_ptr<binobf::ArchitectureBackend> {
    auto result = binobf::make_architecture_backend(binobf::Architecture::X86_64);
    if (!result.has_value()) throw std::runtime_error(result.error().message);
    return std::move(result).value();
}

auto signature() -> binobf::ir::IrFunctionSignature {
    binobf::ir::IrFunctionSignature result{};
    result.parameterTypes = {
        binobf::ir::IrType{binobf::ir::IrWidth::U32},
        binobf::ir::IrType{binobf::ir::IrWidth::U32},
        binobf::ir::IrType{binobf::ir::IrWidth::U32}};
    result.returnType = binobf::ir::IrType{binobf::ir::IrWidth::U64};
    return result;
}

auto request(
    binobf::ir::NativeAbi source,
    binobf::ir::NativeAbi destination,
    binobf::BinaryFormat format) -> binobf::AbiAdapterRequest {
    return binobf::AbiAdapterRequest{
        .architecture = binobf::Architecture::X86,
        .format = format,
        .sourceAbi = source,
        .destinationAbi = destination,
        .signature = signature(),
        .symbol = "external_target",
        .stackAlignment = 16,
    };
}

} // namespace

TEST_CASE(x86_adapters_cover_all_five_abis_with_one_external_call_fixup) {
    auto fixed = backend();
    struct Case {
        binobf::ir::NativeAbi source;
        binobf::ir::NativeAbi destination;
        binobf::BinaryFormat format;
        std::uint64_t stackBytes;
        bool callerCleanup;
    };
    constexpr std::array cases{
        Case{binobf::ir::NativeAbi::WindowsI386Fastcall,
             binobf::ir::NativeAbi::WindowsI386Cdecl, binobf::BinaryFormat::COFF, 12U, true},
        Case{binobf::ir::NativeAbi::WindowsI386Fastcall,
             binobf::ir::NativeAbi::WindowsI386Stdcall, binobf::BinaryFormat::COFF, 12U, false},
        Case{binobf::ir::NativeAbi::WindowsI386Cdecl,
             binobf::ir::NativeAbi::WindowsI386Fastcall, binobf::BinaryFormat::COFF, 4U, false},
        Case{binobf::ir::NativeAbi::WindowsI386Cdecl,
             binobf::ir::NativeAbi::WindowsI386Thiscall, binobf::BinaryFormat::COFF, 8U, false},
        Case{binobf::ir::NativeAbi::WindowsI386Fastcall,
             binobf::ir::NativeAbi::SystemVI386, binobf::BinaryFormat::ELF, 12U, true},
    };
    for (const auto& value : cases) {
        const auto plan = fixed->build_abi_adapter(
            request(value.source, value.destination, value.format));
        REQUIRE(plan.has_value());
        REQUIRE_EQ(plan.value().stackArgumentBytes, value.stackBytes);
        REQUIRE_EQ(plan.value().callerCleansStack, value.callerCleanup);
        REQUIRE_EQ(plan.value().stackDelta, std::int64_t{0});
        REQUIRE(!plan.value().argumentMoves.empty());
        REQUIRE_EQ(plan.value().emission.fixups.size(), std::size_t{1});
        REQUIRE_EQ(plan.value().emission.fixups.front().kind,
                   binobf::MachineFixupKind::PcRelative32);
        REQUIRE_EQ(plan.value().emission.fixups.front().addend, std::int64_t{-4});
        REQUIRE_EQ(plan.value().emission.fixups.front().symbol, "external_target");
        REQUIRE(plan.value().clobbers.flags);
        REQUIRE(plan.value().clobbers.memory);
        REQUIRE(std::ranges::find(plan.value().clobbers.registers, "eax")
                != plan.value().clobbers.registers.end());
    }
}

TEST_CASE(x86_64_adapters_support_windows_sysv_and_macho) {
    auto fixed = backend_x64();
    auto value = binobf::AbiAdapterRequest{};
    value.architecture = binobf::Architecture::X86_64;
    value.format = binobf::BinaryFormat::MachO;
    value.sourceAbi = binobf::ir::NativeAbi::WindowsX64;
    value.destinationAbi = binobf::ir::NativeAbi::SystemVAMD64;
    value.signature = signature();
    value.symbol = "external_target";
    value.stackAlignment = 16;
    const auto plan = fixed->build_abi_adapter(value);
    REQUIRE(plan.has_value());
    REQUIRE_EQ(plan.value().emission.fixups.size(), std::size_t{1});
    REQUIRE_EQ(plan.value().emission.fixups.front().kind,
               binobf::MachineFixupKind::PcRelative32);
    REQUIRE_EQ(plan.value().stackDelta, std::int64_t{0});
    REQUIRE(plan.value().emission.bytes.size() > 0);
}

TEST_CASE(x86_64_unwind_emits_macho_dwarf64_and_preserves_windows_records) {
    auto fixed = backend_x64();
    binobf::UnwindRequest request{};
    request.architecture = binobf::Architecture::X86_64;
    request.format = binobf::BinaryFormat::MachO;
    request.codeStart = binobf::BinaryAddress{0x1000U};
    request.codeSize = 32;
    request.codeSymbol = "selected";
    request.actions.push_back(binobf::UnwindAction{
        .kind = binobf::UnwindActionKind::DefineCanonicalFrameAddress,
        .registerName = "rsp",
        .offset = 8,
        .codeOffset = 0,
    });
    const auto macho = fixed->build_unwind(request);
    REQUIRE(macho.has_value());
    REQUIRE_EQ(macho.value().encoding, binobf::UnwindEncoding::DwarfCfi64);
    REQUIRE_EQ(macho.value().fixups.size(), std::size_t{1});
    request.format = binobf::BinaryFormat::COFF;
    const auto coff = fixed->build_unwind(request);
    REQUIRE(coff.has_value());
    REQUIRE_EQ(coff.value().encoding, binobf::UnwindEncoding::WindowsX64);
}

TEST_CASE(x86_adapter_spills_register_sources_before_parallel_moves) {
    auto fixed = backend();
    auto value = request(
        binobf::ir::NativeAbi::WindowsI386Fastcall,
        binobf::ir::NativeAbi::WindowsI386Fastcall,
        binobf::BinaryFormat::COFF);
    value.signature.parameterTypes.resize(2);
    value.signature.parameterBindings = {
        binobf::ir::IrStorageLocation{binobf::ir::IrStorageKind::Register,
            binobf::ir::IrType{binobf::ir::IrWidth::U32}, "edx", 0, 4U, 4U, 0U},
        binobf::ir::IrStorageLocation{binobf::ir::IrStorageKind::Register,
            binobf::ir::IrType{binobf::ir::IrWidth::U32}, "ecx", 0, 4U, 4U, 1U},
    };
    const auto plan = fixed->build_abi_adapter(value);
    REQUIRE(plan.has_value());
    REQUIRE_EQ(plan.value().argumentMoves.size(), std::size_t{2});
    REQUIRE(plan.value().emission.bytes.size() >= std::size_t{12});
    REQUIRE_EQ(plan.value().emission.bytes[0], std::byte{0x55});
    REQUIRE_EQ(plan.value().emission.bytes[1], std::byte{0x89});
    REQUIRE_EQ(plan.value().emission.bytes[2], std::byte{0xe5});
    REQUIRE_EQ(plan.value().emission.bytes[3], std::byte{0x52});
    REQUIRE_EQ(plan.value().unwind.actions.front().registerName, "esp");
    REQUIRE_EQ(plan.value().unwind.actions.back().offset, INT64_C(4));
}

TEST_CASE(x86_adapter_validates_variadics_and_incompatible_layouts) {
    auto fixed = backend();
    auto variadic = request(
        binobf::ir::NativeAbi::WindowsI386Cdecl,
        binobf::ir::NativeAbi::WindowsI386Stdcall,
        binobf::BinaryFormat::COFF);
    variadic.signature.variadic = true;
    auto plan = fixed->build_abi_adapter(variadic);
    REQUIRE(!plan.has_value());
    REQUIRE_EQ(plan.error().code, "architecture.unsupported_variadic_abi");

    variadic.destinationAbi = binobf::ir::NativeAbi::WindowsI386Cdecl;
    REQUIRE(fixed->build_abi_adapter(variadic).has_value());
    variadic.destinationAbi = binobf::ir::NativeAbi::SystemVI386;
    variadic.format = binobf::BinaryFormat::ELF;
    REQUIRE(fixed->build_abi_adapter(variadic).has_value());

    auto vector = request(
        binobf::ir::NativeAbi::WindowsI386Cdecl,
        binobf::ir::NativeAbi::WindowsI386Fastcall,
        binobf::BinaryFormat::COFF);
    vector.signature.parameterTypes = {
        binobf::ir::IrType{binobf::ir::IrTypeKind::Vector, 32U, 4U}};
    plan = fixed->build_abi_adapter(vector);
    REQUIRE(plan.has_value());

    auto hiddenSret = request(
        binobf::ir::NativeAbi::WindowsI386Cdecl,
        binobf::ir::NativeAbi::WindowsI386Fastcall,
        binobf::BinaryFormat::COFF);
    hiddenSret.signature.parameterTypes = {
        binobf::ir::IrType{binobf::ir::IrTypeKind::Pointer, 32U}};
    hiddenSret.signature.returnType = binobf::ir::IrType{};
    REQUIRE(fixed->build_abi_adapter(hiddenSret).has_value());
}

TEST_CASE(x86_adapter_rejects_malformed_or_overlapping_explicit_bindings) {
    auto fixed = backend();
    auto value = request(
        binobf::ir::NativeAbi::WindowsI386Cdecl,
        binobf::ir::NativeAbi::WindowsI386Cdecl,
        binobf::BinaryFormat::COFF);
    value.signature.parameterBindings = {
        binobf::ir::IrStorageLocation{binobf::ir::IrStorageKind::Stack,
            binobf::ir::IrType{binobf::ir::IrWidth::U32}, "esp", 4, 4U, 4U, 0U},
        binobf::ir::IrStorageLocation{binobf::ir::IrStorageKind::Stack,
            binobf::ir::IrType{binobf::ir::IrWidth::U32}, "esp", 4, 4U, 4U, 1U},
        binobf::ir::IrStorageLocation{binobf::ir::IrStorageKind::Stack,
            binobf::ir::IrType{binobf::ir::IrWidth::U32}, "esp", 12, 4U, 4U, 2U},
    };
    auto plan = fixed->build_abi_adapter(value);
    REQUIRE(!plan.has_value());
    REQUIRE_EQ(plan.error().code, "architecture.incompatible_abi");

    value.signature.parameterBindings[1].offset = 8;
    value.signature.parameterBindings[2].readonly = true;
    plan = fixed->build_abi_adapter(value);
    REQUIRE(!plan.has_value());
    REQUIRE_EQ(plan.error().code, "architecture.incompatible_abi");

    value.signature.parameterBindings[2].readonly = false;
    value.signature.parameterBindings[2].offset =
        std::numeric_limits<std::int64_t>::max() - 3;
    plan = fixed->build_abi_adapter(value);
    REQUIRE(!plan.has_value());
    REQUIRE_EQ(plan.error().code, "architecture.incompatible_abi");
}

TEST_CASE(x86_adapter_accepts_each_canonical_i386_return_binding) {
    auto fixed = backend();
    struct ReturnCase {
        binobf::ir::IrType type;
        const char* name;
        std::uint64_t size;
    };
    const std::array cases{
        ReturnCase{binobf::ir::IrType{binobf::ir::IrWidth::U32}, "eax", 4U},
        ReturnCase{binobf::ir::IrType{binobf::ir::IrWidth::U64}, "edx:eax", 8U},
        ReturnCase{binobf::ir::IrType{binobf::ir::IrTypeKind::FloatingPoint, 64U}, "st0", 8U},
        ReturnCase{binobf::ir::IrType{binobf::ir::IrTypeKind::Vector, 32U, 4U}, "xmm0", 16U},
    };
    for (const auto& value : cases) {
        auto adapter = request(
            binobf::ir::NativeAbi::WindowsI386Cdecl,
            binobf::ir::NativeAbi::WindowsI386Cdecl,
            binobf::BinaryFormat::COFF);
        adapter.signature.returnType = value.type;
        binobf::ir::IrStorageLocation binding{};
        binding.kind = binobf::ir::IrStorageKind::Register;
        binding.type = value.type;
        binding.name = value.name;
        binding.size = value.size;
        binding.alignment = 4U;
        adapter.signature.returnBinding = binding;
        REQUIRE(fixed->build_abi_adapter(adapter).has_value());
    }

    auto incompatible = request(
        binobf::ir::NativeAbi::WindowsI386Cdecl,
        binobf::ir::NativeAbi::WindowsI386Cdecl,
        binobf::BinaryFormat::COFF);
    incompatible.signature.returnType = binobf::ir::IrType{binobf::ir::IrWidth::U32};
    binobf::ir::IrStorageLocation wrong{};
    wrong.kind = binobf::ir::IrStorageKind::Register;
    wrong.type = incompatible.signature.returnType;
    wrong.name = "ebx";
    wrong.size = 4U;
    wrong.alignment = 4U;
    incompatible.signature.returnBinding = wrong;
    const auto rejected = fixed->build_abi_adapter(incompatible);
    REQUIRE(!rejected.has_value());
    REQUIRE_EQ(rejected.error().code, "architecture.incompatible_abi");
}

TEST_CASE(x86_windows_unwind_is_leaf_only_or_owned_safeseh_preservation) {
    auto fixed = backend();
    binobf::UnwindRequest request{};
    request.architecture = binobf::Architecture::X86;
    request.format = binobf::BinaryFormat::COFF;
    request.codeStart = binobf::BinaryAddress{0x1000U, binobf::AddressKind::Virtual};
    request.codeSize = 16;
    auto plan = fixed->build_unwind(request);
    REQUIRE(plan.has_value());
    REQUIRE_EQ(plan.value().disposition, binobf::UnwindDisposition::NotRequired);
    REQUIRE_EQ(plan.value().encoding, binobf::UnwindEncoding::WindowsI386);
    REQUIRE(plan.value().encoded.empty());

    request.handlerSymbol = "handler";
    plan = fixed->build_unwind(request);
    REQUIRE(!plan.has_value());
    REQUIRE_EQ(plan.error().code, "architecture.unwind_unowned");
    request.handlerOwned = true;
    plan = fixed->build_unwind(request);
    REQUIRE(plan.has_value());
    REQUIRE_EQ(plan.value().disposition, binobf::UnwindDisposition::Preserve);
}

TEST_CASE(x86_elf_unwind_emits_bounded_dwarf_cfi_for_an_ebp_frame) {
    auto fixed = backend();
    binobf::UnwindRequest request{};
    request.architecture = binobf::Architecture::X86;
    request.format = binobf::BinaryFormat::ELF;
    request.codeStart = binobf::BinaryAddress{0x2000U, binobf::AddressKind::Virtual};
    request.codeSize = 32;
    request.codeSymbol = "owned_function";
    request.actions = {
        {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "esp", 4},
        {binobf::UnwindActionKind::SaveRegister, "eip", -4},
        {binobf::UnwindActionKind::SaveRegister, "ebp", -8, 1},
        {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "ebp", 8, 4},
        {binobf::UnwindActionKind::RestoreRegister, "ebp", 0, 28},
    };
    const auto plan = fixed->build_unwind(request);
    REQUIRE(plan.has_value());
    REQUIRE_EQ(plan.value().disposition, binobf::UnwindDisposition::Emit);
    REQUIRE_EQ(plan.value().encoding, binobf::UnwindEncoding::DwarfCfi32);
    REQUIRE_EQ(plan.value().actions, request.actions);
    REQUIRE(!plan.value().encoded.empty());
    REQUIRE(plan.value().encoded.size() <= request.limits.maxEmittedBytes);
    REQUIRE_EQ(plan.value().fixups.size(), std::size_t{1});
    REQUIRE_EQ(plan.value().fixups.front().kind, binobf::MachineFixupKind::PcRelative32);
    REQUIRE_EQ(plan.value().fixups.front().symbol, "owned_function");
    REQUIRE_EQ(plan.value().fixups.front().addend, INT64_C(0));
    REQUIRE_EQ(plan.value().encoded[plan.value().fixups.front().offset], std::byte{0});
    REQUIRE(plan.value().encoded[20] != std::byte{0});
}

TEST_CASE(x86_elf_unwind_rejects_unowned_or_out_of_order_actions) {
    auto fixed = backend();
    binobf::UnwindRequest request{};
    request.architecture = binobf::Architecture::X86;
    request.format = binobf::BinaryFormat::ELF;
    request.codeSize = 32;
    auto plan = fixed->build_unwind(request);
    REQUIRE(!plan.has_value());
    REQUIRE_EQ(plan.error().code, "architecture.unwind_unowned");

    request.codeSymbol = "owned_function";
    request.actions = {
        {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "ebp", 8, 8},
        {binobf::UnwindActionKind::RestoreRegister, "ebp", 0, 4},
    };
    plan = fixed->build_unwind(request);
    REQUIRE(!plan.has_value());
    REQUIRE_EQ(plan.error().code, "architecture.unwind_action");

    request.actions = {
        {binobf::UnwindActionKind::SaveRegister, "ebp",
         std::numeric_limits<std::int64_t>::min(), 0},
    };
    plan = fixed->build_unwind(request);
    REQUIRE(!plan.has_value());
    REQUIRE_EQ(plan.error().code, "architecture.unwind_action");
}

TEST_CASE(x86_unwind_rejects_ranges_that_do_not_fit_dwarf32) {
    auto fixed = backend();
    binobf::UnwindRequest request{};
    request.architecture = binobf::Architecture::X86;
    request.format = binobf::BinaryFormat::ELF;
    request.codeStart = binobf::BinaryAddress{UINT64_C(0xfffffff0), binobf::AddressKind::Virtual};
    request.codeSize = 32;
    request.codeSymbol = "owned_function";
    const auto plan = fixed->build_unwind(request);
    REQUIRE(!plan.has_value());
    REQUIRE_EQ(plan.error().code, "architecture.unwind_range");
}

int main() { return binobf::test::run_all(); }

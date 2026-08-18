#include <binobf/architecture/backend.hpp>

#include "../test_support.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <memory>

namespace {

auto backend() -> std::unique_ptr<binobf::ArchitectureBackend> {
    auto result = binobf::make_architecture_backend(binobf::Architecture::X86);
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

TEST_CASE(x86_adapter_cycles_are_broken_deterministically_through_eax) {
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
    REQUIRE(plan.value().emission.bytes.size() >= std::size_t{6});
    REQUIRE_EQ(plan.value().emission.bytes[0], std::byte{0x89});
    REQUIRE_EQ(plan.value().emission.bytes[1], std::byte{0xd0});
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
    request.actions = {
        {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "esp", 4},
        {binobf::UnwindActionKind::SaveRegister, "eip", -4},
        {binobf::UnwindActionKind::SaveRegister, "ebp", -8},
        {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "ebp", 8},
        {binobf::UnwindActionKind::RestoreRegister, "ebp", 0},
    };
    const auto plan = fixed->build_unwind(request);
    REQUIRE(plan.has_value());
    REQUIRE_EQ(plan.value().disposition, binobf::UnwindDisposition::Emit);
    REQUIRE_EQ(plan.value().encoding, binobf::UnwindEncoding::DwarfCfi32);
    REQUIRE_EQ(plan.value().actions, request.actions);
    REQUIRE(!plan.value().encoded.empty());
    REQUIRE(plan.value().encoded.size() <= request.limits.maxEmittedBytes);
}

TEST_CASE(x86_unwind_rejects_ranges_that_do_not_fit_dwarf32) {
    auto fixed = backend();
    binobf::UnwindRequest request{};
    request.architecture = binobf::Architecture::X86;
    request.format = binobf::BinaryFormat::ELF;
    request.codeStart = binobf::BinaryAddress{UINT64_C(0xfffffff0), binobf::AddressKind::Virtual};
    request.codeSize = 32;
    const auto plan = fixed->build_unwind(request);
    REQUIRE(!plan.has_value());
    REQUIRE_EQ(plan.error().code, "architecture.unwind_range");
}

int main() { return binobf::test::run_all(); }

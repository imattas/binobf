#include <binobf/architecture/backend.hpp>
#include <binobf/capabilities/evidence.hpp>
#include <binobf/capabilities/registry.hpp>
#include <binobf/ir/native.hpp>

#include <array>
#include <cstddef>
#include <span>
#include <string_view>

namespace {

struct Golden {
    binobf::Architecture architecture;
    binobf::BinaryFormat format;
    std::string_view triple;
    binobf::MachineSyntax syntax;
};

auto verify_provider(const Golden& golden, std::uint64_t id) -> bool {
    auto backend = binobf::make_architecture_backend(golden.architecture);
    if (!backend.has_value() || backend.value()->codegen() == nullptr) return false;
    binobf::MachineAssemblyRequest request{};
    request.architecture = golden.architecture;
    request.format = golden.format;
    request.triple = golden.triple;
    request.syntax = golden.syntax;
    request.assembly = "nop\nret\n";
    request.expectedInstructionCount = 2U;
    const auto emitted = backend.value()->codegen()->emit(request);
    if (!emitted.has_value() || emitted.value().bytes.empty()) return false;
    const auto decoded = backend.value()->decode(binobf::DecodeRequest{
        .architecture = golden.architecture,
        .bytes = std::span<const std::byte>{emitted.value().bytes},
        .address = {0x1000U, binobf::AddressKind::Virtual},
        .instructionId = binobf::EntityId{id},
        .sectionId = binobf::EntityId{1U},
        .sectionOffset = 0U,
    });
    return decoded.has_value() && !decoded.value().encoding.empty();
}

auto typed_module() -> binobf::ir::IrModule {
    using namespace binobf::ir;
    const IrType u32{IrTypeKind::Integer, 32U};
    const IrType pointer{IrTypeKind::Pointer, 64U};
    const IrFunctionSignature externalSignature{
        .callingConvention = IrCallingConvention::C,
        .parameterTypes = {u32},
        .returnType = u32,
        .variadic = false,
        .parameterBindings = {},
        .returnBinding = std::nullopt,
        .clobbers = IrCallClobbers{{"flags"}, true, true},
        .mayUnwind = true,
    };
    IrFunction function{
        .sourceFunction = binobf::EntityId{10U},
        .name = "installed-consumer",
        .arguments = {},
        .returnType = u32,
        .variableTypes = {pointer, u32},
        .storageLocations = {
            IrStorageLocation{IrStorageKind::Local, u32, "value", 0, 4U, 4U},
        },
        .signature = IrFunctionSignature{
            .callingConvention = IrCallingConvention::C,
            .parameterTypes = {},
            .returnType = u32,
            .variadic = false,
            .parameterBindings = {},
            .returnBinding = std::nullopt,
            .clobbers = {},
            .mayUnwind = true,
        },
        .entry = IrBlockId{0U},
        .blocks = {IrBlock{IrBlockId{0U}, binobf::EntityId{20U}, {
            IrAddressOf{IrVariable{0U}, 0U, binobf::EntityId{30U}},
            IrStore{u32, IrAddress{IrVariable{0U}, std::nullopt, 1U, 0, 0U, 4U},
                    IrIntegerConstant{u32, 7U}, IrByteOrder::Little, false,
                    IrAtomicOrdering::None, binobf::EntityId{31U}, std::nullopt},
            IrLoad{u32, IrVariable{1U},
                   IrAddress{IrVariable{0U}, std::nullopt, 1U, 0, 0U, 4U},
                   IrByteOrder::Little, false, IrAtomicOrdering::None,
                   binobf::EntityId{32U}, std::nullopt},
            IrExternalCall{"external_identity", externalSignature, IrVariable{1U},
                           {IrVariableOperand{IrVariable{1U}}},
                           binobf::EntityId{33U}, 1U},
            IrReturn{u32, IrVariable{1U}, binobf::EntityId{34U}},
        }}},
        .unwindRegions = {
            IrUnwindRegion{1U, IrUnwindRegionKind::Cleanup, std::nullopt,
                           IrBlockId{0U}, {IrBlockId{0U}}, {"cleanup"}},
        },
    };
    return IrModule{
        .entryFunction = function.sourceFunction,
        .declarations = {IrExternalDeclaration{"external_identity", externalSignature}},
        .functions = {std::move(function)},
    };
}

} // namespace

auto main() -> int {
    const std::array goldens{
        Golden{binobf::Architecture::X86, binobf::BinaryFormat::COFF,
               "i686-pc-windows-msvc", binobf::MachineSyntax::Intel},
        Golden{binobf::Architecture::X86_64, binobf::BinaryFormat::ELF,
               "x86_64-unknown-linux-gnu", binobf::MachineSyntax::Intel},
        Golden{binobf::Architecture::ARM64, binobf::BinaryFormat::ELF,
               "aarch64-unknown-linux-gnu", binobf::MachineSyntax::GNU},
    };
    std::uint64_t id = 1U;
    for (const auto& golden : goldens) {
        if (!verify_provider(golden, id++)) return 1;
    }
    if (!binobf::ir::validate_module(typed_module()).has_value()) return 2;
    if (!binobf::validate_capability_evidence(
             binobf::builtin_capability_registry(),
             binobf::builtin_acceptance_evidence()).has_value()) {
        return 3;
    }
    return 0;
}

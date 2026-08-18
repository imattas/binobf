#include <binobf/analysis/object_analyzer.hpp>
#include <binobf/architecture/backend.hpp>
#include <binobf/capabilities/evidence.hpp>
#include <binobf/capabilities/registry.hpp>
#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/transforms/instruction.hpp>
#include <binobf/transforms/pass_manager.hpp>

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace {

auto read_file(const std::filesystem::path& path) -> std::vector<std::byte> {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) return {};
    const auto end = stream.tellg();
    if (end <= 0) return {};
    std::vector<std::byte> bytes(static_cast<std::size_t>(end));
    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return stream ? bytes : std::vector<std::byte>{};
}

auto make_pass(std::size_t index) -> std::unique_ptr<binobf::TransformPass> {
    switch (index) {
    case 0: return binobf::make_instruction_substitution_pass();
    case 1: return binobf::make_constant_rewriting_pass();
    case 2: return binobf::make_branch_inversion_pass();
    case 3: return binobf::make_block_splitting_pass();
    case 4: return binobf::make_dead_code_insertion_pass();
    case 5: return binobf::make_block_reordering_pass();
    case 6: return binobf::make_function_reordering_pass();
    default: return {};
    }
}

auto verify_transforms(const std::filesystem::path& path) -> bool {
    const auto bytes = read_file(path);
    const auto parsed = binobf::parse_object(bytes, path.filename().string());
    if (!parsed.has_value() || parsed.value().architecture != binobf::Architecture::X86) {
        return false;
    }
    const auto analyzed = binobf::analyze_object(parsed.value());
    if (!analyzed.has_value()
        || !std::ranges::any_of(analyzed.value().image.functions, [](const auto& function) {
            return function.complete && !function.instructions.empty();
        })) {
        return false;
    }
    const bool hasUnmodeledUnwind = std::ranges::any_of(
        analyzed.value().image.unwindInfo, [](const auto& unwind) {
            return unwind.format == binobf::UnwindFormat::Unknown;
        });
    const bool hasOpaqueUnwind = std::ranges::any_of(
        analyzed.value().image.unwindInfo, [](const auto& unwind) {
            return unwind.rewriteState == binobf::UnwindRewriteState::Opaque;
        });
    for (std::size_t index = 0; index < 7; ++index) {
        binobf::PassManager manager;
        if (!manager.add(make_pass(index)).has_value()) return false;
        binobf::TransformContext context{UINT64_C(0x3861a57), false};
        const auto outcome = manager.run(context, analyzed.value().image);
        const auto expectedStatus = hasUnmodeledUnwind
            ? binobf::PassStatus::Unsupported
            : hasOpaqueUnwind && index >= 5U
                ? binobf::PassStatus::Unchanged
                : binobf::PassStatus::Applied;
        if (!outcome.has_value() || outcome.value().reports.size() != 1
            || outcome.value().reports.front().status
                != expectedStatus) {
            return false;
        }
        const auto written = binobf::write_object(outcome.value().image);
        if (!written.has_value()) return false;
        const auto reparsed = binobf::parse_object(written.value(), "installed-track3.o");
        if (!reparsed.has_value() || reparsed.value().architecture != binobf::Architecture::X86) {
            return false;
        }
    }
    return true;
}

auto verify_services() -> bool {
    auto backend = binobf::make_architecture_backend(binobf::Architecture::X86);
    if (!backend.has_value()) return false;
    for (const auto service : {
             binobf::BackendService::AnalyzeObject,
             binobf::BackendService::EmitCode,
             binobf::BackendService::EncodeFixups,
             binobf::BackendService::BuildAbiAdapter,
             binobf::BackendService::BuildUnwind}) {
        const auto* record = backend.value()->find_service(service);
        if (record == nullptr || record->support != binobf::SupportLevel::Supported
            || record->evidence.empty()) return false;
    }

    binobf::MachineTransformRequest templateRequest{};
    templateRequest.architecture = binobf::Architecture::X86;
    templateRequest.format = binobf::BinaryFormat::COFF;
    templateRequest.kind = binobf::MachineTransformKind::DeadCodeFill;
    templateRequest.exactSize = 5;
    const auto emitted = backend.value()->emit_transform(templateRequest);
    if (!emitted.has_value() || emitted.value().emission.bytes.size() != 5) return false;

    const auto semantics = backend.value()->fixup_semantics(binobf::BinaryFormat::COFF, 0x14);
    if (!semantics.has_value() || !semantics.value().pcRelative
        || semantics.value().pcBias != 4) return false;
    const auto encoded = backend.value()->encode_fixup(semantics.value(), 0);
    if (!encoded.has_value() || encoded.value().fieldBytes.size() != 4
        || encoded.value().fieldBytes.front() != std::byte{4}) return false;

    binobf::AbiAdapterRequest adapter{};
    adapter.architecture = binobf::Architecture::X86;
    adapter.format = binobf::BinaryFormat::COFF;
    adapter.sourceAbi = binobf::ir::NativeAbi::WindowsI386Cdecl;
    adapter.destinationAbi = binobf::ir::NativeAbi::WindowsI386Fastcall;
    adapter.signature.parameterTypes = {
        binobf::ir::IrType{binobf::ir::IrWidth::U32},
        binobf::ir::IrType{binobf::ir::IrWidth::U32}};
    adapter.signature.returnType = binobf::ir::IrType{binobf::ir::IrWidth::U32};
    adapter.symbol = "installed_external";
    adapter.stackAlignment = 16;
    const auto adapterPlan = backend.value()->build_abi_adapter(adapter);
    if (!adapterPlan.has_value() || adapterPlan.value().emission.fixups.size() != 1) {
        return false;
    }

    binobf::UnwindRequest windows{};
    windows.architecture = binobf::Architecture::X86;
    windows.format = binobf::BinaryFormat::COFF;
    windows.codeStart = {0x1000, binobf::AddressKind::Virtual};
    windows.codeSize = 16;
    const auto windowsPlan = backend.value()->build_unwind(windows);
    if (!windowsPlan.has_value()
        || windowsPlan.value().encoding != binobf::UnwindEncoding::WindowsI386) return false;

    binobf::UnwindRequest systemV{};
    systemV.architecture = binobf::Architecture::X86;
    systemV.format = binobf::BinaryFormat::ELF;
    systemV.codeStart = {0x2000, binobf::AddressKind::Virtual};
    systemV.codeSize = 16;
    systemV.codeSymbol = "installed_owned_function";
    systemV.actions = {
        {binobf::UnwindActionKind::DefineCanonicalFrameAddress, "esp", 4},
        {binobf::UnwindActionKind::SaveRegister, "eip", -4}};
    const auto systemVPlan = backend.value()->build_unwind(systemV);
    return systemVPlan.has_value()
        && systemVPlan.value().encoding == binobf::UnwindEncoding::DwarfCfi32;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 3) return 2;
    if (!verify_services()) return 3;
    if (!verify_transforms(argv[1]) || !verify_transforms(argv[2])) return 4;
    if (!binobf::validate_capability_evidence(
             binobf::builtin_capability_registry(),
             binobf::builtin_acceptance_evidence()).has_value()) return 5;
    return 0;
}

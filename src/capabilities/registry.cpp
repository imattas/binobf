#include <binobf/capabilities/registry.hpp>

#include <algorithm>
#include <cstdlib>
#include <initializer_list>

namespace binobf {
namespace {

using Evidence = std::initializer_list<std::string_view>;

auto format_record(Capability capability,
                   BinaryFormat format,
                   SupportLevel support,
                   std::string_view qualifier = {},
                   Evidence evidence = {}) -> CapabilityRecord {
    return CapabilityRecord{
        .key = {.capability = capability, .format = format},
        .support = support,
        .qualifier = qualifier,
        .evidence = {evidence},
    };
}

auto architecture_record(Capability capability,
                         Architecture architecture,
                         SupportLevel support,
                         std::string_view qualifier = {},
                         Evidence evidence = {}) -> CapabilityRecord {
    return CapabilityRecord{
        .key = {.capability = capability, .architecture = architecture},
        .support = support,
        .qualifier = qualifier,
        .evidence = {evidence},
    };
}

auto builtin_records() -> std::vector<CapabilityRecord> {
    using Architecture::ARM64;
    using Architecture::X86;
    using Architecture::X86_64;
    using BinaryFormat::Archive;
    using BinaryFormat::COFF;
    using BinaryFormat::ELF;
    using BinaryFormat::MachO;
    using BinaryFormat::PE;
    using enum Capability;
    using enum SupportLevel;

    return {
        format_record(Detection, PE, Supported, {}, {"format_detector"}),
        format_record(Detection, COFF, Supported, {}, {"format_detector"}),
        format_record(Detection, ELF, Supported, {}, {"format_detector"}),
        format_record(Detection, MachO, Supported, {}, {"format_detector"}),
        format_record(Detection, Archive, Supported, {}, {"format_detector"}),

        format_record(RelocatableObjectParsing, PE, NotApplicable),
        format_record(RelocatableObjectParsing, COFF, Supported, {}, {"coff_object_parser"}),
        format_record(RelocatableObjectParsing, ELF, Supported, {}, {"elf_object_parser"}),
        format_record(RelocatableObjectParsing, MachO, Supported, {}, {"macho_object_parser"}),
        format_record(RelocatableObjectParsing, Archive, Supported, "members", {"archive"}),

        format_record(LinkedImageParsing, PE, Supported, {}, {"linked_image"}),
        format_record(LinkedImageParsing, COFF, NotApplicable),
        format_record(LinkedImageParsing, ELF, Supported, {}, {"linked_image"}),
        format_record(LinkedImageParsing, MachO, NotApplicable),
        format_record(LinkedImageParsing, Archive, NotApplicable),

        format_record(StructuralVerification, PE, Supported, {}, {"structural_verifier"}),
        format_record(StructuralVerification, COFF, Supported, {}, {"structural_verifier"}),
        format_record(StructuralVerification, ELF, Supported, {}, {"structural_verifier"}),
        format_record(StructuralVerification, MachO, Supported, {}, {"structural_verifier"}),
        format_record(StructuralVerification, Archive, Supported, {}, {"archive"}),

        format_record(Emission, PE, Supported, {}, {"linked_image"}),
        format_record(Emission, COFF, Supported, {}, {"object_writer"}),
        format_record(Emission, ELF, Supported, {}, {"object_writer"}),
        format_record(Emission, MachO, Supported, {}, {"macho_object_writer"}),
        format_record(Emission, Archive, Supported, {}, {"archive"}),

        format_record(BaselineMetadataTransformation, PE, Supported, "strip-debug", {"baseline_transforms"}),
        format_record(BaselineMetadataTransformation, COFF, Supported, {}, {"baseline_transforms"}),
        format_record(BaselineMetadataTransformation, ELF, Supported, "including linked", {"baseline_transforms"}),
        format_record(BaselineMetadataTransformation, MachO, Planned),
        format_record(BaselineMetadataTransformation, Archive, Supported, "per object member", {"baseline_transforms"}),

        format_record(MachineCodeTransformation, PE, Planned),
        format_record(MachineCodeTransformation, COFF, Supported, {}, {"instruction_transforms"}),
        format_record(MachineCodeTransformation, ELF, Supported, {}, {"instruction_transforms"}),
        format_record(MachineCodeTransformation, MachO, Restricted, "x86-64 object backend"),
        format_record(MachineCodeTransformation, Archive, Supported, "per object member", {"instruction_transforms"}),

        format_record(VmLowering, PE, NotApplicable),
        format_record(VmLowering, COFF, Restricted),
        format_record(VmLowering, ELF, Restricted),
        format_record(VmLowering, MachO, Restricted),
        format_record(VmLowering, Archive, Unsupported),

        format_record(VmProtection, PE, NotApplicable),
        format_record(VmProtection, COFF, Restricted),
        format_record(VmProtection, ELF, Restricted),
        format_record(VmProtection, MachO, Restricted),
        format_record(VmProtection, Archive, Unsupported),

        architecture_record(Detection, X86, Supported, {}, {"format_detector"}),
        architecture_record(Detection, X86_64, Supported, {}, {"format_detector"}),
        architecture_record(Detection, ARM64, Supported, {}, {"format_detector"}),

        architecture_record(InstructionDecoding, X86, Supported, {}, {"instruction_decoder"}),
        architecture_record(InstructionDecoding, X86_64, Supported, {}, {"instruction_decoder"}),
        architecture_record(InstructionDecoding, ARM64, Supported, {}, {"instruction_decoder"}),

        architecture_record(ObjectAnalysis, X86, Supported, {}, {"x86_object_backend"}),
        architecture_record(ObjectAnalysis, X86_64, Supported, {}, {"object_analyzer"}),
        architecture_record(ObjectAnalysis, ARM64, Supported, {}, {"arm64_object_backend"}),

        architecture_record(
            CodeGeneration, X86, Supported, {},
            {"x86_abi_adapter", "x86_codegen", "x86_unwind"}),
        architecture_record(CodeGeneration, X86_64, Supported, {}, {"x86_64_codegen"}),
        architecture_record(
            CodeGeneration, ARM64, Supported, {},
            {"arm64_codegen", "arm64_abi_adapter", "arm64_unwind"}),
    };
}

} // namespace

auto CapabilityRegistry::create(std::span<const CapabilityRecord> records)
    -> Result<CapabilityRegistry, Diagnostic> {
    std::vector<CapabilityRecord> sorted(records.begin(), records.end());
    std::ranges::sort(sorted, {}, &CapabilityRecord::key);

    const auto duplicate = std::adjacent_find(
        sorted.begin(), sorted.end(), [](const CapabilityRecord& left, const CapabilityRecord& right) {
            return left.key == right.key;
        });
    if (duplicate != sorted.end()) {
        return Result<CapabilityRegistry, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "capability.duplicate_key",
            "capability registry contains a duplicate key",
        });
    }

    return Result<CapabilityRegistry, Diagnostic>::success(
        CapabilityRegistry{std::move(sorted)});
}

auto CapabilityRegistry::records() const noexcept -> std::span<const CapabilityRecord> {
    return records_;
}

auto CapabilityRegistry::find(const CapabilityKey& key) const noexcept
    -> const CapabilityRecord* {
    const auto found = std::ranges::lower_bound(records_, key, {}, &CapabilityRecord::key);
    if (found == records_.end() || found->key != key) {
        return nullptr;
    }
    return &*found;
}

auto builtin_capability_registry() -> const CapabilityRegistry& {
    static const auto registry = CapabilityRegistry::create(builtin_records());
    if (!registry.has_value()) {
        std::abort();
    }
    return registry.value();
}

auto to_string(Capability capability) noexcept -> std::string_view {
    switch (capability) {
    case Capability::Detection: return "detection";
    case Capability::RelocatableObjectParsing: return "relocatable-object parsing";
    case Capability::LinkedImageParsing: return "linked-image detailed parsing";
    case Capability::StructuralVerification: return "structural verification";
    case Capability::Emission: return "exact linked/object emission";
    case Capability::BaselineMetadataTransformation: return "baseline metadata transformations";
    case Capability::MachineCodeTransformation: return "x86/x86-64 instruction/CFG/layout transformations";
    case Capability::VmLowering: return "selected x86-64 function VM lowering";
    case Capability::VmProtection: return "embedded selected-function VM protection";
    case Capability::InstructionDecoding: return "decoder";
    case Capability::ObjectAnalysis: return "object analysis";
    case Capability::CodeGeneration: return "code generation";
    }
    return "unknown";
}

auto to_string(SupportLevel support) noexcept -> std::string_view {
    switch (support) {
    case SupportLevel::Supported: return "supported";
    case SupportLevel::Experimental: return "experimental";
    case SupportLevel::Restricted: return "restricted";
    case SupportLevel::Planned: return "planned";
    case SupportLevel::Unsupported: return "unsupported";
    case SupportLevel::NotApplicable: return "n/a";
    }
    return "unknown";
}

} // namespace binobf

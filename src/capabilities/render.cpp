#include <binobf/capabilities/render.hpp>

#include <binobf/transforms/registry.hpp>

#include <algorithm>
#include <array>
#include <sstream>
#include <string_view>
#include <vector>

namespace binobf {
namespace {

constexpr std::array kFormats{
    BinaryFormat::PE,
    BinaryFormat::COFF,
    BinaryFormat::ELF,
    BinaryFormat::Archive,
};

constexpr std::array kArchitectures{
    Architecture::X86,
    Architecture::X86_64,
    Architecture::ARM64,
};

constexpr std::array kFormatCapabilities{
    Capability::Detection,
    Capability::RelocatableObjectParsing,
    Capability::Emission,
    Capability::LinkedImageParsing,
    Capability::StructuralVerification,
    Capability::BaselineMetadataTransformation,
    Capability::MachineCodeTransformation,
    Capability::VmLowering,
    Capability::VmProtection,
};

constexpr std::array kFormatTextLabels{
    "detection",
    "parsing",
    "emission",
    "linked-parsing",
    "verification",
    "baseline-transformation",
    "machine-code-transformation",
    "vm-lowering",
    "vm-protection",
};

constexpr std::array kMarkdownFormatCapabilities{
    Capability::Detection,
    Capability::RelocatableObjectParsing,
    Capability::LinkedImageParsing,
    Capability::StructuralVerification,
    Capability::Emission,
    Capability::BaselineMetadataTransformation,
    Capability::MachineCodeTransformation,
    Capability::VmLowering,
    Capability::VmProtection,
};

constexpr std::array kMarkdownFormatLabels{
    "Header/container detection",
    "Relocatable-object parsing",
    "Linked-image detailed parsing",
    "Structural verification",
    "Exact linked/object emission",
    "Baseline metadata transformations",
    "x86/x86-64 instruction/CFG/layout transformations",
    "Selected x86-64 function VM lowering",
    "Embedded selected-function VM protection",
};

constexpr std::array kArchitectureCapabilities{
    Capability::Detection,
    Capability::InstructionDecoding,
    Capability::ObjectAnalysis,
    Capability::CodeGeneration,
};

auto render_record(const CapabilityRecord* record) -> std::string {
    if (record == nullptr) {
        return "missing";
    }
    std::string rendered{to_string(record->support)};
    if (!record->qualifier.empty()) {
        rendered.push_back(' ');
        rendered.append(record->qualifier);
    }
    return rendered;
}

auto format_record(const CapabilityRegistry& registry,
                   Capability capability,
                   BinaryFormat format) -> const CapabilityRecord* {
    return registry.find(CapabilityKey{.capability = capability, .format = format});
}

auto architecture_record(const CapabilityRegistry& registry,
                         Capability capability,
                         Architecture architecture) -> const CapabilityRecord* {
    return registry.find(
        CapabilityKey{.capability = capability, .architecture = architecture});
}

auto pass_risk_name(PassRisk risk) -> std::string_view {
    switch (risk) {
    case PassRisk::Low: return "low";
    case PassRisk::Medium: return "medium";
    case PassRisk::High: return "high";
    }
    return "unknown";
}

template <typename Item>
auto sorted_names(const std::vector<Item>& values) -> std::string {
    std::vector<std::string_view> names;
    names.reserve(values.size());
    for (const auto value : values) {
        names.push_back(to_string(value));
    }
    std::ranges::sort(names);

    std::string rendered;
    for (const auto name : names) {
        if (!rendered.empty()) {
            rendered.push_back(',');
        }
        rendered.append(name);
    }
    return rendered.empty() ? "none" : rendered;
}

} // namespace

auto render_format_capabilities_text(const CapabilityRegistry& registry)
    -> std::string {
    std::ostringstream output;
    for (const auto format : kFormats) {
        output << to_string(format);
        for (std::size_t index = 0; index < kFormatCapabilities.size(); ++index) {
            output << ' ' << kFormatTextLabels[index] << '='
                   << render_record(format_record(
                          registry, kFormatCapabilities[index], format));
        }
        output << '\n';
    }
    return output.str();
}

auto render_architecture_capabilities_text(const CapabilityRegistry& registry)
    -> std::string {
    constexpr std::array labels{"detection", "decoder", "object-analysis", "codegen"};
    std::ostringstream output;
    for (const auto architecture : kArchitectures) {
        output << to_string(architecture);
        for (std::size_t index = 0; index < kArchitectureCapabilities.size(); ++index) {
            output << ' ' << labels[index] << '='
                   << render_record(architecture_record(
                          registry, kArchitectureCapabilities[index], architecture));
        }
        output << '\n';
    }
    return output.str();
}

auto render_pass_capabilities_text() -> std::string {
    std::ostringstream output;
    for (const auto& registration : registered_passes()) {
        const auto pass = registration.factory == nullptr ? nullptr : registration.factory();
        if (pass == nullptr) {
            output << registration.name << " unavailable\n";
            continue;
        }
        const auto requirements = pass->requirements();
        output << pass->name()
               << " risk=" << pass_risk_name(requirements.risk)
               << " cfg=" << (requirements.requiresCfg ? "yes" : "no")
               << " relocations="
               << (requirements.requiresFullRelocations ? "required" : "not-required")
               << " lifted-ir=" << (requirements.requiresLiftedIr ? "yes" : "no")
               << " size-change=" << (requirements.changesCodeSize ? "yes" : "no")
               << " post-link=" << (requirements.supportedPostLink ? "supported" : "unsupported")
               << " formats=" << sorted_names(requirements.formats)
               << " architectures=" << sorted_names(requirements.architectures)
               << '\n';
    }
    return output.str();
}

auto render_feature_matrix_markdown(const CapabilityRegistry& registry)
    -> std::string {
    std::ostringstream output;
    output << "| Capability | PE | COFF object | ELF | Archive |\n"
           << "|---|---:|---:|---:|---:|\n";
    for (std::size_t row = 0; row < kMarkdownFormatCapabilities.size(); ++row) {
        output << "| " << kMarkdownFormatLabels[row];
        for (const auto format : kFormats) {
            output << " | " << render_record(format_record(
                registry, kMarkdownFormatCapabilities[row], format));
        }
        output << " |\n";
    }

    output << "\n"
           << "| Architecture | Detection | Decoder | Object analysis | Code generation |\n"
           << "|---|---:|---:|---:|---:|\n";
    constexpr std::array architectureLabels{"x86", "x86-64", "ARM64"};
    for (std::size_t row = 0; row < kArchitectures.size(); ++row) {
        output << "| " << architectureLabels[row];
        for (const auto capability : kArchitectureCapabilities) {
            output << " | " << render_record(architecture_record(
                registry, capability, kArchitectures[row]));
        }
        output << " |\n";
    }
    return output.str();
}

} // namespace binobf

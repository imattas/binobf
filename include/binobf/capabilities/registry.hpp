#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/result.hpp>
#include <binobf/core/types.hpp>

#include <compare>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace binobf {

enum class Capability : std::uint8_t {
    Detection,
    RelocatableObjectParsing,
    LinkedImageParsing,
    StructuralVerification,
    Emission,
    BaselineMetadataTransformation,
    MachineCodeTransformation,
    VmLowering,
    VmProtection,
    InstructionDecoding,
    ObjectAnalysis,
    CodeGeneration,
};

enum class SupportLevel : std::uint8_t {
    Supported,
    Experimental,
    Restricted,
    Planned,
    Unsupported,
    NotApplicable,
};

struct CapabilityKey {
    Capability capability{Capability::Detection};
    BinaryFormat format{BinaryFormat::Unknown};
    BinaryType binaryType{BinaryType::Unknown};
    Architecture architecture{Architecture::Unknown};

    auto operator<=>(const CapabilityKey&) const = default;
};

struct CapabilityRecord {
    CapabilityKey key;
    SupportLevel support{SupportLevel::Unsupported};
    std::string_view qualifier;
    std::vector<std::string_view> evidence;
};

class CapabilityRegistry {
public:
    [[nodiscard]] static auto create(std::span<const CapabilityRecord> records)
        -> Result<CapabilityRegistry, Diagnostic>;
    [[nodiscard]] auto records() const noexcept -> std::span<const CapabilityRecord>;
    [[nodiscard]] auto find(const CapabilityKey& key) const noexcept
        -> const CapabilityRecord*;

private:
    explicit CapabilityRegistry(std::vector<CapabilityRecord> records)
        : records_(std::move(records)) {}

    std::vector<CapabilityRecord> records_;
};

[[nodiscard]] auto builtin_capability_registry() -> const CapabilityRegistry&;
[[nodiscard]] auto to_string(Capability capability) noexcept -> std::string_view;
[[nodiscard]] auto to_string(SupportLevel support) noexcept -> std::string_view;

} // namespace binobf

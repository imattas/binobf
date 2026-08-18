#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/result.hpp>
#include <binobf/core/types.hpp>

#include <compare>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace binobf {

enum class MachineSyntax : std::uint8_t {
    Intel,
    GNU,
};

enum class RelocationModel : std::uint8_t {
    Static,
    PositionIndependent,
    DynamicNoPic,
};

enum class CodeModel : std::uint8_t {
    Small,
    Kernel,
    Medium,
    Large,
};

enum class MachineFixupKind : std::uint8_t {
    Absolute8,
    Absolute16,
    Absolute32,
    Absolute64,
    PcRelative8,
    PcRelative16,
    PcRelative32,
    PcRelative64,
    GotRelative32,
    PltRelative32,
    SectionRelative32,
    AArch64Branch26,
    AArch64Call26,
    AArch64Page21,
    AArch64PageOffset12,
    Segment12,
    MetadataToken32,
    SectionIndex16,
    SectionRelative7,
    GotOffset32,
    GotPcRelative32,
    Size32,
    TlsOffset32,
    TlsGot32,
    TlsGeneralDynamic32,
    TlsLocalDynamic32,
    AArch64Branch19,
    AArch64Branch14,
    AArch64Adr21,
    AArch64Low12,
    AArch64MoveWide16,
    AArch64GotPage21,
    AArch64GotLow12,
    AArch64TlsPage21,
    AArch64TlsLow12,
    AArch64TlsDescriptor,
};

struct MachineCodeLimits {
    std::size_t maxAssemblyBytes{1U << 20U};
    std::size_t maxLines{65536};
    std::size_t maxSymbols{65536};
    std::size_t maxEmittedBytes{16U << 20U};
    std::size_t maxFixups{1U << 20U};
    std::size_t maxInstructions{1U << 20U};
};

struct MachineAssemblyRequest {
    Architecture architecture{Architecture::Unknown};
    BinaryFormat format{BinaryFormat::Unknown};
    std::string triple;
    std::string cpu;
    std::string features;
    std::string assembly;
    std::string sectionName{".text"};
    BinaryAddress baseAddress{};
    MachineSyntax syntax{MachineSyntax::Intel};
    RelocationModel relocationModel{RelocationModel::Static};
    CodeModel codeModel{CodeModel::Small};
    MachineCodeLimits limits{};
    std::optional<std::size_t> expectedInstructionCount;
};

struct MachineFixup {
    std::uint64_t offset{0};
    std::uint8_t bitWidth{0};
    bool isSigned{false};
    bool pcRelative{false};
    std::int64_t addend{0};
    std::string symbol;
    MachineFixupKind kind{MachineFixupKind::Absolute32};

    auto operator<=>(const MachineFixup&) const = default;
};

struct MachineEmission {
    std::vector<std::byte> bytes;
    std::uint64_t alignment{1};
    std::vector<MachineFixup> fixups;
    std::vector<std::string> clobberedRegisters;
    std::vector<std::string> unwindActions;
    std::string provider;
};

class CodegenProvider {
public:
    virtual ~CodegenProvider() = default;

    [[nodiscard]] virtual auto architecture() const noexcept -> Architecture = 0;
    [[nodiscard]] virtual auto provider_version() const noexcept -> std::string_view = 0;
    [[nodiscard]] virtual auto emit(const MachineAssemblyRequest& request) const
        -> Result<MachineEmission, Diagnostic> = 0;
};

[[nodiscard]] auto make_codegen_provider(Architecture architecture)
    -> Result<std::unique_ptr<CodegenProvider>, Diagnostic>;

} // namespace binobf

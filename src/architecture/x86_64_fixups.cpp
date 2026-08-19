#include "x86_64_fixups.hpp"

#include "x86_fixups.hpp"

#include <algorithm>
#include <array>
#include <string>
#include <utility>

namespace binobf::detail {
namespace {

struct Row {
    BinaryFormat format;
    ObjectFixupSemantics semantics;
};

constexpr auto row(BinaryFormat format, std::uint64_t rawType, MachineFixupKind kind,
                   std::uint8_t width, bool isSigned, bool pcRelative,
                   bool implicitAddend, std::int8_t pcBias = 0) -> Row {
    return Row{format, ObjectFixupSemantics{.kind = kind,
                                             .rawType = rawType,
                                             .bitWidth = width,
                                             .isSigned = isSigned,
                                             .pcRelative = pcRelative,
                                             .implicitAddend = implicitAddend,
                                             .pcBias = pcBias}};
}

constexpr std::array rows{
    row(BinaryFormat::COFF, 0x0000, MachineFixupKind::Absolute32, 0, false, false, false),
    row(BinaryFormat::COFF, 0x0001, MachineFixupKind::Absolute64, 64, false, false, true),
    row(BinaryFormat::COFF, 0x0002, MachineFixupKind::Absolute32, 32, false, false, true),
    row(BinaryFormat::COFF, 0x0003, MachineFixupKind::ImageRelative32, 32, false, false, true),
    row(BinaryFormat::COFF, 0x0004, MachineFixupKind::PcRelative32, 32, true, true, true, 4),
    row(BinaryFormat::COFF, 0x0005, MachineFixupKind::PcRelative32, 32, true, true, true, 5),
    row(BinaryFormat::COFF, 0x0006, MachineFixupKind::PcRelative32, 32, true, true, true, 6),
    row(BinaryFormat::COFF, 0x0007, MachineFixupKind::PcRelative32, 32, true, true, true, 7),
    row(BinaryFormat::COFF, 0x0008, MachineFixupKind::PcRelative32, 32, true, true, true, 8),
    row(BinaryFormat::COFF, 0x0009, MachineFixupKind::PcRelative32, 32, true, true, true, 9),
    row(BinaryFormat::COFF, 0x000a, MachineFixupKind::SectionIndex16, 16, false, false, true),
    row(BinaryFormat::COFF, 0x000b, MachineFixupKind::SectionRelative32, 32, false, false, true),
    row(BinaryFormat::COFF, 0x000c, MachineFixupKind::SectionRelative7, 8, false, false, true),
    row(BinaryFormat::COFF, 0x000d, MachineFixupKind::MetadataToken32, 32, false, false, true),

    row(BinaryFormat::ELF, 0, MachineFixupKind::Absolute32, 0, false, false, false),
    row(BinaryFormat::ELF, 1, MachineFixupKind::Absolute64, 64, false, false, false),
    row(BinaryFormat::ELF, 2, MachineFixupKind::PcRelative32, 32, true, true, false),
    row(BinaryFormat::ELF, 3, MachineFixupKind::GotRelative32, 32, false, false, false),
    row(BinaryFormat::ELF, 4, MachineFixupKind::PltRelative32, 32, true, true, false),
    row(BinaryFormat::ELF, 9, MachineFixupKind::GotPcRelative32, 32, true, true, false),
    row(BinaryFormat::ELF, 10, MachineFixupKind::Absolute32, 32, false, false, false),
    row(BinaryFormat::ELF, 11, MachineFixupKind::Absolute32, 32, true, false, false),
    row(BinaryFormat::ELF, 12, MachineFixupKind::Absolute16, 16, false, false, false),
    row(BinaryFormat::ELF, 13, MachineFixupKind::PcRelative16, 16, true, true, false),
    row(BinaryFormat::ELF, 14, MachineFixupKind::Absolute8, 8, false, false, false),
    row(BinaryFormat::ELF, 15, MachineFixupKind::PcRelative8, 8, true, true, false),

    row(BinaryFormat::MachO, 0, MachineFixupKind::Absolute64, 64, false, false, true),
    row(BinaryFormat::MachO, 1, MachineFixupKind::PcRelative32, 32, true, true, true),
    row(BinaryFormat::MachO, 2, MachineFixupKind::PcRelative32, 32, true, true, true),
};

auto failure(std::string code, std::string message)
    -> Result<ObjectFixupSemantics, Diagnostic> {
    return Result<ObjectFixupSemantics, Diagnostic>::failure(
        Diagnostic{DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

} // namespace

auto x86_64_fixup_semantics(BinaryFormat format, std::uint64_t rawType)
    -> Result<ObjectFixupSemantics, Diagnostic> {
    const auto found = std::ranges::find_if(rows, [&](const auto& item) {
        return item.format == format && item.semantics.rawType == rawType;
    });
    if (found == rows.end()) {
        return failure("architecture.unsupported_fixup",
                       "unsupported x86-64 fixup for format " + std::string{to_string(format)}
                           + " and raw type " + std::to_string(rawType));
    }
    return Result<ObjectFixupSemantics, Diagnostic>::success(found->semantics);
}

auto encode_x86_64_fixup(const ObjectFixupSemantics& semantics, std::int64_t value)
    -> Result<ObjectFixupEncoding, Diagnostic> {
    return encode_x86_fixup(semantics, value);
}

auto decode_x86_64_fixup(const ObjectFixupSemantics& semantics,
                         std::span<const std::byte> fieldBytes)
    -> Result<std::int64_t, Diagnostic> {
    return decode_x86_fixup(semantics, fieldBytes);
}

} // namespace binobf::detail

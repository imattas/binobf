#include "arm64_fixups.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace binobf::detail {
namespace {

using Field = ObjectFixupFieldEncoding;
using Kind = MachineFixupKind;

struct FixupRow {
    BinaryFormat format;
    ObjectFixupSemantics semantics;
};

constexpr auto row(BinaryFormat format, std::uint64_t rawType, Kind kind, std::uint8_t bitWidth,
                   bool isSigned, bool pcRelative, bool implicitAddend,
                   Field fieldEncoding = Field::ScalarLittleEndian, std::uint8_t storageBytes = 0,
                   std::uint8_t rightShift = 0, std::uint8_t valueShift = 0,
                   std::int8_t pcBias = 0) noexcept -> FixupRow {
    return FixupRow{
        format,
        ObjectFixupSemantics{
            .kind = kind,
            .rawType = rawType,
            .bitWidth = bitWidth,
            .isSigned = isSigned,
            .pcRelative = pcRelative,
            .implicitAddend = implicitAddend,
            .pcBias = pcBias,
            .fieldEncoding = fieldEncoding,
            .storageBytes = storageBytes,
            .rightShift = rightShift,
            .valueShift = valueShift,
        },
    };
}

constexpr auto scalar(BinaryFormat format, std::uint64_t rawType, Kind kind, std::uint8_t bitWidth,
                      bool isSigned, bool pcRelative, bool implicitAddend,
                      std::int8_t pcBias = 0) noexcept -> FixupRow {
    return row(format, rawType, kind, bitWidth, isSigned, pcRelative, implicitAddend,
               Field::ScalarLittleEndian, static_cast<std::uint8_t>(bitWidth / 8U), 0, 0, pcBias);
}

constexpr auto instruction(BinaryFormat format, std::uint64_t rawType, Kind kind,
                           std::uint8_t bitWidth, bool isSigned, bool pcRelative,
                           bool implicitAddend, Field fieldEncoding, std::uint8_t rightShift = 0,
                           std::uint8_t valueShift = 0) noexcept -> FixupRow {
    return row(format, rawType, kind, bitWidth, isSigned, pcRelative, implicitAddend, fieldEncoding,
               4, rightShift, valueShift);
}

// Keep this table in raw relocation-number order within each format. AArch64
// ELF uses RELA, so its instruction fields do not carry the object addend.
constexpr std::array rows{
    row(BinaryFormat::COFF, 0x0000, Kind::Absolute32, 0, false, false, false),
    scalar(BinaryFormat::COFF, 0x0001, Kind::Absolute32, 32, false, false, true),
    scalar(BinaryFormat::COFF, 0x0002, Kind::ImageRelative32, 32, false, false, true),
    instruction(BinaryFormat::COFF, 0x0003, Kind::AArch64Branch26, 26, true, true, true,
                Field::AArch64Branch26, 2),
    instruction(BinaryFormat::COFF, 0x0004, Kind::AArch64Page21, 21, true, true, true,
                Field::AArch64Adrp21, 12),
    instruction(BinaryFormat::COFF, 0x0005, Kind::AArch64Adr21, 21, true, true, true,
                Field::AArch64Adr21),
    instruction(BinaryFormat::COFF, 0x0006, Kind::AArch64Low12, 12, false, false, true,
                Field::AArch64Low12),
    instruction(BinaryFormat::COFF, 0x0007, Kind::AArch64Low12, 12, false, false, true,
                Field::AArch64Low12),
    scalar(BinaryFormat::COFF, 0x0008, Kind::SectionRelative32, 32, false, false, true),
    instruction(BinaryFormat::COFF, 0x0009, Kind::AArch64Low12, 12, false, false, true,
                Field::AArch64Low12),
    instruction(BinaryFormat::COFF, 0x000a, Kind::AArch64Low12, 12, false, false, true,
                Field::AArch64Low12, 0, 12),
    instruction(BinaryFormat::COFF, 0x000b, Kind::AArch64Low12, 12, false, false, true,
                Field::AArch64Low12),
    scalar(BinaryFormat::COFF, 0x000c, Kind::MetadataToken32, 32, false, false, true),
    scalar(BinaryFormat::COFF, 0x000d, Kind::SectionIndex16, 16, false, false, true),
    scalar(BinaryFormat::COFF, 0x000e, Kind::Absolute64, 64, false, false, true),
    instruction(BinaryFormat::COFF, 0x000f, Kind::AArch64Branch19, 19, true, true, true,
                Field::AArch64Branch19, 2),
    instruction(BinaryFormat::COFF, 0x0010, Kind::AArch64Branch14, 14, true, true, true,
                Field::AArch64Branch14, 2),
    scalar(BinaryFormat::COFF, 0x0011, Kind::PcRelative32, 32, true, true, true, 4),

    row(BinaryFormat::ELF, 0x000, Kind::Absolute64, 0, false, false, false),
    scalar(BinaryFormat::ELF, 0x101, Kind::Absolute64, 64, false, false, false),
    scalar(BinaryFormat::ELF, 0x102, Kind::Absolute32, 32, false, false, false),
    scalar(BinaryFormat::ELF, 0x103, Kind::Absolute16, 16, false, false, false),
    scalar(BinaryFormat::ELF, 0x104, Kind::PcRelative64, 64, true, true, false),
    scalar(BinaryFormat::ELF, 0x105, Kind::PcRelative32, 32, true, true, false),
    scalar(BinaryFormat::ELF, 0x106, Kind::PcRelative16, 16, true, true, false),
    instruction(BinaryFormat::ELF, 0x107, Kind::AArch64MoveWide16, 16, false, false, false,
                Field::AArch64MoveWide16, 0, 0),
    instruction(BinaryFormat::ELF, 0x108, Kind::AArch64MoveWide16, 16, false, false, false,
                Field::AArch64MoveWide16, 0, 0),
    instruction(BinaryFormat::ELF, 0x109, Kind::AArch64MoveWide16, 16, false, false, false,
                Field::AArch64MoveWide16, 0, 16),
    instruction(BinaryFormat::ELF, 0x10a, Kind::AArch64MoveWide16, 16, false, false, false,
                Field::AArch64MoveWide16, 0, 16),
    instruction(BinaryFormat::ELF, 0x10b, Kind::AArch64MoveWide16, 16, false, false, false,
                Field::AArch64MoveWide16, 0, 32),
    instruction(BinaryFormat::ELF, 0x10c, Kind::AArch64MoveWide16, 16, false, false, false,
                Field::AArch64MoveWide16, 0, 32),
    instruction(BinaryFormat::ELF, 0x10d, Kind::AArch64MoveWide16, 16, false, false, false,
                Field::AArch64MoveWide16, 0, 48),
    instruction(BinaryFormat::ELF, 0x10e, Kind::AArch64MoveWide16, 16, true, false, false,
                Field::AArch64MoveWide16, 0, 0),
    instruction(BinaryFormat::ELF, 0x10f, Kind::AArch64MoveWide16, 16, true, false, false,
                Field::AArch64MoveWide16, 0, 16),
    instruction(BinaryFormat::ELF, 0x110, Kind::AArch64MoveWide16, 16, true, false, false,
                Field::AArch64MoveWide16, 0, 32),
    instruction(BinaryFormat::ELF, 0x111, Kind::AArch64Branch19, 19, true, true, false,
                Field::AArch64Branch19, 2),
    instruction(BinaryFormat::ELF, 0x112, Kind::AArch64Adr21, 21, true, true, false,
                Field::AArch64Adr21),
    instruction(BinaryFormat::ELF, 0x113, Kind::AArch64Page21, 21, true, true, false,
                Field::AArch64Adrp21, 12),
    instruction(BinaryFormat::ELF, 0x114, Kind::AArch64Page21, 21, true, true, false,
                Field::AArch64Adrp21, 12),
    instruction(BinaryFormat::ELF, 0x115, Kind::AArch64Low12, 12, false, false, false,
                Field::AArch64Low12),
    instruction(BinaryFormat::ELF, 0x116, Kind::AArch64Low12, 12, false, false, false,
                Field::AArch64Low12),
    instruction(BinaryFormat::ELF, 0x117, Kind::AArch64Branch14, 14, true, true, false,
                Field::AArch64Branch14, 2),
    instruction(BinaryFormat::ELF, 0x118, Kind::AArch64Branch19, 19, true, true, false,
                Field::AArch64Branch19, 2),
    instruction(BinaryFormat::ELF, 0x11a, Kind::AArch64Branch26, 26, true, true, false,
                Field::AArch64Branch26, 2),
    instruction(BinaryFormat::ELF, 0x11b, Kind::AArch64Call26, 26, true, true, false,
                Field::AArch64Branch26, 2),
    instruction(BinaryFormat::ELF, 0x11c, Kind::AArch64Low12, 12, false, false, false,
                Field::AArch64Low12, 1),
    instruction(BinaryFormat::ELF, 0x11d, Kind::AArch64Low12, 12, false, false, false,
                Field::AArch64Low12, 2),
    instruction(BinaryFormat::ELF, 0x11e, Kind::AArch64Low12, 12, false, false, false,
                Field::AArch64Low12, 3),
    instruction(BinaryFormat::ELF, 0x11f, Kind::AArch64MoveWide16, 16, true, true, false,
                Field::AArch64MoveWide16, 0, 0),
    instruction(BinaryFormat::ELF, 0x120, Kind::AArch64MoveWide16, 16, true, true, false,
                Field::AArch64MoveWide16, 0, 0),
    instruction(BinaryFormat::ELF, 0x121, Kind::AArch64MoveWide16, 16, true, true, false,
                Field::AArch64MoveWide16, 0, 16),
    instruction(BinaryFormat::ELF, 0x122, Kind::AArch64MoveWide16, 16, true, true, false,
                Field::AArch64MoveWide16, 0, 16),
    instruction(BinaryFormat::ELF, 0x123, Kind::AArch64MoveWide16, 16, true, true, false,
                Field::AArch64MoveWide16, 0, 32),
    instruction(BinaryFormat::ELF, 0x124, Kind::AArch64MoveWide16, 16, true, true, false,
                Field::AArch64MoveWide16, 0, 32),
    instruction(BinaryFormat::ELF, 0x125, Kind::AArch64MoveWide16, 16, true, true, false,
                Field::AArch64MoveWide16, 0, 48),
    instruction(BinaryFormat::ELF, 0x12b, Kind::AArch64Low12, 12, false, false, false,
                Field::AArch64Low12, 4),
    instruction(BinaryFormat::ELF, 0x12c, Kind::AArch64MoveWide16, 16, true, false, false,
                Field::AArch64MoveWide16, 0, 0),
    instruction(BinaryFormat::ELF, 0x12d, Kind::AArch64MoveWide16, 16, true, false, false,
                Field::AArch64MoveWide16, 0, 0),
    instruction(BinaryFormat::ELF, 0x12e, Kind::AArch64MoveWide16, 16, true, false, false,
                Field::AArch64MoveWide16, 0, 16),
    instruction(BinaryFormat::ELF, 0x12f, Kind::AArch64MoveWide16, 16, true, false, false,
                Field::AArch64MoveWide16, 0, 16),
    instruction(BinaryFormat::ELF, 0x130, Kind::AArch64MoveWide16, 16, true, false, false,
                Field::AArch64MoveWide16, 0, 32),
    instruction(BinaryFormat::ELF, 0x131, Kind::AArch64MoveWide16, 16, true, false, false,
                Field::AArch64MoveWide16, 0, 32),
    instruction(BinaryFormat::ELF, 0x132, Kind::AArch64MoveWide16, 16, true, false, false,
                Field::AArch64MoveWide16, 0, 48),
    scalar(BinaryFormat::ELF, 0x133, Kind::GotRelative32, 64, true, false, false),
    scalar(BinaryFormat::ELF, 0x134, Kind::GotRelative32, 32, true, false, false),
    instruction(BinaryFormat::ELF, 0x135, Kind::AArch64GotLow12, 19, true, true, false,
                Field::AArch64Branch19, 2),
    instruction(BinaryFormat::ELF, 0x136, Kind::AArch64GotLow12, 12, false, false, false,
                Field::AArch64Low12, 3),
    instruction(BinaryFormat::ELF, 0x137, Kind::AArch64GotPage21, 21, true, true, false,
                Field::AArch64Adrp21, 12),
    instruction(BinaryFormat::ELF, 0x138, Kind::AArch64GotLow12, 12, false, false, false,
                Field::AArch64Low12, 3),
    instruction(BinaryFormat::ELF, 0x139, Kind::AArch64GotLow12, 12, false, false, false,
                Field::AArch64Low12, 3),
    scalar(BinaryFormat::ELF, 0x13a, Kind::PltRelative32, 32, true, true, false),
    scalar(BinaryFormat::ELF, 0x13b, Kind::GotPcRelative32, 32, true, true, false),

    instruction(BinaryFormat::ELF, 0x200, Kind::AArch64TlsPage21, 21, true, true, false,
                Field::AArch64Adr21),
    instruction(BinaryFormat::ELF, 0x201, Kind::AArch64TlsPage21, 21, true, true, false,
                Field::AArch64Adrp21, 12),
    instruction(BinaryFormat::ELF, 0x202, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12),
    instruction(BinaryFormat::ELF, 0x203, Kind::AArch64TlsLow12, 16, false, false, false,
                Field::AArch64MoveWide16, 0, 16),
    instruction(BinaryFormat::ELF, 0x204, Kind::AArch64TlsLow12, 16, false, false, false,
                Field::AArch64MoveWide16),
    instruction(BinaryFormat::ELF, 0x205, Kind::AArch64TlsPage21, 21, true, true, false,
                Field::AArch64Adr21),
    instruction(BinaryFormat::ELF, 0x206, Kind::AArch64TlsPage21, 21, true, true, false,
                Field::AArch64Adrp21, 12),
    instruction(BinaryFormat::ELF, 0x207, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12),
    instruction(BinaryFormat::ELF, 0x208, Kind::AArch64TlsLow12, 16, false, false, false,
                Field::AArch64MoveWide16, 0, 16),
    instruction(BinaryFormat::ELF, 0x209, Kind::AArch64TlsLow12, 16, false, false, false,
                Field::AArch64MoveWide16),
    instruction(BinaryFormat::ELF, 0x20a, Kind::AArch64TlsPage21, 19, true, true, false,
                Field::AArch64Branch19, 2),
    instruction(BinaryFormat::ELF, 0x20b, Kind::AArch64TlsLow12, 16, false, false, false,
                Field::AArch64MoveWide16, 0, 32),
    instruction(BinaryFormat::ELF, 0x20c, Kind::AArch64TlsLow12, 16, false, false, false,
                Field::AArch64MoveWide16, 0, 16),
    instruction(BinaryFormat::ELF, 0x20d, Kind::AArch64TlsLow12, 16, false, false, false,
                Field::AArch64MoveWide16, 0, 16),
    instruction(BinaryFormat::ELF, 0x20e, Kind::AArch64TlsLow12, 16, false, false, false,
                Field::AArch64MoveWide16),
    instruction(BinaryFormat::ELF, 0x20f, Kind::AArch64TlsLow12, 16, false, false, false,
                Field::AArch64MoveWide16),
    instruction(BinaryFormat::ELF, 0x210, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12, 0, 12),
    instruction(BinaryFormat::ELF, 0x211, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12),
    instruction(BinaryFormat::ELF, 0x212, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12),
    instruction(BinaryFormat::ELF, 0x213, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12),
    instruction(BinaryFormat::ELF, 0x214, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12),
    instruction(BinaryFormat::ELF, 0x215, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12, 1),
    instruction(BinaryFormat::ELF, 0x216, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12, 1),
    instruction(BinaryFormat::ELF, 0x217, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12, 2),
    instruction(BinaryFormat::ELF, 0x218, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12, 2),
    instruction(BinaryFormat::ELF, 0x219, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12, 3),
    instruction(BinaryFormat::ELF, 0x21a, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12, 3),
    instruction(BinaryFormat::ELF, 0x21b, Kind::AArch64TlsLow12, 16, false, false, false,
                Field::AArch64MoveWide16, 0, 16),
    instruction(BinaryFormat::ELF, 0x21c, Kind::AArch64TlsLow12, 16, false, false, false,
                Field::AArch64MoveWide16),
    instruction(BinaryFormat::ELF, 0x21d, Kind::AArch64TlsPage21, 21, true, true, false,
                Field::AArch64Adrp21, 12),
    instruction(BinaryFormat::ELF, 0x21e, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12, 3),
    instruction(BinaryFormat::ELF, 0x21f, Kind::AArch64TlsPage21, 19, true, true, false,
                Field::AArch64Branch19, 2),
    instruction(BinaryFormat::ELF, 0x220, Kind::AArch64TlsLow12, 16, false, false, false,
                Field::AArch64MoveWide16, 0, 32),
    instruction(BinaryFormat::ELF, 0x221, Kind::AArch64TlsLow12, 16, false, false, false,
                Field::AArch64MoveWide16, 0, 16),
    instruction(BinaryFormat::ELF, 0x222, Kind::AArch64TlsLow12, 16, false, false, false,
                Field::AArch64MoveWide16, 0, 16),
    instruction(BinaryFormat::ELF, 0x223, Kind::AArch64TlsLow12, 16, false, false, false,
                Field::AArch64MoveWide16),
    instruction(BinaryFormat::ELF, 0x224, Kind::AArch64TlsLow12, 16, false, false, false,
                Field::AArch64MoveWide16),
    instruction(BinaryFormat::ELF, 0x225, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12, 0, 12),
    instruction(BinaryFormat::ELF, 0x226, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12),
    instruction(BinaryFormat::ELF, 0x227, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12),
    instruction(BinaryFormat::ELF, 0x228, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12),
    instruction(BinaryFormat::ELF, 0x229, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12),
    instruction(BinaryFormat::ELF, 0x22a, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12, 1),
    instruction(BinaryFormat::ELF, 0x22b, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12, 1),
    instruction(BinaryFormat::ELF, 0x22c, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12, 2),
    instruction(BinaryFormat::ELF, 0x22d, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12, 2),
    instruction(BinaryFormat::ELF, 0x22e, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12, 3),
    instruction(BinaryFormat::ELF, 0x22f, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12, 3),
    instruction(BinaryFormat::ELF, 0x230, Kind::AArch64TlsDescriptor, 19, true, true, false,
                Field::AArch64Branch19, 2),
    instruction(BinaryFormat::ELF, 0x231, Kind::AArch64TlsDescriptor, 21, true, true, false,
                Field::AArch64Adr21),
    instruction(BinaryFormat::ELF, 0x232, Kind::AArch64TlsDescriptor, 21, true, true, false,
                Field::AArch64Adrp21, 12),
    instruction(BinaryFormat::ELF, 0x233, Kind::AArch64TlsDescriptor, 12, false, false, false,
                Field::AArch64Low12, 3),
    instruction(BinaryFormat::ELF, 0x234, Kind::AArch64TlsDescriptor, 12, false, false, false,
                Field::AArch64Low12),
    instruction(BinaryFormat::ELF, 0x235, Kind::AArch64TlsDescriptor, 16, false, false, false,
                Field::AArch64MoveWide16, 0, 16),
    instruction(BinaryFormat::ELF, 0x236, Kind::AArch64TlsDescriptor, 16, false, false, false,
                Field::AArch64MoveWide16),
    row(BinaryFormat::ELF, 0x237, Kind::AArch64TlsDescriptor, 0, false, false, false),
    row(BinaryFormat::ELF, 0x238, Kind::AArch64TlsDescriptor, 0, false, false, false),
    row(BinaryFormat::ELF, 0x239, Kind::AArch64TlsDescriptor, 0, false, false, false),
    instruction(BinaryFormat::ELF, 0x23a, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12, 4),
    instruction(BinaryFormat::ELF, 0x23b, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12, 4),
    instruction(BinaryFormat::ELF, 0x23c, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12, 4),
    instruction(BinaryFormat::ELF, 0x23d, Kind::AArch64TlsLow12, 12, false, false, false,
                Field::AArch64Low12, 4),

    scalar(BinaryFormat::ELF, 0x404, Kind::TlsGeneralDynamic32, 64, false, false, false),
    scalar(BinaryFormat::ELF, 0x405, Kind::TlsLocalDynamic32, 64, true, false, false),
    scalar(BinaryFormat::ELF, 0x406, Kind::TlsOffset32, 64, true, false, false),
    scalar(BinaryFormat::ELF, 0x407, Kind::AArch64TlsDescriptor, 64, false, false, false),
};

constexpr auto key_less(const FixupRow &left, const FixupRow &right) noexcept -> bool {
    const auto leftFormat = static_cast<std::uint8_t>(left.format);
    const auto rightFormat = static_cast<std::uint8_t>(right.format);
    return leftFormat < rightFormat ||
           (leftFormat == rightFormat && left.semantics.rawType < right.semantics.rawType);
}

consteval auto rows_are_strictly_sorted() -> bool {
    for (std::size_t index = 1; index < rows.size(); ++index) {
        if (!key_less(rows[index - 1U], rows[index]))
            return false;
    }
    return true;
}

static_assert(rows_are_strictly_sorted(), "ARM64 fixup keys must be sorted and unique");

template <typename T> auto failure(std::string code, std::string message) -> Result<T, Diagnostic> {
    return Result<T, Diagnostic>::failure(
        Diagnostic{DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

auto checked_add(std::int64_t left, std::int64_t right) -> std::optional<std::int64_t> {
    if ((right > 0 && left > std::numeric_limits<std::int64_t>::max() - right) ||
        (right < 0 && left < std::numeric_limits<std::int64_t>::min() - right)) {
        return std::nullopt;
    }
    return left + right;
}

constexpr auto bit_mask(std::uint8_t width) noexcept -> std::uint64_t {
    return width == 64U ? std::numeric_limits<std::uint64_t>::max() : (UINT64_C(1) << width) - 1U;
}

auto signed_fits(std::int64_t value, std::uint8_t width) noexcept -> bool {
    if (width == 64U)
        return true;
    const auto maximum = (INT64_C(1) << (width - 1U)) - 1;
    const auto minimum = -(INT64_C(1) << (width - 1U));
    return value >= minimum && value <= maximum;
}

auto semantics_are_valid(const ObjectFixupSemantics &semantics) noexcept -> bool {
    if (semantics.pcBias != 0 && !semantics.pcRelative)
        return false;
    if (semantics.bitWidth == 0U) {
        return semantics.storageBytes == 0U && semantics.rightShift == 0U &&
               semantics.valueShift == 0U && semantics.fieldEncoding == Field::ScalarLittleEndian;
    }
    if (semantics.rightShift >= 63U || semantics.valueShift >= 64U)
        return false;
    switch (semantics.fieldEncoding) {
    case Field::ScalarLittleEndian:
        return (semantics.bitWidth == 8U || semantics.bitWidth == 16U ||
                semantics.bitWidth == 32U || semantics.bitWidth == 64U) &&
               semantics.storageBytes == semantics.bitWidth / 8U && semantics.rightShift == 0U &&
               semantics.valueShift == 0U;
    case Field::AArch64Branch26:
        return semantics.bitWidth == 26U && semantics.storageBytes == 4U &&
               semantics.rightShift == 2U && semantics.valueShift == 0U;
    case Field::AArch64Branch19:
        return semantics.bitWidth == 19U && semantics.storageBytes == 4U &&
               semantics.rightShift == 2U && semantics.valueShift == 0U;
    case Field::AArch64Branch14:
        return semantics.bitWidth == 14U && semantics.storageBytes == 4U &&
               semantics.rightShift == 2U && semantics.valueShift == 0U;
    case Field::AArch64Adr21:
        return semantics.bitWidth == 21U && semantics.storageBytes == 4U &&
               semantics.rightShift == 0U && semantics.valueShift == 0U;
    case Field::AArch64Adrp21:
        return semantics.bitWidth == 21U && semantics.storageBytes == 4U &&
               semantics.rightShift == 12U && semantics.valueShift == 0U;
    case Field::AArch64Low12:
        return semantics.bitWidth == 12U && semantics.storageBytes == 4U &&
               semantics.rightShift <= 4U &&
               (semantics.valueShift == 0U || semantics.valueShift == 12U);
    case Field::AArch64MoveWide16:
        return semantics.bitWidth == 16U && semantics.storageBytes == 4U &&
               semantics.rightShift == 0U && semantics.valueShift % 16U == 0U &&
               semantics.valueShift <= 48U;
    }
    return false;
}

auto little_endian(std::uint64_t value, std::size_t size) -> std::vector<std::byte> {
    std::vector<std::byte> result(size);
    for (std::size_t index = 0; index < size; ++index) {
        result[index] =
            static_cast<std::byte>((value >> static_cast<unsigned int>(index * 8U)) & 0xffU);
    }
    return result;
}

auto read_little_endian(std::span<const std::byte> bytes) noexcept -> std::uint64_t {
    std::uint64_t result = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        result |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(bytes[index]))
                  << static_cast<unsigned int>(index * 8U);
    }
    return result;
}

auto sign_extend(std::uint64_t value, std::uint8_t width) noexcept -> std::int64_t {
    if (width == 64U)
        return std::bit_cast<std::int64_t>(value);
    const auto mask = bit_mask(width);
    value &= mask;
    if ((value & (UINT64_C(1) << (width - 1U))) != 0U)
        value |= ~mask;
    return std::bit_cast<std::int64_t>(value);
}

auto instruction_mask(Field field) noexcept -> std::uint32_t {
    switch (field) {
    case Field::AArch64Branch26:
        return 0x03ffffffU;
    case Field::AArch64Branch19:
        return 0x00ffffe0U;
    case Field::AArch64Branch14:
        return 0x0007ffe0U;
    case Field::AArch64Adr21:
    case Field::AArch64Adrp21:
        return 0x60ffffe0U;
    case Field::AArch64Low12:
        return 0x003ffc00U;
    case Field::AArch64MoveWide16:
        return 0x001fffe0U;
    case Field::ScalarLittleEndian:
        return 0;
    }
    return 0;
}

auto encode_instruction_bits(Field field, std::uint64_t logical) noexcept -> std::uint32_t {
    switch (field) {
    case Field::AArch64Branch26:
        return static_cast<std::uint32_t>(logical & 0x03ffffffU);
    case Field::AArch64Branch19:
        return static_cast<std::uint32_t>((logical & 0x7ffffU) << 5U);
    case Field::AArch64Branch14:
        return static_cast<std::uint32_t>((logical & 0x3fffU) << 5U);
    case Field::AArch64Adr21:
    case Field::AArch64Adrp21:
        return static_cast<std::uint32_t>(((logical & 0x3U) << 29U) |
                                          (((logical >> 2U) & 0x7ffffU) << 5U));
    case Field::AArch64Low12:
        return static_cast<std::uint32_t>((logical & 0xfffU) << 10U);
    case Field::AArch64MoveWide16:
        return static_cast<std::uint32_t>((logical & 0xffffU) << 5U);
    case Field::ScalarLittleEndian:
        return 0;
    }
    return 0;
}

auto decode_instruction_bits(Field field, std::uint32_t encoded) noexcept -> std::uint64_t {
    switch (field) {
    case Field::AArch64Branch26:
        return encoded & 0x03ffffffU;
    case Field::AArch64Branch19:
        return (encoded >> 5U) & 0x7ffffU;
    case Field::AArch64Branch14:
        return (encoded >> 5U) & 0x3fffU;
    case Field::AArch64Adr21:
    case Field::AArch64Adrp21:
        return ((encoded >> 29U) & 0x3U) | (((encoded >> 5U) & 0x7ffffU) << 2U);
    case Field::AArch64Low12:
        return (encoded >> 10U) & 0xfffU;
    case Field::AArch64MoveWide16:
        return (encoded >> 5U) & 0xffffU;
    case Field::ScalarLittleEndian:
        return 0;
    }
    return 0;
}

} // namespace

auto arm64_fixup_semantics(BinaryFormat format, std::uint64_t rawType)
    -> Result<ObjectFixupSemantics, Diagnostic> {
    const FixupRow key{format, ObjectFixupSemantics{.rawType = rawType}};
    const auto found = std::lower_bound(rows.begin(), rows.end(), key, key_less);
    if (found == rows.end() || found->format != format || found->semantics.rawType != rawType) {
        return failure<ObjectFixupSemantics>("architecture.unsupported_fixup",
                                             "unsupported ARM64 fixup for format " +
                                                 std::string{to_string(format)} + " and raw type " +
                                                 std::to_string(rawType));
    }
    return Result<ObjectFixupSemantics, Diagnostic>::success(found->semantics);
}

auto encode_arm64_fixup(const ObjectFixupSemantics &semantics, std::int64_t value)
    -> Result<ObjectFixupEncoding, Diagnostic> {
    if (!semantics_are_valid(semantics)) {
        return failure<ObjectFixupEncoding>("architecture.invalid_fixup",
                                            "ARM64 fixup semantics contain an invalid field shape");
    }
    const auto adjusted = checked_add(value, static_cast<std::int64_t>(semantics.pcBias));
    if (!adjusted) {
        return failure<ObjectFixupEncoding>("architecture.fixup_overflow",
                                            "ARM64 fixup value overflows after PC bias");
    }
    if (semantics.bitWidth == 0U) {
        if (*adjusted != 0) {
            return failure<ObjectFixupEncoding>("architecture.fixup_overflow",
                                                "zero-width ARM64 fixup requires a zero value");
        }
        return Result<ObjectFixupEncoding, Diagnostic>::success(
            ObjectFixupEncoding{.semantics = semantics, .fieldBytes = {}, .writeMask = {}});
    }

    if (semantics.fieldEncoding == Field::ScalarLittleEndian) {
        bool fits = true;
        if (semantics.isSigned) {
            fits = signed_fits(*adjusted, semantics.bitWidth);
        } else {
            fits = *adjusted >= 0 &&
                   (semantics.bitWidth == 64U ||
                    static_cast<std::uint64_t>(*adjusted) <= bit_mask(semantics.bitWidth));
        }
        if (!fits) {
            return failure<ObjectFixupEncoding>("architecture.fixup_overflow",
                                                "ARM64 scalar fixup value does not fit its field");
        }
        auto fieldBytes =
            little_endian(std::bit_cast<std::uint64_t>(*adjusted), semantics.storageBytes);
        return Result<ObjectFixupEncoding, Diagnostic>::success(ObjectFixupEncoding{
            .semantics = semantics,
            .fieldBytes = std::move(fieldBytes),
            .writeMask = std::vector<std::byte>(semantics.storageBytes, std::byte{0xff}),
        });
    }

    const auto scale = INT64_C(1) << semantics.rightShift;
    if (*adjusted % scale != 0) {
        return failure<ObjectFixupEncoding>("architecture.fixup_misaligned",
                                            "ARM64 fixup value violates instruction scaling");
    }

    std::uint64_t logical = 0;
    if (semantics.fieldEncoding == Field::AArch64Low12) {
        const auto raw = std::bit_cast<std::uint64_t>(*adjusted);
        logical = (raw >> semantics.rightShift) & 0xfffU;
        if (semantics.valueShift != 0U)
            logical = (raw >> semantics.valueShift) & 0xfffU;
    } else if (semantics.fieldEncoding == Field::AArch64MoveWide16) {
        logical = (std::bit_cast<std::uint64_t>(*adjusted) >> semantics.valueShift) & 0xffffU;
    } else {
        const auto scaled = *adjusted / scale;
        if (!signed_fits(scaled, semantics.bitWidth)) {
            return failure<ObjectFixupEncoding>("architecture.fixup_overflow",
                                                "ARM64 instruction fixup exceeds its signed range");
        }
        logical = std::bit_cast<std::uint64_t>(scaled) & bit_mask(semantics.bitWidth);
    }

    const auto encoded = encode_instruction_bits(semantics.fieldEncoding, logical);
    const auto mask = instruction_mask(semantics.fieldEncoding);
    return Result<ObjectFixupEncoding, Diagnostic>::success(ObjectFixupEncoding{
        .semantics = semantics,
        .fieldBytes = little_endian(encoded, 4),
        .writeMask = little_endian(mask, 4),
    });
}

auto decode_arm64_fixup(const ObjectFixupSemantics &semantics,
                        std::span<const std::byte> fieldBytes) -> Result<std::int64_t, Diagnostic> {
    if (!semantics_are_valid(semantics) || fieldBytes.size() != semantics.storageBytes) {
        return failure<std::int64_t>("architecture.invalid_fixup",
                                     "ARM64 fixup bytes disagree with the field shape");
    }
    if (semantics.bitWidth == 0U) {
        return Result<std::int64_t, Diagnostic>::success(0);
    }

    if (semantics.fieldEncoding == Field::ScalarLittleEndian) {
        auto raw = read_little_endian(fieldBytes);
        std::int64_t value = 0;
        if (semantics.isSigned) {
            value = sign_extend(raw, semantics.bitWidth);
        } else {
            raw &= bit_mask(semantics.bitWidth);
            if (raw > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
                return failure<std::int64_t>("architecture.fixup_overflow",
                                             "ARM64 scalar fixup exceeds normalized range");
            }
            value = static_cast<std::int64_t>(raw);
        }
        const auto normalized = checked_add(value, -static_cast<std::int64_t>(semantics.pcBias));
        if (!normalized) {
            return failure<std::int64_t>("architecture.fixup_overflow",
                                         "ARM64 fixup overflows while removing PC bias");
        }
        return Result<std::int64_t, Diagnostic>::success(*normalized);
    }

    const auto encoded = static_cast<std::uint32_t>(read_little_endian(fieldBytes));
    const auto logical = decode_instruction_bits(semantics.fieldEncoding, encoded);
    if (semantics.fieldEncoding == Field::AArch64Low12) {
        const auto shift = semantics.valueShift != 0U ? semantics.valueShift : semantics.rightShift;
        return Result<std::int64_t, Diagnostic>::success(
            static_cast<std::int64_t>(logical << shift));
    }
    if (semantics.fieldEncoding == Field::AArch64MoveWide16) {
        const auto expanded = logical << semantics.valueShift;
        if (expanded > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            return failure<std::int64_t>("architecture.fixup_overflow",
                                         "ARM64 move-wide field exceeds normalized range");
        }
        return Result<std::int64_t, Diagnostic>::success(static_cast<std::int64_t>(expanded));
    }

    const auto scaled = sign_extend(logical, semantics.bitWidth);
    const auto scale = INT64_C(1) << semantics.rightShift;
    if (scaled > std::numeric_limits<std::int64_t>::max() / scale ||
        scaled < std::numeric_limits<std::int64_t>::min() / scale) {
        return failure<std::int64_t>("architecture.fixup_overflow",
                                     "ARM64 decoded fixup exceeds normalized range");
    }
    return Result<std::int64_t, Diagnostic>::success(scaled * scale);
}

} // namespace binobf::detail

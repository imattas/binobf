#include "x86_fixups.hpp"

#include <binobf/core/types.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <utility>

namespace binobf::detail {
namespace {

struct FixupRow {
    BinaryFormat format;
    ObjectFixupSemantics semantics;
};

constexpr auto row(
    BinaryFormat format,
    std::uint64_t rawType,
    MachineFixupKind kind,
    std::uint8_t bitWidth,
    bool isSigned,
    bool pcRelative,
    bool implicitAddend,
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
        },
    };
}

constexpr std::array rows{
    row(BinaryFormat::COFF, 0x00, MachineFixupKind::Absolute32, 0, false, false, false),
    row(BinaryFormat::COFF, 0x01, MachineFixupKind::Absolute16, 16, false, false, true),
    row(BinaryFormat::COFF, 0x02, MachineFixupKind::PcRelative16, 16, true, true, true, 2),
    row(BinaryFormat::COFF, 0x06, MachineFixupKind::Absolute32, 32, false, false, true),
    row(BinaryFormat::COFF, 0x07, MachineFixupKind::Absolute32, 32, false, false, true),
    row(BinaryFormat::COFF, 0x09, MachineFixupKind::Segment12, 16, false, false, true),
    row(BinaryFormat::COFF, 0x0a, MachineFixupKind::SectionIndex16, 16, false, false, true),
    row(BinaryFormat::COFF, 0x0b, MachineFixupKind::SectionRelative32, 32, false, false, true),
    row(BinaryFormat::COFF, 0x0c, MachineFixupKind::MetadataToken32, 32, false, false, true),
    row(BinaryFormat::COFF, 0x0d, MachineFixupKind::SectionRelative7, 8, false, false, true),
    row(BinaryFormat::COFF, 0x14, MachineFixupKind::PcRelative32, 32, true, true, true, 4),

    row(BinaryFormat::ELF, 0, MachineFixupKind::Absolute32, 0, false, false, false),
    row(BinaryFormat::ELF, 1, MachineFixupKind::Absolute32, 32, false, false, true),
    row(BinaryFormat::ELF, 2, MachineFixupKind::PcRelative32, 32, true, true, true),
    row(BinaryFormat::ELF, 3, MachineFixupKind::GotRelative32, 32, false, false, true),
    row(BinaryFormat::ELF, 4, MachineFixupKind::PltRelative32, 32, true, true, true),
    row(BinaryFormat::ELF, 9, MachineFixupKind::GotOffset32, 32, true, false, true),
    row(BinaryFormat::ELF, 10, MachineFixupKind::GotPcRelative32, 32, true, true, true),
    row(BinaryFormat::ELF, 14, MachineFixupKind::TlsOffset32, 32, true, false, true),
    row(BinaryFormat::ELF, 15, MachineFixupKind::TlsGot32, 32, false, false, true),
    row(BinaryFormat::ELF, 16, MachineFixupKind::TlsGot32, 32, false, false, true),
    row(BinaryFormat::ELF, 17, MachineFixupKind::TlsOffset32, 32, true, false, true),
    row(BinaryFormat::ELF, 18, MachineFixupKind::TlsGeneralDynamic32, 32, true, false, true),
    row(BinaryFormat::ELF, 19, MachineFixupKind::TlsLocalDynamic32, 32, true, false, true),
    row(BinaryFormat::ELF, 20, MachineFixupKind::Absolute16, 16, false, false, true),
    row(BinaryFormat::ELF, 21, MachineFixupKind::PcRelative16, 16, true, true, true),
    row(BinaryFormat::ELF, 22, MachineFixupKind::Absolute8, 8, false, false, true),
    row(BinaryFormat::ELF, 23, MachineFixupKind::PcRelative8, 8, true, true, true),
    row(BinaryFormat::ELF, 32, MachineFixupKind::TlsOffset32, 32, true, false, true),
    row(BinaryFormat::ELF, 33, MachineFixupKind::TlsGot32, 32, true, false, true),
    row(BinaryFormat::ELF, 34, MachineFixupKind::TlsOffset32, 32, true, false, true),
    row(BinaryFormat::ELF, 35, MachineFixupKind::TlsOffset32, 32, false, false, true),
    row(BinaryFormat::ELF, 36, MachineFixupKind::TlsOffset32, 32, true, false, true),
    row(BinaryFormat::ELF, 37, MachineFixupKind::TlsOffset32, 32, true, false, true),
    row(BinaryFormat::ELF, 38, MachineFixupKind::Size32, 32, false, false, true),
    row(BinaryFormat::ELF, 39, MachineFixupKind::TlsGot32, 32, true, false, true),
    row(BinaryFormat::ELF, 40, MachineFixupKind::TlsGot32, 0, false, false, false),
    row(BinaryFormat::ELF, 41, MachineFixupKind::TlsGot32, 32, true, false, true),
    row(BinaryFormat::ELF, 43, MachineFixupKind::GotRelative32, 32, false, false, true),
};

constexpr auto key_less(const FixupRow& left, const FixupRow& right) noexcept -> bool {
    const auto leftFormat = static_cast<std::uint8_t>(left.format);
    const auto rightFormat = static_cast<std::uint8_t>(right.format);
    return leftFormat < rightFormat
        || (leftFormat == rightFormat
            && left.semantics.rawType < right.semantics.rawType);
}

consteval auto rows_are_strictly_sorted() -> bool {
    for (std::size_t index = 1; index < rows.size(); ++index) {
        if (!key_less(rows[index - 1U], rows[index])) return false;
    }
    return true;
}

static_assert(rows_are_strictly_sorted(), "x86 fixup keys must be sorted and unique");

template <typename T>
auto failure(std::string code, std::string message) -> Result<T, Diagnostic> {
    return Result<T, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

auto adjusted_value(const ObjectFixupSemantics& semantics, std::int64_t value)
    -> std::optional<std::int64_t> {
    const auto bias = static_cast<std::int64_t>(semantics.pcBias);
    if ((bias > 0 && value > std::numeric_limits<std::int64_t>::max() - bias)
        || (bias < 0 && value < std::numeric_limits<std::int64_t>::min() - bias)) {
        return std::nullopt;
    }
    return value + bias;
}

} // namespace

auto x86_fixup_semantics(BinaryFormat format, std::uint64_t rawType)
    -> Result<ObjectFixupSemantics, Diagnostic> {
    const FixupRow key{
        format,
        ObjectFixupSemantics{.rawType = rawType},
    };
    const auto found = std::lower_bound(rows.begin(), rows.end(), key, key_less);
    if (found == rows.end() || found->format != format
        || found->semantics.rawType != rawType) {
        return failure<ObjectFixupSemantics>(
            "architecture.unsupported_fixup",
            "unsupported x86 fixup for format " + std::string{to_string(format)}
                + " and raw type " + std::to_string(rawType));
    }
    return Result<ObjectFixupSemantics, Diagnostic>::success(found->semantics);
}

auto encode_x86_fixup(const ObjectFixupSemantics& semantics, std::int64_t value)
    -> Result<ObjectFixupEncoding, Diagnostic> {
    if ((semantics.bitWidth != 0U && semantics.bitWidth != 8U
         && semantics.bitWidth != 16U && semantics.bitWidth != 32U
         && semantics.bitWidth != 64U)
        || (semantics.pcBias != 0 && !semantics.pcRelative)
        || (semantics.bitWidth == 0U && semantics.implicitAddend)) {
        return failure<ObjectFixupEncoding>(
            "architecture.invalid_fixup",
            "x86 fixup semantics contain an invalid field shape");
    }
    const auto adjusted = adjusted_value(semantics, value);
    if (!adjusted) {
        return failure<ObjectFixupEncoding>(
            "architecture.fixup_overflow", "x86 fixup value overflows after PC bias");
    }
    if (semantics.bitWidth == 0U) {
        if (*adjusted != 0) {
            return failure<ObjectFixupEncoding>(
                "architecture.fixup_overflow", "zero-width x86 fixup requires a zero value");
        }
        return Result<ObjectFixupEncoding, Diagnostic>::success(ObjectFixupEncoding{
            .semantics = semantics,
            .fieldBytes = {},
        });
    }

    bool fits = true;
    if (semantics.isSigned && semantics.bitWidth < 64U) {
        const auto maximum = (INT64_C(1) << (semantics.bitWidth - 1U)) - 1;
        const auto minimum = -(INT64_C(1) << (semantics.bitWidth - 1U));
        fits = *adjusted >= minimum && *adjusted <= maximum;
    } else if (!semantics.isSigned) {
        fits = *adjusted >= 0;
        if (fits && semantics.bitWidth < 63U) {
            const auto maximum = (INT64_C(1) << semantics.bitWidth) - 1;
            fits = *adjusted <= maximum;
        }
    }
    if (!fits) {
        return failure<ObjectFixupEncoding>(
            "architecture.fixup_overflow", "x86 fixup value does not fit its field width");
    }

    std::vector<std::byte> bytes(static_cast<std::size_t>(semantics.bitWidth / 8U));
    const auto encoded = std::bit_cast<std::uint64_t>(*adjusted);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::byte>(
            (encoded >> static_cast<unsigned int>(index * 8U)) & 0xffU);
    }
    return Result<ObjectFixupEncoding, Diagnostic>::success(ObjectFixupEncoding{
        .semantics = semantics,
        .fieldBytes = std::move(bytes),
    });
}

auto decode_x86_fixup(
    const ObjectFixupSemantics& semantics,
    std::span<const std::byte> fieldBytes) -> Result<std::int64_t, Diagnostic> {
    if ((semantics.bitWidth != 0U && semantics.bitWidth != 8U
         && semantics.bitWidth != 16U && semantics.bitWidth != 32U
         && semantics.bitWidth != 64U)
        || fieldBytes.size() != static_cast<std::size_t>(semantics.bitWidth / 8U)) {
        return failure<std::int64_t>(
            "architecture.invalid_fixup", "x86 fixup bytes disagree with the field width");
    }
    std::uint64_t raw = 0;
    for (std::size_t index = 0; index < fieldBytes.size(); ++index) {
        raw |= static_cast<std::uint64_t>(
            std::to_integer<std::uint8_t>(fieldBytes[index]))
            << static_cast<unsigned int>(index * 8U);
    }
    std::int64_t fieldValue = 0;
    if (semantics.bitWidth != 0U && semantics.isSigned) {
        if (semantics.bitWidth < 64U) {
            const auto signBit = UINT64_C(1) << (semantics.bitWidth - 1U);
            const auto mask = (UINT64_C(1) << semantics.bitWidth) - 1U;
            raw &= mask;
            if ((raw & signBit) != 0U) raw |= ~mask;
        }
        fieldValue = std::bit_cast<std::int64_t>(raw);
    } else {
        if (raw > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            return failure<std::int64_t>(
                "architecture.fixup_overflow",
                "unsigned x86 fixup cannot be represented as a normalized addend");
        }
        fieldValue = static_cast<std::int64_t>(raw);
    }
    const auto bias = static_cast<std::int64_t>(semantics.pcBias);
    if ((bias > 0 && fieldValue < std::numeric_limits<std::int64_t>::min() + bias)
        || (bias < 0 && fieldValue > std::numeric_limits<std::int64_t>::max() + bias)) {
        return failure<std::int64_t>(
            "architecture.fixup_overflow", "x86 fixup value overflows while removing PC bias");
    }
    return Result<std::int64_t, Diagnostic>::success(fieldValue - bias);
}

} // namespace binobf::detail

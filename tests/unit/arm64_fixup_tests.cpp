#include "../test_support.hpp"

#include <binobf/architecture/backend.hpp>

#include "../../src/architecture/arm64_fixups.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <span>
#include <vector>

namespace {

using binobf::BinaryFormat;
using binobf::MachineFixupKind;
using binobf::ObjectFixupFieldEncoding;
using binobf::ObjectFixupSemantics;

struct Golden {
    BinaryFormat format;
    std::uint64_t rawType;
    MachineFixupKind kind;
    std::uint8_t bitWidth;
    bool isSigned;
    bool pcRelative;
    bool implicitAddend;
    ObjectFixupFieldEncoding encoding;
    std::uint8_t storageBytes;
    std::uint8_t rightShift;
    std::uint8_t valueShift;
};

constexpr std::array coffGoldens{
    Golden{BinaryFormat::COFF, 0x0000, MachineFixupKind::Absolute32, 0, false, false, false,
           ObjectFixupFieldEncoding::ScalarLittleEndian, 0, 0, 0},
    Golden{BinaryFormat::COFF, 0x0001, MachineFixupKind::Absolute32, 32, false, false, true,
           ObjectFixupFieldEncoding::ScalarLittleEndian, 4, 0, 0},
    Golden{BinaryFormat::COFF, 0x0002, MachineFixupKind::Absolute32, 32, false, false, true,
           ObjectFixupFieldEncoding::ScalarLittleEndian, 4, 0, 0},
    Golden{BinaryFormat::COFF, 0x0003, MachineFixupKind::AArch64Branch26, 26, true, true, true,
           ObjectFixupFieldEncoding::AArch64Branch26, 4, 2, 0},
    Golden{BinaryFormat::COFF, 0x0004, MachineFixupKind::AArch64Page21, 21, true, true, true,
           ObjectFixupFieldEncoding::AArch64Adrp21, 4, 12, 0},
    Golden{BinaryFormat::COFF, 0x0005, MachineFixupKind::AArch64Adr21, 21, true, true, true,
           ObjectFixupFieldEncoding::AArch64Adr21, 4, 0, 0},
    Golden{BinaryFormat::COFF, 0x0006, MachineFixupKind::AArch64Low12, 12, false, false, true,
           ObjectFixupFieldEncoding::AArch64Low12, 4, 0, 0},
    Golden{BinaryFormat::COFF, 0x0007, MachineFixupKind::AArch64Low12, 12, false, false, true,
           ObjectFixupFieldEncoding::AArch64Low12, 4, 0, 0},
    Golden{BinaryFormat::COFF, 0x0008, MachineFixupKind::SectionRelative32, 32, false, false, true,
           ObjectFixupFieldEncoding::ScalarLittleEndian, 4, 0, 0},
    Golden{BinaryFormat::COFF, 0x0009, MachineFixupKind::AArch64Low12, 12, false, false, true,
           ObjectFixupFieldEncoding::AArch64Low12, 4, 0, 0},
    Golden{BinaryFormat::COFF, 0x000a, MachineFixupKind::AArch64Low12, 12, false, false, true,
           ObjectFixupFieldEncoding::AArch64Low12, 4, 0, 12},
    Golden{BinaryFormat::COFF, 0x000b, MachineFixupKind::AArch64Low12, 12, false, false, true,
           ObjectFixupFieldEncoding::AArch64Low12, 4, 0, 0},
    Golden{BinaryFormat::COFF, 0x000c, MachineFixupKind::MetadataToken32, 32, false, false, true,
           ObjectFixupFieldEncoding::ScalarLittleEndian, 4, 0, 0},
    Golden{BinaryFormat::COFF, 0x000d, MachineFixupKind::SectionIndex16, 16, false, false, true,
           ObjectFixupFieldEncoding::ScalarLittleEndian, 2, 0, 0},
    Golden{BinaryFormat::COFF, 0x000e, MachineFixupKind::Absolute64, 64, false, false, true,
           ObjectFixupFieldEncoding::ScalarLittleEndian, 8, 0, 0},
    Golden{BinaryFormat::COFF, 0x000f, MachineFixupKind::AArch64Branch19, 19, true, true, true,
           ObjectFixupFieldEncoding::AArch64Branch19, 4, 2, 0},
    Golden{BinaryFormat::COFF, 0x0010, MachineFixupKind::AArch64Branch14, 14, true, true, true,
           ObjectFixupFieldEncoding::AArch64Branch14, 4, 2, 0},
    Golden{BinaryFormat::COFF, 0x0011, MachineFixupKind::PcRelative32, 32, true, true, true,
           ObjectFixupFieldEncoding::ScalarLittleEndian, 4, 0, 0},
};

constexpr std::array elfGoldens{
    Golden{BinaryFormat::ELF, 0x000, MachineFixupKind::Absolute64, 0, false, false, false,
           ObjectFixupFieldEncoding::ScalarLittleEndian, 0, 0, 0},
    Golden{BinaryFormat::ELF, 0x101, MachineFixupKind::Absolute64, 64, false, false, false,
           ObjectFixupFieldEncoding::ScalarLittleEndian, 8, 0, 0},
    Golden{BinaryFormat::ELF, 0x102, MachineFixupKind::Absolute32, 32, false, false, false,
           ObjectFixupFieldEncoding::ScalarLittleEndian, 4, 0, 0},
    Golden{BinaryFormat::ELF, 0x103, MachineFixupKind::Absolute16, 16, false, false, false,
           ObjectFixupFieldEncoding::ScalarLittleEndian, 2, 0, 0},
    Golden{BinaryFormat::ELF, 0x104, MachineFixupKind::PcRelative64, 64, true, true, false,
           ObjectFixupFieldEncoding::ScalarLittleEndian, 8, 0, 0},
    Golden{BinaryFormat::ELF, 0x105, MachineFixupKind::PcRelative32, 32, true, true, false,
           ObjectFixupFieldEncoding::ScalarLittleEndian, 4, 0, 0},
    Golden{BinaryFormat::ELF, 0x106, MachineFixupKind::PcRelative16, 16, true, true, false,
           ObjectFixupFieldEncoding::ScalarLittleEndian, 2, 0, 0},
    Golden{BinaryFormat::ELF, 0x107, MachineFixupKind::AArch64MoveWide16, 16, false, false, false,
           ObjectFixupFieldEncoding::AArch64MoveWide16, 4, 0, 0},
    Golden{BinaryFormat::ELF, 0x109, MachineFixupKind::AArch64MoveWide16, 16, false, false, false,
           ObjectFixupFieldEncoding::AArch64MoveWide16, 4, 0, 16},
    Golden{BinaryFormat::ELF, 0x10b, MachineFixupKind::AArch64MoveWide16, 16, false, false, false,
           ObjectFixupFieldEncoding::AArch64MoveWide16, 4, 0, 32},
    Golden{BinaryFormat::ELF, 0x10d, MachineFixupKind::AArch64MoveWide16, 16, false, false, false,
           ObjectFixupFieldEncoding::AArch64MoveWide16, 4, 0, 48},
    Golden{BinaryFormat::ELF, 0x111, MachineFixupKind::AArch64Branch19, 19, true, true, false,
           ObjectFixupFieldEncoding::AArch64Branch19, 4, 2, 0},
    Golden{BinaryFormat::ELF, 0x112, MachineFixupKind::AArch64Adr21, 21, true, true, false,
           ObjectFixupFieldEncoding::AArch64Adr21, 4, 0, 0},
    Golden{BinaryFormat::ELF, 0x113, MachineFixupKind::AArch64Page21, 21, true, true, false,
           ObjectFixupFieldEncoding::AArch64Adrp21, 4, 12, 0},
    Golden{BinaryFormat::ELF, 0x115, MachineFixupKind::AArch64Low12, 12, false, false, false,
           ObjectFixupFieldEncoding::AArch64Low12, 4, 0, 0},
    Golden{BinaryFormat::ELF, 0x117, MachineFixupKind::AArch64Branch14, 14, true, true, false,
           ObjectFixupFieldEncoding::AArch64Branch14, 4, 2, 0},
    Golden{BinaryFormat::ELF, 0x118, MachineFixupKind::AArch64Branch19, 19, true, true, false,
           ObjectFixupFieldEncoding::AArch64Branch19, 4, 2, 0},
    Golden{BinaryFormat::ELF, 0x11a, MachineFixupKind::AArch64Branch26, 26, true, true, false,
           ObjectFixupFieldEncoding::AArch64Branch26, 4, 2, 0},
    Golden{BinaryFormat::ELF, 0x11b, MachineFixupKind::AArch64Call26, 26, true, true, false,
           ObjectFixupFieldEncoding::AArch64Branch26, 4, 2, 0},
    Golden{BinaryFormat::ELF, 0x12b, MachineFixupKind::AArch64Low12, 12, false, false, false,
           ObjectFixupFieldEncoding::AArch64Low12, 4, 4, 0},
    Golden{BinaryFormat::ELF, 0x137, MachineFixupKind::AArch64GotPage21, 21, true, true, false,
           ObjectFixupFieldEncoding::AArch64Adrp21, 4, 12, 0},
    Golden{BinaryFormat::ELF, 0x138, MachineFixupKind::AArch64GotLow12, 12, false, false, false,
           ObjectFixupFieldEncoding::AArch64Low12, 4, 3, 0},
    Golden{BinaryFormat::ELF, 0x201, MachineFixupKind::AArch64TlsPage21, 21, true, true, false,
           ObjectFixupFieldEncoding::AArch64Adrp21, 4, 12, 0},
    Golden{BinaryFormat::ELF, 0x202, MachineFixupKind::AArch64TlsLow12, 12, false, false, false,
           ObjectFixupFieldEncoding::AArch64Low12, 4, 0, 0},
    Golden{BinaryFormat::ELF, 0x21d, MachineFixupKind::AArch64TlsPage21, 21, true, true, false,
           ObjectFixupFieldEncoding::AArch64Adrp21, 4, 12, 0},
    Golden{BinaryFormat::ELF, 0x21e, MachineFixupKind::AArch64TlsLow12, 12, false, false, false,
           ObjectFixupFieldEncoding::AArch64Low12, 4, 3, 0},
    Golden{BinaryFormat::ELF, 0x232, MachineFixupKind::AArch64TlsDescriptor, 21, true, true, false,
           ObjectFixupFieldEncoding::AArch64Adrp21, 4, 12, 0},
    Golden{BinaryFormat::ELF, 0x233, MachineFixupKind::AArch64TlsDescriptor, 12, false, false,
           false, ObjectFixupFieldEncoding::AArch64Low12, 4, 3, 0},
    Golden{BinaryFormat::ELF, 0x239, MachineFixupKind::AArch64TlsDescriptor, 0, false, false, false,
           ObjectFixupFieldEncoding::ScalarLittleEndian, 0, 0, 0},
};

auto bytes(std::initializer_list<unsigned int> values) -> std::vector<std::byte> {
    std::vector<std::byte> result;
    result.reserve(values.size());
    for (const auto value : values)
        result.push_back(static_cast<std::byte>(value));
    return result;
}

auto apply_mask(std::vector<std::byte> original, const binobf::ObjectFixupEncoding &encoding)
    -> std::vector<std::byte> {
    REQUIRE_EQ(original.size(), encoding.fieldBytes.size());
    REQUIRE_EQ(original.size(), encoding.writeMask.size());
    for (std::size_t index = 0; index < original.size(); ++index) {
        const auto oldValue = std::to_integer<std::uint8_t>(original[index]);
        const auto newValue = std::to_integer<std::uint8_t>(encoding.fieldBytes[index]);
        const auto mask = std::to_integer<std::uint8_t>(encoding.writeMask[index]);
        original[index] = static_cast<std::byte>((oldValue & static_cast<std::uint8_t>(~mask)) |
                                                 (newValue & mask));
    }
    return original;
}

auto require_semantics(BinaryFormat format, std::uint64_t rawType) -> ObjectFixupSemantics {
    const auto result = binobf::detail::arm64_fixup_semantics(format, rawType);
    REQUIRE(result.has_value());
    return result.value();
}

void require_golden(const Golden &golden) {
    const auto semantics = require_semantics(golden.format, golden.rawType);
    REQUIRE_EQ(semantics.kind, golden.kind);
    REQUIRE_EQ(semantics.bitWidth, golden.bitWidth);
    REQUIRE_EQ(semantics.isSigned, golden.isSigned);
    REQUIRE_EQ(semantics.pcRelative, golden.pcRelative);
    REQUIRE_EQ(semantics.implicitAddend, golden.implicitAddend);
    REQUIRE_EQ(semantics.fieldEncoding, golden.encoding);
    REQUIRE_EQ(semantics.storageBytes, golden.storageBytes);
    REQUIRE_EQ(semantics.rightShift, golden.rightShift);
    REQUIRE_EQ(semantics.valueShift, golden.valueShift);
}

} // namespace

TEST_CASE(arm64_fixup_tables_cover_all_coff_types_and_elf_families) {
    for (const auto &golden : coffGoldens)
        require_golden(golden);
    for (const auto &golden : elfGoldens)
        require_golden(golden);

    constexpr std::array additionalElfTypes{
        UINT64_C(0x108), UINT64_C(0x10a), UINT64_C(0x10c), UINT64_C(0x10e), UINT64_C(0x10f),
        UINT64_C(0x110), UINT64_C(0x114), UINT64_C(0x116), UINT64_C(0x11c), UINT64_C(0x11d),
        UINT64_C(0x11e), UINT64_C(0x11f), UINT64_C(0x120), UINT64_C(0x121), UINT64_C(0x122),
        UINT64_C(0x123), UINT64_C(0x124), UINT64_C(0x125), UINT64_C(0x135), UINT64_C(0x200),
        UINT64_C(0x203), UINT64_C(0x204), UINT64_C(0x205), UINT64_C(0x206), UINT64_C(0x207),
        UINT64_C(0x208), UINT64_C(0x209), UINT64_C(0x20a), UINT64_C(0x20b), UINT64_C(0x20c),
        UINT64_C(0x20d), UINT64_C(0x20e), UINT64_C(0x20f), UINT64_C(0x210), UINT64_C(0x211),
        UINT64_C(0x212), UINT64_C(0x213), UINT64_C(0x214), UINT64_C(0x215), UINT64_C(0x216),
        UINT64_C(0x217), UINT64_C(0x218), UINT64_C(0x219), UINT64_C(0x21a), UINT64_C(0x21b),
        UINT64_C(0x21c), UINT64_C(0x21f), UINT64_C(0x220), UINT64_C(0x221), UINT64_C(0x222),
        UINT64_C(0x223), UINT64_C(0x224), UINT64_C(0x225), UINT64_C(0x226), UINT64_C(0x227),
        UINT64_C(0x228), UINT64_C(0x229), UINT64_C(0x22a), UINT64_C(0x22b), UINT64_C(0x22c),
        UINT64_C(0x22d), UINT64_C(0x22e), UINT64_C(0x22f), UINT64_C(0x230), UINT64_C(0x231),
        UINT64_C(0x234), UINT64_C(0x235), UINT64_C(0x236), UINT64_C(0x237), UINT64_C(0x238),
        UINT64_C(0x23a), UINT64_C(0x23b), UINT64_C(0x23c), UINT64_C(0x23d), UINT64_C(0x404),
        UINT64_C(0x405), UINT64_C(0x406), UINT64_C(0x407),
    };
    for (const auto rawType : additionalElfTypes) {
        REQUIRE(binobf::detail::arm64_fixup_semantics(BinaryFormat::ELF, rawType).has_value());
    }
}

TEST_CASE(arm64_branch_encodings_preserve_opcodes_and_round_trip_boundaries) {
    const auto branch26 = require_semantics(BinaryFormat::ELF, 0x11b);
    const auto encoded = binobf::detail::encode_arm64_fixup(branch26, 0x100);
    REQUIRE(encoded.has_value());
    REQUIRE_EQ(encoded.value().writeMask, bytes({0xff, 0xff, 0xff, 0x03}));
    REQUIRE_EQ(apply_mask(bytes({0x00, 0x00, 0x00, 0x94}), encoded.value()),
               bytes({0x40, 0x00, 0x00, 0x94}));
    const auto decoded = binobf::detail::decode_arm64_fixup(
        branch26, std::span<const std::byte>{encoded.value().fieldBytes});
    REQUIRE(decoded.has_value());
    REQUIRE_EQ(decoded.value(), INT64_C(0x100));

    for (const auto rawType : {UINT64_C(0x11a), UINT64_C(0x118), UINT64_C(0x117)}) {
        const auto semantics = require_semantics(BinaryFormat::ELF, rawType);
        const auto maximum =
            ((INT64_C(1) << (semantics.bitWidth - 1U)) - 1) * (INT64_C(1) << semantics.rightShift);
        const auto minimum =
            -(INT64_C(1) << (semantics.bitWidth - 1U)) * (INT64_C(1) << semantics.rightShift);
        REQUIRE(binobf::detail::encode_arm64_fixup(semantics, maximum).has_value());
        REQUIRE(binobf::detail::encode_arm64_fixup(semantics, minimum).has_value());
        REQUIRE(!binobf::detail::encode_arm64_fixup(semantics, maximum + 4).has_value());
        REQUIRE(!binobf::detail::encode_arm64_fixup(semantics, minimum - 4).has_value());
        const auto misaligned = binobf::detail::encode_arm64_fixup(semantics, 2);
        REQUIRE(!misaligned.has_value());
        REQUIRE_EQ(misaligned.error().code, "architecture.fixup_misaligned");
    }
}

TEST_CASE(arm64_adr_adrp_low12_and_movewide_fields_encode_exact_bits) {
    const auto adr =
        binobf::detail::encode_arm64_fixup(require_semantics(BinaryFormat::ELF, 0x112), 0x12345);
    REQUIRE(adr.has_value());
    REQUIRE_EQ(adr.value().writeMask, bytes({0xe0, 0xff, 0xff, 0x60}));
    REQUIRE_EQ(
        binobf::detail::decode_arm64_fixup(adr.value().semantics, adr.value().fieldBytes).value(),
        INT64_C(0x12345));

    const auto adrpSemantics = require_semantics(BinaryFormat::ELF, 0x113);
    const auto adrp = binobf::detail::encode_arm64_fixup(adrpSemantics, -0x12345000);
    REQUIRE(adrp.has_value());
    REQUIRE_EQ(binobf::detail::decode_arm64_fixup(adrpSemantics, adrp.value().fieldBytes).value(),
               INT64_C(-0x12345000));
    REQUIRE(!binobf::detail::encode_arm64_fixup(adrpSemantics, 1).has_value());

    const auto ldst64 = require_semantics(BinaryFormat::ELF, 0x11e);
    REQUIRE_EQ(ldst64.rightShift, std::uint8_t{3});
    const auto low12 = binobf::detail::encode_arm64_fixup(ldst64, 0xff8);
    REQUIRE(low12.has_value());
    REQUIRE_EQ(low12.value().writeMask, bytes({0x00, 0xfc, 0x3f, 0x00}));
    REQUIRE_EQ(binobf::detail::decode_arm64_fixup(ldst64, low12.value().fieldBytes).value(),
               INT64_C(0xff8));
    REQUIRE(!binobf::detail::encode_arm64_fixup(ldst64, 3).has_value());

    const auto move = require_semantics(BinaryFormat::ELF, 0x10b);
    const auto moved = binobf::detail::encode_arm64_fixup(move, INT64_C(0x1234567800000000));
    REQUIRE(moved.has_value());
    REQUIRE_EQ(moved.value().writeMask, bytes({0xe0, 0xff, 0x1f, 0x00}));
    REQUIRE_EQ(binobf::detail::decode_arm64_fixup(move, moved.value().fieldBytes).value(),
               INT64_C(0x567800000000));
}

TEST_CASE(arm64_fixups_reject_overflow_invalid_shapes_and_unknown_types) {
    const auto branch = require_semantics(BinaryFormat::ELF, 0x11b);
    const auto minimum =
        binobf::detail::encode_arm64_fixup(branch, std::numeric_limits<std::int64_t>::min());
    REQUIRE(!minimum.has_value());
    REQUIRE_EQ(minimum.error().code, "architecture.fixup_overflow");

    auto invalid = branch;
    invalid.storageBytes = 3;
    const auto invalidEncoding = binobf::detail::encode_arm64_fixup(invalid, 0);
    REQUIRE(!invalidEncoding.has_value());
    REQUIRE_EQ(invalidEncoding.error().code, "architecture.invalid_fixup");
    const auto invalidDecode = binobf::detail::decode_arm64_fixup(
        branch, std::array{std::byte{0}, std::byte{0}, std::byte{0}});
    REQUIRE(!invalidDecode.has_value());
    REQUIRE_EQ(invalidDecode.error().code, "architecture.invalid_fixup");

    REQUIRE(!binobf::detail::arm64_fixup_semantics(BinaryFormat::ELF, 0xffff).has_value());
    REQUIRE(!binobf::detail::arm64_fixup_semantics(BinaryFormat::PE, 0x11b).has_value());

    const auto backend = binobf::make_architecture_backend(binobf::Architecture::ARM64);
    REQUIRE(backend.has_value());
    REQUIRE(backend.value()->fixup_semantics(BinaryFormat::ELF, 0x11b).has_value());
    REQUIRE(backend.value()->encode_fixup(branch, 0).has_value());
}

int main() { return binobf::test::run_all(); }

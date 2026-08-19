#include "../test_support.hpp"

#include <binobf/architecture/backend.hpp>

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

static_assert(static_cast<std::uint8_t>(binobf::MachineFixupKind::AArch64PageOffset12) == 14U);

struct FixupGolden {
    binobf::BinaryFormat format;
    std::uint64_t rawType;
    binobf::MachineFixupKind kind;
    std::uint8_t bitWidth;
    bool isSigned;
    bool pcRelative;
    bool implicitAddend;
    std::int8_t pcBias;
};

constexpr std::array goldens{
    FixupGolden{binobf::BinaryFormat::COFF, 0x00, binobf::MachineFixupKind::Absolute32, 0, false, false, false, 0},
    FixupGolden{binobf::BinaryFormat::COFF, 0x01, binobf::MachineFixupKind::Absolute16, 16, false, false, true, 0},
    FixupGolden{binobf::BinaryFormat::COFF, 0x02, binobf::MachineFixupKind::PcRelative16, 16, true, true, true, 2},
    FixupGolden{binobf::BinaryFormat::COFF, 0x06, binobf::MachineFixupKind::Absolute32, 32, false, false, true, 0},
    FixupGolden{binobf::BinaryFormat::COFF, 0x07, binobf::MachineFixupKind::Absolute32, 32, false, false, true, 0},
    FixupGolden{binobf::BinaryFormat::COFF, 0x09, binobf::MachineFixupKind::Segment12, 16, false, false, true, 0},
    FixupGolden{binobf::BinaryFormat::COFF, 0x0a, binobf::MachineFixupKind::SectionIndex16, 16, false, false, true, 0},
    FixupGolden{binobf::BinaryFormat::COFF, 0x0b, binobf::MachineFixupKind::SectionRelative32, 32, false, false, true, 0},
    FixupGolden{binobf::BinaryFormat::COFF, 0x0c, binobf::MachineFixupKind::MetadataToken32, 32, false, false, true, 0},
    FixupGolden{binobf::BinaryFormat::COFF, 0x0d, binobf::MachineFixupKind::SectionRelative7, 8, false, false, true, 0},
    FixupGolden{binobf::BinaryFormat::COFF, 0x14, binobf::MachineFixupKind::PcRelative32, 32, true, true, true, 4},

    FixupGolden{binobf::BinaryFormat::ELF, 0, binobf::MachineFixupKind::Absolute32, 0, false, false, false, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 1, binobf::MachineFixupKind::Absolute32, 32, false, false, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 2, binobf::MachineFixupKind::PcRelative32, 32, true, true, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 3, binobf::MachineFixupKind::GotRelative32, 32, false, false, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 4, binobf::MachineFixupKind::PltRelative32, 32, true, true, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 9, binobf::MachineFixupKind::GotOffset32, 32, true, false, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 10, binobf::MachineFixupKind::GotPcRelative32, 32, true, true, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 14, binobf::MachineFixupKind::TlsOffset32, 32, true, false, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 15, binobf::MachineFixupKind::TlsGot32, 32, false, false, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 16, binobf::MachineFixupKind::TlsGot32, 32, false, false, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 17, binobf::MachineFixupKind::TlsOffset32, 32, true, false, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 18, binobf::MachineFixupKind::TlsGeneralDynamic32, 32, true, false, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 19, binobf::MachineFixupKind::TlsLocalDynamic32, 32, true, false, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 20, binobf::MachineFixupKind::Absolute16, 16, false, false, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 21, binobf::MachineFixupKind::PcRelative16, 16, true, true, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 22, binobf::MachineFixupKind::Absolute8, 8, false, false, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 23, binobf::MachineFixupKind::PcRelative8, 8, true, true, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 32, binobf::MachineFixupKind::TlsOffset32, 32, true, false, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 33, binobf::MachineFixupKind::TlsGot32, 32, true, false, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 34, binobf::MachineFixupKind::TlsOffset32, 32, true, false, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 35, binobf::MachineFixupKind::TlsOffset32, 32, false, false, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 36, binobf::MachineFixupKind::TlsOffset32, 32, true, false, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 37, binobf::MachineFixupKind::TlsOffset32, 32, true, false, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 38, binobf::MachineFixupKind::Size32, 32, false, false, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 39, binobf::MachineFixupKind::TlsGot32, 32, true, false, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 40, binobf::MachineFixupKind::TlsGot32, 0, false, false, false, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 41, binobf::MachineFixupKind::TlsGot32, 32, true, false, true, 0},
    FixupGolden{binobf::BinaryFormat::ELF, 43, binobf::MachineFixupKind::GotRelative32, 32, false, false, true, 0},
};

auto expected_bytes(std::int64_t value, std::uint8_t bitWidth) -> std::vector<std::byte> {
    std::vector<std::byte> bytes(static_cast<std::size_t>(bitWidth / 8U));
    const auto encoded = std::bit_cast<std::uint64_t>(value);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::byte>(
            (encoded >> static_cast<unsigned int>(index * 8U)) & 0xffU);
    }
    return bytes;
}

} // namespace

TEST_CASE(x86_fixup_tables_expose_stable_semantics_and_little_endian_encoding) {
    const auto backend = binobf::make_architecture_backend(binobf::Architecture::X86);
    REQUIRE(backend.has_value());
    for (const auto& golden : goldens) {
        const auto semantics = backend.value()->fixup_semantics(golden.format, golden.rawType);
        REQUIRE(semantics.has_value());
        REQUIRE_EQ(semantics.value().kind, golden.kind);
        REQUIRE_EQ(semantics.value().rawType, golden.rawType);
        REQUIRE_EQ(semantics.value().bitWidth, golden.bitWidth);
        REQUIRE_EQ(semantics.value().isSigned, golden.isSigned);
        REQUIRE_EQ(semantics.value().pcRelative, golden.pcRelative);
        REQUIRE_EQ(semantics.value().implicitAddend, golden.implicitAddend);
        REQUIRE_EQ(semantics.value().pcBias, golden.pcBias);

        const auto zero = backend.value()->encode_fixup(semantics.value(), 0);
        REQUIRE(zero.has_value());
        REQUIRE_EQ(zero.value().semantics, semantics.value());
        REQUIRE_EQ(zero.value().fieldBytes,
                   expected_bytes(golden.pcBias, golden.bitWidth));

        const auto one = backend.value()->encode_fixup(semantics.value(), 1);
        if (golden.bitWidth == 0) {
            REQUIRE(!one.has_value());
            REQUIRE_EQ(one.error().code, "architecture.fixup_overflow");
            continue;
        }
        REQUIRE(one.has_value());
        REQUIRE_EQ(one.value().fieldBytes,
                   expected_bytes(static_cast<std::int64_t>(golden.pcBias) + 1,
                                  golden.bitWidth));

        const auto bias = static_cast<std::int64_t>(golden.pcBias);
        if (golden.isSigned) {
            const auto maximumField = (INT64_C(1) << (golden.bitWidth - 1U)) - 1;
            const auto minimumField = -(INT64_C(1) << (golden.bitWidth - 1U));
            REQUIRE(backend.value()->encode_fixup(
                semantics.value(), maximumField - bias).has_value());
            REQUIRE(backend.value()->encode_fixup(
                semantics.value(), minimumField - bias).has_value());
            const auto above = backend.value()->encode_fixup(
                semantics.value(), maximumField - bias + 1);
            const auto below = backend.value()->encode_fixup(
                semantics.value(), minimumField - bias - 1);
            REQUIRE(!above.has_value());
            REQUIRE(!below.has_value());
            REQUIRE_EQ(above.error().code, "architecture.fixup_overflow");
            REQUIRE_EQ(below.error().code, "architecture.fixup_overflow");
        } else {
            const auto maximum = (UINT64_C(1) << golden.bitWidth) - 1U;
            REQUIRE(backend.value()->encode_fixup(
                semantics.value(), static_cast<std::int64_t>(maximum)).has_value());
            const auto negative = backend.value()->encode_fixup(semantics.value(), -1);
            const auto above = backend.value()->encode_fixup(
                semantics.value(), static_cast<std::int64_t>(maximum + 1U));
            REQUIRE(!negative.has_value());
            REQUIRE(!above.has_value());
            REQUIRE_EQ(negative.error().code, "architecture.fixup_overflow");
            REQUIRE_EQ(above.error().code, "architecture.fixup_overflow");
        }
    }
}

TEST_CASE(x86_fixup_services_reject_unknown_invalid_and_support_x64_requests) {
    const auto backend = binobf::make_architecture_backend(binobf::Architecture::X86);
    REQUIRE(backend.has_value());
    const auto unknown = backend.value()->fixup_semantics(binobf::BinaryFormat::COFF, 0xffffU);
    REQUIRE(!unknown.has_value());
    REQUIRE_EQ(unknown.error().code, "architecture.unsupported_fixup");
    const auto wrongFormat = backend.value()->fixup_semantics(binobf::BinaryFormat::PE, 1U);
    REQUIRE(!wrongFormat.has_value());
    REQUIRE_EQ(wrongFormat.error().code, "architecture.unsupported_fixup");

    binobf::ObjectFixupSemantics invalid{};
    invalid.bitWidth = 12;
    const auto rejected = backend.value()->encode_fixup(invalid, 0);
    REQUIRE(!rejected.has_value());
    REQUIRE_EQ(rejected.error().code, "architecture.invalid_fixup");

    const auto x64 = binobf::make_architecture_backend(binobf::Architecture::X86_64);
    REQUIRE(x64.has_value());
    const auto x64Absolute = x64.value()->fixup_semantics(binobf::BinaryFormat::ELF, 1U);
    REQUIRE(x64Absolute.has_value());
    REQUIRE_EQ(x64Absolute.value().bitWidth, std::uint8_t{64});
    const auto x64Branch = x64.value()->fixup_semantics(binobf::BinaryFormat::MachO, 2U);
    REQUIRE(x64Branch.has_value());
    REQUIRE(x64Branch.value().pcRelative);
}

TEST_CASE(machine_fixup_comparison_includes_new_provider_neutral_kinds) {
    binobf::MachineFixup left;
    left.kind = binobf::MachineFixupKind::TlsGeneralDynamic32;
    auto right = left;
    REQUIRE_EQ(left, right);
    right.kind = binobf::MachineFixupKind::TlsLocalDynamic32;
    REQUIRE(left != right);
}

int main() {
    return binobf::test::run_all();
}

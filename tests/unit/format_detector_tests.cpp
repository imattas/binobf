#include "../test_support.hpp"

#include <binobf/formats/detector.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace {

void put_u16(std::vector<std::byte>& bytes, std::size_t offset, std::uint16_t value) {
    bytes.at(offset) = static_cast<std::byte>(value & 0xffU);
    bytes.at(offset + 1) = static_cast<std::byte>((value >> 8U) & 0xffU);
}

void put_u32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        bytes.at(offset + index) = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

void put_u64(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value) {
    for (std::size_t index = 0; index < 8; ++index) {
        bytes.at(offset + index) = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

auto make_elf(
    std::uint8_t elfClass,
    std::uint16_t type,
    std::uint16_t machine,
    std::uint64_t entry = 0) -> std::vector<std::byte> {
    const auto size = elfClass == 1 ? std::size_t{52} : std::size_t{64};
    std::vector<std::byte> bytes(size);
    bytes[0] = std::byte{0x7f};
    bytes[1] = std::byte{'E'};
    bytes[2] = std::byte{'L'};
    bytes[3] = std::byte{'F'};
    bytes[4] = static_cast<std::byte>(elfClass);
    bytes[5] = std::byte{1};
    bytes[6] = std::byte{1};
    put_u16(bytes, 16, type);
    put_u16(bytes, 18, machine);
    put_u32(bytes, 20, 1);
    if (elfClass == 1) {
        put_u32(bytes, 24, static_cast<std::uint32_t>(entry));
        put_u16(bytes, 40, 52);
    } else {
        put_u64(bytes, 24, entry);
        put_u16(bytes, 52, 64);
    }
    return bytes;
}

auto make_pe(
    std::uint16_t machine,
    bool is64Bit,
    std::uint16_t characteristics,
    std::uint32_t entry) -> std::vector<std::byte> {
    constexpr std::size_t peOffset = 64;
    const std::uint16_t optionalSize = is64Bit ? 240 : 224;
    const auto sectionOffset = peOffset + 4 + 20 + optionalSize;
    std::vector<std::byte> bytes(sectionOffset + 40);
    bytes[0] = std::byte{'M'};
    bytes[1] = std::byte{'Z'};
    put_u32(bytes, 0x3c, static_cast<std::uint32_t>(peOffset));
    bytes[peOffset] = std::byte{'P'};
    bytes[peOffset + 1] = std::byte{'E'};
    put_u16(bytes, peOffset + 4, machine);
    put_u16(bytes, peOffset + 6, 1);
    put_u16(bytes, peOffset + 20, optionalSize);
    put_u16(bytes, peOffset + 22, characteristics);
    put_u16(bytes, peOffset + 24, is64Bit ? 0x20b : 0x10b);
    put_u32(bytes, peOffset + 24 + 16, entry);
    return bytes;
}

auto make_coff(std::uint16_t machine, std::uint16_t sectionCount = 1)
    -> std::vector<std::byte> {
    std::vector<std::byte> bytes(20 + static_cast<std::size_t>(sectionCount) * 40);
    put_u16(bytes, 0, machine);
    put_u16(bytes, 2, sectionCount);
    put_u16(bytes, 16, 0);
    return bytes;
}

void require_detection(
    const std::vector<std::byte>& bytes,
    std::string_view sourceName,
    binobf::BinaryFormat format,
    binobf::BinaryType type,
    binobf::Architecture architecture,
    std::uint64_t entry = 0) {
    const auto result = binobf::detect_binary(bytes, sourceName);
    REQUIRE(result.has_value());
    REQUIRE_EQ(result.value().format, format);
    REQUIRE_EQ(result.value().type, type);
    REQUIRE_EQ(result.value().architecture, architecture);
    REQUIRE_EQ(result.value().entryPoint, entry);
}

void require_error_code(
    const std::vector<std::byte>& bytes,
    std::string_view sourceName,
    std::string_view code) {
    const auto result = binobf::detect_binary(bytes, sourceName);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, code);
}

} // namespace

TEST_CASE(elf_headers_map_class_machine_type_and_entry_point) {
    require_detection(
        make_elf(1, 1, 3), "fixture.o", binobf::BinaryFormat::ELF,
        binobf::BinaryType::RelocatableObject, binobf::Architecture::X86);
    require_detection(
        make_elf(2, 2, 62, UINT64_C(0x401020)), "fixture", binobf::BinaryFormat::ELF,
        binobf::BinaryType::Executable, binobf::Architecture::X86_64, UINT64_C(0x401020));
    require_detection(
        make_elf(2, 3, 183), "fixture.so", binobf::BinaryFormat::ELF,
        binobf::BinaryType::SharedLibrary, binobf::Architecture::ARM64);
}

TEST_CASE(pe_headers_map_machine_kind_and_driver_extension) {
    require_detection(
        make_pe(0x014c, false, 0x0002, 0x1020), "fixture.exe", binobf::BinaryFormat::PE,
        binobf::BinaryType::Executable, binobf::Architecture::X86, 0x1020);
    require_detection(
        make_pe(0x8664, true, 0x2002, 0x2030), "fixture.dll", binobf::BinaryFormat::PE,
        binobf::BinaryType::SharedLibrary, binobf::Architecture::X86_64, 0x2030);
    require_detection(
        make_pe(0xaa64, true, 0x0002, 0x3040), "FIXTURE.SYS", binobf::BinaryFormat::PE,
        binobf::BinaryType::KernelDriver, binobf::Architecture::ARM64, 0x3040);
}

TEST_CASE(coff_object_headers_require_complete_section_tables) {
    require_detection(
        make_coff(0x014c), "fixture.obj", binobf::BinaryFormat::COFF,
        binobf::BinaryType::RelocatableObject, binobf::Architecture::X86);
    require_detection(
        make_coff(0x8664, 2), "fixture.obj", binobf::BinaryFormat::COFF,
        binobf::BinaryType::RelocatableObject, binobf::Architecture::X86_64);
    require_detection(
        make_coff(0xaa64), "fixture.obj", binobf::BinaryFormat::COFF,
        binobf::BinaryType::RelocatableObject, binobf::Architecture::ARM64);

    auto truncated = make_coff(0x8664, 2);
    truncated.resize(99);
    require_error_code(truncated, "broken.obj", "format.truncated");
}

TEST_CASE(archive_magic_is_exact_and_architecture_neutral) {
    const std::array signature{
        std::byte{'!'}, std::byte{'<'}, std::byte{'a'}, std::byte{'r'},
        std::byte{'c'}, std::byte{'h'}, std::byte{'>'}, std::byte{'\n'},
    };
    const std::vector<std::byte> archive(signature.begin(), signature.end());
    require_detection(
        archive, "fixture.a", binobf::BinaryFormat::Archive,
        binobf::BinaryType::StaticLibrary, binobf::Architecture::Unknown);
}

TEST_CASE(recognized_but_malformed_headers_return_specific_errors) {
    require_error_code({}, "empty", "format.unknown");
    require_error_code(
        {std::byte{0x7f}, std::byte{'E'}, std::byte{'L'}, std::byte{'F'}},
        "short.elf", "format.truncated");

    auto wrongEndian = make_elf(2, 2, 62);
    wrongEndian[5] = std::byte{2};
    require_error_code(wrongEndian, "big-endian.elf", "format.unsupported");

    auto badClass = make_elf(2, 2, 62);
    badClass[4] = std::byte{3};
    require_error_code(badClass, "bad-class.elf", "format.invalid");

    auto badPeOffset = make_pe(0x8664, true, 0x0002, 0x1000);
    put_u32(badPeOffset, 0x3c, 0xfffffff0U);
    require_error_code(badPeOffset, "bad.exe", "format.invalid");

    auto noSections = make_coff(0x8664);
    put_u16(noSections, 2, 0);
    require_error_code(noSections, "bad.obj", "format.invalid");

    require_error_code(
        {std::byte{'M'}, std::byte{'Z'}, std::byte{0}, std::byte{0}},
        "fake.sys", "format.truncated");
    require_error_code(
        {std::byte{'n'}, std::byte{'o'}, std::byte{'p'}, std::byte{'e'}},
        "fake.sys", "format.unknown");
}

int main() {
    return binobf::test::run_all();
}

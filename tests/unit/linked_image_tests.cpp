#include "../test_support.hpp"

#include <binobf/formats/linked_image.hpp>
#include <binobf/formats/linked_writer.hpp>
#include <binobf/verify/structural_verifier.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
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

void put_name(std::vector<std::byte>& bytes, std::size_t offset, std::string_view name) {
    for (std::size_t index = 0; index < name.size(); ++index) {
        bytes.at(offset + index) = static_cast<std::byte>(name[index]);
    }
}

auto minimal_pe64() -> std::vector<std::byte> {
    constexpr std::size_t peOffset = 0x40;
    constexpr std::size_t optionalOffset = peOffset + 24;
    constexpr std::size_t sectionOffset = optionalOffset + 240;
    std::vector<std::byte> bytes(0x400);
    bytes[0] = std::byte{'M'};
    bytes[1] = std::byte{'Z'};
    put_u32(bytes, 0x3c, peOffset);
    put_name(bytes, peOffset, "PE");
    put_u16(bytes, peOffset + 4, 0x8664);
    put_u16(bytes, peOffset + 6, 1);
    put_u16(bytes, peOffset + 20, 240);
    put_u16(bytes, peOffset + 22, 0x0022);
    put_u16(bytes, optionalOffset, 0x20b);
    put_u32(bytes, optionalOffset + 16, 0x1000);
    put_u64(bytes, optionalOffset + 24, UINT64_C(0x140000000));
    put_u32(bytes, optionalOffset + 32, 0x1000);
    put_u32(bytes, optionalOffset + 36, 0x200);
    put_u32(bytes, optionalOffset + 56, 0x2000);
    put_u32(bytes, optionalOffset + 60, 0x200);
    put_u16(bytes, optionalOffset + 68, 3);
    put_u32(bytes, optionalOffset + 108, 16);
    put_name(bytes, sectionOffset, ".text");
    put_u32(bytes, sectionOffset + 8, 1);
    put_u32(bytes, sectionOffset + 12, 0x1000);
    put_u32(bytes, sectionOffset + 16, 0x200);
    put_u32(bytes, sectionOffset + 20, 0x200);
    put_u32(bytes, sectionOffset + 36, 0x60000020);
    bytes[0x200] = std::byte{0xc3};
    return bytes;
}

auto rich_pe64() -> std::vector<std::byte> {
    auto bytes = minimal_pe64();
    bytes.resize(0x800);
    constexpr std::size_t optionalOffset = 0x58;
    constexpr std::size_t sectionOffset = optionalOffset + 240;
    put_u32(bytes, optionalOffset + 16, 0x1300);
    put_name(bytes, sectionOffset, ".text");
    put_u32(bytes, sectionOffset + 8, 0x400);
    put_u32(bytes, sectionOffset + 16, 0x400);
    put_u32(bytes, sectionOffset + 36, 0x60000020);
    const auto directories = optionalOffset + 112;
    put_u32(bytes, directories, 0x1000);
    put_u32(bytes, directories + 4, 0x100);
    put_u32(bytes, directories + 8, 0x1100);
    put_u32(bytes, directories + 12, 0x40);
    put_u32(bytes, directories + 2 * 8, 0x1200);
    put_u32(bytes, directories + 2 * 8 + 4, 16);
    put_u32(bytes, directories + 3 * 8, 0x1210);
    put_u32(bytes, directories + 3 * 8 + 4, 12);
    put_u32(bytes, directories + 4 * 8, 0x700);
    put_u32(bytes, directories + 4 * 8 + 4, 0x10);
    put_u32(bytes, directories + 5 * 8, 0x11c0);
    put_u32(bytes, directories + 5 * 8 + 4, 0x0c);
    put_u32(bytes, directories + 6 * 8, 0x11e0);
    put_u32(bytes, directories + 6 * 8 + 4, 28);
    put_u32(bytes, directories + 9 * 8, 0x1220);
    put_u32(bytes, directories + 9 * 8 + 4, 40);
    put_u32(bytes, directories + 10 * 8, 0x1250);
    put_u32(bytes, directories + 10 * 8 + 4, 0x70);

    put_u32(bytes, 0x200 + 16, 1);
    put_u32(bytes, 0x200 + 20, 1);
    put_u32(bytes, 0x200 + 24, 1);
    put_u32(bytes, 0x200 + 28, 0x1050);
    put_u32(bytes, 0x200 + 32, 0x1054);
    put_u32(bytes, 0x200 + 36, 0x1058);
    put_u32(bytes, 0x250, 0x1300);
    put_u32(bytes, 0x254, 0x1060);
    put_u16(bytes, 0x258, 0);
    put_name(bytes, 0x260, "fixture_export");

    put_u32(bytes, 0x300, 0x1140);
    put_u32(bytes, 0x30c, 0x1160);
    put_u32(bytes, 0x310, 0x1170);
    put_u64(bytes, 0x340, 0x1190);
    put_name(bytes, 0x360, "fixture.dll");
    put_u16(bytes, 0x390, 7);
    put_name(bytes, 0x392, "imported_function");

    put_u32(bytes, 0x3c0, 0x1000);
    put_u32(bytes, 0x3c4, 12);
    put_u16(bytes, 0x3c8, 0xa300);
    put_u16(bytes, 0x3ca, 0);

    put_u32(bytes, 0x3e0 + 12, 2);
    put_u32(bytes, 0x3e0 + 16, 16);
    put_u32(bytes, 0x3e0 + 24, 0x650);
    put_name(bytes, 0x650, "RSDS");
    put_u32(bytes, 0x410, 0x1300);
    put_u32(bytes, 0x414, 0x1301);
    put_u32(bytes, 0x418, 0x1280);
    put_u32(bytes, 0x450, 0x70);
    put_u32(bytes, 0x700, 16);
    put_u16(bytes, 0x704, 0x0200);
    put_u16(bytes, 0x706, 2);
    return bytes;
}

auto minimal_elf64() -> std::vector<std::byte> {
    std::vector<std::byte> bytes(0x2c0);
    bytes[0] = std::byte{0x7f};
    bytes[1] = std::byte{'E'};
    bytes[2] = std::byte{'L'};
    bytes[3] = std::byte{'F'};
    bytes[4] = std::byte{2};
    bytes[5] = std::byte{1};
    bytes[6] = std::byte{1};
    put_u16(bytes, 16, 2);
    put_u16(bytes, 18, 62);
    put_u32(bytes, 20, 1);
    put_u64(bytes, 24, UINT64_C(0x400100));
    put_u64(bytes, 32, 64);
    put_u64(bytes, 40, 0x200);
    put_u16(bytes, 52, 64);
    put_u16(bytes, 54, 56);
    put_u16(bytes, 56, 1);
    put_u16(bytes, 58, 64);
    put_u16(bytes, 60, 3);
    put_u16(bytes, 62, 2);

    put_u32(bytes, 64, 1);
    put_u32(bytes, 68, 5);
    put_u64(bytes, 72, 0x100);
    put_u64(bytes, 80, UINT64_C(0x400100));
    put_u64(bytes, 88, UINT64_C(0x400100));
    put_u64(bytes, 96, 1);
    put_u64(bytes, 104, 1);
    put_u64(bytes, 112, 0x100);
    bytes[0x100] = std::byte{0xc3};
    constexpr std::string_view names{"\0.text\0.shstrtab\0", 17};
    for (std::size_t index = 0; index < names.size(); ++index) {
        bytes[0x180 + index] = static_cast<std::byte>(names[index]);
    }

    const auto text = std::size_t{0x240};
    put_u32(bytes, text, 1);
    put_u32(bytes, text + 4, 1);
    put_u64(bytes, text + 8, 0x6);
    put_u64(bytes, text + 16, UINT64_C(0x400100));
    put_u64(bytes, text + 24, 0x100);
    put_u64(bytes, text + 32, 1);
    put_u64(bytes, text + 48, 16);

    const auto strings = std::size_t{0x280};
    put_u32(bytes, strings, 7);
    put_u32(bytes, strings + 4, 3);
    put_u64(bytes, strings + 24, 0x180);
    put_u64(bytes, strings + 32, names.size());
    put_u64(bytes, strings + 48, 1);
    return bytes;
}

void put_elf64_section(
    std::vector<std::byte>& bytes,
    std::size_t header,
    std::uint32_t name,
    std::uint32_t type,
    std::uint64_t flags,
    std::uint64_t address,
    std::uint64_t offset,
    std::uint64_t size,
    std::uint32_t link = 0,
    std::uint32_t info = 0,
    std::uint64_t alignment = 1,
    std::uint64_t entrySize = 0) {
    put_u32(bytes, header, name);
    put_u32(bytes, header + 4, type);
    put_u64(bytes, header + 8, flags);
    put_u64(bytes, header + 16, address);
    put_u64(bytes, header + 24, offset);
    put_u64(bytes, header + 32, size);
    put_u32(bytes, header + 40, link);
    put_u32(bytes, header + 44, info);
    put_u64(bytes, header + 48, alignment);
    put_u64(bytes, header + 56, entrySize);
}

auto rich_elf64(bool pie) -> std::vector<std::byte> {
    std::vector<std::byte> bytes(0x800);
    bytes[0] = std::byte{0x7f};
    bytes[1] = std::byte{'E'};
    bytes[2] = std::byte{'L'};
    bytes[3] = std::byte{'F'};
    bytes[4] = std::byte{2};
    bytes[5] = std::byte{1};
    bytes[6] = std::byte{1};
    put_u16(bytes, 16, 3);
    put_u16(bytes, 18, 62);
    put_u32(bytes, 20, 1);
    put_u64(bytes, 24, UINT64_C(0x400100));
    put_u64(bytes, 32, 64);
    put_u64(bytes, 40, 0x500);
    put_u16(bytes, 52, 64);
    put_u16(bytes, 54, 56);
    put_u16(bytes, 56, 1);
    put_u16(bytes, 58, 64);
    put_u16(bytes, 60, 10);
    put_u16(bytes, 62, 9);
    put_u32(bytes, 64, 1);
    put_u32(bytes, 68, 7);
    put_u64(bytes, 72, 0x100);
    put_u64(bytes, 80, UINT64_C(0x400100));
    put_u64(bytes, 88, UINT64_C(0x400100));
    put_u64(bytes, 96, 0x300);
    put_u64(bytes, 104, 0x300);
    put_u64(bytes, 112, 0x100);
    bytes[0x100] = std::byte{0xc3};

    constexpr std::string_view dynamicStrings{"\0imported\0exported\0needed.so\0", 29};
    for (std::size_t index = 0; index < dynamicStrings.size(); ++index) {
        bytes[0x180 + index] = static_cast<std::byte>(dynamicStrings[index]);
    }
    put_u32(bytes, 0x1a0 + 24, 1);
    bytes[0x1a0 + 24 + 4] = std::byte{0x12};
    put_u16(bytes, 0x1a0 + 24 + 6, 0);
    put_u32(bytes, 0x1a0 + 48, 10);
    bytes[0x1a0 + 48 + 4] = std::byte{0x12};
    put_u16(bytes, 0x1a0 + 48 + 6, 1);
    put_u64(bytes, 0x1a0 + 48 + 8, UINT64_C(0x400100));
    put_u64(bytes, 0x1a0 + 48 + 16, 1);
    put_u64(bytes, 0x1e8, UINT64_C(0x400108));
    put_u64(bytes, 0x1f0, (UINT64_C(1) << 32U) | 6U);
    put_u64(bytes, 0x1f8, 0);
    put_u64(bytes, 0x210, UINT64_C(0x6ffffdfb));
    put_u64(bytes, 0x218, pie ? UINT64_C(0x08000000) : 0);
    put_u64(bytes, 0x220, 1);
    put_u64(bytes, 0x228, 19);
    put_u64(bytes, 0x230, 0);
    put_u64(bytes, 0x238, 0);
    put_u32(bytes, 0x240, 4);
    put_u32(bytes, 0x244, 4);
    put_u32(bytes, 0x248, 3);
    put_name(bytes, 0x24c, "GNU");

    std::string names(1, '\0');
    for (const auto name : {
             ".text", ".dynstr", ".dynsym", ".rela.dyn", ".dynamic",
             ".note.gnu.build-id", ".eh_frame", ".debug_info", ".shstrtab"}) {
        names.append(name);
        names.push_back('\0');
    }
    for (std::size_t index = 0; index < names.size(); ++index) {
        bytes[0x380 + index] = static_cast<std::byte>(names[index]);
    }
    const auto nameOf = [&](std::string_view name) {
        return static_cast<std::uint32_t>(names.find(name));
    };
    put_elf64_section(bytes, 0x540, nameOf(".text"), 1, 0x6, 0x400100, 0x100, 0x10, 0, 0, 16);
    put_elf64_section(bytes, 0x580, nameOf(".dynstr"), 3, 0x2, 0x400180, 0x180, dynamicStrings.size(), 0, 0, 1);
    put_elf64_section(bytes, 0x5c0, nameOf(".dynsym"), 11, 0x2, 0x4001a0, 0x1a0, 72, 2, 1, 8, 24);
    put_elf64_section(bytes, 0x600, nameOf(".rela.dyn"), 4, 0x2, 0x4001e8, 0x1e8, 24, 3, 1, 8, 24);
    put_elf64_section(bytes, 0x640, nameOf(".dynamic"), 6, 0x3, 0x400210, 0x210, 48, 2, 0, 8, 16);
    put_elf64_section(bytes, 0x680, nameOf(".note.gnu.build-id"), 7, 0x2, 0x400240, 0x240, 16, 0, 0, 4);
    put_elf64_section(bytes, 0x6c0, nameOf(".eh_frame"), 1, 0x2, 0x400260, 0x260, 16, 0, 0, 8);
    put_elf64_section(bytes, 0x700, nameOf(".debug_info"), 1, 0, 0, 0x300, 16, 0, 0, 1);
    put_elf64_section(bytes, 0x740, nameOf(".shstrtab"), 3, 0, 0, 0x380, names.size(), 0, 0, 1);
    return bytes;
}

auto sectionless_elf64_pie() -> std::vector<std::byte> {
    std::vector<std::byte> bytes(0x300);
    bytes[0] = std::byte{0x7f};
    bytes[1] = std::byte{'E'};
    bytes[2] = std::byte{'L'};
    bytes[3] = std::byte{'F'};
    bytes[4] = std::byte{2};
    bytes[5] = std::byte{1};
    bytes[6] = std::byte{1};
    put_u16(bytes, 16, 3);
    put_u16(bytes, 18, 62);
    put_u32(bytes, 20, 1);
    put_u64(bytes, 24, UINT64_C(0x400100));
    put_u64(bytes, 32, 64);
    put_u64(bytes, 40, 0);
    put_u16(bytes, 52, 64);
    put_u16(bytes, 54, 56);
    put_u16(bytes, 56, 3);
    put_u16(bytes, 58, 64);
    put_u16(bytes, 60, 0);
    put_u16(bytes, 62, 0);

    put_u32(bytes, 64, 1);
    put_u32(bytes, 68, 5);
    put_u64(bytes, 72, 0);
    put_u64(bytes, 80, UINT64_C(0x400000));
    put_u64(bytes, 88, UINT64_C(0x400000));
    put_u64(bytes, 96, 0x300);
    put_u64(bytes, 104, 0x300);
    put_u64(bytes, 112, 0x1000);

    put_u32(bytes, 120, 3);
    put_u32(bytes, 124, 4);
    put_u64(bytes, 128, 0x200);
    put_u64(bytes, 136, UINT64_C(0x400200));
    put_u64(bytes, 144, UINT64_C(0x400200));
    put_u64(bytes, 152, 21);
    put_u64(bytes, 160, 21);
    put_u64(bytes, 168, 1);

    put_u32(bytes, 176, 2);
    put_u32(bytes, 180, 6);
    put_u64(bytes, 184, 0x220);
    put_u64(bytes, 192, UINT64_C(0x400220));
    put_u64(bytes, 200, UINT64_C(0x400220));
    put_u64(bytes, 208, 32);
    put_u64(bytes, 216, 32);
    put_u64(bytes, 224, 8);
    put_name(bytes, 0x200, "/lib64/ld-linux.so.2");
    put_u64(bytes, 0x220, UINT64_C(0x6ffffdfb));
    put_u64(bytes, 0x228, UINT64_C(0x08000000));
    put_u64(bytes, 0x230, 0);
    put_u64(bytes, 0x238, 0);
    bytes[0x100] = std::byte{0xc3};
    return bytes;
}

auto minimal_macho64() -> std::vector<std::byte> {
    constexpr std::size_t segmentOffset = 32;
    constexpr std::size_t symtabOffset = segmentOffset + 152;
    constexpr std::size_t mainOffset = symtabOffset + 24;
    std::vector<std::byte> bytes(0x400);
    put_u32(bytes, 0, 0xfeedfacfU);
    put_u32(bytes, 4, 0x01000007U);
    put_u32(bytes, 8, 3);
    put_u32(bytes, 12, 2);
    put_u32(bytes, 16, 3);
    put_u32(bytes, 20, 200);
    put_u32(bytes, segmentOffset, 0x19U);
    put_u32(bytes, segmentOffset + 4, 152);
    put_name(bytes, segmentOffset + 8, "__TEXT");
    put_u64(bytes, segmentOffset + 24, UINT64_C(0x100000000));
    put_u64(bytes, segmentOffset + 32, 0x1000);
    put_u64(bytes, segmentOffset + 40, 0);
    put_u64(bytes, segmentOffset + 48, 0x300);
    put_u32(bytes, segmentOffset + 56, 7);
    put_u32(bytes, segmentOffset + 60, 5);
    put_u32(bytes, segmentOffset + 64, 1);
    const auto sectionOffset = segmentOffset + 72;
    put_name(bytes, sectionOffset, "__text");
    put_name(bytes, sectionOffset + 16, "__TEXT");
    put_u64(bytes, sectionOffset + 32, UINT64_C(0x100000200));
    put_u64(bytes, sectionOffset + 40, 1);
    put_u32(bytes, sectionOffset + 48, 0x200);
    put_u32(bytes, sectionOffset + 52, 0);
    put_u32(bytes, sectionOffset + 64, 0x80000400U);
    put_u32(bytes, symtabOffset, 2);
    put_u32(bytes, symtabOffset + 4, 24);
    put_u32(bytes, symtabOffset + 8, 0x300);
    put_u32(bytes, symtabOffset + 12, 1);
    put_u32(bytes, symtabOffset + 16, 0x310);
    put_u32(bytes, symtabOffset + 20, 16);
    put_u32(bytes, mainOffset, 0x80000028U);
    put_u32(bytes, mainOffset + 4, 24);
    put_u64(bytes, mainOffset + 8, 0x200);
    bytes[0x200] = std::byte{0xc3};
    put_u32(bytes, 0x300, 1);
    bytes[0x304] = std::byte{0x0f};
    bytes[0x305] = std::byte{1};
    put_u64(bytes, 0x308, UINT64_C(0x100000200));
    put_name(bytes, 0x311, "_main");
    return bytes;
}

} // namespace

TEST_CASE(linked_parser_normalizes_minimal_pe64) {
    const auto bytes = minimal_pe64();
    const auto parsed = binobf::parse_linked_image(bytes, "fixture.exe");
    REQUIRE(parsed.has_value());
    REQUIRE_EQ(parsed.value().image.format, binobf::BinaryFormat::PE);
    REQUIRE_EQ(parsed.value().image.type, binobf::BinaryType::Executable);
    REQUIRE_EQ(parsed.value().image.architecture, binobf::Architecture::X86_64);
    REQUIRE_EQ(parsed.value().image.sections.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().sectionLayout.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().image.entryPoint->value, UINT64_C(0x140001000));
    REQUIRE_EQ(parsed.value().sourceBytes, bytes);
}

TEST_CASE(linked_parser_normalizes_minimal_elf64) {
    const auto bytes = minimal_elf64();
    const auto parsed = binobf::parse_linked_image(bytes, "fixture.elf");
    REQUIRE(parsed.has_value());
    REQUIRE_EQ(parsed.value().image.format, binobf::BinaryFormat::ELF);
    REQUIRE_EQ(parsed.value().image.type, binobf::BinaryType::Executable);
    REQUIRE_EQ(parsed.value().image.segments.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().image.sections.size(), std::size_t{2});
    REQUIRE_EQ(parsed.value().image.sections.front().name, ".text");
    REQUIRE_EQ(parsed.value().image.entryPoint->value, UINT64_C(0x400100));
}

TEST_CASE(linked_parser_normalizes_minimal_macho64) {
    const auto bytes = minimal_macho64();
    const auto parsed = binobf::parse_linked_image(bytes, "fixture.macho");
    REQUIRE(parsed.has_value());
    REQUIRE_EQ(parsed.value().image.format, binobf::BinaryFormat::MachO);
    REQUIRE_EQ(parsed.value().image.type, binobf::BinaryType::Executable);
    REQUIRE_EQ(parsed.value().image.architecture, binobf::Architecture::X86_64);
    REQUIRE_EQ(parsed.value().image.sections.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().image.functions.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().image.functions.front().name, "_main");
    REQUIRE_EQ(parsed.value().image.entryPoint->value, UINT64_C(0x100000200));
    const auto verified = binobf::verify_linked_image(bytes, "fixture.macho");
    REQUIRE(verified.has_value());
}

TEST_CASE(pe_linked_parser_normalizes_directories_and_dynamic_metadata) {
    const auto parsed = binobf::parse_linked_image(rich_pe64(), "fixture.exe");
    REQUIRE(parsed.has_value());
    REQUIRE_EQ(parsed.value().image.imports.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().image.imports.front().library, "fixture.dll");
    REQUIRE_EQ(parsed.value().image.imports.front().name, "imported_function");
    REQUIRE_EQ(parsed.value().image.exports.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().image.exports.front().name, "fixture_export");
    REQUIRE_EQ(parsed.value().image.relocations.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().image.resources.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().image.unwindInfo.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().image.functions.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().image.debugInfo.size(), std::size_t{1});
    REQUIRE(parsed.value().signedImage);
    REQUIRE_EQ(parsed.value().directories.size(), std::size_t{9});
}

TEST_CASE(pe_linked_parser_rejects_unmappable_import_metadata) {
    auto bytes = rich_pe64();
    put_u32(bytes, 0x30c, 0x90000000);
    const auto parsed = binobf::parse_linked_image(bytes, "fixture.exe");
    REQUIRE(!parsed.has_value());
    REQUIRE_EQ(parsed.error().code, "linked.import_name");
}

TEST_CASE(elf_linked_parser_normalizes_dynamic_symbols_relocations_and_metadata) {
    const auto parsed = binobf::parse_linked_image(rich_elf64(false), "fixture.so");
    REQUIRE(parsed.has_value());
    REQUIRE_EQ(parsed.value().image.type, binobf::BinaryType::SharedLibrary);
    REQUIRE_EQ(parsed.value().image.symbols.size(), std::size_t{3});
    REQUIRE_EQ(parsed.value().image.imports.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().image.imports.front().name, "imported");
    REQUIRE_EQ(parsed.value().image.exports.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().image.exports.front().name, "exported");
    REQUIRE_EQ(parsed.value().image.relocations.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().image.debugInfo.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().directories.size(), std::size_t{3});
}

TEST_CASE(elf_linked_parser_recognizes_df_1_pie) {
    const auto parsed = binobf::parse_linked_image(rich_elf64(true), "fixture-pie");
    REQUIRE(parsed.has_value());
    REQUIRE_EQ(parsed.value().image.type, binobf::BinaryType::Executable);
    REQUIRE(parsed.value().positionIndependent);
}

TEST_CASE(elf_linked_parser_uses_program_metadata_without_section_headers) {
    const auto parsed = binobf::parse_linked_image(sectionless_elf64_pie(), "stripped-pie");
    REQUIRE(parsed.has_value());
    REQUIRE_EQ(parsed.value().image.type, binobf::BinaryType::Executable);
    REQUIRE(parsed.value().positionIndependent);
    REQUIRE(parsed.value().image.sections.empty());
    REQUIRE_EQ(parsed.value().image.segments.size(), std::size_t{3});
    REQUIRE_EQ(parsed.value().directories.size(), std::size_t{2});
}

TEST_CASE(linked_baseline_rewrite_is_byte_identical) {
    for (const auto& parsed : {
             binobf::parse_linked_image(rich_pe64(), "fixture.exe"),
             binobf::parse_linked_image(rich_elf64(false), "fixture.so")}) {
        REQUIRE(parsed.has_value());
        const auto rewritten = binobf::rewrite_linked_image(parsed.value());
        REQUIRE(rewritten.has_value());
        REQUIRE_EQ(rewritten.value().bytes, parsed.value().sourceBytes);
        REQUIRE_EQ(rewritten.value().stats.bytesChanged, std::size_t{0});
    }
}

TEST_CASE(pe_debug_rewrite_requires_signature_intent_and_repairs_metadata) {
    const auto parsed = binobf::parse_linked_image(rich_pe64(), "fixture.exe");
    REQUIRE(parsed.has_value());
    auto options = binobf::LinkedRewriteOptions{.stripDebug = true};
    const auto rejected = binobf::rewrite_linked_image(parsed.value(), options);
    REQUIRE(!rejected.has_value());
    REQUIRE_EQ(rejected.error().code, "linked.signature_intent_required");

    options.allowSignatureInvalidation = true;
    const auto rewritten = binobf::rewrite_linked_image(parsed.value(), options);
    REQUIRE(rewritten.has_value());
    REQUIRE_EQ(rewritten.value().image.image.debugInfo.size(), std::size_t{0});
    REQUIRE(!rewritten.value().image.signedImage);
    REQUIRE_EQ(rewritten.value().stats.debugRecordsRemoved, std::size_t{1});
    REQUIRE(rewritten.value().stats.signatureRemoved);
    REQUIRE(rewritten.value().stats.bytesChanged > 0);
}

TEST_CASE(linked_driver_policy_keeps_rewriting_conservative) {
    const auto parsed = binobf::parse_linked_image(rich_pe64(), "fixture.sys");
    REQUIRE(parsed.has_value());
    REQUIRE_EQ(parsed.value().image.type, binobf::BinaryType::KernelDriver);
    const auto rewritten = binobf::rewrite_linked_image(
        parsed.value(),
        binobf::LinkedRewriteOptions{
            .stripDebug = true,
            .allowSignatureInvalidation = true,
        });
    REQUIRE(rewritten.has_value());
    REQUIRE_EQ(rewritten.value().image.image.type, binobf::BinaryType::KernelDriver);
    REQUIRE_EQ(rewritten.value().stats.debugRecordsRemoved, std::size_t{1});
}

TEST_CASE(elf_debug_rewrite_preserves_dynamic_contract) {
    const auto parsed = binobf::parse_linked_image(rich_elf64(false), "fixture.so");
    REQUIRE(parsed.has_value());
    const auto rewritten = binobf::rewrite_linked_image(
        parsed.value(), binobf::LinkedRewriteOptions{.stripDebug = true});
    REQUIRE(rewritten.has_value());
    REQUIRE_EQ(rewritten.value().image.image.debugInfo.size(), std::size_t{0});
    REQUIRE_EQ(rewritten.value().image.image.imports.size(), parsed.value().image.imports.size());
    REQUIRE_EQ(rewritten.value().image.image.exports.size(), parsed.value().image.exports.size());
    REQUIRE_EQ(rewritten.value().stats.debugSectionsRemoved, std::size_t{1});
    REQUIRE(rewritten.value().stats.bytesChanged > 0);
}

TEST_CASE(linked_structural_verifier_reports_format_relationships) {
    const auto verified = binobf::verify_linked_image(rich_pe64(), "fixture.exe");
    REQUIRE(verified.has_value());
    REQUIRE_EQ(verified.value().image.imports.size(), std::size_t{1});
    REQUIRE_EQ(verified.value().checks.front().name, "headers");
    REQUIRE_EQ(verified.value().checks.front().status, binobf::VerificationStatus::Passed);
    REQUIRE(verified.value().checks.size() >= std::size_t{8});
}

TEST_CASE(linked_parser_rejects_unmapped_entry_points) {
    auto pe = minimal_pe64();
    put_u32(pe, 0x58 + 16, 0x90000000);
    const auto invalidPe = binobf::parse_linked_image(pe, "fixture.exe");
    REQUIRE(!invalidPe.has_value());
    REQUIRE_EQ(invalidPe.error().code, "linked.entry_point");

    auto elf = minimal_elf64();
    put_u64(elf, 24, UINT64_C(0x90000000));
    const auto invalidElf = binobf::parse_linked_image(elf, "fixture.elf");
    REQUIRE(!invalidElf.has_value());
    REQUIRE_EQ(invalidElf.error().code, "linked.entry_point");
}

TEST_CASE(linked_verifier_detects_pe_checksum_corruption) {
    const auto parsed = binobf::parse_linked_image(rich_pe64(), "fixture.exe");
    REQUIRE(parsed.has_value());
    const auto rewritten = binobf::rewrite_linked_image(
        parsed.value(),
        binobf::LinkedRewriteOptions{
            .stripDebug = true,
            .allowSignatureInvalidation = true,
        });
    REQUIRE(rewritten.has_value());
    auto corrupted = rewritten.value().bytes;
    corrupted[0x650] = std::byte{1};
    const auto verified = binobf::verify_linked_image(corrupted, "fixture.exe");
    REQUIRE(!verified.has_value());
    REQUIRE_EQ(verified.error().code, "linked.checksum_mismatch");
}

TEST_CASE(linked_parser_enforces_limits_before_table_allocation) {
    auto limits = binobf::LinkedParseLimits{};
    limits.maxSections = 0;
    const auto parsed = binobf::parse_linked_image(minimal_pe64(), "fixture.exe", limits);
    REQUIRE(!parsed.has_value());
    REQUIRE_EQ(parsed.error().code, "linked.section_limit");
}

TEST_CASE(linked_parser_rejects_relocatable_objects_and_truncated_tables) {
    auto object = minimal_elf64();
    put_u16(object, 16, 1);
    const auto unsupported = binobf::parse_linked_image(object, "fixture.o");
    REQUIRE(!unsupported.has_value());
    REQUIRE_EQ(unsupported.error().code, "linked.unsupported_type");

    auto truncated = minimal_pe64();
    truncated.resize(0x180);
    const auto malformed = binobf::parse_linked_image(truncated, "truncated.exe");
    REQUIRE(!malformed.has_value());
    REQUIRE_EQ(malformed.error().code, "linked.header_range");
}

int main() {
    return binobf::test::run_all();
}

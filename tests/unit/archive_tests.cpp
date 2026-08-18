#include "../test_support.hpp"

#include <binobf/formats/archive.hpp>
#include <binobf/formats/archive_writer.hpp>

#include <algorithm>
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

void put_u32_be(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        bytes.at(offset + index) = static_cast<std::byte>(
            (value >> ((3U - index) * 8U)) & 0xffU);
    }
}

auto coff_object() -> std::vector<std::byte> {
    std::vector<std::byte> bytes(64);
    put_u16(bytes, 0, 0x8664);
    put_u16(bytes, 2, 1);
    constexpr std::string_view name{".text"};
    for (std::size_t index = 0; index < name.size(); ++index) {
        bytes[20 + index] = static_cast<std::byte>(name[index]);
    }
    bytes[20 + 16] = std::byte{4};
    bytes[20 + 20] = std::byte{60};
    bytes[20 + 36] = std::byte{0x20};
    bytes[20 + 38] = std::byte{0x50};
    bytes[20 + 39] = std::byte{0x60};
    bytes[60] = std::byte{0xc3};
    return bytes;
}

auto indexed_coff_object() -> std::vector<std::byte> {
    auto bytes = coff_object();
    bytes.resize(86);
    put_u32(bytes, 8, 64);
    put_u32(bytes, 12, 1);
    bytes[64] = std::byte{'f'};
    bytes[65] = std::byte{'o'};
    bytes[66] = std::byte{'o'};
    put_u16(bytes, 64 + 12, 1);
    put_u16(bytes, 64 + 14, 0x20);
    bytes[64 + 16] = std::byte{2};
    put_u32(bytes, 82, 4);
    return bytes;
}

void append_text(std::vector<std::byte>& bytes, std::string_view text) {
    for (const auto value : text) bytes.push_back(static_cast<std::byte>(value));
}

void append_field(std::vector<std::byte>& bytes, std::string value, std::size_t width) {
    value.resize(width, ' ');
    append_text(bytes, value.substr(0, width));
}

auto append_member(
    std::vector<std::byte>& bytes,
    std::string name,
    const std::vector<std::byte>& contents) -> std::size_t {
    const auto header = bytes.size();
    append_field(bytes, std::move(name), 16);
    append_field(bytes, "0", 12);
    append_field(bytes, "0", 6);
    append_field(bytes, "0", 6);
    append_field(bytes, "644", 8);
    append_field(bytes, std::to_string(contents.size()), 10);
    append_text(bytes, "`\n");
    bytes.insert(bytes.end(), contents.begin(), contents.end());
    if ((contents.size() & 1U) != 0) bytes.push_back(std::byte{'\n'});
    return header;
}

auto empty_archive() -> std::vector<std::byte> {
    std::vector<std::byte> bytes;
    append_text(bytes, "!<arch>\n");
    return bytes;
}

} // namespace

TEST_CASE(archive_parser_classifies_objects_and_opaque_members) {
    auto bytes = empty_archive();
    append_member(bytes, "one.obj/", coff_object());
    append_member(bytes, "readme.txt/", {std::byte{'o'}, std::byte{'k'}});
    const auto parsed = binobf::parse_archive(bytes, "fixture.lib");
    REQUIRE(parsed.has_value());
    REQUIRE_EQ(parsed.value().flavor, binobf::ArchiveFlavor::Coff);
    REQUIRE_EQ(parsed.value().members.size(), std::size_t{2});
    REQUIRE_EQ(parsed.value().members[0].kind, binobf::ArchiveMemberKind::Object);
    REQUIRE_EQ(parsed.value().members[0].name, "one.obj");
    REQUIRE_EQ(parsed.value().members[1].kind, binobf::ArchiveMemberKind::Opaque);
    REQUIRE_EQ(parsed.value().architecture, binobf::Architecture::X86_64);
}

TEST_CASE(archive_parser_resolves_gnu_and_bsd_long_names) {
    auto gnu = empty_archive();
    std::vector<std::byte> names;
    append_text(names, "a_very_long_member_name.obj/\n");
    append_member(gnu, "//", names);
    append_member(gnu, "/0", coff_object());
    const auto parsedGnu = binobf::parse_archive(gnu, "fixture.a");
    REQUIRE(parsedGnu.has_value());
    REQUIRE_EQ(parsedGnu.value().members[1].name, "a_very_long_member_name.obj");
    REQUIRE_EQ(parsedGnu.value().members[1].kind, binobf::ArchiveMemberKind::Object);

    auto bsd = empty_archive();
    constexpr std::string_view bsdName{"bsd_extended_member.obj"};
    std::vector<std::byte> payload;
    append_text(payload, bsdName);
    const auto object = coff_object();
    payload.insert(payload.end(), object.begin(), object.end());
    append_member(bsd, "#1/23", payload);
    const auto parsedBsd = binobf::parse_archive(bsd, "fixture.a");
    REQUIRE(parsedBsd.has_value());
    REQUIRE_EQ(parsedBsd.value().flavor, binobf::ArchiveFlavor::Bsd);
    REQUIRE_EQ(parsedBsd.value().members.front().name, bsdName);
    REQUIRE_EQ(parsedBsd.value().members.front().contents, object);
}

TEST_CASE(archive_parser_reads_gnu_symbol_index_relationships) {
    auto bytes = empty_archive();
    std::vector<std::byte> index(12);
    put_u32_be(index, 0, 1);
    put_u32_be(index, 4, 80);
    index[8] = std::byte{'f'};
    index[9] = std::byte{'o'};
    index[10] = std::byte{'o'};
    append_member(bytes, "/", index);
    REQUIRE_EQ(append_member(bytes, "one.obj/", coff_object()), std::size_t{80});
    const auto parsed = binobf::parse_archive(bytes, "fixture.a");
    REQUIRE(parsed.has_value());
    REQUIRE_EQ(parsed.value().symbols.size(), std::size_t{1});
    REQUIRE_EQ(parsed.value().symbols.front().name, "foo");
    REQUIRE_EQ(parsed.value().symbols.front().member, parsed.value().members[1].id);
}

TEST_CASE(archive_parser_rejects_bad_headers_ranges_and_limits) {
    auto badTrailer = empty_archive();
    append_member(badTrailer, "one.obj/", coff_object());
    badTrailer[8 + 58] = std::byte{'x'};
    const auto malformed = binobf::parse_archive(badTrailer, "fixture.a");
    REQUIRE(!malformed.has_value());
    REQUIRE_EQ(malformed.error().code, "archive.member_header");

    auto limits = binobf::ArchiveParseLimits{};
    limits.maxMembers = 0;
    const auto limited = binobf::parse_archive(badTrailer, "fixture.a", limits);
    REQUIRE(!limited.has_value());
    REQUIRE_EQ(limited.error().code, "archive.member_limit");
}

TEST_CASE(archive_writer_preserves_an_unchanged_archive_exactly) {
    auto bytes = empty_archive();
    std::vector<std::byte> names;
    append_text(names, "a_very_long_member_name.obj/\n");
    append_member(bytes, "//", names);
    append_member(bytes, "/0", indexed_coff_object());
    const auto parsed = binobf::parse_archive(bytes, "fixture.a");
    REQUIRE(parsed.has_value());
    const auto written = binobf::write_archive(parsed.value());
    REQUIRE(written.has_value());
    REQUIRE_EQ(written.value(), bytes);
}

TEST_CASE(archive_writer_rebuilds_gnu_and_coff_symbol_indexes) {
    auto bytes = empty_archive();
    append_member(bytes, "one.obj/", indexed_coff_object());
    auto parsed = binobf::parse_archive(bytes, "fixture.a");
    REQUIRE(parsed.has_value());
    parsed.value().members.front().contents[60] = std::byte{0x90};
    const auto gnu = binobf::write_archive(parsed.value());
    REQUIRE(gnu.has_value());
    const auto reparsedGnu = binobf::parse_archive(gnu.value(), "fixture.a");
    REQUIRE(reparsedGnu.has_value());
    REQUIRE_EQ(reparsedGnu.value().symbols.size(), std::size_t{1});
    REQUIRE_EQ(reparsedGnu.value().symbols.front().name, "foo");
    REQUIRE_EQ(reparsedGnu.value().members[1].contents[60], std::byte{0x90});

    parsed.value().flavor = binobf::ArchiveFlavor::Coff;
    const auto coff = binobf::write_archive(parsed.value());
    REQUIRE(coff.has_value());
    const auto reparsedCoff = binobf::parse_archive(coff.value(), "fixture.lib");
    REQUIRE(reparsedCoff.has_value());
    REQUIRE_EQ(reparsedCoff.value().flavor, binobf::ArchiveFlavor::Coff);
    REQUIRE_EQ(reparsedCoff.value().symbols.size(), std::size_t{1});
    REQUIRE_EQ(reparsedCoff.value().symbols.front().name, "foo");
    const auto indexCount = std::count_if(
        reparsedCoff.value().members.begin(), reparsedCoff.value().members.end(),
        [](const binobf::ArchiveMember& member) {
            return member.kind == binobf::ArchiveMemberKind::SymbolIndex;
        });
    REQUIRE_EQ(indexCount, std::ptrdiff_t{2});
}

int main() {
    return binobf::test::run_all();
}

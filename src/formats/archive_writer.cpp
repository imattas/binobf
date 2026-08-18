#include <binobf/formats/archive_writer.hpp>

#include "object_parser_internal.hpp"

#include <binobf/formats/object_parser.hpp>

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace binobf {
namespace {

struct IndexedSymbol {
    std::string name;
    EntityId member;
};

struct OrdinaryMember {
    const ArchiveMember* member{nullptr};
    std::string headerName;
    std::uint32_t headerOffset{0};
};

auto failure(std::string code, std::string message)
    -> Result<std::vector<std::byte>, Diagnostic> {
    return Result<std::vector<std::byte>, Diagnostic>::failure(
        Diagnostic{DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

void append_text(std::vector<std::byte>& output, std::string_view value) {
    for (const auto character : value) output.push_back(static_cast<std::byte>(character));
}

auto integer_text(std::uint64_t value, int base = 10) -> std::string {
    char buffer[32]{};
    const auto converted = std::to_chars(std::begin(buffer), std::end(buffer), value, base);
    return std::string{buffer, converted.ptr};
}

auto append_field(std::vector<std::byte>& output, std::string value, std::size_t width) -> bool {
    if (value.size() > width) return false;
    value.resize(width, ' ');
    append_text(output, value);
    return true;
}

auto append_member(
    std::vector<std::byte>& output,
    std::string name,
    std::span<const std::byte> contents,
    std::uint64_t timestamp,
    std::uint32_t owner,
    std::uint32_t group,
    std::uint32_t mode) -> bool {
    if (!append_field(output, std::move(name), 16)
        || !append_field(output, integer_text(timestamp), 12)
        || !append_field(output, integer_text(owner), 6)
        || !append_field(output, integer_text(group), 6)
        || !append_field(output, integer_text(mode, 8), 8)
        || !append_field(output, integer_text(contents.size()), 10)) {
        return false;
    }
    append_text(output, "`\n");
    output.insert(output.end(), contents.begin(), contents.end());
    if ((contents.size() & 1U) != 0) output.push_back(std::byte{'\n'});
    return true;
}

void append_be32(std::vector<std::byte>& output, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
    }
}

void append_le16(std::vector<std::byte>& output, std::uint16_t value) {
    output.push_back(static_cast<std::byte>(value & 0xffU));
    output.push_back(static_cast<std::byte>((value >> 8U) & 0xffU));
}

void append_le32(std::vector<std::byte>& output, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        output.push_back(static_cast<std::byte>((value >> (index * 8U)) & 0xffU));
    }
}

auto member_index(const std::vector<OrdinaryMember>& members, EntityId id)
    -> std::optional<std::size_t> {
    const auto found = std::find_if(
        members.begin(), members.end(), [id](const OrdinaryMember& member) {
            return member.member->id == id;
        });
    return found == members.end()
        ? std::nullopt
        : std::optional<std::size_t>{static_cast<std::size_t>(found - members.begin())};
}

auto is_unchanged(const ArchiveImage& image) -> bool {
    if (image.members.size() != image.layout.size()) return false;
    for (std::size_t index = 0; index < image.members.size(); ++index) {
        const auto& member = image.members[index];
        const auto& layout = image.layout[index];
        if (member.id != layout.member || member.name != layout.originalName
            || member.timestamp != layout.originalTimestamp
            || member.owner != layout.originalOwner || member.group != layout.originalGroup
            || member.mode != layout.originalMode
            || layout.payloadSize != member.contents.size()
            || !formats::detail::contains_range(
                static_cast<std::size_t>(layout.dataOffset), member.contents.size(),
                image.sourceBytes.size())) return false;
        const auto original = std::span<const std::byte>{image.sourceBytes}.subspan(
            static_cast<std::size_t>(layout.dataOffset), member.contents.size());
        if (!std::equal(original.begin(), original.end(), member.contents.begin())) return false;
    }
    return true;
}

auto import_symbol(const ArchiveMember& member) -> std::optional<std::string> {
    if (member.contents.size() <= 20) return std::nullopt;
    std::string name;
    for (std::size_t index = 20; index < member.contents.size(); ++index) {
        const auto byte = member.contents[index];
        if (byte == std::byte{0}) return name.empty() ? std::nullopt : std::optional{name};
        name.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
    }
    return std::nullopt;
}

auto advance_offset(std::size_t offset, std::size_t payload) -> std::optional<std::size_t> {
    const auto withHeader = formats::detail::checked_add(offset, std::size_t{60});
    if (!withHeader.has_value()) return std::nullopt;
    const auto paddedPayload = formats::detail::checked_add(payload, payload & 1U);
    if (!paddedPayload.has_value()) return std::nullopt;
    return formats::detail::checked_add(*withHeader, *paddedPayload);
}

} // namespace

auto write_archive(const ArchiveImage& image)
    -> Result<std::vector<std::byte>, Diagnostic> {
    if (is_unchanged(image)) {
        return Result<std::vector<std::byte>, Diagnostic>::success(image.sourceBytes);
    }
    std::vector<OrdinaryMember> members;
    std::vector<IndexedSymbol> symbols;
    std::vector<std::byte> longNames;
    for (const auto& member : image.members) {
        if (member.kind == ArchiveMemberKind::SymbolIndex
            || member.kind == ArchiveMemberKind::LongNameTable) continue;
        OrdinaryMember output{.member = &member, .headerName = {}, .headerOffset = 0};
        if (member.name.size() <= 15 && member.name.find(' ') == std::string::npos) {
            output.headerName = member.name + '/';
        } else {
            const auto offset = longNames.size();
            if (offset > UINT32_MAX) {
                return failure("archive.name_table_limit", "archive long-name table is too large");
            }
            output.headerName = '/' + std::to_string(offset);
            append_text(longNames, member.name);
            append_text(longNames, "/\n");
        }
        members.push_back(std::move(output));
        if (member.kind == ArchiveMemberKind::Object) {
            const auto parsed = parse_object(member.contents, member.name);
            if (!parsed.has_value()) {
                return failure(
                    "archive.member_invalid",
                    "object member failed to parse during index rebuild: " + member.name);
            }
            for (const auto& symbol : parsed.value().symbols) {
                if (symbol.defined && symbol.visibility == SymbolVisibility::External
                    && !symbol.name.empty()) {
                    symbols.push_back(IndexedSymbol{symbol.name, member.id});
                }
            }
        } else if (member.kind == ArchiveMemberKind::ImportObject) {
            const auto name = import_symbol(member);
            if (name.has_value()) symbols.push_back(IndexedSymbol{*name, member.id});
        }
    }
    if (members.size() > UINT32_MAX || symbols.size() > UINT32_MAX
        || members.size() > UINT16_MAX) {
        return failure("archive.index_limit", "archive index count exceeds the supported format");
    }
    std::stable_sort(
        symbols.begin(), symbols.end(), [](const IndexedSymbol& left, const IndexedSymbol& right) {
            if (left.name != right.name) return left.name < right.name;
            return left.member.value() < right.member.value();
        });
    std::size_t symbolNamesSize = 0;
    for (const auto& symbol : symbols) {
        const auto terminatedNameSize = formats::detail::checked_add(
            symbol.name.size(), std::size_t{1});
        const auto next = terminatedNameSize.has_value()
            ? formats::detail::checked_add(symbolNamesSize, *terminatedNameSize)
            : std::nullopt;
        if (!next.has_value()) return failure("archive.index_limit", "archive symbol names overflow");
        symbolNamesSize = *next;
    }
    const auto firstOffsetsSize = formats::detail::checked_multiply(
        symbols.size(), std::size_t{4});
    const auto memberOffsetsSize = formats::detail::checked_multiply(
        members.size(), std::size_t{4});
    const auto secondIndicesSize = formats::detail::checked_multiply(
        symbols.size(), std::size_t{2});
    if (!firstOffsetsSize.has_value() || !memberOffsetsSize.has_value()
        || !secondIndicesSize.has_value()) {
        return failure("archive.index_limit", "archive index size overflows");
    }
    const auto firstPrefixSize = formats::detail::checked_add(
        std::size_t{4}, *firstOffsetsSize);
    const auto firstIndexSize = firstPrefixSize.has_value()
        ? formats::detail::checked_add(*firstPrefixSize, symbolNamesSize) : std::nullopt;
    const auto secondMembersEnd = formats::detail::checked_add(
        std::size_t{4}, *memberOffsetsSize);
    const auto secondCountEnd = secondMembersEnd.has_value()
        ? formats::detail::checked_add(*secondMembersEnd, std::size_t{4}) : std::nullopt;
    const auto secondIndicesEnd = secondCountEnd.has_value()
        ? formats::detail::checked_add(*secondCountEnd, *secondIndicesSize) : std::nullopt;
    const auto secondIndexSize = secondIndicesEnd.has_value()
        ? formats::detail::checked_add(*secondIndicesEnd, symbolNamesSize) : std::nullopt;
    if (!firstIndexSize.has_value() || !secondIndexSize.has_value()) {
        return failure("archive.index_limit", "archive index size overflows");
    }
    const bool coff = image.flavor == ArchiveFlavor::Coff;
    std::size_t offset = 8;
    const auto afterFirstIndex = advance_offset(offset, *firstIndexSize);
    if (!afterFirstIndex.has_value()) {
        return failure("archive.offset_limit", "archive first index size overflows");
    }
    offset = *afterFirstIndex;
    if (coff) {
        const auto afterSecondIndex = advance_offset(offset, *secondIndexSize);
        if (!afterSecondIndex.has_value()) {
            return failure("archive.offset_limit", "archive second index size overflows");
        }
        offset = *afterSecondIndex;
    }
    if (!longNames.empty()) {
        const auto afterLongNames = advance_offset(offset, longNames.size());
        if (!afterLongNames.has_value()) {
            return failure("archive.offset_limit", "archive name-table size overflows");
        }
        offset = *afterLongNames;
    }
    for (auto& member : members) {
        if (offset > UINT32_MAX) {
            return failure("archive.offset_limit", "archive member offset exceeds 32-bit index range");
        }
        member.headerOffset = static_cast<std::uint32_t>(offset);
        const auto next = advance_offset(offset, member.member->contents.size());
        if (!next.has_value()) return failure("archive.offset_limit", "archive size overflows");
        offset = *next;
    }

    std::vector<std::byte> firstIndex;
    append_be32(firstIndex, static_cast<std::uint32_t>(symbols.size()));
    for (const auto& symbol : symbols) {
        const auto index = member_index(members, symbol.member);
        if (!index.has_value()) return failure("archive.symbol_member", "archive symbol member is missing");
        append_be32(firstIndex, members[*index].headerOffset);
    }
    for (const auto& symbol : symbols) {
        append_text(firstIndex, symbol.name);
        firstIndex.push_back(std::byte{0});
    }

    std::vector<std::byte> secondIndex;
    if (coff) {
        append_le32(secondIndex, static_cast<std::uint32_t>(members.size()));
        for (const auto& member : members) append_le32(secondIndex, member.headerOffset);
        append_le32(secondIndex, static_cast<std::uint32_t>(symbols.size()));
        for (const auto& symbol : symbols) {
            const auto index = member_index(members, symbol.member);
            if (!index.has_value()) return failure("archive.symbol_member", "archive symbol member is missing");
            append_le16(secondIndex, static_cast<std::uint16_t>(*index + 1));
        }
        for (const auto& symbol : symbols) {
            append_text(secondIndex, symbol.name);
            secondIndex.push_back(std::byte{0});
        }
    }

    std::vector<std::byte> output;
    output.reserve(offset);
    append_text(output, "!<arch>\n");
    if (!append_member(output, "/", firstIndex, 0, 0, 0, 0)) {
        return failure("archive.header_limit", "archive index header value does not fit");
    }
    if (coff && !append_member(output, "/", secondIndex, 0, 0, 0, 0)) {
        return failure("archive.header_limit", "COFF second index header value does not fit");
    }
    if (!longNames.empty() && !append_member(output, "//", longNames, 0, 0, 0, 0)) {
        return failure("archive.header_limit", "archive name-table header value does not fit");
    }
    for (const auto& member : members) {
        if (output.size() != member.headerOffset
            || !append_member(
                output, member.headerName, member.member->contents,
                member.member->timestamp, member.member->owner,
                member.member->group, member.member->mode)) {
            return failure("archive.layout_mismatch", "archive member layout changed during emission");
        }
    }
    const auto reparsed = parse_archive(output, image.sourceName);
    if (!reparsed.has_value()) {
        return failure(
            "archive.reparse_failed",
            "rebuilt archive failed to parse: " + reparsed.error().code);
    }
    return Result<std::vector<std::byte>, Diagnostic>::success(std::move(output));
}

} // namespace binobf

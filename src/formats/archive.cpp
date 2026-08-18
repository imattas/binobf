#include <binobf/formats/archive.hpp>

#include "object_parser_internal.hpp"

#include <binobf/formats/detector.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace binobf {
namespace {

constexpr std::size_t archiveMagicSize = 8;
constexpr std::size_t memberHeaderSize = 60;

auto failure(std::string code, std::string message) -> Result<ArchiveImage, Diagnostic> {
    return Result<ArchiveImage, Diagnostic>::failure(
        Diagnostic{DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

auto text(std::span<const std::byte> bytes) -> std::string {
    std::string value;
    value.reserve(bytes.size());
    for (const auto byte : bytes) {
        value.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
    }
    return value;
}

auto trim_field(std::string value) -> std::string {
    while (!value.empty() && value.back() == ' ') value.pop_back();
    return value;
}

template <typename Integer>
auto parse_number(std::span<const std::byte> bytes, int base) -> std::optional<Integer> {
    auto value = trim_field(text(bytes));
    if (value.empty()) return Integer{0};
    Integer parsed{};
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed, base);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size()) return std::nullopt;
    return parsed;
}

auto read_be32(std::span<const std::byte> bytes, std::size_t offset)
    -> std::optional<std::uint32_t> {
    if (!formats::detail::contains_range(offset, 4, bytes.size())) return std::nullopt;
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value = (value << 8U) | std::to_integer<std::uint8_t>(bytes[offset + index]);
    }
    return value;
}

auto read_le16(std::span<const std::byte> bytes, std::size_t offset)
    -> std::optional<std::uint16_t> {
    if (!formats::detail::contains_range(offset, 2, bytes.size())) return std::nullopt;
    return static_cast<std::uint16_t>(
        std::to_integer<std::uint8_t>(bytes[offset])
        | (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[offset + 1])) << 8U));
}

auto read_le32(std::span<const std::byte> bytes, std::size_t offset)
    -> std::optional<std::uint32_t> {
    if (!formats::detail::contains_range(offset, 4, bytes.size())) return std::nullopt;
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + index]))
            << (index * 8U);
    }
    return value;
}

auto read_cstring(std::span<const std::byte> bytes, std::size_t& cursor, std::size_t limit)
    -> std::optional<std::string> {
    std::string value;
    while (cursor < bytes.size() && value.size() <= limit) {
        const auto byte = bytes[cursor++];
        if (byte == std::byte{0}) return value;
        value.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
    }
    return std::nullopt;
}

auto is_import_object(std::span<const std::byte> bytes) noexcept -> bool {
    return bytes.size() >= 20
        && bytes[0] == std::byte{0} && bytes[1] == std::byte{0}
        && bytes[2] == std::byte{0xff} && bytes[3] == std::byte{0xff};
}

auto import_architecture(std::span<const std::byte> bytes) noexcept -> Architecture {
    if (!is_import_object(bytes) || bytes.size() < 8) return Architecture::Unknown;
    const auto machine = static_cast<std::uint16_t>(
        std::to_integer<std::uint8_t>(bytes[6])
        | (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[7])) << 8U));
    switch (machine) {
    case 0x014c: return Architecture::X86;
    case 0x8664: return Architecture::X86_64;
    case 0xaa64: return Architecture::ARM64;
    default: return Architecture::Unknown;
    }
}

auto long_name_at(std::span<const std::byte> table, std::size_t offset, std::size_t limit)
    -> std::optional<std::string> {
    if (offset >= table.size()) return std::nullopt;
    std::string name;
    for (auto index = offset; index < table.size() && name.size() <= limit; ++index) {
        const auto byte = table[index];
        if (byte == std::byte{0}) return name;
        if (byte == std::byte{'/'} && index + 1 < table.size()
            && table[index + 1] == std::byte{'\n'}) return name;
        name.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
    }
    return std::nullopt;
}

auto lower(std::string_view value) -> std::string {
    std::string result{value};
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

} // namespace

auto parse_archive(
    std::span<const std::byte> bytes,
    std::string_view sourceName,
    const ArchiveParseLimits& limits) -> Result<ArchiveImage, Diagnostic> {
    constexpr std::array magic{
        std::byte{'!'}, std::byte{'<'}, std::byte{'a'}, std::byte{'r'},
        std::byte{'c'}, std::byte{'h'}, std::byte{'>'}, std::byte{'\n'},
    };
    if (bytes.size() > limits.maxInputBytes) {
        return failure("archive.input_limit", "archive exceeds the configured byte limit");
    }
    if (bytes.size() < magic.size()
        || !std::equal(magic.begin(), magic.end(), bytes.begin())) {
        return failure("archive.magic", "input does not contain the ar archive signature");
    }

    ArchiveImage result;
    result.sourceName = std::string{sourceName};
    result.sourceBytes.assign(bytes.begin(), bytes.end());
    result.flavor = lower(sourceName).ends_with(".lib")
        ? ArchiveFlavor::Coff : ArchiveFlavor::Gnu;
    formats::detail::EntityIdAllocator ids;
    std::vector<std::string> rawNames;
    std::size_t cursor = archiveMagicSize;
    bool sawBsd = false;
    while (cursor < bytes.size()) {
        if (result.members.size() >= limits.maxMembers) {
            return failure("archive.member_limit", "archive member count exceeds the configured limit");
        }
        if (!formats::detail::contains_range(cursor, memberHeaderSize, bytes.size())) {
            return failure("archive.member_header", "archive member header is truncated");
        }
        const auto header = bytes.subspan(cursor, memberHeaderSize);
        if (header[58] != std::byte{'`'} || header[59] != std::byte{'\n'}) {
            return failure("archive.member_header", "archive member trailer is invalid");
        }
        const auto storedSize = parse_number<std::uint64_t>(header.subspan(48, 10), 10);
        const auto timestamp = parse_number<std::uint64_t>(header.subspan(16, 12), 10);
        const auto owner = parse_number<std::uint32_t>(header.subspan(28, 6), 10);
        const auto group = parse_number<std::uint32_t>(header.subspan(34, 6), 10);
        const auto mode = parse_number<std::uint32_t>(header.subspan(40, 8), 8);
        if (!storedSize.has_value() || !timestamp.has_value() || !owner.has_value()
            || !group.has_value() || !mode.has_value()) {
            return failure("archive.member_header", "archive member numeric field is invalid");
        }
        const auto dataOffset = formats::detail::checked_add(cursor, memberHeaderSize);
        const auto size = formats::detail::to_size(*storedSize);
        if (!dataOffset.has_value() || !size.has_value()
            || !formats::detail::contains_range(*dataOffset, *size, bytes.size())) {
            return failure("archive.member_range", "archive member data is outside the input");
        }
        auto rawName = trim_field(text(header.first(16)));
        auto payloadOffset = *dataOffset;
        auto payloadSize = *size;
        std::string resolvedName = rawName;
        if (rawName.starts_with("#1/")) {
            const auto nameLengthText = std::span<const std::byte>{header}.first(16).subspan(3);
            const auto nameLength = parse_number<std::size_t>(nameLengthText, 10);
            if (!nameLength.has_value() || *nameLength > payloadSize
                || *nameLength > limits.maxNameBytes) {
                return failure("archive.member_name", "BSD extended member name is invalid");
            }
            resolvedName = text(bytes.subspan(payloadOffset, *nameLength));
            payloadOffset += *nameLength;
            payloadSize -= *nameLength;
            sawBsd = true;
        } else if (rawName != "/" && rawName != "//" && rawName != "/SYM64/") {
            if (rawName.ends_with('/')) rawName.pop_back();
            resolvedName = rawName;
        }
        const auto id = ids.allocate();
        const auto payload = bytes.subspan(payloadOffset, payloadSize);
        result.members.push_back(ArchiveMember{
            .id = id,
            .name = std::move(resolvedName),
            .timestamp = *timestamp,
            .owner = *owner,
            .group = *group,
            .mode = *mode,
            .kind = ArchiveMemberKind::Opaque,
            .format = BinaryFormat::Unknown,
            .architecture = Architecture::Unknown,
            .contents = std::vector<std::byte>{payload.begin(), payload.end()},
        });
        result.layout.push_back(ArchiveMemberLayout{
            .member = id,
            .originalName = result.members.back().name,
            .originalTimestamp = *timestamp,
            .originalOwner = *owner,
            .originalGroup = *group,
            .originalMode = *mode,
            .headerOffset = cursor,
            .dataOffset = payloadOffset,
            .storedSize = *storedSize,
            .payloadSize = payloadSize,
        });
        rawNames.push_back(std::move(rawName));
        const auto paddedSize = formats::detail::checked_add(*size, *size & 1U);
        const auto next = paddedSize.has_value()
            ? formats::detail::checked_add(*dataOffset, *paddedSize) : std::nullopt;
        if (!next.has_value() || *next > bytes.size()) {
            return failure("archive.member_range", "archive member padding is outside the input");
        }
        if ((*size & 1U) != 0 && bytes[*dataOffset + *size] != std::byte{'\n'}) {
            return failure("archive.member_padding", "archive member padding byte is invalid");
        }
        cursor = *next;
    }
    if (sawBsd) result.flavor = ArchiveFlavor::Bsd;

    std::span<const std::byte> longNames;
    for (std::size_t index = 0; index < result.members.size(); ++index) {
        if (rawNames[index] == "//") {
            result.members[index].kind = ArchiveMemberKind::LongNameTable;
            longNames = result.members[index].contents;
        } else if (rawNames[index] == "/" || rawNames[index] == "/SYM64/"
            || rawNames[index] == "__.SYMDEF" || rawNames[index] == "__.SYMDEF SORTED") {
            result.members[index].kind = ArchiveMemberKind::SymbolIndex;
        }
    }
    for (std::size_t index = 0; index < result.members.size(); ++index) {
        if (rawNames[index].size() > 1 && rawNames[index][0] == '/'
            && std::isdigit(static_cast<unsigned char>(rawNames[index][1])) != 0) {
            const auto offsetText = std::string_view{rawNames[index]}.substr(1);
            std::size_t offset = 0;
            const auto parsed = std::from_chars(
                offsetText.data(), offsetText.data() + offsetText.size(), offset, 10);
            if (parsed.ec != std::errc{} || parsed.ptr != offsetText.data() + offsetText.size()) {
                return failure("archive.member_name", "GNU long-name offset is invalid");
            }
            const auto name = long_name_at(longNames, offset, limits.maxNameBytes);
            if (!name.has_value()) {
                return failure("archive.member_name", "GNU long-name offset is outside the table");
            }
            result.members[index].name = *name;
        }
        auto& member = result.members[index];
        if (member.kind != ArchiveMemberKind::Opaque) continue;
        if (is_import_object(member.contents)) {
            member.kind = ArchiveMemberKind::ImportObject;
            member.format = BinaryFormat::COFF;
            member.architecture = import_architecture(member.contents);
            if (result.architecture == Architecture::Unknown) {
                result.architecture = member.architecture;
            } else if (member.architecture != Architecture::Unknown
                && result.architecture != member.architecture) {
                result.architecture = Architecture::Unknown;
            }
            continue;
        }
        const auto detected = detect_binary(member.contents, member.name);
        if (detected.has_value() && detected.value().type == BinaryType::RelocatableObject) {
            member.kind = ArchiveMemberKind::Object;
            member.format = detected.value().format;
            member.architecture = detected.value().architecture;
            if (result.architecture == Architecture::Unknown) {
                result.architecture = member.architecture;
            } else if (result.architecture != member.architecture) {
                result.architecture = Architecture::Unknown;
            }
        }
    }
    for (std::size_t index = 0; index < result.members.size(); ++index) {
        result.layout[index].originalName = result.members[index].name;
    }

    std::vector<std::size_t> slashMembers;
    for (std::size_t index = 0; index < rawNames.size(); ++index) {
        if (rawNames[index] == "/") slashMembers.push_back(index);
    }
    if (slashMembers.size() >= 2) result.flavor = ArchiveFlavor::Coff;
    if (!slashMembers.empty()) {
        const auto indexMember = slashMembers.front();
        const auto& data = result.members[indexMember].contents;
        const auto count = read_be32(data, 0);
        if (!count.has_value() || *count > limits.maxSymbols) {
            return failure("archive.symbol_index", "archive symbol count is invalid");
        }
        const auto offsetsBytes = formats::detail::checked_multiply(*count, std::size_t{4});
        if (!offsetsBytes.has_value()
            || !formats::detail::contains_range(4, *offsetsBytes, data.size())) {
            return failure("archive.symbol_index", "archive symbol offsets are truncated");
        }
        std::size_t stringCursor = 4 + *offsetsBytes;
        for (std::size_t symbolIndex = 0; symbolIndex < *count; ++symbolIndex) {
            const auto memberOffset = read_be32(data, 4 + symbolIndex * 4).value();
            const auto name = read_cstring(data, stringCursor, limits.maxNameBytes);
            if (!name.has_value()) {
                return failure("archive.symbol_index", "archive symbol name is unterminated");
            }
            const auto layout = std::find_if(
                result.layout.begin(), result.layout.end(),
                [&](const ArchiveMemberLayout& candidate) {
                    return candidate.headerOffset == memberOffset;
                });
            if (layout == result.layout.end()) {
                return failure("archive.symbol_index", "archive symbol references an unknown member");
            }
            result.symbols.push_back(ArchiveSymbol{*name, layout->member});
        }
    }
    if (slashMembers.size() >= 2) {
        const auto& data = result.members[slashMembers[1]].contents;
        const auto memberCount = read_le32(data, 0);
        if (!memberCount.has_value() || *memberCount > limits.maxMembers) {
            return failure("archive.symbol_index", "COFF linker member count is invalid");
        }
        const auto memberOffsetsBytes = formats::detail::checked_multiply(
            *memberCount, std::size_t{4});
        if (!memberOffsetsBytes.has_value()
            || !formats::detail::contains_range(4, *memberOffsetsBytes, data.size())) {
            return failure("archive.symbol_index", "COFF linker member offsets are truncated");
        }
        const auto symbolCountOffset = formats::detail::checked_add(
            std::size_t{4}, *memberOffsetsBytes);
        if (!symbolCountOffset.has_value()) {
            return failure("archive.symbol_index", "COFF linker member offset overflow");
        }
        const auto symbolCount = read_le32(data, *symbolCountOffset);
        if (!symbolCount.has_value() || *symbolCount > limits.maxSymbols) {
            return failure("archive.symbol_index", "COFF linker symbol count is invalid");
        }
        const auto indicesOffset = formats::detail::checked_add(*symbolCountOffset, std::size_t{4});
        const auto indicesBytes = formats::detail::checked_multiply(*symbolCount, std::size_t{2});
        if (!indicesOffset.has_value() || !indicesBytes.has_value()
            || !formats::detail::contains_range(*indicesOffset, *indicesBytes, data.size())) {
            return failure("archive.symbol_index", "COFF linker symbol indices are truncated");
        }
        std::vector<EntityId> indexedMembers;
        indexedMembers.reserve(*memberCount);
        for (std::size_t memberIndex = 0; memberIndex < *memberCount; ++memberIndex) {
            const auto memberOffset = read_le32(data, 4 + memberIndex * 4).value();
            const auto layout = std::find_if(
                result.layout.begin(), result.layout.end(),
                [&](const ArchiveMemberLayout& candidate) {
                    return candidate.headerOffset == memberOffset;
                });
            if (layout == result.layout.end()) {
                return failure(
                    "archive.symbol_index", "COFF linker member references an unknown member");
            }
            indexedMembers.push_back(layout->member);
        }
        std::size_t stringCursor = *indicesOffset + *indicesBytes;
        std::vector<ArchiveSymbol> coffSymbols;
        coffSymbols.reserve(*symbolCount);
        for (std::size_t symbolIndex = 0; symbolIndex < *symbolCount; ++symbolIndex) {
            const auto memberIndex = read_le16(data, *indicesOffset + symbolIndex * 2).value();
            const auto name = read_cstring(data, stringCursor, limits.maxNameBytes);
            if (memberIndex == 0 || memberIndex > indexedMembers.size() || !name.has_value()) {
                return failure("archive.symbol_index", "COFF linker symbol entry is invalid");
            }
            coffSymbols.push_back(ArchiveSymbol{*name, indexedMembers[memberIndex - 1]});
        }
        result.symbols = std::move(coffSymbols);
    }
    const bool anyImport = std::any_of(
        result.members.begin(), result.members.end(), [](const ArchiveMember& member) {
            return member.kind == ArchiveMemberKind::ImportObject;
        });
    if (anyImport) result.type = BinaryType::ImportLibrary;
    return Result<ArchiveImage, Diagnostic>::success(std::move(result));
}

} // namespace binobf

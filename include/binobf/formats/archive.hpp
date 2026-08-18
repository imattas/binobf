#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/result.hpp>
#include <binobf/core/types.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace binobf {

enum class ArchiveFlavor : std::uint8_t {
    Gnu,
    Coff,
    Bsd,
    Unknown,
};

enum class ArchiveMemberKind : std::uint8_t {
    Object,
    ImportObject,
    SymbolIndex,
    LongNameTable,
    Opaque,
};

struct ArchiveMember {
    EntityId id;
    std::string name;
    std::uint64_t timestamp{0};
    std::uint32_t owner{0};
    std::uint32_t group{0};
    std::uint32_t mode{0};
    ArchiveMemberKind kind{ArchiveMemberKind::Opaque};
    BinaryFormat format{BinaryFormat::Unknown};
    Architecture architecture{Architecture::Unknown};
    std::vector<std::byte> contents;
};

struct ArchiveMemberLayout {
    EntityId member;
    std::string originalName;
    std::uint64_t originalTimestamp{0};
    std::uint32_t originalOwner{0};
    std::uint32_t originalGroup{0};
    std::uint32_t originalMode{0};
    std::uint64_t headerOffset{0};
    std::uint64_t dataOffset{0};
    std::uint64_t storedSize{0};
    std::uint64_t payloadSize{0};
};

struct ArchiveSymbol {
    std::string name;
    EntityId member;
};

struct ArchiveImage {
    std::string sourceName;
    std::vector<std::byte> sourceBytes;
    ArchiveFlavor flavor{ArchiveFlavor::Unknown};
    BinaryType type{BinaryType::StaticLibrary};
    Architecture architecture{Architecture::Unknown};
    std::vector<ArchiveMember> members;
    std::vector<ArchiveMemberLayout> layout;
    std::vector<ArchiveSymbol> symbols;
};

struct ArchiveParseLimits {
    std::size_t maxInputBytes{512U * 1024U * 1024U};
    std::size_t maxMembers{1'000'000};
    std::size_t maxSymbols{4'000'000};
    std::size_t maxNameBytes{1U * 1024U * 1024U};
};

[[nodiscard]] auto parse_archive(
    std::span<const std::byte> bytes,
    std::string_view sourceName = {},
    const ArchiveParseLimits& limits = {}) -> Result<ArchiveImage, Diagnostic>;

} // namespace binobf

#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/model.hpp>
#include <binobf/core/result.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace binobf {

enum class LinkedDirectoryKind : std::uint8_t {
    Export,
    Import,
    Resource,
    Exception,
    SecurityCertificate,
    BaseRelocation,
    Debug,
    Tls,
    LoadConfiguration,
    ImportAddressTable,
    DelayImport,
    Dynamic,
    Interpreter,
    Notes,
    Unwind,
    Unknown,
};

struct LinkedDirectory {
    LinkedDirectoryKind kind{LinkedDirectoryKind::Unknown};
    std::uint32_t formatIndex{0};
    std::uint64_t headerOffset{0};
    std::uint64_t address{0};
    std::optional<std::uint64_t> fileOffset;
    std::uint64_t size{0};
    bool addressIsFileOffset{false};
};

struct LinkedSectionLayout {
    EntityId section;
    std::uint64_t headerOffset{0};
    std::uint64_t fileOffset{0};
    std::uint64_t fileSize{0};
    std::uint64_t memorySize{0};
};

struct LinkedSegmentLayout {
    EntityId segment;
    std::uint32_t formatIndex{0};
    std::uint64_t headerOffset{0};
    std::uint64_t fileOffset{0};
    std::uint64_t fileSize{0};
    std::uint64_t memorySize{0};
    std::uint64_t alignment{1};
};

struct LinkedImage {
    BinaryImage image;
    std::string sourceName;
    std::vector<std::byte> sourceBytes;
    std::uint64_t imageBase{0};
    std::uint64_t headerSize{0};
    std::uint64_t fileAlignment{1};
    std::uint64_t memoryAlignment{1};
    std::uint64_t checksumOffset{0};
    std::uint32_t checksum{0};
    bool positionIndependent{false};
    bool signedImage{false};
    std::vector<LinkedDirectory> directories;
    std::vector<LinkedSectionLayout> sectionLayout;
    std::vector<LinkedSegmentLayout> segmentLayout;
};

struct LinkedParseLimits {
    std::size_t maxInputBytes{512U * 1024U * 1024U};
    std::size_t maxSections{4096};
    std::size_t maxSegments{4096};
    std::size_t maxDirectories{64};
    std::size_t maxSymbols{1'000'000};
    std::size_t maxImports{1'000'000};
    std::size_t maxExports{1'000'000};
    std::size_t maxRelocations{4'000'000};
    std::size_t maxStringBytes{1U * 1024U * 1024U};
};

[[nodiscard]] auto parse_linked_image(
    std::span<const std::byte> bytes,
    std::string_view sourceName = {},
    const LinkedParseLimits& limits = {}) -> Result<LinkedImage, Diagnostic>;

} // namespace binobf

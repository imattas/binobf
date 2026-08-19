#include <binobf/formats/detector.hpp>

#include <array>
#include <limits>
#include <optional>

namespace binobf {
namespace {

constexpr std::size_t coffHeaderSize = 20;
constexpr std::size_t coffBigObjHeaderSize = 56;
constexpr std::size_t coffSectionSize = 40;
constexpr std::size_t maxBigObjSectionCount = 65'536;

auto error(std::string code, std::string message) -> Result<DetectionResult, Diagnostic> {
    return Result<DetectionResult, Diagnostic>::failure(
        Diagnostic{DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

constexpr auto contains_range(std::size_t offset, std::size_t length, std::size_t size) noexcept
    -> bool {
    return offset <= size && length <= size - offset;
}

auto checked_add(std::size_t left, std::size_t right) noexcept -> std::optional<std::size_t> {
    if (right > std::numeric_limits<std::size_t>::max() - left) {
        return std::nullopt;
    }
    return left + right;
}

auto checked_multiply(std::size_t left, std::size_t right) noexcept
    -> std::optional<std::size_t> {
    if (left != 0 && right > std::numeric_limits<std::size_t>::max() / left) {
        return std::nullopt;
    }
    return left * right;
}

auto read_u16(std::span<const std::byte> bytes, std::size_t offset)
    -> std::optional<std::uint16_t> {
    if (!contains_range(offset, 2, bytes.size())) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[offset]))
        | static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[offset + 1])) << 8U);
}

auto read_u32(std::span<const std::byte> bytes, std::size_t offset)
    -> std::optional<std::uint32_t> {
    if (!contains_range(offset, 4, bytes.size())) {
        return std::nullopt;
    }
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + index]))
            << static_cast<unsigned int>(index * 8U);
    }
    return value;
}

auto read_u64(std::span<const std::byte> bytes, std::size_t offset)
    -> std::optional<std::uint64_t> {
    if (!contains_range(offset, 8, bytes.size())) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(bytes[offset + index]))
            << static_cast<unsigned int>(index * 8U);
    }
    return value;
}

template <std::size_t Extent>
auto starts_with(std::span<const std::byte> bytes, const std::array<std::byte, Extent>& magic)
    -> bool {
    if (bytes.size() < magic.size()) {
        return false;
    }
    for (std::size_t index = 0; index < magic.size(); ++index) {
        if (bytes[index] != magic[index]) {
            return false;
        }
    }
    return true;
}

auto coff_architecture(std::uint16_t machine) noexcept -> Architecture {
    switch (machine) {
    case 0x014c: return Architecture::X86;
    case 0x8664: return Architecture::X86_64;
    case 0xaa64: return Architecture::ARM64;
    default: return Architecture::Unknown;
    }
}

auto elf_architecture(std::uint16_t machine) noexcept -> Architecture {
    switch (machine) {
    case 3: return Architecture::X86;
    case 62: return Architecture::X86_64;
    case 183: return Architecture::ARM64;
    default: return Architecture::Unknown;
    }
}

auto elf_type(std::uint16_t type) noexcept -> BinaryType {
    switch (type) {
    case 1: return BinaryType::RelocatableObject;
    case 2: return BinaryType::Executable;
    case 3: return BinaryType::SharedLibrary;
    default: return BinaryType::Unknown;
    }
}

auto has_case_insensitive_suffix(std::string_view input, std::string_view suffix) noexcept -> bool {
    if (suffix.size() > input.size()) {
        return false;
    }
    const auto offset = input.size() - suffix.size();
    for (std::size_t index = 0; index < suffix.size(); ++index) {
        auto left = input[offset + index];
        auto right = suffix[index];
        if (left >= 'A' && left <= 'Z') {
            left = static_cast<char>(left - 'A' + 'a');
        }
        if (right >= 'A' && right <= 'Z') {
            right = static_cast<char>(right - 'A' + 'a');
        }
        if (left != right) {
            return false;
        }
    }
    return true;
}

auto validate_section_table(
    std::size_t tableOffset,
    std::size_t sectionCount,
    std::size_t inputSize) -> bool {
    if (sectionCount == 0 || sectionCount > maxBigObjSectionCount) {
        return false;
    }
    const auto tableSize = checked_multiply(sectionCount, coffSectionSize);
    return tableSize.has_value() && contains_range(tableOffset, *tableSize, inputSize);
}

auto detect_elf(std::span<const std::byte> bytes) -> Result<DetectionResult, Diagnostic> {
    if (bytes.size() < 16) {
        return error("format.truncated", "ELF identification header is truncated");
    }

    const auto elfClass = std::to_integer<std::uint8_t>(bytes[4]);
    const auto dataEncoding = std::to_integer<std::uint8_t>(bytes[5]);
    const auto version = std::to_integer<std::uint8_t>(bytes[6]);
    if (elfClass != 1 && elfClass != 2) {
        return error("format.invalid", "ELF class is neither 32-bit nor 64-bit");
    }
    if (dataEncoding != 1) {
        return error("format.unsupported", "only little-endian ELF input is supported");
    }
    if (version != 1) {
        return error("format.invalid", "ELF identification version is invalid");
    }

    const auto requiredSize = elfClass == 1 ? std::size_t{52} : std::size_t{64};
    if (bytes.size() < requiredSize) {
        return error("format.truncated", "ELF file header is truncated");
    }

    const auto type = read_u16(bytes, 16).value();
    const auto machine = read_u16(bytes, 18).value();
    const auto headerSizeOffset = elfClass == 1 ? std::size_t{40} : std::size_t{52};
    const auto declaredHeaderSize = read_u16(bytes, headerSizeOffset).value();
    if (declaredHeaderSize < requiredSize || declaredHeaderSize > bytes.size()) {
        return error("format.invalid", "ELF header size is inconsistent with the input");
    }

    const auto binaryType = elf_type(type);
    if (binaryType == BinaryType::Unknown) {
        return error("format.unsupported", "ELF object type is unsupported");
    }

    const auto entry = elfClass == 1
        ? static_cast<std::uint64_t>(read_u32(bytes, 24).value())
        : read_u64(bytes, 24).value();
    return Result<DetectionResult, Diagnostic>::success(DetectionResult{
        .format = BinaryFormat::ELF,
        .type = binaryType,
        .architecture = elf_architecture(machine),
        .entryPoint = entry,
    });
}

auto detect_pe(
    std::span<const std::byte> bytes,
    std::string_view sourceName) -> Result<DetectionResult, Diagnostic> {
    if (bytes.size() < 64) {
        return error("format.truncated", "DOS header is truncated");
    }

    const auto peOffsetValue = read_u32(bytes, 0x3c).value();
    const auto peOffset = static_cast<std::size_t>(peOffsetValue);
    if (peOffset > bytes.size()) {
        return error("format.invalid", "PE header offset is outside the input");
    }
    if (!contains_range(peOffset, 4 + coffHeaderSize, bytes.size())) {
        return error("format.truncated", "PE signature or COFF header is truncated");
    }
    constexpr std::array peMagic{
        std::byte{'P'}, std::byte{'E'}, std::byte{0}, std::byte{0},
    };
    if (!starts_with(bytes.subspan(peOffset), peMagic)) {
        return error("format.invalid", "DOS header does not point to a PE signature");
    }

    const auto coffOffset = peOffset + 4;
    const auto machine = read_u16(bytes, coffOffset).value();
    const auto sectionCount = read_u16(bytes, coffOffset + 2).value();
    const auto optionalSize = read_u16(bytes, coffOffset + 16).value();
    const auto characteristics = read_u16(bytes, coffOffset + 18).value();
    const auto optionalOffset = coffOffset + coffHeaderSize;
    if (optionalSize < 20 || !contains_range(optionalOffset, optionalSize, bytes.size())) {
        return error("format.truncated", "PE optional header is truncated");
    }

    const auto optionalMagic = read_u16(bytes, optionalOffset).value();
    if (optionalMagic != 0x10b && optionalMagic != 0x20b) {
        return error("format.invalid", "PE optional-header magic is invalid");
    }
    const auto architecture = coff_architecture(machine);
    if (architecture == Architecture::Unknown) {
        return error("format.unsupported", "PE machine architecture is unsupported");
    }
    const auto sectionOffset = checked_add(optionalOffset, optionalSize);
    if (!sectionOffset.has_value()) {
        return error("format.invalid", "PE section-table offset overflows");
    }
    if (sectionCount == 0) {
        return error("format.invalid", "PE section count is invalid");
    }
    if (!validate_section_table(*sectionOffset, sectionCount, bytes.size())) {
        return error("format.truncated", "PE section table is truncated");
    }
    if ((characteristics & 0x0002U) == 0) {
        return error("format.invalid", "PE image is not marked executable");
    }

    auto type = BinaryType::Executable;
    if (has_case_insensitive_suffix(sourceName, ".sys")) {
        type = BinaryType::KernelDriver;
    } else if ((characteristics & 0x2000U) != 0) {
        type = BinaryType::SharedLibrary;
    }
    return Result<DetectionResult, Diagnostic>::success(DetectionResult{
        .format = BinaryFormat::PE,
        .type = type,
        .architecture = architecture,
        .entryPoint = read_u32(bytes, optionalOffset + 16).value(),
    });
}

auto detect_coff(std::span<const std::byte> bytes) -> Result<DetectionResult, Diagnostic> {
    const bool bigObjSignature = bytes.size() >= 4
        && read_u16(bytes, 0) == 0U && read_u16(bytes, 2) == 0xffffU;
    if (bigObjSignature) {
        if (bytes.size() < coffBigObjHeaderSize) {
            return error("format.truncated", "COFF bigobj header is truncated");
        }
        constexpr std::array bigObjClassId{
            std::byte{0xd1}, std::byte{0xba}, std::byte{0xa1}, std::byte{0xc7},
            std::byte{0xba}, std::byte{0xee}, std::byte{0x4b}, std::byte{0xa9},
            std::byte{0xaf}, std::byte{0x20}, std::byte{0xfa}, std::byte{0xf6},
            std::byte{0x6a}, std::byte{0xa4}, std::byte{0xdc}, std::byte{0xb8},
        };
        if (read_u16(bytes, 4) != 2U
            || !starts_with(bytes.subspan(12), bigObjClassId)) {
            return error("format.invalid", "COFF bigobj signature or version is invalid");
        }
        const auto sectionCount = static_cast<std::size_t>(read_u32(bytes, 44).value());
        if (!validate_section_table(coffBigObjHeaderSize, sectionCount, bytes.size())) {
            return error("format.truncated", "COFF bigobj section table is truncated");
        }
        return Result<DetectionResult, Diagnostic>::success(DetectionResult{
            .format = BinaryFormat::COFF,
            .type = BinaryType::RelocatableObject,
            .architecture = coff_architecture(read_u16(bytes, 6).value()),
            .entryPoint = 0,
        });
    }
    if (bytes.size() < coffHeaderSize) {
        return error("format.truncated", "COFF header is truncated");
    }
    const auto machine = read_u16(bytes, 0).value();
    const auto sectionCount = read_u16(bytes, 2).value();
    const auto optionalSize = read_u16(bytes, 16).value();
    if (optionalSize != 0) {
        return error("format.invalid", "COFF object unexpectedly has an optional header");
    }
    if (sectionCount == 0) {
        return error("format.invalid", "COFF section count is invalid");
    }
    if (!validate_section_table(coffHeaderSize, sectionCount, bytes.size())) {
        return error("format.truncated", "COFF section table is truncated");
    }
    return Result<DetectionResult, Diagnostic>::success(DetectionResult{
        .format = BinaryFormat::COFF,
        .type = BinaryType::RelocatableObject,
        .architecture = coff_architecture(machine),
        .entryPoint = 0,
    });
}

auto macho_architecture(std::uint32_t cpuType) noexcept -> Architecture {
    switch (cpuType) {
    case 0x01000007U: return Architecture::X86_64;
    case 0x0100000cU: return Architecture::ARM64;
    default: return Architecture::Unknown;
    }
}

auto detect_macho(std::span<const std::byte> bytes) -> Result<DetectionResult, Diagnostic> {
    if (bytes.size() < 32U) {
        return error("format.truncated", "Mach-O 64-bit header is truncated");
    }
    constexpr std::array magic64{
        std::byte{0xcf}, std::byte{0xfa}, std::byte{0xed}, std::byte{0xfe}};
    if (!starts_with(bytes, magic64)) {
        return error("format.unsupported", "only little-endian 64-bit Mach-O is supported");
    }
    const auto cpuType = read_u32(bytes, 4).value();
    const auto fileType = read_u32(bytes, 12).value();
    const auto commandCount = static_cast<std::size_t>(read_u32(bytes, 16).value());
    const auto commandBytes = static_cast<std::size_t>(read_u32(bytes, 20).value());
    BinaryType type = BinaryType::Unknown;
    switch (fileType) {
    case 1U: type = BinaryType::RelocatableObject; break;
    case 2U: type = BinaryType::Executable; break;
    case 6U: type = BinaryType::SharedLibrary; break;
    case 8U: type = BinaryType::SharedLibrary; break;
    default:
        return error("format.unsupported", "Mach-O file type is unsupported");
    }
    if (commandCount > 4096U || commandBytes > bytes.size() - 32U) {
        return error("format.invalid", "Mach-O load-command table is inconsistent");
    }
    const auto architecture = macho_architecture(cpuType);
    if (architecture == Architecture::Unknown) {
        return error("format.unsupported", "Mach-O CPU type is unsupported");
    }
    return Result<DetectionResult, Diagnostic>::success(DetectionResult{
        .format = BinaryFormat::MachO,
        .type = type,
        .architecture = architecture,
        .entryPoint = 0,
    });
}

} // namespace

auto detect_binary(std::span<const std::byte> bytes, std::string_view sourceName)
    -> Result<DetectionResult, Diagnostic> {
    constexpr std::array archiveMagic{
        std::byte{'!'}, std::byte{'<'}, std::byte{'a'}, std::byte{'r'},
        std::byte{'c'}, std::byte{'h'}, std::byte{'>'}, std::byte{'\n'},
    };
    if (starts_with(bytes, archiveMagic)) {
        return Result<DetectionResult, Diagnostic>::success(DetectionResult{
            .format = BinaryFormat::Archive,
            .type = BinaryType::StaticLibrary,
            .architecture = Architecture::Unknown,
            .entryPoint = 0,
        });
    }

    constexpr std::array elfMagic{
        std::byte{0x7f}, std::byte{'E'}, std::byte{'L'}, std::byte{'F'},
    };
    if (starts_with(bytes, elfMagic)) {
        return detect_elf(bytes);
    }

    if (bytes.size() >= 4 && bytes[0] == std::byte{0xcf}
        && bytes[1] == std::byte{0xfa} && bytes[2] == std::byte{0xed}
        && bytes[3] == std::byte{0xfe}) {
        return detect_macho(bytes);
    }

    if (bytes.size() >= 2 && bytes[0] == std::byte{'M'} && bytes[1] == std::byte{'Z'}) {
        return detect_pe(bytes, sourceName);
    }

    if (bytes.size() >= 2) {
        if (bytes.size() >= 4 && read_u16(bytes, 0) == 0U
            && read_u16(bytes, 2) == 0xffffU) {
            return detect_coff(bytes);
        }
        const auto machine = read_u16(bytes, 0).value();
        if (coff_architecture(machine) != Architecture::Unknown) {
            return detect_coff(bytes);
        }
    }
    return error("format.unknown", "input does not contain a recognized binary format");
}

} // namespace binobf

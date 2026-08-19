#include "../linked_parser_internal.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace binobf::formats::detail {
namespace {

constexpr std::size_t peSignatureSize = 4;
constexpr std::size_t coffHeaderSize = 20;
constexpr std::size_t sectionHeaderSize = 40;

auto section_name(std::span<const std::byte> bytes) -> std::string {
    std::string name;
    for (const auto value : bytes) {
        if (value == std::byte{0}) break;
        name.push_back(static_cast<char>(std::to_integer<unsigned char>(value)));
    }
    return name;
}

auto section_kind(std::string_view name, std::uint32_t flags) noexcept -> SectionKind {
    if ((flags & UINT32_C(0x00000020)) != 0) return SectionKind::Code;
    if ((flags & UINT32_C(0x00000080)) != 0) return SectionKind::UninitializedData;
    if (name.starts_with(".debug") || name == ".pdata") return SectionKind::Debug;
    if ((flags & UINT32_C(0x00000040)) != 0) return SectionKind::InitializedData;
    return SectionKind::Metadata;
}

auto directory_kind(std::uint32_t index) noexcept -> LinkedDirectoryKind {
    constexpr std::array kinds{
        LinkedDirectoryKind::Export,
        LinkedDirectoryKind::Import,
        LinkedDirectoryKind::Resource,
        LinkedDirectoryKind::Exception,
        LinkedDirectoryKind::SecurityCertificate,
        LinkedDirectoryKind::BaseRelocation,
        LinkedDirectoryKind::Debug,
        LinkedDirectoryKind::Unknown,
        LinkedDirectoryKind::Unknown,
        LinkedDirectoryKind::Tls,
        LinkedDirectoryKind::LoadConfiguration,
        LinkedDirectoryKind::Unknown,
        LinkedDirectoryKind::ImportAddressTable,
        LinkedDirectoryKind::DelayImport,
        LinkedDirectoryKind::Unknown,
        LinkedDirectoryKind::Unknown,
    };
    return index < kinds.size() ? kinds[index] : LinkedDirectoryKind::Unknown;
}

auto diagnostic(std::string code, std::string message) -> Diagnostic {
    return Diagnostic{DiagnosticSeverity::Error, std::move(code), std::move(message)};
}

auto rva_to_file(
    const LinkedImage& image,
    std::uint64_t rva,
    std::uint64_t size,
    std::size_t fileSize) -> std::optional<std::size_t> {
    if (rva < image.headerSize && size <= image.headerSize - rva
        && rva <= fileSize && size <= fileSize - static_cast<std::size_t>(rva)) {
        return static_cast<std::size_t>(rva);
    }
    for (std::size_t index = 0; index < image.sectionLayout.size(); ++index) {
        const auto& layout = image.sectionLayout[index];
        const auto& section = image.image.sections[index];
        if (section.address.value < image.imageBase) continue;
        const auto sectionRva = section.address.value - image.imageBase;
        if (rva < sectionRva) continue;
        const auto delta = rva - sectionRva;
        if (delta > layout.fileSize || size > layout.fileSize - delta) continue;
        const auto offset = layout.fileOffset + delta;
        if (offset > fileSize || size > fileSize - static_cast<std::size_t>(offset)) continue;
        return static_cast<std::size_t>(offset);
    }
    return std::nullopt;
}

auto section_for_rva(const LinkedImage& image, std::uint64_t rva)
    -> std::optional<std::pair<EntityId, std::uint64_t>> {
    for (std::size_t index = 0; index < image.sectionLayout.size(); ++index) {
        const auto& layout = image.sectionLayout[index];
        const auto& section = image.image.sections[index];
        if (section.address.value < image.imageBase) continue;
        const auto start = section.address.value - image.imageBase;
        const auto span = std::max(layout.memorySize, layout.fileSize);
        if (rva >= start && rva - start < span) {
            return std::pair{section.id, rva - start};
        }
    }
    return std::nullopt;
}

auto read_cstring_at(
    std::span<const std::byte> bytes,
    std::size_t offset,
    std::size_t limit) -> std::optional<std::string> {
    if (offset >= bytes.size()) return std::nullopt;
    std::string value;
    const auto available = std::min(limit, bytes.size() - offset);
    value.reserve(std::min<std::size_t>(available, 256));
    for (std::size_t index = 0; index < available; ++index) {
        const auto byte = bytes[offset + index];
        if (byte == std::byte{0}) return value;
        value.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
    }
    return std::nullopt;
}

auto read_cstring_rva(
    const LinkedImage& image,
    std::span<const std::byte> bytes,
    std::uint64_t rva,
    std::size_t limit) -> std::optional<std::string> {
    const auto offset = rva_to_file(image, rva, 1, bytes.size());
    return offset.has_value() ? read_cstring_at(bytes, *offset, limit) : std::nullopt;
}

auto parse_imports(
    LinkedImage& image,
    std::span<const std::byte> bytes,
    const LinkedDirectory& directory,
    const LinkedParseLimits& limits,
    EntityIdAllocator& ids,
    bool pe64) -> std::optional<Diagnostic> {
    if (!directory.fileOffset.has_value()) {
        return diagnostic("linked.import_range", "PE import directory is not file-backed");
    }
    constexpr std::size_t descriptorSize = 20;
    const auto start = static_cast<std::size_t>(*directory.fileOffset);
    const auto end = start + static_cast<std::size_t>(directory.size);
    const ByteReader reader(bytes);
    bool terminated = false;
    for (auto cursor = start; cursor + descriptorSize <= end; cursor += descriptorSize) {
        const auto originalThunk = reader.u32(cursor).value();
        const auto nameRva = reader.u32(cursor + 12).value();
        const auto firstThunk = reader.u32(cursor + 16).value();
        if (originalThunk == 0 && nameRva == 0 && firstThunk == 0) {
            terminated = true;
            break;
        }
        const auto library = read_cstring_rva(image, bytes, nameRva, limits.maxStringBytes);
        if (!library.has_value()) {
            return diagnostic("linked.import_name", "PE import library name is unmappable or unterminated");
        }
        const std::uint64_t thunkRva = originalThunk != 0 ? originalThunk : firstThunk;
        const auto width = pe64 ? std::size_t{8} : std::size_t{4};
        bool thunkTerminated = false;
        for (std::size_t index = 0; image.image.imports.size() < limits.maxImports; ++index) {
            const auto entryRva = thunkRva + static_cast<std::uint64_t>(index * width);
            const auto entryOffset = rva_to_file(image, entryRva, width, bytes.size());
            if (!entryOffset.has_value()) {
                return diagnostic("linked.import_thunk", "PE import thunk is outside a section");
            }
            const std::uint64_t value = pe64
                ? reader.u64(*entryOffset).value()
                : reader.u32(*entryOffset).value();
            if (value == 0) {
                thunkTerminated = true;
                break;
            }
            const auto ordinalMask = pe64 ? UINT64_C(0x8000000000000000) : UINT64_C(0x80000000);
            Import imported{
                .id = ids.allocate(),
                .library = *library,
                .name = {},
                .ordinal = std::nullopt,
                .lineage = {},
            };
            if ((value & ordinalMask) != 0) {
                imported.ordinal = static_cast<std::uint32_t>(value & UINT64_C(0xffff));
            } else {
                const auto nameOffset = rva_to_file(image, value, 2, bytes.size());
                if (!nameOffset.has_value()) {
                    return diagnostic("linked.import_name", "PE import-by-name record is unmappable");
                }
                const auto name = read_cstring_at(bytes, *nameOffset + 2, limits.maxStringBytes);
                if (!name.has_value()) {
                    return diagnostic("linked.import_name", "PE import name is unterminated");
                }
                imported.name = *name;
            }
            image.image.imports.push_back(std::move(imported));
        }
        if (image.image.imports.size() >= limits.maxImports) {
            return diagnostic("linked.import_limit", "PE import count exceeds the configured limit");
        }
        if (!thunkTerminated) {
            return diagnostic("linked.import_thunk", "PE import thunk lacks a terminator");
        }
    }
    if (!terminated) {
        return diagnostic("linked.import_range", "PE import directory lacks a terminating descriptor");
    }
    return std::nullopt;
}

auto parse_exports(
    LinkedImage& image,
    std::span<const std::byte> bytes,
    const LinkedDirectory& directory,
    const LinkedParseLimits& limits,
    EntityIdAllocator& ids) -> std::optional<Diagnostic> {
    if (!directory.fileOffset.has_value() || directory.size < 40) {
        return diagnostic("linked.export_range", "PE export directory is truncated");
    }
    const ByteReader reader(bytes);
    const auto offset = static_cast<std::size_t>(*directory.fileOffset);
    const auto ordinalBase = reader.u32(offset + 16).value();
    const auto functionCount = reader.u32(offset + 20).value();
    const auto nameCount = reader.u32(offset + 24).value();
    const auto functionRva = reader.u32(offset + 28).value();
    const auto nameRva = reader.u32(offset + 32).value();
    const auto ordinalRva = reader.u32(offset + 36).value();
    if (functionCount > limits.maxExports || nameCount > limits.maxExports) {
        return diagnostic("linked.export_limit", "PE export count exceeds the configured limit");
    }
    const auto functionsOffset = rva_to_file(image, functionRva, functionCount * 4ULL, bytes.size());
    const auto namesOffset = rva_to_file(image, nameRva, nameCount * 4ULL, bytes.size());
    const auto ordinalsOffset = rva_to_file(image, ordinalRva, nameCount * 2ULL, bytes.size());
    if (!functionsOffset.has_value() || (nameCount != 0 && (!namesOffset.has_value() || !ordinalsOffset.has_value()))) {
        return diagnostic("linked.export_range", "PE export arrays are unmappable");
    }
    std::vector<std::string> names(functionCount);
    for (std::size_t index = 0; index < nameCount; ++index) {
        const auto exportedNameRva = reader.u32(*namesOffset + index * 4).value();
        const auto ordinalIndex = reader.u16(*ordinalsOffset + index * 2).value();
        if (ordinalIndex >= functionCount) {
            return diagnostic("linked.export_ordinal", "PE export name ordinal is out of range");
        }
        const auto name = read_cstring_rva(image, bytes, exportedNameRva, limits.maxStringBytes);
        if (!name.has_value()) {
            return diagnostic("linked.export_name", "PE export name is unmappable or unterminated");
        }
        names[ordinalIndex] = *name;
    }
    for (std::size_t index = 0; index < functionCount; ++index) {
        const auto targetRva = reader.u32(*functionsOffset + index * 4).value();
        if (targetRva == 0) continue;
        image.image.exports.push_back(Export{
            .id = ids.allocate(),
            .name = names[index],
            .address = BinaryAddress{
                image.imageBase + static_cast<std::uint64_t>(targetRva), AddressKind::Virtual},
            .ordinal = ordinalBase + static_cast<std::uint32_t>(index),
            .lineage = {},
        });
    }
    return std::nullopt;
}

auto parse_relocations(
    LinkedImage& image,
    std::span<const std::byte> bytes,
    const LinkedDirectory& directory,
    const LinkedParseLimits& limits,
    EntityIdAllocator& ids) -> std::optional<Diagnostic> {
    if (!directory.fileOffset.has_value()) {
        return diagnostic("linked.relocation_range", "PE relocation directory is unmappable");
    }
    const ByteReader reader(bytes);
    auto cursor = static_cast<std::size_t>(*directory.fileOffset);
    const auto end = cursor + static_cast<std::size_t>(directory.size);
    std::uint32_t formatIndex = 0;
    while (cursor < end) {
        if (end - cursor < 8) {
            return diagnostic("linked.relocation_range", "PE relocation block header is truncated");
        }
        const auto pageRva = reader.u32(cursor).value();
        const auto blockSize = reader.u32(cursor + 4).value();
        if (blockSize < 8 || (blockSize - 8) % 2 != 0 || blockSize > end - cursor) {
            return diagnostic("linked.relocation_range", "PE relocation block size is invalid");
        }
        const auto entryCount = (blockSize - 8) / 2;
        for (std::size_t index = 0; index < entryCount; ++index) {
            const auto encoded = reader.u16(cursor + 8 + index * 2).value();
            const auto type = static_cast<std::uint16_t>(encoded >> 12U);
            if (type == 0) continue;
            if (image.image.relocations.size() >= limits.maxRelocations) {
                return diagnostic("linked.relocation_limit", "PE relocation count exceeds the configured limit");
            }
            const auto targetRva = static_cast<std::uint64_t>(pageRva) + (encoded & 0x0fffU);
            const auto target = section_for_rva(image, targetRva);
            if (!target.has_value()) {
                return diagnostic("linked.relocation_target", "PE relocation target is outside a section");
            }
            image.image.relocations.push_back(Relocation{
                .id = ids.allocate(),
                .formatIndex = formatIndex++,
                .formatTableIndex = 0,
                .section = target->first,
                .offset = target->second,
                .kind = type == 3 || type == 10
                    ? RelocationKind::ImageRelative
                    : RelocationKind::ArchitectureSpecific,
                .rawType = type,
                .targetSymbol = std::nullopt,
                .addend = 0,
                .lineage = {},
            });
        }
        cursor += blockSize;
    }
    return std::nullopt;
}

auto parse_debug(
    LinkedImage& image,
    std::span<const std::byte> bytes,
    const LinkedDirectory& directory,
    EntityIdAllocator& ids) -> std::optional<Diagnostic> {
    if (!directory.fileOffset.has_value() || directory.size % 28 != 0) {
        return diagnostic("linked.debug_range", "PE debug directory size is invalid");
    }
    const ByteReader reader(bytes);
    const auto count = directory.size / 28;
    for (std::size_t index = 0; index < count; ++index) {
        const auto offset = static_cast<std::size_t>(*directory.fileOffset) + index * 28;
        const auto type = reader.u32(offset + 12).value();
        const auto dataSize = reader.u32(offset + 16).value();
        const auto dataOffset = reader.u32(offset + 24).value();
        if (dataSize != 0 && !contains_range(dataOffset, dataSize, bytes.size())) {
            return diagnostic("linked.debug_range", "PE debug raw-data range is outside the input");
        }
        image.image.debugInfo.push_back(DebugInfo{
            .id = ids.allocate(),
            .format = type == 2 ? "pe-codeview" : "pe-debug-" + std::to_string(type),
            .source = std::nullopt,
            .lineage = {},
        });
    }
    return std::nullopt;
}

auto parse_resources(
    LinkedImage& image,
    std::span<const std::byte> bytes,
    const LinkedDirectory& directory,
    EntityIdAllocator& ids) -> std::optional<Diagnostic> {
    if (!directory.fileOffset.has_value()
        || directory.size > bytes.size() - static_cast<std::size_t>(*directory.fileOffset)) {
        return diagnostic("linked.resource_range", "PE resource tree is outside the input");
    }
    const auto contents = bytes.subspan(
        static_cast<std::size_t>(*directory.fileOffset), static_cast<std::size_t>(directory.size));
    image.image.resources.push_back(Resource{
        .id = ids.allocate(),
        .type = "pe-resource-tree",
        .name = ".rsrc",
        .bytes = std::vector<std::byte>{contents.begin(), contents.end()},
        .lineage = {},
    });
    return std::nullopt;
}

auto parse_exception_directory(
    LinkedImage& image,
    std::span<const std::byte> bytes,
    const LinkedDirectory& directory,
    EntityIdAllocator& ids) -> std::optional<Diagnostic> {
    if (!directory.fileOffset.has_value() || directory.size % 12 != 0) {
        return diagnostic("linked.exception_range", "PE exception directory size is invalid");
    }
    const ByteReader reader(bytes);
    const auto count = directory.size / 12;
    for (std::size_t index = 0; index < count; ++index) {
        const auto offset = static_cast<std::size_t>(*directory.fileOffset) + index * 12;
        const auto begin = reader.u32(offset).value();
        const auto end = reader.u32(offset + 4).value();
        const auto unwind = reader.u32(offset + 8).value();
        if (begin == 0 && end == 0 && unwind == 0) continue;
        if (end <= begin || !rva_to_file(image, unwind, 4, bytes.size()).has_value()) {
            return diagnostic("linked.exception_range", "PE runtime-function entry is invalid");
        }
        const auto section = section_for_rva(image, begin);
        if (!section.has_value() || !section_for_rva(image, end - 1).has_value()) {
            return diagnostic("linked.exception_range", "PE runtime-function range is outside a section");
        }
        const auto functionId = ids.allocate();
        image.image.functions.push_back(Function{
            .id = functionId,
            .name = "unwind_" + std::to_string(index),
            .section = section->first,
            .symbol = std::nullopt,
            .address = BinaryAddress{
                image.imageBase + static_cast<std::uint64_t>(begin), AddressKind::Virtual},
            .size = static_cast<std::uint64_t>(end - begin),
            .discovery = FunctionDiscovery::Unwind,
            .instructions = {},
            .basicBlocks = {},
            .entryBlock = std::nullopt,
            .externallyVisible = false,
            .complete = false,
            .lineage = {},
        });
        const auto entry = bytes.subspan(offset, 12);
        image.image.unwindInfo.push_back(UnwindInfo{
            .id = ids.allocate(),
            .function = functionId,
            .encoded = std::vector<std::byte>{entry.begin(), entry.end()},
            .section = {},
            .sectionOffset = 0,
            .codeOffset = 0,
            .codeSize = 0,
            .format = UnwindFormat::Unknown,
            .relocations = {},
            .rewriteState = UnwindRewriteState::Opaque,
            .lineage = {},
        });
    }
    return std::nullopt;
}

auto validate_tls(
    std::span<const std::byte> bytes,
    const LinkedDirectory& directory,
    bool pe64) -> std::optional<Diagnostic> {
    const auto minimumSize = pe64 ? std::uint64_t{40} : std::uint64_t{24};
    if (!directory.fileOffset.has_value() || directory.size < minimumSize
        || directory.size > bytes.size() - static_cast<std::size_t>(*directory.fileOffset)) {
        return diagnostic("linked.tls_range", "PE TLS directory is truncated");
    }
    return std::nullopt;
}

auto validate_load_configuration(
    std::span<const std::byte> bytes,
    const LinkedDirectory& directory) -> std::optional<Diagnostic> {
    if (!directory.fileOffset.has_value() || directory.size < 4) {
        return diagnostic("linked.load_config_range", "PE load-configuration directory is truncated");
    }
    const ByteReader reader(bytes);
    const auto declaredSize = reader.u32(static_cast<std::size_t>(*directory.fileOffset)).value();
    if (declaredSize < 4 || declaredSize > directory.size) {
        return diagnostic("linked.load_config_range", "PE load-configuration size is invalid");
    }
    return std::nullopt;
}

auto validate_certificates(std::span<const std::byte> bytes, const LinkedDirectory& directory)
    -> std::optional<Diagnostic> {
    if (!directory.fileOffset.has_value()
        || !contains_range(*directory.fileOffset, directory.size, bytes.size())) {
        return diagnostic("linked.security_range", "PE certificate table is outside the input");
    }
    const ByteReader reader(bytes);
    auto cursor = static_cast<std::size_t>(*directory.fileOffset);
    const auto end = cursor + static_cast<std::size_t>(directory.size);
    while (cursor < end) {
        if (end - cursor < 8) {
            return diagnostic("linked.security_range", "PE certificate header is truncated");
        }
        const auto length = reader.u32(cursor).value();
        if (length < 8 || length > end - cursor) {
            return diagnostic("linked.security_range", "PE certificate length is invalid");
        }
        const auto aligned = (static_cast<std::size_t>(length) + 7U) & ~std::size_t{7};
        if (aligned > end - cursor) {
            return diagnostic("linked.security_range", "PE certificate alignment exceeds the table");
        }
        cursor += aligned;
    }
    return std::nullopt;
}

} // namespace

auto parse_pe_linked(
    std::span<const std::byte> bytes,
    const DetectionResult& detection,
    const LinkedParseLimits& limits) -> Result<LinkedImage, Diagnostic> {
    const ByteReader reader(bytes);
    const auto peOffsetValue = reader.u32(0x3c);
    if (!peOffsetValue.has_value()) {
        return linked_failure("linked.pe_header", "PE DOS header is truncated");
    }
    const auto peOffset = static_cast<std::size_t>(*peOffsetValue);
    const auto coffOffset = checked_add(peOffset, peSignatureSize);
    const auto optionalOffset = coffOffset.has_value()
        ? checked_add(*coffOffset, coffHeaderSize)
        : std::optional<std::size_t>{};
    if (!coffOffset.has_value() || !optionalOffset.has_value()) {
        return linked_failure("linked.pe_header", "PE header offset overflows");
    }
    const auto sectionCount = reader.u16(*coffOffset + 2);
    const auto optionalSize = reader.u16(*coffOffset + 16);
    if (!sectionCount.has_value() || !optionalSize.has_value()) {
        return linked_failure("linked.pe_header", "PE COFF header is truncated");
    }
    if (static_cast<std::size_t>(*sectionCount) > limits.maxSections) {
        return linked_failure("linked.section_limit", "PE section count exceeds the configured limit");
    }
    const auto sectionTable = checked_add(*optionalOffset, *optionalSize);
    const auto sectionBytes = checked_multiply(*sectionCount, sectionHeaderSize);
    if (!sectionTable.has_value() || !sectionBytes.has_value()
        || !contains_range(*sectionTable, *sectionBytes, bytes.size())) {
        return linked_failure("linked.section_range", "PE section table is outside the input");
    }
    const auto magic = reader.u16(*optionalOffset);
    if (!magic.has_value() || (*magic != 0x10b && *magic != 0x20b)) {
        return linked_failure("linked.pe_optional_header", "PE optional header magic is unsupported");
    }
    const bool pe64 = *magic == 0x20b;
    const std::size_t minimumOptionalSize = pe64 ? 112 : 96;
    if (*optionalSize < minimumOptionalSize) {
        return linked_failure("linked.pe_optional_header", "PE optional header is too small");
    }
    const auto entryRva = reader.u32(*optionalOffset + 16);
    const auto imageBase = pe64
        ? reader.u64(*optionalOffset + 24)
        : std::optional<std::uint64_t>{reader.u32(*optionalOffset + 28)};
    const auto sizeOfHeaders = reader.u32(*optionalOffset + 60);
    const auto sizeOfImage = reader.u32(*optionalOffset + 56);
    const auto sectionAlignment = reader.u32(*optionalOffset + 32);
    const auto fileAlignment = reader.u32(*optionalOffset + 36);
    const auto directoryCount = reader.u32(*optionalOffset + (pe64 ? 108 : 92));
    if (!entryRva.has_value() || !imageBase.has_value() || !sizeOfHeaders.has_value()
        || !sizeOfImage.has_value()
        || !sectionAlignment.has_value() || !fileAlignment.has_value()
        || !directoryCount.has_value()) {
        return linked_failure("linked.pe_optional_header", "PE optional fields are truncated");
    }
    if (static_cast<std::size_t>(*directoryCount) > limits.maxDirectories) {
        return linked_failure(
            "linked.directory_limit", "PE data-directory count exceeds the configured limit");
    }
    const auto availableDirectoryBytes = static_cast<std::size_t>(*optionalSize) - minimumOptionalSize;
    const auto requiredDirectoryBytes = checked_multiply(*directoryCount, std::size_t{8});
    if (!requiredDirectoryBytes.has_value() || *requiredDirectoryBytes > availableDirectoryBytes) {
        return linked_failure(
            "linked.directory_range", "PE data-directory table exceeds the optional header");
    }
    const auto sectionTableEnd = checked_add(*sectionTable, *sectionBytes);
    if (!sectionTableEnd.has_value() || *sizeOfHeaders > bytes.size()
        || *sectionTableEnd > *sizeOfHeaders) {
        return linked_failure(
            "linked.header_range", "PE declared headers do not contain the section table");
    }
    if (*fileAlignment == 0 || *sectionAlignment == 0
        || !std::has_single_bit(*fileAlignment) || !std::has_single_bit(*sectionAlignment)) {
        return linked_failure("linked.alignment", "PE file or section alignment is invalid");
    }

    const auto dllCharacteristics = reader.u16(*optionalOffset + 70).value_or(0);
    LinkedImage result;
    result.image.format = BinaryFormat::PE;
    result.image.type = detection.type;
    result.image.architecture = detection.architecture;
    result.image.objectMetadata.characteristics = reader.u16(*coffOffset + 18).value();
    result.image.objectMetadata.formatFlags = dllCharacteristics;
    result.imageBase = *imageBase;
    result.headerSize = *sizeOfHeaders;
    result.fileAlignment = *fileAlignment;
    result.memoryAlignment = *sectionAlignment;
    result.checksumOffset = *optionalOffset + 64;
    result.checksum = reader.u32(*optionalOffset + 64).value_or(0);
    result.sourceBytes.assign(bytes.begin(), bytes.end());
    result.image.entryPoint = BinaryAddress{
        *imageBase + static_cast<std::uint64_t>(*entryRva), AddressKind::Virtual};
    result.positionIndependent = (dllCharacteristics & 0x0040U) != 0;

    EntityIdAllocator ids;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> rawRanges;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> virtualRanges;
    for (std::size_t index = 0; index < *sectionCount; ++index) {
        const auto headerOffset = *sectionTable + index * sectionHeaderSize;
        const auto nameBytes = reader.bytes(headerOffset, 8);
        const auto virtualSize = reader.u32(headerOffset + 8);
        const auto virtualAddress = reader.u32(headerOffset + 12);
        const auto rawSize = reader.u32(headerOffset + 16);
        const auto rawOffset = reader.u32(headerOffset + 20);
        const auto characteristics = reader.u32(headerOffset + 36);
        if (!nameBytes.has_value() || !virtualSize.has_value() || !virtualAddress.has_value()
            || !rawSize.has_value() || !rawOffset.has_value() || !characteristics.has_value()) {
            return linked_failure("linked.section_range", "PE section header is truncated");
        }
        if (*rawSize != 0 && !contains_range(*rawOffset, *rawSize, bytes.size())) {
            return linked_failure("linked.section_range", "PE section raw range is outside the input");
        }
        if ((*rawSize != 0 && (*rawOffset < *sizeOfHeaders
                || *rawOffset % *fileAlignment != 0 || *rawSize % *fileAlignment != 0))
            || *virtualAddress % *sectionAlignment != 0) {
            return linked_failure("linked.alignment", "PE section alignment is invalid");
        }
        const auto mappedSize = std::max(*virtualSize, *rawSize);
        if (*virtualAddress > *sizeOfImage || mappedSize > *sizeOfImage - *virtualAddress) {
            return linked_failure("linked.section_range", "PE section exceeds SizeOfImage");
        }
        for (const auto [start, size] : rawRanges) {
            if (*rawSize != 0 && *rawOffset < start + size
                && start < static_cast<std::uint64_t>(*rawOffset) + *rawSize) {
                return linked_failure("linked.section_overlap", "PE section raw ranges overlap");
            }
        }
        for (const auto [start, size] : virtualRanges) {
            if (mappedSize != 0 && *virtualAddress < start + size
                && start < static_cast<std::uint64_t>(*virtualAddress) + mappedSize) {
                return linked_failure("linked.section_overlap", "PE section virtual ranges overlap");
            }
        }
        if (*rawSize != 0) rawRanges.emplace_back(*rawOffset, *rawSize);
        if (mappedSize != 0) virtualRanges.emplace_back(*virtualAddress, mappedSize);
        const auto name = section_name(*nameBytes);
        const auto id = ids.allocate();
        Section section{
            .id = id,
            .formatIndex = static_cast<std::uint32_t>(index + 1),
            .formatType = 0,
            .formatFlags = *characteristics,
            .name = name,
            .kind = section_kind(name, *characteristics),
            .address = BinaryAddress{
                *imageBase + static_cast<std::uint64_t>(*virtualAddress), AddressKind::Virtual},
            .logicalSize = *virtualSize,
            .alignment = *sectionAlignment,
            .readable = (*characteristics & UINT32_C(0x40000000)) != 0,
            .writable = (*characteristics & UINT32_C(0x80000000)) != 0,
            .executable = (*characteristics & UINT32_C(0x20000000)) != 0,
            .contents = {},
            .lineage = {},
        };
        if (*rawSize != 0) {
            const auto contents = bytes.subspan(*rawOffset, *rawSize);
            section.contents.assign(contents.begin(), contents.end());
        }
        result.image.sections.push_back(std::move(section));
        result.sectionLayout.push_back(LinkedSectionLayout{
            .section = id,
            .headerOffset = headerOffset,
            .fileOffset = *rawOffset,
            .fileSize = *rawSize,
            .memorySize = mappedSize,
        });
        const auto segmentId = ids.allocate();
        result.image.segments.push_back(Segment{
            .id = segmentId,
            .name = name,
            .address = BinaryAddress{
                *imageBase + static_cast<std::uint64_t>(*virtualAddress), AddressKind::Virtual},
            .fileSize = *rawSize,
            .memorySize = mappedSize,
            .readable = (*characteristics & UINT32_C(0x40000000)) != 0,
            .writable = (*characteristics & UINT32_C(0x80000000)) != 0,
            .executable = (*characteristics & UINT32_C(0x20000000)) != 0,
            .lineage = {},
        });
        result.segmentLayout.push_back(LinkedSegmentLayout{
            .segment = segmentId,
            .formatIndex = static_cast<std::uint32_t>(index),
            .headerOffset = headerOffset,
            .fileOffset = *rawOffset,
            .fileSize = *rawSize,
            .memorySize = *virtualSize,
            .alignment = std::max<std::uint64_t>(*sectionAlignment, 1),
        });
    }
    if (*entryRva != 0) {
        const auto entrySection = section_for_rva(result, *entryRva);
        const auto executable = entrySection.has_value()
            ? std::find_if(
                result.image.sections.begin(), result.image.sections.end(),
                [&](const Section& section) {
                    return section.id == entrySection->first && section.executable;
                })
            : result.image.sections.end();
        if (executable == result.image.sections.end()
            || !rva_to_file(result, *entryRva, 1, bytes.size()).has_value()) {
            return linked_failure(
                "linked.entry_point", "PE entry point is outside file-backed executable code");
        }
    }

    const auto directoryOffset = *optionalOffset + minimumOptionalSize;
    for (std::size_t index = 0; index < *directoryCount; ++index) {
        const auto address = reader.u32(directoryOffset + index * 8).value();
        const auto size = reader.u32(directoryOffset + index * 8 + 4).value();
        if (address == 0 && size == 0) continue;
        if (address == 0 || size == 0) {
            return linked_failure(
                "linked.directory_range", "PE data-directory address and size are inconsistent");
        }
        const bool fileAddressed = index == 4;
        const auto mappedOffset = fileAddressed
            ? (contains_range(address, size, bytes.size())
                ? std::optional<std::size_t>{address}
                : std::nullopt)
            : rva_to_file(result, address, size, bytes.size());
        if (!mappedOffset.has_value()) {
            return linked_failure(
                "linked.directory_range", "PE data directory is outside file-backed image ranges");
        }
        result.directories.push_back(LinkedDirectory{
            .kind = directory_kind(static_cast<std::uint32_t>(index)),
            .formatIndex = static_cast<std::uint32_t>(index),
            .headerOffset = directoryOffset + index * 8,
            .address = address,
            .fileOffset = *mappedOffset,
            .size = size,
            .addressIsFileOffset = fileAddressed,
        });
        if (fileAddressed) result.signedImage = true;
    }
    for (const auto& directory : result.directories) {
        std::optional<Diagnostic> error;
        switch (directory.kind) {
        case LinkedDirectoryKind::Import:
            error = parse_imports(result, bytes, directory, limits, ids, pe64);
            break;
        case LinkedDirectoryKind::Export:
            error = parse_exports(result, bytes, directory, limits, ids);
            break;
        case LinkedDirectoryKind::BaseRelocation:
            error = parse_relocations(result, bytes, directory, limits, ids);
            break;
        case LinkedDirectoryKind::Debug:
            error = parse_debug(result, bytes, directory, ids);
            break;
        case LinkedDirectoryKind::Resource:
            error = parse_resources(result, bytes, directory, ids);
            break;
        case LinkedDirectoryKind::Exception:
            if (result.image.architecture == Architecture::X86_64) {
                error = parse_exception_directory(result, bytes, directory, ids);
            }
            break;
        case LinkedDirectoryKind::Tls:
            error = validate_tls(bytes, directory, pe64);
            break;
        case LinkedDirectoryKind::LoadConfiguration:
            error = validate_load_configuration(bytes, directory);
            break;
        case LinkedDirectoryKind::SecurityCertificate:
            error = validate_certificates(bytes, directory);
            break;
        default:
            break;
        }
        if (error.has_value()) {
            return Result<LinkedImage, Diagnostic>::failure(std::move(*error));
        }
    }
    // PE export names are the only stable function identities available in a
    // stripped linked image. Attach them to exception-derived functions so
    // downstream analysis and VM lowering can select exported entry points.
    for (const auto& exported : result.image.exports) {
        const auto function = std::find_if(
            result.image.functions.begin(), result.image.functions.end(),
            [&](const Function& candidate) {
                return candidate.address.value == exported.address.value;
            });
        if (function != result.image.functions.end() && !exported.name.empty()) {
            function->name = exported.name;
            function->externallyVisible = true;
        }
    }
    return Result<LinkedImage, Diagnostic>::success(std::move(result));
}

} // namespace binobf::formats::detail

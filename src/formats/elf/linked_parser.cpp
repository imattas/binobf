#include "../linked_parser_internal.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <optional>
#include <vector>

namespace binobf::formats::detail {
namespace {

struct ElfSectionHeader {
    std::uint32_t name{0};
    std::uint32_t type{0};
    std::uint64_t flags{0};
    std::uint64_t address{0};
    std::uint64_t offset{0};
    std::uint64_t size{0};
    std::uint32_t link{0};
    std::uint32_t info{0};
    std::uint64_t alignment{1};
    std::uint64_t entrySize{0};
};

struct ElfProgramHeader {
    std::uint32_t type{0};
    std::uint32_t flags{0};
    std::uint64_t headerOffset{0};
    std::uint64_t fileOffset{0};
    std::uint64_t virtualAddress{0};
    std::uint64_t fileSize{0};
    std::uint64_t memorySize{0};
    std::uint64_t alignment{1};
};

auto section_kind(std::string_view name, const ElfSectionHeader& header) noexcept
    -> SectionKind {
    if (name.starts_with(".debug") || name.starts_with(".zdebug")) return SectionKind::Debug;
    if (header.type == 8) return SectionKind::UninitializedData;
    if ((header.flags & UINT64_C(0x4)) != 0) return SectionKind::Code;
    if (header.type == 2 || header.type == 11) return SectionKind::SymbolTable;
    if (header.type == 3) return SectionKind::StringTable;
    if (header.type == 4 || header.type == 9) return SectionKind::Relocation;
    if ((header.flags & UINT64_C(0x2)) != 0) return SectionKind::InitializedData;
    return SectionKind::Metadata;
}

auto symbol_kind(std::uint8_t info) noexcept -> SymbolKind {
    switch (info & 0x0fU) {
    case 1: return SymbolKind::Object;
    case 2: return SymbolKind::Function;
    case 3: return SymbolKind::Section;
    case 4: return SymbolKind::File;
    case 6: return SymbolKind::Tls;
    default: return SymbolKind::Unknown;
    }
}

auto symbol_visibility(std::uint8_t info, std::uint8_t other) noexcept -> SymbolVisibility {
    if ((other & 0x03U) == 2) return SymbolVisibility::Hidden;
    return (info >> 4U) == 0 ? SymbolVisibility::Local : SymbolVisibility::External;
}

auto relocation_kind(Architecture architecture, std::uint64_t type) noexcept -> RelocationKind {
    if (architecture == Architecture::X86_64) {
        if (type == 1) return RelocationKind::Absolute;
        if (type == 2 || type == 4) return RelocationKind::PcRelative;
        if (type == 6 || type == 7 || type == 8) return RelocationKind::ImageRelative;
    }
    if (architecture == Architecture::X86) {
        if (type == 1) return RelocationKind::Absolute;
        if (type == 2) return RelocationKind::PcRelative;
    }
    return RelocationKind::ArchitectureSpecific;
}

} // namespace

auto parse_elf_linked(
    std::span<const std::byte> bytes,
    const DetectionResult& detection,
    const LinkedParseLimits& limits) -> Result<LinkedImage, Diagnostic> {
    const ByteReader reader(bytes);
    const auto elfClass = reader.u8(4);
    if (!elfClass.has_value() || (*elfClass != 1 && *elfClass != 2)) {
        return linked_failure("linked.elf_header", "ELF class is unsupported");
    }
    const bool elf64 = *elfClass == 2;
    const auto programOffset = elf64
        ? reader.u64(32)
        : std::optional<std::uint64_t>{reader.u32(28)};
    const auto sectionOffset = elf64
        ? reader.u64(40)
        : std::optional<std::uint64_t>{reader.u32(32)};
    const auto headerSize = reader.u16(elf64 ? 52 : 40);
    const auto programEntrySize = reader.u16(elf64 ? 54 : 42);
    const auto programCount = reader.u16(elf64 ? 56 : 44);
    const auto sectionEntrySize = reader.u16(elf64 ? 58 : 46);
    const auto sectionCount = reader.u16(elf64 ? 60 : 48);
    const auto sectionNameIndex = reader.u16(elf64 ? 62 : 50);
    if (!programOffset.has_value() || !sectionOffset.has_value() || !headerSize.has_value()
        || !programEntrySize.has_value() || !programCount.has_value()
        || !sectionEntrySize.has_value() || !sectionCount.has_value()
        || !sectionNameIndex.has_value()) {
        return linked_failure("linked.elf_header", "ELF header is truncated");
    }
    if (static_cast<std::size_t>(*programCount) > limits.maxSegments) {
        return linked_failure("linked.segment_limit", "ELF segment count exceeds the configured limit");
    }
    if (static_cast<std::size_t>(*sectionCount) > limits.maxSections) {
        return linked_failure("linked.section_limit", "ELF section count exceeds the configured limit");
    }
    const auto expectedProgramEntrySize = elf64 ? std::size_t{56} : std::size_t{32};
    const auto expectedSectionEntrySize = elf64 ? std::size_t{64} : std::size_t{40};
    if ((*programCount != 0 && *programEntrySize != expectedProgramEntrySize)
        || (*sectionCount != 0 && *sectionEntrySize != expectedSectionEntrySize)) {
        return linked_failure("linked.elf_entry_size", "ELF table entry size is unsupported");
    }
    const auto programTable = to_size(*programOffset);
    const auto sectionTable = to_size(*sectionOffset);
    const auto programBytes = checked_multiply(*programCount, expectedProgramEntrySize);
    const auto sectionBytes = checked_multiply(*sectionCount, expectedSectionEntrySize);
    if (!programTable.has_value() || !programBytes.has_value()
        || !contains_range(*programTable, *programBytes, bytes.size())) {
        return linked_failure("linked.segment_range", "ELF program-header table is outside the input");
    }
    if (!sectionTable.has_value() || !sectionBytes.has_value()
        || !contains_range(*sectionTable, *sectionBytes, bytes.size())) {
        return linked_failure("linked.section_range", "ELF section-header table is outside the input");
    }

    LinkedImage result;
    result.image.format = BinaryFormat::ELF;
    result.image.type = detection.type;
    result.image.architecture = detection.architecture;
    result.image.objectMetadata.osAbi = reader.u8(7).value_or(0);
    result.image.objectMetadata.abiVersion = reader.u8(8).value_or(0);
    result.image.objectMetadata.characteristics = reader.u16(16).value_or(0);
    result.image.objectMetadata.formatFlags = elf64
        ? reader.u32(48).value_or(0)
        : reader.u32(36).value_or(0);
    result.headerSize = *headerSize;
    result.positionIndependent = detection.type == BinaryType::SharedLibrary;
    result.sourceBytes.assign(bytes.begin(), bytes.end());
    result.image.entryPoint = BinaryAddress{detection.entryPoint, AddressKind::Virtual};
    EntityIdAllocator ids;

    std::uint64_t imageBase = UINT64_MAX;
    std::vector<ElfProgramHeader> programHeaders;
    programHeaders.reserve(*programCount);
    for (std::size_t index = 0; index < *programCount; ++index) {
        const auto offset = *programTable + index * expectedProgramEntrySize;
        const auto type = reader.u32(offset).value();
        const auto flags = elf64 ? reader.u32(offset + 4).value() : reader.u32(offset + 24).value();
        const auto fileOffset = elf64 ? reader.u64(offset + 8).value() : reader.u32(offset + 4).value();
        const auto virtualAddress = elf64 ? reader.u64(offset + 16).value() : reader.u32(offset + 8).value();
        const auto fileSize = elf64 ? reader.u64(offset + 32).value() : reader.u32(offset + 16).value();
        const auto memorySize = elf64 ? reader.u64(offset + 40).value() : reader.u32(offset + 20).value();
        const auto alignment = elf64 ? reader.u64(offset + 48).value() : reader.u32(offset + 28).value();
        if ((alignment > 1 && !std::has_single_bit(alignment))
            || (alignment > 1 && virtualAddress % alignment != fileOffset % alignment)
            || (type == 1 && fileSize > memorySize)) {
            return linked_failure("linked.segment_alignment", "ELF segment layout is invalid");
        }
        programHeaders.push_back(ElfProgramHeader{
            .type = type,
            .flags = flags,
            .headerOffset = offset,
            .fileOffset = fileOffset,
            .virtualAddress = virtualAddress,
            .fileSize = fileSize,
            .memorySize = memorySize,
            .alignment = std::max<std::uint64_t>(alignment, 1),
        });
        const auto fileOffsetSize = to_size(fileOffset);
        const auto fileSizeValue = to_size(fileSize);
        if (!fileOffsetSize.has_value() || !fileSizeValue.has_value()
            || !contains_range(*fileOffsetSize, *fileSizeValue, bytes.size())) {
            return linked_failure("linked.segment_range", "ELF segment file range is outside the input");
        }
        const auto id = ids.allocate();
        result.image.segments.push_back(Segment{
            .id = id,
            .name = "PHDR" + std::to_string(index),
            .address = BinaryAddress{virtualAddress, AddressKind::Virtual},
            .fileSize = fileSize,
            .memorySize = memorySize,
            .readable = (flags & 0x4U) != 0,
            .writable = (flags & 0x2U) != 0,
            .executable = (flags & 0x1U) != 0,
            .lineage = {},
        });
        result.segmentLayout.push_back(LinkedSegmentLayout{
            .segment = id,
            .formatIndex = static_cast<std::uint32_t>(index),
            .headerOffset = offset,
            .fileOffset = fileOffset,
            .fileSize = fileSize,
            .memorySize = memorySize,
            .alignment = std::max<std::uint64_t>(alignment, 1),
        });
        if (type == 1 && virtualAddress >= fileOffset) {
            imageBase = std::min(imageBase, virtualAddress - fileOffset);
        }
    }
    result.imageBase = imageBase == UINT64_MAX ? 0 : imageBase;
    for (const auto& program : programHeaders) {
        if (program.type == 1) {
            result.memoryAlignment = std::max(result.memoryAlignment, program.alignment);
        }
    }
    if (detection.entryPoint != 0) {
        const auto executableEntry = std::find_if(
            result.image.segments.begin(), result.image.segments.end(),
            [&](const Segment& segment) {
                return segment.executable
                    && detection.entryPoint >= segment.address.value
                    && detection.entryPoint - segment.address.value < segment.memorySize;
            });
        if (executableEntry == result.image.segments.end()) {
            return linked_failure(
                "linked.entry_point", "ELF entry point is outside an executable segment");
        }
    }

    std::vector<ElfSectionHeader> headers;
    headers.reserve(*sectionCount);
    for (std::size_t index = 0; index < *sectionCount; ++index) {
        const auto offset = *sectionTable + index * expectedSectionEntrySize;
        ElfSectionHeader header;
        header.name = reader.u32(offset).value();
        header.type = reader.u32(offset + 4).value();
        if (elf64) {
            header.flags = reader.u64(offset + 8).value();
            header.address = reader.u64(offset + 16).value();
            header.offset = reader.u64(offset + 24).value();
            header.size = reader.u64(offset + 32).value();
            header.link = reader.u32(offset + 40).value();
            header.info = reader.u32(offset + 44).value();
            header.alignment = reader.u64(offset + 48).value();
            header.entrySize = reader.u64(offset + 56).value();
        } else {
            header.flags = reader.u32(offset + 8).value();
            header.address = reader.u32(offset + 12).value();
            header.offset = reader.u32(offset + 16).value();
            header.size = reader.u32(offset + 20).value();
            header.link = reader.u32(offset + 24).value();
            header.info = reader.u32(offset + 28).value();
            header.alignment = reader.u32(offset + 32).value();
            header.entrySize = reader.u32(offset + 36).value();
        }
        if (header.type != 8 && header.size != 0) {
            const auto dataOffset = to_size(header.offset);
            const auto dataSize = to_size(header.size);
            if (!dataOffset.has_value() || !dataSize.has_value()
                || !contains_range(*dataOffset, *dataSize, bytes.size())) {
                return linked_failure("linked.section_range", "ELF section data is outside the input");
            }
        }
        if (header.alignment > 1 && !std::has_single_bit(header.alignment)) {
            return linked_failure("linked.section_alignment", "ELF section alignment is invalid");
        }
        if ((header.flags & UINT64_C(0x2)) != 0 && header.size != 0) {
            const auto containingLoad = std::find_if(
                programHeaders.begin(), programHeaders.end(),
                [&](const ElfProgramHeader& program) {
                    if (program.type != 1 || header.address < program.virtualAddress) {
                        return false;
                    }
                    const auto memoryDelta = header.address - program.virtualAddress;
                    if (memoryDelta > program.memorySize
                        || header.size > program.memorySize - memoryDelta) return false;
                    if (header.type == 8) return true;
                    if (header.offset < program.fileOffset) return false;
                    const auto fileDelta = header.offset - program.fileOffset;
                    return fileDelta <= program.fileSize
                        && header.size <= program.fileSize - fileDelta;
                });
            if (containingLoad == programHeaders.end()) {
                return linked_failure(
                    "linked.section_mapping", "allocated ELF section is outside PT_LOAD ranges");
            }
        }
        headers.push_back(header);
    }
    if (*sectionCount != 0 && *sectionNameIndex >= *sectionCount) {
        return linked_failure("linked.section_names", "ELF section-name table index is invalid");
    }
    std::span<const std::byte> names;
    if (*sectionCount != 0) {
        const auto& strings = headers[*sectionNameIndex];
        if (strings.type != 3) {
            return linked_failure("linked.section_names", "ELF section-name table is not a string table");
        }
        names = bytes.subspan(static_cast<std::size_t>(strings.offset), static_cast<std::size_t>(strings.size));
    }
    for (std::size_t index = 1; index < headers.size(); ++index) {
        const auto& header = headers[index];
        const auto name = read_string(names, header.name);
        if (!name.has_value()) {
            return linked_failure("linked.section_names", "ELF section name is outside the string table");
        }
        const auto id = ids.allocate();
        Section section{
            .id = id,
            .formatIndex = static_cast<std::uint32_t>(index),
            .formatType = header.type,
            .formatFlags = header.flags,
            .formatLink = header.link,
            .formatInfo = header.info,
            .formatEntrySize = header.entrySize,
            .isSectionNameTable = index == *sectionNameIndex,
            .name = *name,
            .kind = section_kind(*name, header),
            .address = BinaryAddress{header.address, AddressKind::Virtual},
            .logicalSize = header.size,
            .alignment = std::max<std::uint64_t>(header.alignment, 1),
            .readable = (header.flags & UINT64_C(0x2)) != 0,
            .writable = (header.flags & UINT64_C(0x1)) != 0,
            .executable = (header.flags & UINT64_C(0x4)) != 0,
            .contents = {},
            .lineage = {},
        };
        if (header.type != 8 && header.size != 0) {
            const auto contents = bytes.subspan(
                static_cast<std::size_t>(header.offset), static_cast<std::size_t>(header.size));
            section.contents.assign(contents.begin(), contents.end());
        }
        result.image.sections.push_back(std::move(section));
        result.sectionLayout.push_back(LinkedSectionLayout{
            .section = id,
            .headerOffset = *sectionTable + index * expectedSectionEntrySize,
            .fileOffset = header.offset,
            .fileSize = header.type == 8 ? 0 : header.size,
            .memorySize = header.size,
        });
    }

    auto section_id = [&](std::size_t formatIndex) -> std::optional<EntityId> {
        if (formatIndex == 0 || formatIndex >= headers.size()) return std::nullopt;
        return result.image.sections[formatIndex - 1].id;
    };
    auto section_for_address = [&](std::uint64_t address)
        -> std::optional<std::pair<EntityId, std::uint64_t>> {
        for (const auto& section : result.image.sections) {
            if (address >= section.address.value
                && address - section.address.value < section.logicalSize) {
                return std::pair{section.id, address - section.address.value};
            }
        }
        return std::nullopt;
    };
    auto section_bytes = [&](const ElfSectionHeader& header) -> std::span<const std::byte> {
        if (header.type == 8 || header.size == 0) return {};
        return bytes.subspan(
            static_cast<std::size_t>(header.offset), static_cast<std::size_t>(header.size));
    };

    for (std::size_t index = 1; index < headers.size(); ++index) {
        const auto& header = headers[index];
        const auto& section = result.image.sections[index - 1];
        LinkedDirectoryKind kind = LinkedDirectoryKind::Unknown;
        if (header.type == 6) kind = LinkedDirectoryKind::Dynamic;
        else if (header.type == 7 || section.name.starts_with(".note")) kind = LinkedDirectoryKind::Notes;
        else if (section.name == ".eh_frame" || section.name == ".eh_frame_hdr") kind = LinkedDirectoryKind::Unwind;
        if (kind != LinkedDirectoryKind::Unknown) {
            result.directories.push_back(LinkedDirectory{
                .kind = kind,
                .formatIndex = static_cast<std::uint32_t>(index),
                .headerOffset = result.sectionLayout[index - 1].headerOffset,
                .address = header.address,
                .fileOffset = header.offset,
                .size = header.size,
                .addressIsFileOffset = false,
            });
        }
        if (section.kind == SectionKind::Debug && section.logicalSize != 0) {
            result.image.debugInfo.push_back(DebugInfo{
                .id = ids.allocate(),
                .format = "elf-" + section.name,
                .source = std::nullopt,
                .lineage = {},
            });
        }
    }

    for (std::size_t index = 1; index < headers.size(); ++index) {
        const auto& header = headers[index];
        if (header.type != 6) continue;
        const auto expected = elf64 ? std::uint64_t{16} : std::uint64_t{8};
        if (header.entrySize != expected || header.size % expected != 0
            || header.link >= headers.size() || headers[header.link].type != 3) {
            return linked_failure("linked.dynamic_range", "ELF dynamic section metadata is invalid");
        }
        const auto strings = section_bytes(headers[header.link]);
        const auto count = header.size / expected;
        bool terminated = false;
        for (std::size_t entryIndex = 0; entryIndex < count; ++entryIndex) {
            const auto offset = static_cast<std::size_t>(header.offset + entryIndex * expected);
            const auto tag = elf64
                ? reader.i64(offset).value()
                : static_cast<std::int64_t>(reader.i32(offset).value());
            const auto value = elf64
                ? reader.u64(offset + 8).value()
                : static_cast<std::uint64_t>(reader.u32(offset + 4).value());
            if (tag == 0) {
                terminated = true;
                break;
            }
            if (tag == 1) {
                const auto needed = read_string(strings, value);
                if (!needed.has_value() || needed->size() > limits.maxStringBytes) {
                    return linked_failure("linked.dynamic_string", "ELF DT_NEEDED string is invalid");
                }
            }
            if (tag == INT64_C(0x6ffffdfb) && (value & UINT64_C(0x08000000)) != 0) {
                result.image.type = BinaryType::Executable;
                result.positionIndependent = true;
            }
        }
        if (!terminated) {
            return linked_failure("linked.dynamic_range", "ELF dynamic section lacks DT_NULL");
        }
    }

    const bool hasDynamicSection = std::any_of(
        headers.begin(), headers.end(), [](const ElfSectionHeader& header) {
            return header.type == 6;
        });
    if (!hasDynamicSection) {
        for (const auto& program : programHeaders) {
            if (program.type != 2) continue;
            const auto entrySize = elf64 ? std::uint64_t{16} : std::uint64_t{8};
            if (program.fileSize == 0 || program.fileSize % entrySize != 0) {
                return linked_failure(
                    "linked.dynamic_range", "ELF PT_DYNAMIC size is invalid");
            }
            const auto count = program.fileSize / entrySize;
            bool terminated = false;
            for (std::size_t index = 0; index < count; ++index) {
                const auto offset = static_cast<std::size_t>(
                    program.fileOffset + static_cast<std::uint64_t>(index) * entrySize);
                const auto tag = elf64
                    ? reader.i64(offset).value()
                    : static_cast<std::int64_t>(reader.i32(offset).value());
                const auto value = elf64
                    ? reader.u64(offset + 8).value()
                    : static_cast<std::uint64_t>(reader.u32(offset + 4).value());
                if (tag == 0) {
                    terminated = true;
                    break;
                }
                if (tag == INT64_C(0x6ffffdfb) && (value & UINT64_C(0x08000000)) != 0) {
                    result.image.type = BinaryType::Executable;
                    result.positionIndependent = true;
                }
            }
            if (!terminated) {
                return linked_failure("linked.dynamic_range", "ELF PT_DYNAMIC lacks DT_NULL");
            }
        }
    }

    for (std::size_t index = 0; index < programHeaders.size(); ++index) {
        const auto& program = programHeaders[index];
        LinkedDirectoryKind kind = LinkedDirectoryKind::Unknown;
        if (program.type == 2) kind = LinkedDirectoryKind::Dynamic;
        else if (program.type == 3) kind = LinkedDirectoryKind::Interpreter;
        else if (program.type == 4) kind = LinkedDirectoryKind::Notes;
        else if (program.type == UINT32_C(0x6474e550)) kind = LinkedDirectoryKind::Unwind;
        if (kind == LinkedDirectoryKind::Unknown) continue;
        if (program.type == 3) {
            const auto interpreter = read_string(
                bytes.subspan(
                    static_cast<std::size_t>(program.fileOffset),
                    static_cast<std::size_t>(program.fileSize)),
                0);
            if (!interpreter.has_value() || interpreter->size() > limits.maxStringBytes) {
                return linked_failure(
                    "linked.interpreter_range", "ELF interpreter path is invalid");
            }
        }
        const auto duplicate = std::find_if(
            result.directories.begin(), result.directories.end(),
            [&](const LinkedDirectory& directory) {
                return directory.kind == kind && directory.fileOffset == program.fileOffset
                    && directory.size == program.fileSize;
            });
        if (duplicate == result.directories.end()) {
            result.directories.push_back(LinkedDirectory{
                .kind = kind,
                .formatIndex = static_cast<std::uint32_t>(index),
                .headerOffset = program.headerOffset,
                .address = program.virtualAddress,
                .fileOffset = program.fileOffset,
                .size = program.fileSize,
                .addressIsFileOffset = false,
            });
        }
    }

    std::vector<std::vector<EntityId>> symbolIds(headers.size());
    for (std::size_t tableIndex = 1; tableIndex < headers.size(); ++tableIndex) {
        const auto& header = headers[tableIndex];
        if (header.type != 2 && header.type != 11) continue;
        const auto expected = elf64 ? std::uint64_t{24} : std::uint64_t{16};
        if (header.entrySize != expected || header.size % expected != 0
            || header.link >= headers.size() || headers[header.link].type != 3) {
            return linked_failure("linked.symbol_range", "ELF symbol table metadata is invalid");
        }
        const auto count = header.size / expected;
        if (count > limits.maxSymbols || result.image.symbols.size() > limits.maxSymbols - count) {
            return linked_failure("linked.symbol_limit", "ELF symbol count exceeds the configured limit");
        }
        const auto strings = section_bytes(headers[header.link]);
        auto& tableIds = symbolIds[tableIndex];
        tableIds.reserve(static_cast<std::size_t>(count));
        for (std::size_t symbolIndex = 0; symbolIndex < count; ++symbolIndex) {
            const auto offset = static_cast<std::size_t>(header.offset + symbolIndex * expected);
            const auto nameOffset = reader.u32(offset).value();
            const auto info = reader.u8(offset + (elf64 ? 4 : 12)).value();
            const auto other = reader.u8(offset + (elf64 ? 5 : 13)).value();
            const auto sectionIndex = reader.u16(offset + (elf64 ? 6 : 14)).value();
            const auto value = elf64
                ? reader.u64(offset + 8).value()
                : static_cast<std::uint64_t>(reader.u32(offset + 4).value());
            const auto size = elf64
                ? reader.u64(offset + 16).value()
                : static_cast<std::uint64_t>(reader.u32(offset + 8).value());
            const auto name = read_string(strings, nameOffset);
            if (!name.has_value() || name->size() > limits.maxStringBytes) {
                return linked_failure("linked.symbol_name", "ELF symbol name is invalid");
            }
            const auto id = ids.allocate();
            tableIds.push_back(id);
            const auto relatedSection = section_id(sectionIndex);
            const auto visibility = symbol_visibility(info, other);
            std::optional<SymbolDefinitionKind> definition;
            std::uint64_t commonAlignment = 0;
            if (sectionIndex == 0) {
                definition = SymbolDefinitionKind::Undefined;
            } else if (sectionIndex == 0xfff1U) {
                definition = SymbolDefinitionKind::Absolute;
            } else if (sectionIndex == 0xfff2U) {
                definition = SymbolDefinitionKind::Common;
                commonAlignment = value;
            } else if (relatedSection.has_value()) {
                definition = SymbolDefinitionKind::SectionRelative;
            }
            const auto normalizedKind = symbol_kind(info);
            result.image.symbols.push_back(Symbol{
                .id = id,
                .formatIndex = static_cast<std::uint32_t>(symbolIndex),
                .formatTableIndex = static_cast<std::uint32_t>(tableIndex),
                .formatType = info,
                .formatStorage = static_cast<std::uint8_t>(info >> 4U),
                .formatOther = other,
                .formatSectionIndex = sectionIndex,
                .auxiliaryData = {},
                .name = *name,
                .section = relatedSection,
                .address = BinaryAddress{value, AddressKind::Virtual},
                .size = size,
                .kind = normalizedKind,
                .visibility = visibility,
                .defined = sectionIndex != 0,
                .definition = definition,
                .commonAlignment = commonAlignment,
                .tlsModel = normalizedKind == SymbolKind::Tls
                    ? TlsModel::Unknown
                    : TlsModel::None,
                .lineage = {},
            });
            if (header.type == 11 && !name->empty() && (info >> 4U) != 0) {
                if (sectionIndex == 0) {
                    if (result.image.imports.size() >= limits.maxImports) {
                        return linked_failure("linked.import_limit", "ELF import count exceeds the configured limit");
                    }
                    result.image.imports.push_back(Import{
                        .id = ids.allocate(),
                        .library = {},
                        .name = *name,
                        .ordinal = std::nullopt,
                        .lineage = {},
                    });
                } else if (visibility != SymbolVisibility::Hidden) {
                    if (result.image.exports.size() >= limits.maxExports) {
                        return linked_failure("linked.export_limit", "ELF export count exceeds the configured limit");
                    }
                    result.image.exports.push_back(Export{
                        .id = ids.allocate(),
                        .name = *name,
                        .address = BinaryAddress{value, AddressKind::Virtual},
                        .ordinal = std::nullopt,
                        .lineage = {},
                    });
                }
            }
        }
    }

    for (std::size_t tableIndex = 1; tableIndex < headers.size(); ++tableIndex) {
        const auto& header = headers[tableIndex];
        if (header.type != 4 && header.type != 9) continue;
        const bool rela = header.type == 4;
        const auto expected = elf64
            ? (rela ? std::uint64_t{24} : std::uint64_t{16})
            : (rela ? std::uint64_t{12} : std::uint64_t{8});
        if (header.entrySize != expected || header.size % expected != 0
            || header.link >= symbolIds.size() || symbolIds[header.link].empty()) {
            return linked_failure("linked.relocation_range", "ELF relocation table metadata is invalid");
        }
        const auto count = header.size / expected;
        if (count > limits.maxRelocations
            || result.image.relocations.size() > limits.maxRelocations - count) {
            return linked_failure("linked.relocation_limit", "ELF relocation count exceeds the configured limit");
        }
        for (std::size_t relocationIndex = 0; relocationIndex < count; ++relocationIndex) {
            const auto offset = static_cast<std::size_t>(header.offset + relocationIndex * expected);
            const auto targetAddress = elf64
                ? reader.u64(offset).value()
                : static_cast<std::uint64_t>(reader.u32(offset).value());
            const auto info = elf64
                ? reader.u64(offset + 8).value()
                : static_cast<std::uint64_t>(reader.u32(offset + 4).value());
            const auto symbolIndex = elf64 ? info >> 32U : info >> 8U;
            const auto rawType = elf64 ? info & UINT64_C(0xffffffff) : info & UINT64_C(0xff);
            if (symbolIndex >= symbolIds[header.link].size()) {
                return linked_failure("linked.relocation_symbol", "ELF relocation symbol index is invalid");
            }
            std::optional<std::pair<EntityId, std::uint64_t>> target;
            if (header.info != 0 && header.info < headers.size()) {
                const auto id = section_id(header.info);
                if (id.has_value()) {
                    const auto& targetHeader = headers[header.info];
                    const auto relative = targetAddress >= targetHeader.address
                        ? targetAddress - targetHeader.address
                        : targetAddress;
                    target = std::pair{*id, relative};
                }
            } else {
                target = section_for_address(targetAddress);
            }
            const auto targetSection = target.has_value()
                ? std::find_if(
                    result.image.sections.begin(), result.image.sections.end(),
                    [&](const Section& section) { return section.id == target->first; })
                : result.image.sections.end();
            if (!target.has_value() || targetSection == result.image.sections.end()
                || target->second >= targetSection->logicalSize) {
                return linked_failure("linked.relocation_target", "ELF relocation target is outside a section");
            }
            std::int64_t addend = 0;
            if (rela) {
                addend = elf64
                    ? reader.i64(offset + 16).value()
                    : static_cast<std::int64_t>(reader.i32(offset + 8).value());
            }
            result.image.relocations.push_back(Relocation{
                .id = ids.allocate(),
                .formatIndex = static_cast<std::uint32_t>(relocationIndex),
                .formatTableIndex = static_cast<std::uint32_t>(tableIndex),
                .section = target->first,
                .offset = target->second,
                .kind = relocation_kind(detection.architecture, rawType),
                .rawType = rawType,
                .targetSymbol = symbolIds[header.link][static_cast<std::size_t>(symbolIndex)],
                .addend = addend,
                .lineage = {},
            });
        }
    }
    return Result<LinkedImage, Diagnostic>::success(std::move(result));
}

} // namespace binobf::formats::detail

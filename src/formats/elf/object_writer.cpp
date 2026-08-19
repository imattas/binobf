#include "../object_writer_internal.hpp"
#include "../../architecture/arm64_fixups.hpp"
#include "../../architecture/x86_fixups.hpp"
#include "../../architecture/x86_64_fixups.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace binobf::formats::detail {
namespace {

constexpr std::uint64_t shtSymtab = 2;
constexpr std::uint64_t shtStrtab = 3;
constexpr std::uint64_t shtRela = 4;
constexpr std::uint64_t shtNobits = 8;
constexpr std::uint64_t shtRel = 9;
constexpr std::uint64_t shtDynsym = 11;
constexpr std::uint64_t shtGroup = 17;
constexpr std::uint64_t shtSymtabShndx = 18;

struct EncodedSection {
    const Section* source{nullptr};
    std::vector<std::byte> bytes;
    std::uint64_t fileOffset{0};
    std::uint64_t logicalSize{0};
    std::uint32_t nameOffset{0};
};

auto failure(std::string code, std::string message)
    -> Result<std::vector<std::byte>, Diagnostic> {
    return Result<std::vector<std::byte>, Diagnostic>::failure(
        Diagnostic{DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

auto checked_add(std::size_t left, std::size_t right) noexcept
    -> std::optional<std::size_t> {
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

auto checked_align(std::size_t value, std::size_t alignment) noexcept
    -> std::optional<std::size_t> {
    if (alignment == 0) {
        return std::nullopt;
    }
    const auto remainder = value % alignment;
    return remainder == 0 ? std::optional{value} : checked_add(value, alignment - remainder);
}

auto to_size(std::uint64_t value) noexcept -> std::optional<std::size_t> {
    if (value > std::numeric_limits<std::size_t>::max()) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(value);
}

void put_u16(std::span<std::byte> output, std::size_t offset, std::uint16_t value) {
    output[offset] = static_cast<std::byte>(value & 0xffU);
    output[offset + 1] = static_cast<std::byte>((value >> 8U) & 0xffU);
}

void put_u32(std::span<std::byte> output, std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        output[offset + index] = static_cast<std::byte>(
            (value >> static_cast<unsigned int>(index * 8U)) & 0xffU);
    }
}

void put_u64(std::span<std::byte> output, std::size_t offset, std::uint64_t value) {
    for (std::size_t index = 0; index < 8; ++index) {
        output[offset + index] = static_cast<std::byte>(
            (value >> static_cast<unsigned int>(index * 8U)) & 0xffU);
    }
}

void put_i32(std::span<std::byte> output, std::size_t offset, std::int32_t value) {
    put_u32(output, offset, std::bit_cast<std::uint32_t>(value));
}

void put_i64(std::span<std::byte> output, std::size_t offset, std::int64_t value) {
    put_u64(output, offset, std::bit_cast<std::uint64_t>(value));
}

auto read_u32(std::span<const std::byte> input, std::size_t offset)
    -> std::optional<std::uint32_t> {
    if (offset > input.size() || 4U > input.size() - offset) return std::nullopt;
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(
            std::to_integer<std::uint8_t>(input[offset + index]))
            << static_cast<unsigned int>(index * 8U);
    }
    return value;
}

auto append_string(std::vector<std::byte>& table, const std::string& value)
    -> std::optional<std::uint32_t> {
    if (table.size() > std::numeric_limits<std::uint32_t>::max()) {
        return std::nullopt;
    }
    const auto offset = static_cast<std::uint32_t>(table.size());
    const auto newSize = checked_add(table.size(), value.size());
    const auto terminatedSize = newSize ? checked_add(*newSize, 1) : std::nullopt;
    if (!terminatedSize || *terminatedSize > std::numeric_limits<std::uint32_t>::max()) {
        return std::nullopt;
    }
    table.reserve(*terminatedSize);
    for (const char character : value) {
        table.push_back(static_cast<std::byte>(character));
    }
    table.push_back(std::byte{0});
    return offset;
}

auto machine_for(Architecture architecture) noexcept -> std::uint16_t {
    switch (architecture) {
    case Architecture::X86: return 3;
    case Architecture::X86_64: return 62;
    case Architecture::ARM64: return 183;
    case Architecture::Unknown: return 0;
    }
    return 0;
}

} // namespace

auto write_elf_object(const BinaryImage& image)
    -> Result<std::vector<std::byte>, Diagnostic> {
    const bool is64Bit = image.architecture != Architecture::X86;
    const std::size_t headerSize = is64Bit ? 64 : 52;
    const std::size_t sectionHeaderSize = is64Bit ? 64 : 40;
    const std::size_t symbolEntrySize = is64Bit ? 24 : 16;

    std::vector<const Section*> orderedSections;
    orderedSections.reserve(image.sections.size());
    for (const auto& section : image.sections) {
        orderedSections.push_back(&section);
    }
    std::sort(orderedSections.begin(), orderedSections.end(), [](const auto* left, const auto* right) {
        return left->formatIndex < right->formatIndex;
    });
    for (std::size_t index = 0; index < orderedSections.size(); ++index) {
        if (orderedSections[index]->formatIndex != index + 1) {
            return failure("object.model_invalid", "ELF section indices must be contiguous");
        }
    }

    std::unordered_map<std::uint32_t, const Section*> sectionsByIndex;
    std::unordered_map<std::uint64_t, const Section*> sectionsById;
    std::unordered_map<std::uint64_t, const Symbol*> symbolsById;
    std::unordered_map<std::uint32_t, std::vector<const Symbol*>> symbolsByTable;
    std::unordered_map<std::uint32_t, std::vector<const Relocation*>> relocationsByTable;
    std::unordered_map<std::uint64_t, const SectionAssociation*> associationsBySection;
    std::unordered_map<std::uint64_t, std::vector<const ExtendedSectionIndex*>>
        extendedIndicesBySection;
    for (const auto* section : orderedSections) {
        sectionsByIndex.emplace(section->formatIndex, section);
        sectionsById.emplace(section->id.value(), section);
    }
    for (const auto& symbol : image.symbols) {
        symbolsById.emplace(symbol.id.value(), &symbol);
        symbolsByTable[symbol.formatTableIndex].push_back(&symbol);
    }
    for (const auto& relocation : image.relocations) {
        relocationsByTable[relocation.formatTableIndex].push_back(&relocation);
    }
    for (const auto& association : image.sectionAssociations) {
        associationsBySection.emplace(association.section.value(), &association);
    }
    for (const auto& extended : image.extendedSectionIndices) {
        extendedIndicesBySection[extended.indexSection.value()].push_back(&extended);
    }
    for (auto& [table, symbols] : symbolsByTable) {
        static_cast<void>(table);
        std::sort(symbols.begin(), symbols.end(), [](const auto* left, const auto* right) {
            return left->formatIndex < right->formatIndex;
        });
        for (std::size_t index = 0; index < symbols.size(); ++index) {
            if (symbols[index]->formatIndex != index + 1) {
                return failure("object.model_invalid", "ELF symbol indices must be contiguous");
            }
        }
    }
    for (auto& [table, relocations] : relocationsByTable) {
        static_cast<void>(table);
        std::sort(relocations.begin(), relocations.end(), [](const auto* left, const auto* right) {
            return left->formatIndex < right->formatIndex;
        });
        for (std::size_t index = 0; index < relocations.size(); ++index) {
            if (relocations[index]->formatIndex != index) {
                return failure("object.model_invalid", "ELF relocation indices must be contiguous");
            }
        }
    }

    std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> symbolNameOffsets;
    std::vector<EncodedSection> encodedSections;
    encodedSections.reserve(orderedSections.size());
    std::uint32_t sectionNameTableIndex = 0;
    std::vector<std::byte> sectionNames{std::byte{0}};
    std::unordered_map<std::uint32_t, std::uint32_t> sectionNameOffsets;
    for (const auto* section : orderedSections) {
        const auto offset = append_string(sectionNames, section->name);
        if (!offset) {
            return failure("object.size_limit", "ELF section-name table exceeds 32-bit offsets");
        }
        sectionNameOffsets.emplace(section->formatIndex, *offset);
        if (section->isSectionNameTable) {
            sectionNameTableIndex = section->formatIndex;
        }
    }

    for (const auto* section : orderedSections) {
        EncodedSection encoded;
        encoded.source = section;
        encoded.nameOffset = sectionNameOffsets.at(section->formatIndex);
        if (section->formatType == shtStrtab) {
            const bool containsSectionNames = section->isSectionNameTable;
            if (containsSectionNames) {
                encoded.bytes = sectionNames;
            }
            std::vector<const Symbol*> linkedSymbols;
            for (const auto* candidate : orderedSections) {
                if ((candidate->formatType == shtSymtab || candidate->formatType == shtDynsym)
                    && candidate->formatLink == section->formatIndex) {
                    const auto found = symbolsByTable.find(candidate->formatIndex);
                    if (found != symbolsByTable.end()) {
                        linkedSymbols.insert(
                            linkedSymbols.end(), found->second.begin(), found->second.end());
                    }
                }
            }
            if (linkedSymbols.empty() && !containsSectionNames) {
                encoded.bytes = section->contents;
            } else if (!linkedSymbols.empty()) {
                if (!containsSectionNames) {
                    encoded.bytes.clear();
                }
                if (encoded.bytes.empty()) {
                    encoded.bytes.push_back(std::byte{0});
                }
                for (const auto* symbol : linkedSymbols) {
                    const auto offset = append_string(encoded.bytes, symbol->name);
                    if (!offset) {
                        return failure("object.size_limit", "ELF symbol string table is too large");
                    }
                    auto& offsets = symbolNameOffsets[symbol->formatTableIndex];
                    if (offsets.size() <= symbol->formatIndex) {
                        offsets.resize(static_cast<std::size_t>(symbol->formatIndex) + 1);
                    }
                    offsets[symbol->formatIndex] = *offset;
                }
            }
        } else if (section->formatType == shtGroup) {
            const auto association = associationsBySection.find(section->id.value());
            if (association == associationsBySection.end()
                || association->second->kind != SectionAssociationKind::ElfGroup) {
                return failure("object.model_invalid", "ELF group has no normalized association");
            }
            const auto wordCount = checked_add(association->second->members.size(), 1U);
            const auto byteCount = wordCount ? checked_multiply(*wordCount, 4U) : std::nullopt;
            if (!byteCount) {
                return failure("object.size_limit", "ELF group member table is too large");
            }
            encoded.bytes.assign(*byteCount, std::byte{0});
            auto output = std::span<std::byte>{encoded.bytes};
            const auto sourceFlags = read_u32(section->contents, 0);
            put_u32(output, 0,
                    sourceFlags.has_value() && (*sourceFlags & 1U) != 0U
                        ? *sourceFlags
                        : 1U);
            for (std::size_t index = 0; index < association->second->members.size(); ++index) {
                const auto member = sectionsById.find(
                    association->second->members[index].value());
                if (member == sectionsById.end()) {
                    return failure("object.model_invalid", "ELF group member is missing");
                }
                put_u32(output, (index + 1U) * 4U, member->second->formatIndex);
            }
        } else if (section->formatType == shtSymtabShndx) {
            const auto symbols = symbolsByTable.find(section->formatLink);
            const auto entryCount = checked_add(
                symbols == symbolsByTable.end() ? 0U : symbols->second.size(), 1U);
            const auto byteCount = entryCount ? checked_multiply(*entryCount, 4U) : std::nullopt;
            if (!byteCount) {
                return failure("object.size_limit", "ELF extended-index table is too large");
            }
            encoded.bytes.assign(*byteCount, std::byte{0});
            auto output = std::span<std::byte>{encoded.bytes};
            const auto records = extendedIndicesBySection.find(section->id.value());
            if (records != extendedIndicesBySection.end()) {
                for (const auto* record : records->second) {
                    const auto symbol = symbolsById.find(record->symbol.value());
                    const auto target = sectionsById.find(record->section.value());
                    if (symbol == symbolsById.end() || target == sectionsById.end()
                        || symbol->second->formatTableIndex != section->formatLink) {
                        return failure(
                            "object.model_invalid", "ELF extended-index owner is missing");
                    }
                    put_u32(output, static_cast<std::size_t>(symbol->second->formatIndex) * 4U,
                            target->second->formatIndex);
                }
            }
        } else if (section->formatType != shtSymtab && section->formatType != shtDynsym
            && section->formatType != shtRel && section->formatType != shtRela
            && section->formatType != shtNobits) {
            encoded.bytes = section->contents;
            const auto logicalSize = to_size(section->logicalSize);
            if (!logicalSize) {
                return failure("object.size_limit", "ELF section size exceeds host limits");
            }
            encoded.bytes.resize(*logicalSize, std::byte{0});
        }
        encodedSections.push_back(std::move(encoded));
    }

    for (auto& encoded : encodedSections) {
        const auto& section = *encoded.source;
        if (section.formatType == shtSymtab || section.formatType == shtDynsym) {
            if (section.formatEntrySize != symbolEntrySize) {
                return failure("object.model_invalid", "ELF symbol-table entry size is invalid");
            }
            const auto found = symbolsByTable.find(section.formatIndex);
            const std::size_t symbolCount = found == symbolsByTable.end() ? 0 : found->second.size();
            const auto entryCount = checked_add(symbolCount, 1);
            const auto tableSize = entryCount ? checked_multiply(*entryCount, symbolEntrySize)
                                              : std::nullopt;
            if (!tableSize) {
                return failure("object.size_limit", "ELF symbol table size overflows");
            }
            encoded.bytes.assign(*tableSize, std::byte{0});
            if (found != symbolsByTable.end()) {
                const auto nameOffsets = symbolNameOffsets.find(section.formatIndex);
                if (nameOffsets == symbolNameOffsets.end()) {
                    return failure("object.model_invalid", "ELF symbol names have no string table");
                }
                for (const auto* symbol : found->second) {
                    const auto offset = static_cast<std::size_t>(symbol->formatIndex)
                        * symbolEntrySize;
                    auto output = std::span<std::byte>{encoded.bytes};
                    put_u32(output, offset, nameOffsets->second.at(symbol->formatIndex));
                    const auto info = static_cast<std::uint8_t>(
                        static_cast<std::uint8_t>(symbol->formatStorage << 4U)
                        | static_cast<std::uint8_t>(symbol->formatType));
                    if (is64Bit) {
                        output[offset + 4] = static_cast<std::byte>(info);
                        output[offset + 5] = static_cast<std::byte>(symbol->formatOther);
                        put_u16(output, offset + 6,
                                static_cast<std::uint16_t>(symbol->formatSectionIndex));
                        put_u64(output, offset + 8, symbol->address.value);
                        put_u64(output, offset + 16, symbol->size);
                    } else {
                        put_u32(output, offset + 4, static_cast<std::uint32_t>(symbol->address.value));
                        put_u32(output, offset + 8, static_cast<std::uint32_t>(symbol->size));
                        output[offset + 12] = static_cast<std::byte>(info);
                        output[offset + 13] = static_cast<std::byte>(symbol->formatOther);
                        put_u16(output, offset + 14,
                                static_cast<std::uint16_t>(symbol->formatSectionIndex));
                    }
                }
            }
        } else if (section.formatType == shtRel || section.formatType == shtRela) {
            const std::size_t entrySize = is64Bit
                ? (section.formatType == shtRela ? 24 : 16)
                : (section.formatType == shtRela ? 12 : 8);
            if (section.formatEntrySize != entrySize) {
                return failure("object.model_invalid", "ELF relocation entry size is invalid");
            }
            const auto found = relocationsByTable.find(section.formatIndex);
            const std::size_t count = found == relocationsByTable.end() ? 0 : found->second.size();
            const auto tableSize = checked_multiply(count, entrySize);
            if (!tableSize) {
                return failure("object.size_limit", "ELF relocation table size overflows");
            }
            encoded.bytes.assign(*tableSize, std::byte{0});
            if (found != relocationsByTable.end()) {
                for (const auto* relocation : found->second) {
                    const auto offset = static_cast<std::size_t>(relocation->formatIndex) * entrySize;
                    std::uint32_t symbolIndex = 0;
                    if (relocation->targetSymbol.has_value()) {
                        symbolIndex = symbolsById.at(relocation->targetSymbol->value())->formatIndex;
                    }
                    auto output = std::span<std::byte>{encoded.bytes};
                    if (is64Bit) {
                        put_u64(output, offset, relocation->offset);
                        put_u64(output, offset + 8,
                                (static_cast<std::uint64_t>(symbolIndex) << 32U)
                                    | relocation->rawType);
                        if (section.formatType == shtRela) {
                            put_i64(output, offset + 16, relocation->addend);
                        }
                    } else {
                        put_u32(output, offset, static_cast<std::uint32_t>(relocation->offset));
                        put_u32(output, offset + 4,
                                (symbolIndex << 8U)
                                    | static_cast<std::uint32_t>(relocation->rawType));
                        if (section.formatType == shtRela) {
                            put_i32(output, offset + 8,
                                    static_cast<std::int32_t>(relocation->addend));
                        }
                    }
                }
            }
        }
        encoded.logicalSize = section.formatType == shtNobits
            ? section.logicalSize
            : static_cast<std::uint64_t>(encoded.bytes.size());
    }

    if (image.architecture == Architecture::X86
        || image.architecture == Architecture::ARM64) {
        for (const auto& relocationSection : encodedSections) {
            if (relocationSection.source->formatType != shtRel) continue;
            const auto relocations = relocationsByTable.find(
                relocationSection.source->formatIndex);
            if (relocations == relocationsByTable.end()) continue;
            const auto target = std::find_if(
                encodedSections.begin(), encodedSections.end(), [&](const auto& candidate) {
                    return candidate.source->formatIndex
                        == relocationSection.source->formatInfo;
                });
            if (target == encodedSections.end()) {
                return failure("object.model_invalid", "ELF REL target section is missing");
            }
            auto targetBytes = std::span<std::byte>{target->bytes};
            for (const auto* relocation : relocations->second) {
                const auto semantics = image.architecture == Architecture::ARM64
                    ? binobf::detail::arm64_fixup_semantics(
                          BinaryFormat::ELF, relocation->rawType)
                    : image.architecture == Architecture::X86_64
                        ? binobf::detail::x86_64_fixup_semantics(
                              BinaryFormat::ELF, relocation->rawType)
                        : binobf::detail::x86_fixup_semantics(
                              BinaryFormat::ELF, relocation->rawType);
                if (!semantics.has_value()) {
                    continue;
                }
                const auto encoded = image.architecture == Architecture::ARM64
                    ? binobf::detail::encode_arm64_fixup(
                          semantics.value(), relocation->addend)
                    : image.architecture == Architecture::X86_64
                        ? binobf::detail::encode_x86_64_fixup(
                              semantics.value(), relocation->addend)
                        : binobf::detail::encode_x86_fixup(
                              semantics.value(), relocation->addend);
                if (!encoded.has_value()) {
                    return failure(encoded.error().code, encoded.error().message);
                }
                const auto byteCount = encoded.value().fieldBytes.size();
                if (relocation->offset > targetBytes.size()
                    || byteCount > targetBytes.size()
                        - static_cast<std::size_t>(relocation->offset)) {
                    return failure("object.size_limit", "ELF REL implicit addend is out of range");
                }
                if (encoded.value().writeMask.size() != byteCount) {
                    return failure(
                        "object.model_invalid", "ELF relocation mask has an invalid size");
                }
                const auto destination = static_cast<std::size_t>(relocation->offset);
                for (std::size_t index = 0; index < byteCount; ++index) {
                    const auto mask = std::to_integer<std::uint8_t>(
                        encoded.value().writeMask[index]);
                    const auto oldByte = std::to_integer<std::uint8_t>(
                        targetBytes[destination + index]);
                    const auto newByte = std::to_integer<std::uint8_t>(
                        encoded.value().fieldBytes[index]);
                    targetBytes[destination + index] = static_cast<std::byte>(
                        (oldByte & static_cast<std::uint8_t>(~mask)) | (newByte & mask));
                }
            }
        }
    }

    std::size_t cursor = headerSize;
    for (auto& encoded : encodedSections) {
        const auto alignment = to_size(encoded.source->alignment);
        const auto aligned = alignment ? checked_align(cursor, *alignment) : std::nullopt;
        if (!aligned) {
            return failure("object.size_limit", "ELF section layout overflows");
        }
        cursor = *aligned;
        encoded.fileOffset = cursor;
        if (encoded.source->formatType != shtNobits) {
            const auto next = checked_add(cursor, encoded.bytes.size());
            if (!next) {
                return failure("object.size_limit", "ELF section layout exceeds host limits");
            }
            cursor = *next;
        }
    }
    const auto sectionTableAlignment = is64Bit ? std::size_t{8} : std::size_t{4};
    const auto sectionTableOffset = checked_align(cursor, sectionTableAlignment);
    const auto sectionHeaderCount = checked_add(orderedSections.size(), 1);
    const auto sectionTableSize = sectionHeaderCount
        ? checked_multiply(*sectionHeaderCount, sectionHeaderSize)
        : std::nullopt;
    const auto outputSize = sectionTableOffset && sectionTableSize
        ? checked_add(*sectionTableOffset, *sectionTableSize)
        : std::nullopt;
    if (!sectionTableOffset || !sectionHeaderCount || !sectionTableSize || !outputSize
        || *sectionHeaderCount > std::numeric_limits<std::uint16_t>::max()) {
        return failure("object.size_limit", "ELF section-header layout exceeds limits");
    }
    const bool extendedSectionCount = image.objectMetadata.elfExtendedSectionCount
        || *sectionHeaderCount >= 0xff00U;
    const bool extendedSectionNameIndex = image.objectMetadata.elfExtendedSectionNameIndex
        || sectionNameTableIndex >= 0xffffU;

    std::vector<std::byte> output(*outputSize, std::byte{0});
    for (const auto& encoded : encodedSections) {
        if (!encoded.bytes.empty()) {
            const auto destination = static_cast<std::size_t>(encoded.fileOffset);
            std::copy(encoded.bytes.begin(), encoded.bytes.end(), output.data() + destination);
        }
    }
    auto outputSpan = std::span<std::byte>{output};
    output[0] = std::byte{0x7f};
    output[1] = std::byte{'E'};
    output[2] = std::byte{'L'};
    output[3] = std::byte{'F'};
    output[4] = is64Bit ? std::byte{2} : std::byte{1};
    output[5] = std::byte{1};
    output[6] = std::byte{1};
    output[7] = static_cast<std::byte>(image.objectMetadata.osAbi);
    output[8] = static_cast<std::byte>(image.objectMetadata.abiVersion);
    put_u16(outputSpan, 16, 1);
    put_u16(outputSpan, 18, machine_for(image.architecture));
    put_u32(outputSpan, 20, 1);
    if (is64Bit) {
        put_u64(outputSpan, 40, *sectionTableOffset);
        put_u32(outputSpan, 48, static_cast<std::uint32_t>(image.objectMetadata.formatFlags));
        put_u16(outputSpan, 52, 64);
        put_u16(outputSpan, 58, 64);
        put_u16(outputSpan, 60, extendedSectionCount
                ? 0U
                : static_cast<std::uint16_t>(*sectionHeaderCount));
        put_u16(outputSpan, 62, extendedSectionNameIndex
                ? 0xffffU
                : static_cast<std::uint16_t>(sectionNameTableIndex));
    } else {
        put_u32(outputSpan, 32, static_cast<std::uint32_t>(*sectionTableOffset));
        put_u32(outputSpan, 36, static_cast<std::uint32_t>(image.objectMetadata.formatFlags));
        put_u16(outputSpan, 40, 52);
        put_u16(outputSpan, 46, 40);
        put_u16(outputSpan, 48, extendedSectionCount
                ? 0U
                : static_cast<std::uint16_t>(*sectionHeaderCount));
        put_u16(outputSpan, 50, extendedSectionNameIndex
                ? 0xffffU
                : static_cast<std::uint16_t>(sectionNameTableIndex));
    }
    if (extendedSectionCount) {
        if (is64Bit) {
            put_u64(outputSpan, *sectionTableOffset + 32U, *sectionHeaderCount);
        } else {
            put_u32(outputSpan, *sectionTableOffset + 20U,
                    static_cast<std::uint32_t>(*sectionHeaderCount));
        }
    }
    if (extendedSectionNameIndex) {
        const auto linkOffset = is64Bit ? std::size_t{40} : std::size_t{24};
        put_u32(outputSpan, *sectionTableOffset + linkOffset, sectionNameTableIndex);
    }

    for (const auto& encoded : encodedSections) {
        const auto index = static_cast<std::size_t>(encoded.source->formatIndex);
        const auto headerOffset = *sectionTableOffset + index * sectionHeaderSize;
        const auto& section = *encoded.source;
        std::uint32_t sectionLink = section.formatLink;
        std::uint32_t sectionInfo = section.formatInfo;
        if (section.formatType == shtSymtab || section.formatType == shtDynsym) {
            sectionInfo = 1;
            bool sawNonLocal = false;
            const auto symbols = symbolsByTable.find(section.formatIndex);
            if (symbols != symbolsByTable.end()) {
                for (const auto* symbol : symbols->second) {
                    if (symbol->formatStorage == 0) {
                        if (sawNonLocal) {
                            return failure(
                                "object.model_invalid", "ELF local symbols must precede globals");
                        }
                        sectionInfo = symbol->formatIndex + 1U;
                    } else {
                        sawNonLocal = true;
                    }
                }
            }
        } else if (section.formatType == shtGroup) {
            const auto association = associationsBySection.find(section.id.value());
            if (association == associationsBySection.end()
                || !association->second->signatureSymbol.has_value()) {
                return failure("object.model_invalid", "ELF group signature is missing");
            }
            const auto signature = symbolsById.find(
                association->second->signatureSymbol->value());
            if (signature == symbolsById.end()) {
                return failure("object.model_invalid", "ELF group signature symbol is missing");
            }
            sectionLink = signature->second->formatTableIndex;
            sectionInfo = signature->second->formatIndex;
        }
        put_u32(outputSpan, headerOffset, encoded.nameOffset);
        put_u32(outputSpan, headerOffset + 4, static_cast<std::uint32_t>(section.formatType));
        if (is64Bit) {
            put_u64(outputSpan, headerOffset + 8, section.formatFlags);
            put_u64(outputSpan, headerOffset + 16, section.address.value);
            put_u64(outputSpan, headerOffset + 24, encoded.fileOffset);
            put_u64(outputSpan, headerOffset + 32, encoded.logicalSize);
            put_u32(outputSpan, headerOffset + 40, sectionLink);
            put_u32(outputSpan, headerOffset + 44, sectionInfo);
            put_u64(outputSpan, headerOffset + 48, section.alignment);
            put_u64(outputSpan, headerOffset + 56, section.formatEntrySize);
        } else {
            put_u32(outputSpan, headerOffset + 8, static_cast<std::uint32_t>(section.formatFlags));
            put_u32(outputSpan, headerOffset + 12, static_cast<std::uint32_t>(section.address.value));
            put_u32(outputSpan, headerOffset + 16, static_cast<std::uint32_t>(encoded.fileOffset));
            put_u32(outputSpan, headerOffset + 20, static_cast<std::uint32_t>(encoded.logicalSize));
            put_u32(outputSpan, headerOffset + 24, sectionLink);
            put_u32(outputSpan, headerOffset + 28, sectionInfo);
            put_u32(outputSpan, headerOffset + 32, static_cast<std::uint32_t>(section.alignment));
            put_u32(outputSpan, headerOffset + 36,
                    static_cast<std::uint32_t>(section.formatEntrySize));
        }
    }
    return Result<std::vector<std::byte>, Diagnostic>::success(std::move(output));
}

} // namespace binobf::formats::detail

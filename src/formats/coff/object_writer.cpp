#include "../object_writer_internal.hpp"

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

constexpr std::size_t coffHeaderSize = 20;
constexpr std::size_t sectionHeaderSize = 40;
constexpr std::size_t symbolEntrySize = 18;
constexpr std::size_t relocationEntrySize = 10;

struct EncodedSection {
    const Section* source{nullptr};
    std::vector<const Relocation*> relocations;
    std::uint32_t rawOffset{0};
    std::uint32_t relocationOffset{0};
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

auto to_u32(std::size_t value) noexcept -> std::optional<std::uint32_t> {
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(value);
}

void put_u16(std::span<std::byte> output, std::size_t offset, std::uint16_t value) {
    output[offset] = static_cast<std::byte>(value & 0xffU);
    output[offset + 1] = static_cast<std::byte>((value >> 8U) & 0xffU);
}

void put_i16(std::span<std::byte> output, std::size_t offset, std::int16_t value) {
    put_u16(output, offset, std::bit_cast<std::uint16_t>(value));
}

void put_u32(std::span<std::byte> output, std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        output[offset + index] = static_cast<std::byte>(
            (value >> static_cast<unsigned int>(index * 8U)) & 0xffU);
    }
}

auto machine_for(Architecture architecture) noexcept -> std::uint16_t {
    switch (architecture) {
    case Architecture::X86: return 0x014c;
    case Architecture::X86_64: return 0x8664;
    case Architecture::ARM64: return 0xaa64;
    case Architecture::Unknown: return 0;
    }
    return 0;
}

auto append_string(std::vector<std::byte>& table, const std::string& value)
    -> std::optional<std::uint32_t> {
    if (table.size() > std::numeric_limits<std::uint32_t>::max()) {
        return std::nullopt;
    }
    const auto offset = static_cast<std::uint32_t>(table.size());
    const auto withValue = checked_add(table.size(), value.size());
    const auto terminated = withValue ? checked_add(*withValue, 1) : std::nullopt;
    if (!terminated || *terminated > std::numeric_limits<std::uint32_t>::max()) {
        return std::nullopt;
    }
    table.reserve(*terminated);
    for (const char character : value) {
        table.push_back(static_cast<std::byte>(character));
    }
    table.push_back(std::byte{0});
    return offset;
}

void put_inline_name(std::span<std::byte> output, std::size_t offset, const std::string& name) {
    for (std::size_t index = 0; index < name.size(); ++index) {
        output[offset + index] = static_cast<std::byte>(name[index]);
    }
}

auto decimal_name(std::uint32_t offset) -> std::optional<std::string> {
    const auto encoded = '/' + std::to_string(offset);
    return encoded.size() <= 8 ? std::optional{encoded} : std::nullopt;
}

} // namespace

auto write_coff_object(const BinaryImage& image)
    -> Result<std::vector<std::byte>, Diagnostic> {
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
            return failure("object.model_invalid", "COFF section indices must be contiguous");
        }
    }

    std::vector<const Symbol*> orderedSymbols;
    orderedSymbols.reserve(image.symbols.size());
    std::unordered_map<std::uint64_t, const Symbol*> symbolsById;
    for (const auto& symbol : image.symbols) {
        orderedSymbols.push_back(&symbol);
        symbolsById.emplace(symbol.id.value(), &symbol);
    }
    std::sort(orderedSymbols.begin(), orderedSymbols.end(), [](const auto* left, const auto* right) {
        return left->formatIndex < right->formatIndex;
    });

    std::size_t rawSymbolCount = 0;
    for (const auto* symbol : orderedSymbols) {
        if (symbol->formatIndex != rawSymbolCount) {
            return failure(
                "object.model_invalid",
                "COFF raw symbol indices must be covered by primary or auxiliary records");
        }
        const auto auxiliaryCount = symbol->auxiliaryData.size() / symbolEntrySize;
        const auto recordCount = checked_add(auxiliaryCount, 1);
        const auto next = recordCount ? checked_add(rawSymbolCount, *recordCount) : std::nullopt;
        if (!next || *next > std::numeric_limits<std::uint32_t>::max()) {
            return failure("object.size_limit", "COFF symbol table exceeds 32-bit entry count");
        }
        rawSymbolCount = *next;
    }

    std::vector<std::byte> stringTable(4, std::byte{0});
    std::unordered_map<std::uint32_t, std::uint32_t> sectionNameOffsets;
    std::unordered_map<std::uint64_t, std::uint32_t> symbolNameOffsets;
    for (const auto* section : orderedSections) {
        if (section->name.size() > 8) {
            const auto offset = append_string(stringTable, section->name);
            if (!offset || !decimal_name(*offset)) {
                return failure("object.size_limit", "COFF long section-name offset exceeds 8 bytes");
            }
            sectionNameOffsets.emplace(section->formatIndex, *offset);
        }
    }
    for (const auto* symbol : orderedSymbols) {
        if (symbol->name.size() > 8) {
            const auto offset = append_string(stringTable, symbol->name);
            if (!offset) {
                return failure("object.size_limit", "COFF symbol string table exceeds 32-bit offsets");
            }
            symbolNameOffsets.emplace(symbol->id.value(), *offset);
        }
    }
    put_u32(std::span<std::byte>{stringTable}, 0, static_cast<std::uint32_t>(stringTable.size()));

    std::unordered_map<std::uint32_t, std::vector<const Relocation*>> relocationsBySection;
    for (const auto& relocation : image.relocations) {
        relocationsBySection[relocation.formatTableIndex].push_back(&relocation);
    }
    for (auto& [sectionIndex, relocations] : relocationsBySection) {
        static_cast<void>(sectionIndex);
        std::sort(relocations.begin(), relocations.end(), [](const auto* left, const auto* right) {
            return left->formatIndex < right->formatIndex;
        });
    }

    const auto sectionTableSize = checked_multiply(orderedSections.size(), sectionHeaderSize);
    auto cursor = sectionTableSize ? checked_add(coffHeaderSize, *sectionTableSize) : std::nullopt;
    if (!cursor) {
        return failure("object.size_limit", "COFF section-header layout overflows");
    }
    std::vector<EncodedSection> encodedSections;
    encodedSections.reserve(orderedSections.size());
    for (const auto* section : orderedSections) {
        EncodedSection encoded;
        encoded.source = section;
        const auto relocations = relocationsBySection.find(section->formatIndex);
        if (relocations != relocationsBySection.end()) {
            encoded.relocations = relocations->second;
        }
        if (!section->contents.empty()) {
            const auto alignment = static_cast<std::size_t>(section->alignment);
            cursor = checked_align(*cursor, alignment);
            if (!cursor || !to_u32(*cursor)) {
                return failure("object.size_limit", "COFF section data offset exceeds 32 bits");
            }
            encoded.rawOffset = *to_u32(*cursor);
            cursor = checked_add(*cursor, section->contents.size());
            if (!cursor) {
                return failure("object.size_limit", "COFF section data layout overflows");
            }
        }
        encodedSections.push_back(std::move(encoded));
    }
    for (auto& encoded : encodedSections) {
        if (encoded.relocations.empty()) {
            continue;
        }
        cursor = checked_align(*cursor, 4);
        if (!cursor || !to_u32(*cursor)) {
            return failure("object.size_limit", "COFF relocation offset exceeds 32 bits");
        }
        encoded.relocationOffset = *to_u32(*cursor);
        const auto relocationSize = checked_multiply(
            encoded.relocations.size(), relocationEntrySize);
        cursor = relocationSize ? checked_add(*cursor, *relocationSize) : std::nullopt;
        if (!cursor) {
            return failure("object.size_limit", "COFF relocation layout overflows");
        }
    }
    cursor = checked_align(*cursor, 4);
    if (!cursor || !to_u32(*cursor)) {
        return failure("object.size_limit", "COFF symbol-table offset exceeds 32 bits");
    }
    const auto symbolTableOffset = *to_u32(*cursor);
    const auto symbolTableSize = checked_multiply(rawSymbolCount, symbolEntrySize);
    cursor = symbolTableSize ? checked_add(*cursor, *symbolTableSize) : std::nullopt;
    cursor = cursor ? checked_add(*cursor, stringTable.size()) : std::nullopt;
    if (!cursor || *cursor > std::numeric_limits<std::uint32_t>::max()) {
        return failure("object.size_limit", "COFF output exceeds 32-bit file offsets");
    }

    std::vector<std::byte> output(*cursor, std::byte{0});
    auto outputSpan = std::span<std::byte>{output};
    put_u16(outputSpan, 0, machine_for(image.architecture));
    put_u16(outputSpan, 2, static_cast<std::uint16_t>(orderedSections.size()));
    put_u32(outputSpan, 4, 0);
    put_u32(outputSpan, 8,
            rawSymbolCount == 0 && stringTable.size() == 4 ? 0 : symbolTableOffset);
    put_u32(outputSpan, 12, static_cast<std::uint32_t>(rawSymbolCount));
    put_u16(outputSpan, 16, 0);
    put_u16(outputSpan, 18,
            static_cast<std::uint16_t>(image.objectMetadata.characteristics));

    for (std::size_t position = 0; position < encodedSections.size(); ++position) {
        const auto& encoded = encodedSections[position];
        const auto& section = *encoded.source;
        const auto headerOffset = coffHeaderSize + position * sectionHeaderSize;
        if (section.name.size() <= 8) {
            put_inline_name(outputSpan, headerOffset, section.name);
        } else {
            const auto name = decimal_name(sectionNameOffsets.at(section.formatIndex));
            if (!name) {
                return failure("object.size_limit", "COFF section-name encoding is too long");
            }
            put_inline_name(outputSpan, headerOffset, *name);
        }
        const auto rawSize = static_cast<std::uint32_t>(section.contents.size());
        const auto virtualSize = section.logicalSize == rawSize
            ? 0U
            : static_cast<std::uint32_t>(section.logicalSize);
        put_u32(outputSpan, headerOffset + 8, virtualSize);
        put_u32(outputSpan, headerOffset + 16, rawSize);
        put_u32(outputSpan, headerOffset + 20, encoded.rawOffset);
        put_u32(outputSpan, headerOffset + 24, encoded.relocationOffset);
        put_u16(outputSpan, headerOffset + 32,
                static_cast<std::uint16_t>(encoded.relocations.size()));
        put_u32(outputSpan, headerOffset + 36,
                static_cast<std::uint32_t>(section.formatFlags));
        if (!section.contents.empty()) {
            std::copy(
                section.contents.begin(), section.contents.end(),
                output.data() + encoded.rawOffset);
        }
        for (std::size_t index = 0; index < encoded.relocations.size(); ++index) {
            const auto* relocation = encoded.relocations[index];
            const auto entryOffset = static_cast<std::size_t>(encoded.relocationOffset)
                + index * relocationEntrySize;
            put_u32(outputSpan, entryOffset, static_cast<std::uint32_t>(relocation->offset));
            put_u32(outputSpan, entryOffset + 4,
                    symbolsById.at(relocation->targetSymbol->value())->formatIndex);
            put_u16(outputSpan, entryOffset + 8,
                    static_cast<std::uint16_t>(relocation->rawType));
        }
    }

    for (const auto* symbol : orderedSymbols) {
        const auto entryOffset = static_cast<std::size_t>(symbolTableOffset)
            + static_cast<std::size_t>(symbol->formatIndex) * symbolEntrySize;
        if (symbol->name.size() <= 8) {
            put_inline_name(outputSpan, entryOffset, symbol->name);
        } else {
            put_u32(outputSpan, entryOffset, 0);
            put_u32(outputSpan, entryOffset + 4, symbolNameOffsets.at(symbol->id.value()));
        }
        put_u32(outputSpan, entryOffset + 8, static_cast<std::uint32_t>(symbol->address.value));
        put_i16(outputSpan, entryOffset + 12,
                static_cast<std::int16_t>(symbol->formatSectionIndex));
        put_u16(outputSpan, entryOffset + 14, static_cast<std::uint16_t>(symbol->formatType));
        output[entryOffset + 16] = static_cast<std::byte>(symbol->formatStorage);
        output[entryOffset + 17] = static_cast<std::byte>(
            symbol->auxiliaryData.size() / symbolEntrySize);
        if (!symbol->auxiliaryData.empty()) {
            std::copy(
                symbol->auxiliaryData.begin(), symbol->auxiliaryData.end(),
                output.data() + entryOffset + symbolEntrySize);
        }
    }
    const auto stringOffset = static_cast<std::size_t>(symbolTableOffset) + *symbolTableSize;
    std::copy(stringTable.begin(), stringTable.end(), output.data() + stringOffset);
    return Result<std::vector<std::byte>, Diagnostic>::success(std::move(output));
}

} // namespace binobf::formats::detail

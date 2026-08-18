#include "../formats/object_writer_internal.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace binobf::formats::detail {
namespace {

constexpr std::size_t maximumSectionCount = 16'384;
constexpr std::size_t maximumSymbolCount = 1'000'000;
constexpr std::size_t maximumRelocationCount = 4'000'000;
constexpr std::uint64_t maximumCoffValue = std::numeric_limits<std::uint32_t>::max();

auto invalid(std::string message) -> std::optional<Diagnostic> {
    return Diagnostic{
        DiagnosticSeverity::Error, "object.model_invalid", std::move(message)};
}

auto size_limit(std::string message) -> std::optional<Diagnostic> {
    return Diagnostic{
        DiagnosticSeverity::Error, "object.size_limit", std::move(message)};
}

auto pair_key(std::uint32_t table, std::uint32_t index) noexcept -> std::uint64_t {
    return (static_cast<std::uint64_t>(table) << 32U) | index;
}

auto is_power_of_two(std::uint64_t value) noexcept -> bool {
    return value != 0 && (value & (value - 1)) == 0;
}

auto supports_architecture(BinaryFormat format, Architecture architecture) noexcept -> bool {
    if (format == BinaryFormat::ELF) {
        return architecture == Architecture::X86 || architecture == Architecture::X86_64
            || architecture == Architecture::ARM64;
    }
    return architecture == Architecture::X86 || architecture == Architecture::X86_64
        || architecture == Architecture::ARM64;
}

} // namespace

auto validate_object_model(const BinaryImage& image) -> std::optional<Diagnostic> {
    if (image.type != BinaryType::RelocatableObject) {
        return invalid("object model is not a relocatable object");
    }
    if (!supports_architecture(image.format, image.architecture)) {
        return invalid("object architecture is unsupported by the selected format");
    }
    if (image.sections.empty()) {
        return invalid("object model has no sections");
    }
    if (image.sections.size() > maximumSectionCount
        || image.symbols.size() > maximumSymbolCount
        || image.relocations.size() > maximumRelocationCount) {
        return size_limit("object entity count exceeds the supported limit");
    }

    std::unordered_set<std::uint64_t> entityIds;
    std::unordered_set<std::uint32_t> sectionIndices;
    std::unordered_map<std::uint64_t, const Section*> sectionsById;
    std::unordered_map<std::uint32_t, const Section*> sectionsByIndex;
    std::size_t sectionNameTableCount = 0;
    for (const auto& section : image.sections) {
        if (!section.id.valid() || !entityIds.insert(section.id.value()).second) {
            return invalid("section entity ID is invalid or duplicated");
        }
        if (section.formatIndex == 0 || !sectionIndices.insert(section.formatIndex).second) {
            return invalid("section format index is zero or duplicated");
        }
        if (!is_power_of_two(section.alignment)) {
            return invalid("section alignment is not a nonzero power of two");
        }
        if (section.name.find('\0') != std::string::npos) {
            return invalid("section name contains an embedded null byte");
        }
        if (section.contents.size() > section.logicalSize) {
            return invalid("section contents exceed its logical size");
        }
        if (section.isSectionNameTable) {
            ++sectionNameTableCount;
        }
        sectionsById.emplace(section.id.value(), &section);
        sectionsByIndex.emplace(section.formatIndex, &section);
        if (image.format == BinaryFormat::COFF) {
            if (section.logicalSize > maximumCoffValue
                || section.contents.size() > maximumCoffValue
                || section.formatFlags > maximumCoffValue) {
                return size_limit("COFF section field exceeds 32-bit encoding");
            }
            if (section.formatType != 0 || section.formatLink != 0
                || section.formatInfo != 0 || section.formatEntrySize != 0) {
                return invalid("COFF section contains unsupported foreign metadata");
            }
        } else if (image.architecture == Architecture::X86
            && (section.address.value > maximumCoffValue
                || section.logicalSize > maximumCoffValue
                || section.contents.size() > maximumCoffValue
                || section.formatFlags > maximumCoffValue
                || section.formatEntrySize > maximumCoffValue)) {
            return size_limit("ELF32 section field exceeds 32-bit encoding");
        } else if (image.format == BinaryFormat::ELF
            && section.formatType > maximumCoffValue) {
            return size_limit("ELF section type exceeds 32-bit encoding");
        }
    }

    if (image.format == BinaryFormat::ELF) {
        if (sectionNameTableCount != 1) {
            return invalid("ELF object must identify exactly one section-name table");
        }
        if (image.objectMetadata.formatFlags > maximumCoffValue) {
            return size_limit("ELF header flags exceed 32-bit encoding");
        }
        for (const auto& section : image.sections) {
            if (section.formatIndex >= 0xff00U) {
                return size_limit("ELF section index requires unsupported extended numbering");
            }
            if (section.isSectionNameTable && section.formatType != 3) {
                return invalid("ELF section-name table is not a string table");
            }
            if (section.formatType == 2 || section.formatType == 11) {
                const auto linked = sectionsByIndex.find(section.formatLink);
                if (linked == sectionsByIndex.end() || linked->second->formatType != 3) {
                    return invalid("ELF symbol table has no string-table owner");
                }
            } else if (section.formatType == 4 || section.formatType == 9) {
                const auto symbols = sectionsByIndex.find(section.formatLink);
                const auto target = sectionsByIndex.find(section.formatInfo);
                if (symbols == sectionsByIndex.end()
                    || (symbols->second->formatType != 2 && symbols->second->formatType != 11)
                    || target == sectionsByIndex.end()) {
                    return invalid("ELF relocation table has invalid link or target metadata");
                }
            }
        }
    } else {
        if (image.objectMetadata.characteristics
            > std::numeric_limits<std::uint16_t>::max()) {
            return size_limit("COFF characteristics exceed 16-bit encoding");
        }
        if (image.sections.size() > std::numeric_limits<std::uint16_t>::max()) {
            return size_limit("COFF section count exceeds the standard header limit");
        }
        if (sectionNameTableCount != 0) {
            return invalid("COFF object cannot contain an ELF section-name-table marker");
        }
        for (const auto& [index, section] : sectionsByIndex) {
            static_cast<void>(section);
            if (index > image.sections.size()) {
                return invalid("COFF section indices are not contiguous");
            }
        }
    }

    std::unordered_set<std::uint64_t> symbolIndices;
    std::unordered_map<std::uint64_t, const Symbol*> symbolsById;
    for (const auto& symbol : image.symbols) {
        if (!symbol.id.valid() || !entityIds.insert(symbol.id.value()).second) {
            return invalid("symbol entity ID is invalid or duplicated");
        }
        if (!symbolIndices.insert(pair_key(symbol.formatTableIndex, symbol.formatIndex)).second) {
            return invalid("symbol table index is duplicated");
        }
        if (symbol.name.find('\0') != std::string::npos) {
            return invalid("symbol name contains an embedded null byte");
        }
        const Section* referencedSection = nullptr;
        if (symbol.section.has_value()) {
            const auto found = sectionsById.find(symbol.section->value());
            if (found == sectionsById.end()) {
                return invalid("symbol references an unknown section entity");
            }
            referencedSection = found->second;
        }
        if (image.format == BinaryFormat::ELF) {
            const auto owner = sectionsByIndex.find(symbol.formatTableIndex);
            if (owner == sectionsByIndex.end()
                || (owner->second->formatType != 2 && owner->second->formatType != 11)) {
                return invalid("ELF symbol has no symbol-table owner");
            }
            if (symbol.formatIndex == 0 || symbol.formatType > 0x0fU
                || symbol.formatStorage > 0x0fU || !symbol.auxiliaryData.empty()
                || symbol.formatSectionIndex < 0 || symbol.formatSectionIndex > 0xffff) {
                return invalid("ELF symbol has invalid raw metadata");
            }
            if (referencedSection != nullptr
                && symbol.formatSectionIndex
                    != static_cast<std::int32_t>(referencedSection->formatIndex)) {
                return invalid("ELF symbol section metadata disagrees with its entity reference");
            }
            if (image.architecture == Architecture::X86
                && (symbol.address.value > maximumCoffValue
                    || symbol.size > maximumCoffValue)) {
                return size_limit("ELF32 symbol field exceeds 32-bit encoding");
            }
        } else {
            if (symbol.formatTableIndex != 0 || symbol.formatType > 0xffffU
                || symbol.formatOther != 0
                || symbol.auxiliaryData.size() % 18 != 0
                || symbol.auxiliaryData.size() / 18 > 0xffU
                || symbol.formatSectionIndex < std::numeric_limits<std::int16_t>::min()
                || symbol.formatSectionIndex > std::numeric_limits<std::int16_t>::max()) {
                return invalid("COFF symbol has invalid raw metadata");
            }
            if (referencedSection != nullptr
                && symbol.formatSectionIndex
                    != static_cast<std::int32_t>(referencedSection->formatIndex)) {
                return invalid("COFF symbol section metadata disagrees with its entity reference");
            }
            if (symbol.address.value > maximumCoffValue) {
                return size_limit("COFF symbol value exceeds 32-bit encoding");
            }
        }
        symbolsById.emplace(symbol.id.value(), &symbol);
    }

    std::unordered_set<std::uint64_t> relocationIndices;
    std::unordered_map<std::uint32_t, std::size_t> coffRelocationsPerSection;
    for (const auto& relocation : image.relocations) {
        if (!relocation.id.valid() || !entityIds.insert(relocation.id.value()).second) {
            return invalid("relocation entity ID is invalid or duplicated");
        }
        if (!relocationIndices.insert(
                pair_key(relocation.formatTableIndex, relocation.formatIndex)).second) {
            return invalid("relocation table index is duplicated");
        }
        const auto targetSection = sectionsById.find(relocation.section.value());
        if (targetSection == sectionsById.end()) {
            return invalid("relocation references an unknown target section");
        }
        const Symbol* targetSymbol = nullptr;
        if (relocation.targetSymbol.has_value()) {
            const auto found = symbolsById.find(relocation.targetSymbol->value());
            if (found == symbolsById.end()) {
                return invalid("relocation references an unknown symbol entity");
            }
            targetSymbol = found->second;
        }
        if (image.format == BinaryFormat::ELF) {
            const auto owner = sectionsByIndex.find(relocation.formatTableIndex);
            if (owner == sectionsByIndex.end()
                || (owner->second->formatType != 4 && owner->second->formatType != 9)
                || owner->second->formatInfo != targetSection->second->formatIndex) {
                return invalid("ELF relocation has no matching relocation-table owner");
            }
            if (targetSymbol != nullptr
                && targetSymbol->formatTableIndex != owner->second->formatLink) {
                return invalid("ELF relocation symbol belongs to a different symbol table");
            }
            if (image.architecture == Architecture::X86
                && (relocation.offset > maximumCoffValue || relocation.rawType > 0xffU
                    || relocation.addend < std::numeric_limits<std::int32_t>::min()
                    || relocation.addend > std::numeric_limits<std::int32_t>::max())) {
                return size_limit("ELF32 relocation field exceeds its encoding");
            }
            if (image.architecture != Architecture::X86
                && relocation.rawType > maximumCoffValue) {
                return size_limit("ELF64 relocation type exceeds 32-bit encoding");
            }
        } else {
            if (relocation.formatTableIndex != targetSection->second->formatIndex
                || relocation.offset > maximumCoffValue || relocation.rawType > 0xffffU
                || targetSymbol == nullptr) {
                return invalid("COFF relocation has invalid raw metadata or references");
            }
            auto& count = coffRelocationsPerSection[relocation.formatTableIndex];
            ++count;
            if (count > std::numeric_limits<std::uint16_t>::max()) {
                return size_limit("COFF relocation count requires unsupported overflow encoding");
            }
        }
    }
    return std::nullopt;
}

} // namespace binobf::formats::detail

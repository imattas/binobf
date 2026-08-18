#include "../formats/object_writer_internal.hpp"

#include <binobf/verify/object_ownership.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace binobf {
namespace {

auto ownership_failure(
    std::string code,
    std::string message,
    std::optional<EntityId> entity = std::nullopt) -> Result<std::size_t, Diagnostic> {
    if (entity.has_value()) {
        message += " (entity " + std::to_string(entity->value()) + ')';
    }
    return Result<std::size_t, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

auto ownership_power_of_two(std::uint64_t value) noexcept -> bool {
    return value != 0U && (value & (value - 1U)) == 0U;
}

} // namespace

auto validate_object_ownership(const BinaryImage& image)
    -> Result<std::size_t, Diagnostic> {
    std::unordered_map<std::uint64_t, const Section*> sections;
    std::unordered_map<std::uint64_t, const Symbol*> symbols;
    std::unordered_map<std::uint64_t, const Relocation*> relocations;
    std::unordered_map<std::uint64_t, const Function*> functions;
    std::unordered_set<std::uint64_t> entityIds;
    for (const auto& section : image.sections) {
        if (!section.id.valid() || !entityIds.insert(section.id.value()).second) {
            return ownership_failure(
                "object.ownership_entity",
                "ownership model contains an invalid or duplicate entity ID",
                section.id);
        }
        sections.emplace(section.id.value(), &section);
    }
    for (const auto& symbol : image.symbols) {
        if (!symbol.id.valid() || !entityIds.insert(symbol.id.value()).second) {
            return ownership_failure(
                "object.ownership_entity",
                "ownership model contains an invalid or duplicate entity ID",
                symbol.id);
        }
        symbols.emplace(symbol.id.value(), &symbol);
    }
    for (const auto& relocation : image.relocations) {
        if (!relocation.id.valid() || !entityIds.insert(relocation.id.value()).second) {
            return ownership_failure(
                "object.ownership_entity",
                "ownership model contains an invalid or duplicate entity ID",
                relocation.id);
        }
        relocations.emplace(relocation.id.value(), &relocation);
    }
    for (const auto& function : image.functions) {
        if (!function.id.valid() || !entityIds.insert(function.id.value()).second) {
            return ownership_failure(
                "object.ownership_entity",
                "ownership model contains an invalid or duplicate entity ID",
                function.id);
        }
        functions.emplace(function.id.value(), &function);
    }
    for (const auto& unwind : image.unwindInfo) {
        if (!unwind.id.valid() || !entityIds.insert(unwind.id.value()).second) {
            return ownership_failure(
                "object.ownership_entity",
                "ownership model contains an invalid or duplicate entity ID",
                unwind.id);
        }
    }

    std::size_t validated = 0;
    for (const auto& symbol : image.symbols) {
        if (!symbol.definition.has_value()) {
            if (symbol.tlsModel != TlsModel::Unknown
                && symbol.tlsModel != TlsModel::None
                && symbol.kind != SymbolKind::Tls) {
                return ownership_failure(
                    "object.ownership_tls_model",
                    "TLS model belongs to a non-TLS symbol",
                    symbol.id);
            }
            continue;
        }
        ++validated;
        const auto ownedSection = symbol.section.has_value()
            ? sections.find(symbol.section->value())
            : sections.end();
        if (symbol.section.has_value() && ownedSection == sections.end()) {
            return ownership_failure(
                "object.ownership_symbol_definition",
                "normalized symbol references an absent section",
                symbol.id);
        }
        switch (*symbol.definition) {
        case SymbolDefinitionKind::Undefined:
            if (symbol.defined || symbol.section.has_value() || symbol.commonAlignment != 0U
                || symbol.formatSectionIndex != 0) {
                return ownership_failure(
                    "object.ownership_symbol_definition",
                    "undefined symbol disagrees with raw definition fields",
                    symbol.id);
            }
            break;
        case SymbolDefinitionKind::SectionRelative:
            if (!symbol.defined || ownedSection == sections.end()
                || symbol.commonAlignment != 0U) {
                return ownership_failure(
                    "object.ownership_symbol_definition",
                    "section-relative symbol has incomplete ownership",
                    symbol.id);
            }
            if (symbol.formatSectionIndex != 0xffff
                && symbol.formatSectionIndex != static_cast<std::int32_t>(
                    ownedSection->second->formatIndex)) {
                return ownership_failure(
                    "object.ownership_symbol_definition",
                    "section-relative symbol disagrees with its raw section index",
                    symbol.id);
            }
            break;
        case SymbolDefinitionKind::Absolute: {
            const auto expected = image.format == BinaryFormat::ELF ? 0xfff1 : -1;
            if (!symbol.defined || symbol.section.has_value() || symbol.commonAlignment != 0U
                || symbol.formatSectionIndex != expected) {
                return ownership_failure(
                    "object.ownership_symbol_definition",
                    "absolute symbol disagrees with raw definition fields",
                    symbol.id);
            }
            break;
        }
        case SymbolDefinitionKind::Common: {
            const auto expected = image.format == BinaryFormat::ELF ? 0xfff2 : 0;
            if (!symbol.defined || symbol.section.has_value()
                || !ownership_power_of_two(symbol.commonAlignment)
                || symbol.formatSectionIndex != expected
                || (image.format == BinaryFormat::ELF
                    && symbol.address.value != symbol.commonAlignment)) {
                return ownership_failure(
                    "object.ownership_symbol_definition",
                    "common symbol requires a nonzero power-of-two alignment",
                    symbol.id);
            }
            break;
        }
        }
        if (symbol.tlsModel != TlsModel::Unknown
            && symbol.tlsModel != TlsModel::None
            && symbol.kind != SymbolKind::Tls) {
            return ownership_failure(
                "object.ownership_tls_model",
                "TLS model belongs to a non-TLS symbol",
                symbol.id);
        }
    }

    std::unordered_map<std::uint64_t, const SectionAssociation*> associations;
    std::unordered_set<std::uint64_t> associatedMembership;
    std::unordered_map<std::uint64_t, std::uint64_t> parents;
    for (const auto& association : image.sectionAssociations) {
        ++validated;
        if (sections.find(association.section.value()) == sections.end()
            || !associations.emplace(association.section.value(), &association).second) {
            return ownership_failure(
                "object.ownership_association",
                "section association has an absent or duplicate owner",
                association.section);
        }
        if (!associatedMembership.insert(association.section.value()).second) {
            return ownership_failure(
                "object.ownership_duplicate_membership",
                "section belongs to more than one association",
                association.section);
        }
        for (const auto member : association.members) {
            if (sections.find(member.value()) == sections.end()) {
                return ownership_failure(
                    "object.ownership_association",
                    "association member section is absent",
                    member);
            }
            if (!associatedMembership.insert(member.value()).second) {
                return ownership_failure(
                    "object.ownership_duplicate_membership",
                    "section belongs to more than one association",
                    member);
            }
        }
        if (association.kind != SectionAssociationKind::Ordinary) {
            if (!association.signatureSymbol.has_value()
                || symbols.find(association.signatureSymbol->value()) == symbols.end()) {
                return ownership_failure(
                    "object.ownership_signature",
                    "COMDAT or group association has no signature symbol",
                    association.section);
            }
        }
        if (association.parentSection.has_value()) {
            if (sections.find(association.parentSection->value()) == sections.end()) {
                return ownership_failure(
                    "object.ownership_association",
                    "association parent section is absent",
                    association.section);
            }
            parents.emplace(
                association.section.value(), association.parentSection->value());
        }
    }

    for (const auto& [start, association] : associations) {
        static_cast<void>(association);
        std::unordered_set<std::uint64_t> path;
        auto current = start;
        while (true) {
            if (!path.insert(current).second) {
                return ownership_failure(
                    "object.ownership_association_cycle",
                    "section association parent graph contains a cycle",
                    EntityId{current});
            }
            const auto parent = parents.find(current);
            if (parent == parents.end()) break;
            current = parent->second;
        }
    }

    for (const auto& association : image.sectionAssociations) {
        switch (association.kind) {
        case SectionAssociationKind::Ordinary:
            if (association.coffSelection != CoffComdatSelection::None
                || association.signatureSymbol.has_value()
                || association.parentSection.has_value() || !association.members.empty()) {
                return ownership_failure(
                    "object.ownership_association",
                    "ordinary section association contains format-specific ownership",
                    association.section);
            }
            break;
        case SectionAssociationKind::CoffComdat:
            if (image.format != BinaryFormat::COFF
                || association.coffSelection == CoffComdatSelection::None
                || association.coffSelection == CoffComdatSelection::Associative
                || association.parentSection.has_value() || !association.members.empty()) {
                return ownership_failure(
                    "object.ownership_association",
                    "COFF COMDAT association has invalid selection or membership",
                    association.section);
            }
            break;
        case SectionAssociationKind::CoffAssociativeComdat: {
            const auto parent = association.parentSection.has_value()
                ? associations.find(association.parentSection->value())
                : associations.end();
            if (image.format != BinaryFormat::COFF
                || association.coffSelection != CoffComdatSelection::Associative
                || parent == associations.end()
                || parent->second->kind != SectionAssociationKind::CoffComdat
                || !association.members.empty()) {
                return ownership_failure(
                    "object.ownership_association",
                    "associative COMDAT has no valid primary COMDAT owner",
                    association.section);
            }
            break;
        }
        case SectionAssociationKind::ElfGroup: {
            const auto owner = sections.find(association.section.value());
            if (image.format != BinaryFormat::ELF
                || owner == sections.end() || owner->second->formatType != 17U
                || association.coffSelection != CoffComdatSelection::None
                || association.parentSection.has_value() || association.members.empty()) {
                return ownership_failure(
                    "object.ownership_association",
                    "ELF group has invalid format-specific ownership",
                    association.section);
            }
            break;
        }
        }
    }

    std::unordered_set<std::uint64_t> relocationTableSections;
    std::unordered_map<std::uint64_t, const RelocationTableEncoding*>
        relocationTablesBySection;
    for (const auto& encoding : image.relocationTableEncodings) {
        ++validated;
        if (sections.find(encoding.section.value()) == sections.end()
            || !relocationTableSections.insert(encoding.section.value()).second
            || (encoding.coffOverflow && image.format != BinaryFormat::COFF)) {
            return ownership_failure(
                "object.ownership_relocation_table",
                "relocation-table encoding has no unique target section",
                encoding.section);
        }
        const auto actualCount = static_cast<std::uint64_t>(std::count_if(
            image.relocations.begin(), image.relocations.end(),
            [&](const auto& relocation) { return relocation.section == encoding.section; }));
        if (encoding.declaredCount != actualCount
            || (encoding.coffOverflow
                && encoding.declaredCount <= std::numeric_limits<std::uint16_t>::max())) {
            return ownership_failure(
                "object.ownership_relocation_table",
                "relocation-table declared count disagrees with owned relocations",
                encoding.section);
        }
        relocationTablesBySection.emplace(encoding.section.value(), &encoding);
    }
    if (image.format == BinaryFormat::COFF) {
        for (const auto& section : image.sections) {
            const bool rawOverflow = (section.formatFlags & 0x01000000U) != 0U;
            const auto normalized = relocationTablesBySection.find(section.id.value());
            if (rawOverflow != (normalized != relocationTablesBySection.end()
                                && normalized->second->coffOverflow)) {
                return ownership_failure(
                    "object.ownership_relocation_table",
                    "COFF relocation-overflow flag disagrees with normalized ownership",
                    section.id);
            }
        }
    }

    std::unordered_map<std::uint64_t, std::unordered_set<std::uint32_t>> safeSehIndices;
    std::unordered_set<std::uint64_t> safeSehSymbols;
    for (const auto& entry : image.coffSafeSehEntries) {
        ++validated;
        const auto owner = sections.find(entry.section.value());
        const auto handler = symbols.find(entry.symbol.value());
        const auto byteOffset = static_cast<std::uint64_t>(entry.formatIndex) * 4U;
        if (image.format != BinaryFormat::COFF || owner == sections.end()
            || handler == symbols.end() || owner->second->name != ".sxdata"
            || byteOffset > owner->second->contents.size()
            || 4U > owner->second->contents.size() - byteOffset
            || !safeSehIndices[entry.section.value()].insert(entry.formatIndex).second
            || !safeSehSymbols.insert(entry.symbol.value()).second
            || handler->second->kind != SymbolKind::Function
            || !handler->second->defined) {
            return ownership_failure(
                "object.ownership_safeseh",
                "SafeSEH entry has no exact section or handler-symbol owner",
                entry.symbol);
        }
    }

    std::unordered_map<std::uint64_t, const ExtendedSectionIndex*> extendedBySymbol;
    for (const auto& extended : image.extendedSectionIndices) {
        ++validated;
        const auto symbol = symbols.find(extended.symbol.value());
        const auto indexSection = sections.find(extended.indexSection.value());
        const auto targetSection = sections.find(extended.section.value());
        if (image.format != BinaryFormat::ELF || symbol == symbols.end()
            || indexSection == sections.end() || targetSection == sections.end()
            || !extendedBySymbol.emplace(extended.symbol.value(), &extended).second
            || indexSection->second->formatType != 18U
            || indexSection->second->formatLink != symbol->second->formatTableIndex
            || symbol->second->formatSectionIndex != 0xffff
            || symbol->second->section != extended.section
            || extended.rawSectionIndex != targetSection->second->formatIndex) {
            return ownership_failure(
                "object.ownership_extended_index",
                "extended symbol section index has no exact companion ownership",
                extended.symbol);
        }
    }
    for (const auto& symbol : image.symbols) {
        if (symbol.definition == SymbolDefinitionKind::SectionRelative
            && symbol.formatSectionIndex == 0xffff
            && extendedBySymbol.find(symbol.id.value()) == extendedBySymbol.end()) {
            return ownership_failure(
                "object.ownership_extended_index",
                "SHN_XINDEX symbol has no companion index entry",
                symbol.id);
        }
    }

    struct CodeRange {
        EntityId section;
        std::uint64_t begin{0};
        std::uint64_t end{0};
        EntityId unwind;
    };
    std::vector<CodeRange> codeRanges;
    for (const auto& unwind : image.unwindInfo) {
        if (unwind.format == UnwindFormat::Unknown) continue;
        ++validated;
        const auto function = functions.find(unwind.function.value());
        const auto recordSection = sections.find(unwind.section.value());
        if (function == functions.end() || recordSection == sections.end()) {
            return ownership_failure(
                "object.ownership_unwind",
                "normalized unwind record has no function or section owner",
                unwind.id);
        }
        const auto codeSection = sections.find(function->second->section.value());
        const auto encodedSize = static_cast<std::uint64_t>(unwind.encoded.size());
        if (codeSection == sections.end() || encodedSize == 0U || unwind.codeSize == 0U
            || unwind.sectionOffset > recordSection->second->logicalSize
            || encodedSize > recordSection->second->logicalSize - unwind.sectionOffset
            || unwind.codeOffset > codeSection->second->logicalSize
            || unwind.codeSize > codeSection->second->logicalSize - unwind.codeOffset
            || (unwind.format == UnwindFormat::WindowsI386
                && image.format != BinaryFormat::COFF)
            || (unwind.format == UnwindFormat::DwarfCfi32
                && image.format != BinaryFormat::ELF)) {
            return ownership_failure(
                "object.ownership_unwind",
                "normalized unwind range or format is invalid",
                unwind.id);
        }
        std::unordered_set<std::uint64_t> ownedRelocations;
        for (const auto relocationId : unwind.relocations) {
            const auto relocation = relocations.find(relocationId.value());
            if (relocation == relocations.end()
                || !ownedRelocations.insert(relocationId.value()).second
                || relocation->second->section != unwind.section
                || relocation->second->offset < unwind.sectionOffset
                || relocation->second->offset >= unwind.sectionOffset + encodedSize) {
                return ownership_failure(
                    "object.ownership_unwind_relocation",
                    "unwind relocation lies outside its encoded owner record",
                    unwind.id);
            }
        }
        codeRanges.push_back(CodeRange{
            function->second->section,
            unwind.codeOffset,
            unwind.codeOffset + unwind.codeSize,
            unwind.id,
        });
    }
    std::ranges::sort(codeRanges, [](const auto& left, const auto& right) {
        if (left.section != right.section) return left.section < right.section;
        if (left.begin != right.begin) return left.begin < right.begin;
        return left.end < right.end;
    });
    for (std::size_t index = 1; index < codeRanges.size(); ++index) {
        if (codeRanges[index - 1U].section == codeRanges[index].section
            && codeRanges[index].begin < codeRanges[index - 1U].end) {
            return ownership_failure(
                "object.ownership_unwind_overlap",
                "normalized unwind code ranges overlap",
                codeRanges[index].unwind);
        }
    }

    return Result<std::size_t, Diagnostic>::success(validated);
}

} // namespace binobf

namespace binobf::formats::detail {
namespace {

constexpr std::size_t maximumSectionCount = 65'536;
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
    const bool coffUsesBigObj = image.format == BinaryFormat::COFF
        && (image.objectMetadata.coffBigObj
            || std::ranges::any_of(image.sections, [](const auto& section) {
                return section.formatIndex
                    > static_cast<std::uint32_t>(
                        std::numeric_limits<std::int16_t>::max());
            }));

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
        if (image.objectMetadata.coffBigObj) {
            return invalid("ELF object contains COFF bigobj metadata");
        }
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
        if (image.objectMetadata.elfExtendedSectionCount
            || image.objectMetadata.elfExtendedSectionNameIndex) {
            return invalid("COFF object contains ELF extended-numbering metadata");
        }
        if (image.objectMetadata.characteristics
            > std::numeric_limits<std::uint16_t>::max()) {
            return size_limit("COFF characteristics exceed 16-bit encoding");
        }
        if (!coffUsesBigObj
            && image.sections.size() > std::numeric_limits<std::uint16_t>::max()) {
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
                && symbol.formatSectionIndex != 0xffff
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
            const auto symbolEntrySize = coffUsesBigObj
                ? std::size_t{20}
                : std::size_t{18};
            if (symbol.formatTableIndex != 0 || symbol.formatType > 0xffffU
                || symbol.formatOther != 0
                || symbol.auxiliaryData.size() % symbolEntrySize != 0
                || symbol.auxiliaryData.size() / symbolEntrySize > 0xffU
                || (!coffUsesBigObj
                    && (symbol.formatSectionIndex
                            < std::numeric_limits<std::int16_t>::min()
                        || symbol.formatSectionIndex
                            > std::numeric_limits<std::int16_t>::max()))) {
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
        }
    }
    for (const auto& [formatSectionIndex, count] : coffRelocationsPerSection) {
        if (count <= std::numeric_limits<std::uint16_t>::max()) {
            continue;
        }
        const auto targetSection = std::find_if(
            image.sections.begin(), image.sections.end(), [&](const auto& section) {
                return section.formatIndex == formatSectionIndex;
            });
        const auto overflow = std::find_if(
            image.relocationTableEncodings.begin(),
            image.relocationTableEncodings.end(), [&](const auto& encoding) {
                return targetSection != image.sections.end()
                    && encoding.section == targetSection->id && encoding.coffOverflow
                    && encoding.declaredCount == count;
            });
        if (overflow == image.relocationTableEncodings.end()) {
            return invalid("COFF relocation count has no overflow-table ownership");
        }
    }
    const auto ownership = validate_object_ownership(image);
    if (!ownership.has_value()) {
        return ownership.error();
    }
    return std::nullopt;
}

} // namespace binobf::formats::detail

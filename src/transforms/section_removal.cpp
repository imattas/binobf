#include <binobf/transforms/baseline.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace binobf {
namespace {

auto failure(std::string message) -> Result<TransformResult, Diagnostic> {
    return Result<TransformResult, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error, "pass.unsafe_reference", std::move(message)});
}

auto remove_sections(
    TransformContext& context,
    BinaryImage& image,
    std::string_view passName,
    const std::function<bool(const Section&)>& selected)
    -> Result<TransformResult, Diagnostic> {
    std::unordered_set<std::uint64_t> removedIds;
    std::unordered_set<std::uint32_t> removedIndices;
    for (const auto& section : image.sections) {
        if (selected(section)) {
            removedIds.insert(section.id.value());
            removedIndices.insert(section.formatIndex);
        }
    }
    if (removedIds.empty()) {
        const PassStatistics statistics{
            .examined = image.sections.size(), .changed = 0, .skipped = image.sections.size()};
        std::vector<Diagnostic> diagnostics;
        diagnostics.emplace_back(
            DiagnosticSeverity::Info,
            "pass.no_matching_sections",
            std::string{passName} + " found no eligible sections");
        return Result<TransformResult, Diagnostic>::success(TransformResult{
            .changed = false,
            .statistics = statistics,
            .diagnostics = std::move(diagnostics)});
    }
    bool closureChanged = true;
    while (closureChanged) {
        closureChanged = false;
        if (image.format == BinaryFormat::ELF) {
            for (const auto& section : image.sections) {
                if ((section.formatType == 4 || section.formatType == 9)
                    && removedIndices.contains(section.formatInfo)
                    && removedIds.insert(section.id.value()).second) {
                    removedIndices.insert(section.formatIndex);
                    closureChanged = true;
                }
            }
        }
        const bool removesSymbols = std::any_of(
            image.symbols.begin(), image.symbols.end(), [&removedIds](const auto& symbol) {
                return symbol.section.has_value() && removedIds.contains(symbol.section->value());
            });
        if (removesSymbols) {
            for (const auto& section : image.sections) {
                if (section.name == ".llvm_addrsig"
                    && removedIds.insert(section.id.value()).second) {
                    removedIndices.insert(section.formatIndex);
                    closureChanged = true;
                }
            }
        }
    }
    if (image.format == BinaryFormat::ELF
        && std::any_of(image.sections.begin(), image.sections.end(), [](const auto& section) {
            return section.formatType == 17;
        })) {
        return failure("ELF section groups require index-aware rewriting before removal");
    }
    const PassStatistics statistics{
        .examined = image.sections.size(),
        .changed = removedIds.size(),
        .skipped = image.sections.size() - removedIds.size(),
    };
    std::unordered_set<std::uint64_t> removedSymbolIds;
    for (const auto& symbol : image.symbols) {
        if (symbol.section.has_value() && removedIds.contains(symbol.section->value())) {
            if (symbol.visibility == SymbolVisibility::External) {
                return failure("refusing to remove a section that defines an external symbol");
            }
            removedSymbolIds.insert(symbol.id.value());
        }
    }
    for (const auto& relocation : image.relocations) {
        if (!removedIds.contains(relocation.section.value())
            && relocation.targetSymbol.has_value()
            && removedSymbolIds.contains(relocation.targetSymbol->value())) {
            return failure("surviving relocation targets a symbol owned by a removed section");
        }
    }
    if (image.format == BinaryFormat::COFF && !removedSymbolIds.empty()) {
        for (const auto& symbol : image.symbols) {
            if (!removedSymbolIds.contains(symbol.id.value())
                && !symbol.auxiliaryData.empty()
                && symbol.kind != SymbolKind::Section && symbol.kind != SymbolKind::File) {
                return failure("opaque COFF auxiliary records may contain shifted symbol indices");
            }
        }
    }

    std::vector<const Section*> ordered;
    for (const auto& section : image.sections) {
        if (!removedIds.contains(section.id.value())) ordered.push_back(&section);
    }
    std::sort(ordered.begin(), ordered.end(), [](const auto* left, const auto* right) {
        return left->formatIndex < right->formatIndex;
    });
    std::unordered_map<std::uint32_t, std::uint32_t> sectionIndexMap;
    for (std::size_t index = 0; index < ordered.size(); ++index) {
        sectionIndexMap.emplace(ordered[index]->formatIndex, static_cast<std::uint32_t>(index + 1));
    }
    for (const auto& section : image.sections) {
        if (removedIds.contains(section.id.value())) continue;
        if (section.formatLink != 0 && removedIndices.contains(section.formatLink)) {
            return failure("surviving section links to a removed section");
        }
        if ((section.formatType == 4 || section.formatType == 9)
            && removedIndices.contains(section.formatInfo)) {
            return failure("surviving ELF relocation section targets a removed section");
        }
    }

    image.relocations.erase(std::remove_if(
        image.relocations.begin(), image.relocations.end(), [&removedIds](const auto& relocation) {
            return removedIds.contains(relocation.section.value());
        }), image.relocations.end());
    image.symbols.erase(std::remove_if(
        image.symbols.begin(), image.symbols.end(), [&removedSymbolIds](const auto& symbol) {
            return removedSymbolIds.contains(symbol.id.value());
        }), image.symbols.end());
    image.sections.erase(std::remove_if(
        image.sections.begin(), image.sections.end(), [&removedIds](const auto& section) {
            return removedIds.contains(section.id.value());
        }), image.sections.end());

    const auto transform = context.allocate_transform_id();
    std::unordered_map<std::uint64_t, std::uint32_t> newSectionById;
    for (auto& section : image.sections) {
        const auto oldIndex = section.formatIndex;
        section.formatIndex = sectionIndexMap.at(oldIndex);
        newSectionById.emplace(section.id.value(), section.formatIndex);
        if (section.formatLink != 0) section.formatLink = sectionIndexMap.at(section.formatLink);
        if (section.formatType == 4 || section.formatType == 9) {
            section.formatInfo = sectionIndexMap.at(section.formatInfo);
        }
        section.lineage.parents.push_back(TransformationRecord{
            .transform = transform, .source = section.id, .passName = std::string{passName}});
    }
    for (auto& symbol : image.symbols) {
        if (symbol.section.has_value()) {
            symbol.formatSectionIndex = static_cast<std::int32_t>(
                newSectionById.at(symbol.section->value()));
        }
        if (image.format == BinaryFormat::ELF) {
            symbol.formatTableIndex = sectionIndexMap.at(symbol.formatTableIndex);
        }
        symbol.lineage.parents.push_back(TransformationRecord{
            .transform = transform, .source = symbol.id, .passName = std::string{passName}});
    }
    if (image.format == BinaryFormat::ELF) {
        std::unordered_map<std::uint32_t, std::uint32_t> next;
        for (auto& symbol : image.symbols) symbol.formatIndex = ++next[symbol.formatTableIndex];
        for (auto& section : image.sections) {
            if (section.formatType == 2 || section.formatType == 11) {
                std::uint32_t firstGlobal = 1;
                for (const auto& symbol : image.symbols) {
                    if (symbol.formatTableIndex == section.formatIndex) {
                        if (symbol.formatStorage != 0) {
                            firstGlobal = symbol.formatIndex;
                            break;
                        }
                        firstGlobal = symbol.formatIndex + 1;
                    }
                }
                section.formatInfo = firstGlobal;
            }
        }
        std::unordered_map<std::uint32_t, std::uint32_t> relocationNext;
        for (auto& relocation : image.relocations) {
            relocation.formatTableIndex = sectionIndexMap.at(relocation.formatTableIndex);
            relocation.formatIndex = relocationNext[relocation.formatTableIndex]++;
        }
    } else {
        std::uint32_t nextSymbol = 0;
        for (auto& symbol : image.symbols) {
            symbol.formatIndex = nextSymbol;
            nextSymbol += 1U + static_cast<std::uint32_t>(symbol.auxiliaryData.size() / 18);
            if (symbol.kind == SymbolKind::Section && symbol.auxiliaryData.size() == 18
                && std::to_integer<std::uint8_t>(symbol.auxiliaryData[14]) == 5) {
                const auto oldAssociated = static_cast<std::uint16_t>(
                    std::to_integer<std::uint8_t>(symbol.auxiliaryData[12])
                    | (std::to_integer<std::uint8_t>(symbol.auxiliaryData[13]) << 8U));
                const auto mapped = sectionIndexMap.find(oldAssociated);
                if (mapped == sectionIndexMap.end()) {
                    return failure("associative COFF section references a removed section");
                }
                symbol.auxiliaryData[12] = static_cast<std::byte>(mapped->second & 0xffU);
                symbol.auxiliaryData[13] = static_cast<std::byte>((mapped->second >> 8U) & 0xffU);
            }
        }
        std::sort(image.relocations.begin(), image.relocations.end(), [&newSectionById](const auto& left, const auto& right) {
            const auto leftSection = newSectionById.at(left.section.value());
            const auto rightSection = newSectionById.at(right.section.value());
            return leftSection == rightSection ? left.formatIndex < right.formatIndex
                                               : leftSection < rightSection;
        });
        std::uint32_t nextRelocation = 0;
        for (auto& relocation : image.relocations) {
            relocation.formatTableIndex = newSectionById.at(relocation.section.value());
            relocation.formatIndex = nextRelocation++;
        }
    }
    std::vector<Diagnostic> diagnostics;
    diagnostics.emplace_back(
        DiagnosticSeverity::Info, "pass.sections_removed",
        std::string{passName} + " removed " + std::to_string(statistics.changed) + " sections");
    return Result<TransformResult, Diagnostic>::success(TransformResult{
        .changed = true, .statistics = statistics, .diagnostics = std::move(diagnostics)});
}

class SectionRemovalPass final : public TransformPass {
public:
    SectionRemovalPass(std::string name, std::function<bool(const Section&)> predicate)
        : name_(std::move(name)), predicate_(std::move(predicate)) {}
    auto name() const noexcept -> std::string_view override { return name_; }
    auto dependencies() const -> std::vector<std::string> override { return {}; }
    auto requirements() const -> PassRequirements override {
        return PassRequirements{.requiresFullRelocations = true,
            .formats = {BinaryFormat::COFF, BinaryFormat::ELF},
            .architectures = {Architecture::X86, Architecture::X86_64, Architecture::ARM64}};
    }
    auto supports(const TransformContext&, const BinaryImage& image) const -> bool override {
        return image.type == BinaryType::RelocatableObject
            && (image.format == BinaryFormat::COFF || image.format == BinaryFormat::ELF);
    }
    auto run(TransformContext& context, BinaryImage& image) const
        -> Result<TransformResult, Diagnostic> override {
        return remove_sections(context, image, name_, predicate_);
    }
private:
    std::string name_;
    std::function<bool(const Section&)> predicate_;
};

class StripLocalSymbolsPass final : public TransformPass {
public:
    auto name() const noexcept -> std::string_view override {
        return "strip-local-symbols";
    }
    auto dependencies() const -> std::vector<std::string> override { return {}; }
    auto requirements() const -> PassRequirements override {
        return PassRequirements{
            .requiresFullRelocations = true,
            .formats = {BinaryFormat::COFF, BinaryFormat::ELF},
            .architectures = {
                Architecture::X86, Architecture::X86_64, Architecture::ARM64}};
    }
    auto supports(const TransformContext&, const BinaryImage& image) const -> bool override {
        return image.type == BinaryType::RelocatableObject
            && (image.format == BinaryFormat::COFF || image.format == BinaryFormat::ELF);
    }

    auto run(TransformContext& context, BinaryImage& image) const
        -> Result<TransformResult, Diagnostic> override {
        std::unordered_set<std::uint64_t> referenced;
        for (const auto& relocation : image.relocations) {
            if (relocation.targetSymbol.has_value()) {
                referenced.insert(relocation.targetSymbol->value());
            }
        }
        std::unordered_set<std::uint64_t> removed;
        for (const auto& symbol : image.symbols) {
            if (symbol.visibility == SymbolVisibility::Local && symbol.defined
                && symbol.kind != SymbolKind::Section
                && !context.is_symbol_preserved(symbol.name)
                && !(context.has_function_selection()
                    && context.is_symbol_selected(image, symbol))
                && !referenced.contains(symbol.id.value())
                && !symbol.name.starts_with("@feat.")) {
                removed.insert(symbol.id.value());
            }
        }
        const PassStatistics statistics{
            .examined = image.symbols.size(),
            .changed = removed.size(),
            .skipped = image.symbols.size() - removed.size(),
        };
        if (removed.empty()) {
            std::vector<Diagnostic> diagnostics;
            diagnostics.emplace_back(
                DiagnosticSeverity::Info,
                "pass.no_matching_symbols",
                "strip-local-symbols found no unreferenced private symbols");
            return Result<TransformResult, Diagnostic>::success(TransformResult{
                .changed = false,
                .statistics = statistics,
                .diagnostics = std::move(diagnostics)});
        }
        if (std::any_of(image.sections.begin(), image.sections.end(), [](const auto& section) {
                return section.name == ".llvm_addrsig" || section.formatType == 17;
            })) {
            return failure(
                "raw symbol-index metadata must be removed before local symbols are stripped");
        }
        if (image.format == BinaryFormat::COFF
            && std::any_of(image.symbols.begin(), image.symbols.end(), [&removed](const auto& symbol) {
                return !removed.contains(symbol.id.value()) && !symbol.auxiliaryData.empty()
                    && symbol.kind != SymbolKind::Section && symbol.kind != SymbolKind::File;
            })) {
            return failure(
                "opaque COFF auxiliary records may contain shifted symbol indices");
        }

        std::unordered_map<std::uint64_t, std::uint32_t> oldIndices;
        for (const auto& symbol : image.symbols) {
            oldIndices.emplace(symbol.id.value(), symbol.formatIndex);
        }
        image.symbols.erase(std::remove_if(
            image.symbols.begin(), image.symbols.end(), [&removed](const auto& symbol) {
                return removed.contains(symbol.id.value());
            }), image.symbols.end());

        const auto transform = context.allocate_transform_id();
        if (image.format == BinaryFormat::ELF) {
            std::unordered_map<std::uint32_t, std::uint32_t> next;
            for (auto& symbol : image.symbols) {
                symbol.formatIndex = ++next[symbol.formatTableIndex];
                if (symbol.formatIndex != oldIndices.at(symbol.id.value())) {
                    symbol.lineage.parents.push_back(TransformationRecord{
                        transform, symbol.id, std::string{name()}});
                }
            }
            for (auto& section : image.sections) {
                if (section.formatType != 2 && section.formatType != 11) continue;
                std::uint32_t firstGlobal = 1;
                for (const auto& symbol : image.symbols) {
                    if (symbol.formatTableIndex != section.formatIndex) continue;
                    if (symbol.formatStorage != 0) {
                        firstGlobal = symbol.formatIndex;
                        break;
                    }
                    firstGlobal = symbol.formatIndex + 1;
                }
                section.formatInfo = firstGlobal;
            }
        } else {
            std::uint32_t next = 0;
            for (auto& symbol : image.symbols) {
                symbol.formatIndex = next;
                next += 1U + static_cast<std::uint32_t>(symbol.auxiliaryData.size() / 18);
                if (symbol.formatIndex != oldIndices.at(symbol.id.value())) {
                    symbol.lineage.parents.push_back(TransformationRecord{
                        transform, symbol.id, std::string{name()}});
                }
            }
        }
        std::vector<Diagnostic> diagnostics;
        diagnostics.emplace_back(
            DiagnosticSeverity::Info,
            "pass.symbols_removed",
            "strip-local-symbols removed " + std::to_string(removed.size()) + " symbols");
        return Result<TransformResult, Diagnostic>::success(TransformResult{
            .changed = true,
            .statistics = statistics,
            .diagnostics = std::move(diagnostics)});
    }
};

} // namespace

auto make_strip_debug_pass() -> std::unique_ptr<TransformPass> {
    return std::make_unique<SectionRemovalPass>("strip-debug", [](const Section& section) {
        return section.kind == SectionKind::Debug || section.name.starts_with(".debug")
            || section.name.starts_with(".zdebug");
    });
}

auto make_metadata_cleanup_pass() -> std::unique_ptr<TransformPass> {
    return std::make_unique<SectionRemovalPass>("cleanup-metadata", [](const Section& section) {
        return section.name == ".comment" || section.name == ".llvm_addrsig";
    });
}

auto make_strip_local_symbols_pass() -> std::unique_ptr<TransformPass> {
    return std::make_unique<StripLocalSymbolsPass>();
}

} // namespace binobf

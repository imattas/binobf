#include <binobf/transforms/baseline.hpp>

#include <binobf/support/deterministic_rng.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace binobf {
namespace {

auto generated_name(std::uint64_t value) -> std::string {
    constexpr std::array digits{
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    };
    std::string name = "__bo_0000000000000000";
    for (std::size_t index = 0; index < 16; ++index) {
        const auto nibble = static_cast<std::size_t>(value & 0x0fU);
        name[name.size() - 1 - index] = digits[nibble];
        value >>= 4U;
    }
    return name;
}

auto is_private_symbol(const BinaryImage& image, const Symbol& symbol) -> bool {
    if (!symbol.defined || symbol.name.empty()
        || symbol.kind == SymbolKind::Section || symbol.kind == SymbolKind::File
        || symbol.visibility != SymbolVisibility::Local) {
        return false;
    }
    if (image.format == BinaryFormat::ELF) {
        return symbol.formatStorage == 0;
    }
    if (image.format == BinaryFormat::COFF) {
        return symbol.formatStorage == 3 && symbol.name != "@feat.00";
    }
    return false;
}

class RenamePrivateSymbolsPass final : public TransformPass {
public:
    auto name() const noexcept -> std::string_view override {
        return "rename-private-symbols";
    }

    auto dependencies() const -> std::vector<std::string> override { return {}; }

    auto requirements() const -> PassRequirements override {
        return PassRequirements{
            .requiresCfg = false,
            .requiresFullRelocations = false,
            .requiresLiftedIr = false,
            .changesCodeSize = false,
            .supportedPostLink = false,
            .formats = {BinaryFormat::COFF, BinaryFormat::ELF},
            .architectures = {Architecture::X86, Architecture::X86_64, Architecture::ARM64},
        };
    }

    auto supports(const TransformContext&, const BinaryImage& image) const -> bool override {
        return image.type == BinaryType::RelocatableObject
            && (image.format == BinaryFormat::COFF || image.format == BinaryFormat::ELF)
            && image.architecture != Architecture::Unknown;
    }

    auto run(TransformContext& context, BinaryImage& image) const
        -> Result<TransformResult, Diagnostic> override {
        PassStatistics statistics;
        statistics.examined = image.symbols.size();
        std::unordered_set<std::string> occupiedNames;
        occupiedNames.reserve(image.symbols.size() * 2);
        for (const auto& symbol : image.symbols) {
            occupiedNames.insert(symbol.name);
        }
        DeterministicRng rng{context.seed() ^ UINT64_C(0x72656e616d652d70)};
        TransformId transform;
        for (auto& symbol : image.symbols) {
            if (!is_private_symbol(image, symbol)
                || context.is_symbol_preserved(symbol.name)) {
                ++statistics.skipped;
                continue;
            }
            std::string replacement;
            do {
                replacement = generated_name(rng.next_u64());
            } while (occupiedNames.contains(replacement));
            if (!transform.valid()) {
                transform = context.allocate_transform_id();
            }
            occupiedNames.erase(symbol.name);
            occupiedNames.insert(replacement);
            symbol.lineage.parents.push_back(TransformationRecord{
                .transform = transform,
                .source = symbol.id,
                .passName = std::string{name()},
            });
            context.record_symbol_rename(symbol.name, replacement);
            symbol.name = std::move(replacement);
            ++statistics.changed;
        }
        std::vector<Diagnostic> diagnostics;
        diagnostics.emplace_back(
            DiagnosticSeverity::Info,
            "pass.rename_private_symbols",
            "renamed " + std::to_string(statistics.changed)
                + " private symbols and preserved " + std::to_string(statistics.skipped));
        return Result<TransformResult, Diagnostic>::success(TransformResult{
            .changed = statistics.changed != 0,
            .statistics = statistics,
            .diagnostics = std::move(diagnostics),
        });
    }
};

} // namespace

auto make_rename_private_symbols_pass() -> std::unique_ptr<TransformPass> {
    return std::make_unique<RenamePrivateSymbolsPass>();
}

} // namespace binobf

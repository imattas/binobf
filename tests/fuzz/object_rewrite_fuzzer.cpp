#include <binobf/architecture/backend.hpp>
#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/transforms/object_rewrite.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

namespace {

[[noreturn]] void fail() { std::abort(); }

auto section_symbol() -> binobf::Symbol {
    binobf::Symbol symbol{};
    symbol.id = binobf::EntityId{2};
    symbol.formatIndex = 0;
    symbol.formatStorage = 3;
    symbol.formatSectionIndex = 1;
    symbol.name = ".text";
    symbol.section = binobf::EntityId{1};
    symbol.kind = binobf::SymbolKind::Section;
    symbol.visibility = binobf::SymbolVisibility::Local;
    symbol.defined = true;
    symbol.definition = binobf::SymbolDefinitionKind::SectionRelative;
    return symbol;
}

auto function_symbol(binobf::BinaryFormat format) -> binobf::Symbol {
    binobf::Symbol symbol{};
    symbol.id = binobf::EntityId{3};
    symbol.formatIndex = 1;
    symbol.formatTableIndex = format == binobf::BinaryFormat::ELF ? 3U : 0U;
    symbol.formatType = 2;
    symbol.formatStorage = format == binobf::BinaryFormat::ELF ? 1U : 2U;
    symbol.formatSectionIndex = 1;
    symbol.name = "fuzz_function";
    symbol.section = binobf::EntityId{1};
    symbol.size = 16;
    symbol.kind = binobf::SymbolKind::Function;
    symbol.visibility = binobf::SymbolVisibility::External;
    symbol.defined = true;
    symbol.definition = binobf::SymbolDefinitionKind::SectionRelative;
    return symbol;
}

auto seed_image(binobf::BinaryFormat format) -> binobf::BinaryImage {
    binobf::BinaryImage image{};
    image.format = format;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86;
    image.sections.push_back(binobf::Section{
        .id = binobf::EntityId{1}, .formatIndex = 1,
        .formatType = format == binobf::BinaryFormat::ELF ? UINT64_C(1) : UINT64_C(0),
        .formatFlags = format == binobf::BinaryFormat::ELF ? UINT64_C(6) : UINT64_C(0x60500020),
        .name = ".text", .kind = binobf::SectionKind::Code, .address = {},
        .logicalSize = 16, .alignment = 4, .readable = true, .executable = true,
        .contents = {
            std::byte{0xe8}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
            std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
            std::byte{0x90}, std::byte{0x90}, std::byte{0xc3}},
        .lineage = {}});
    if (format == binobf::BinaryFormat::COFF) {
        image.symbols = {section_symbol(), function_symbol(format)};
    } else {
        binobf::Section strings{};
        strings.id = binobf::EntityId{4};
        strings.formatIndex = 2;
        strings.formatType = 3;
        strings.name = ".strtab";
        strings.kind = binobf::SectionKind::StringTable;
        strings.alignment = 1;
        image.sections.push_back(std::move(strings));
        binobf::Section symbols{};
        symbols.id = binobf::EntityId{5};
        symbols.formatIndex = 3;
        symbols.formatType = 2;
        symbols.formatLink = 2;
        symbols.formatInfo = 1;
        symbols.formatEntrySize = 16;
        symbols.name = ".symtab";
        symbols.kind = binobf::SectionKind::SymbolTable;
        symbols.alignment = 4;
        image.sections.push_back(std::move(symbols));
        binobf::Section sectionNames{};
        sectionNames.id = binobf::EntityId{6};
        sectionNames.formatIndex = 4;
        sectionNames.formatType = 3;
        sectionNames.isSectionNameTable = true;
        sectionNames.name = ".shstrtab";
        sectionNames.kind = binobf::SectionKind::StringTable;
        sectionNames.alignment = 1;
        image.sections.push_back(std::move(sectionNames));
        binobf::Section relocations{};
        relocations.id = binobf::EntityId{7};
        relocations.formatIndex = 5;
        relocations.formatType = 9;
        relocations.formatLink = 3;
        relocations.formatInfo = 1;
        relocations.formatEntrySize = 8;
        relocations.name = ".rel.text";
        relocations.kind = binobf::SectionKind::Relocation;
        relocations.alignment = 4;
        image.sections.push_back(std::move(relocations));
        auto symbol = function_symbol(format);
        image.symbols = {symbol};
    }
    binobf::Relocation relocation{};
    relocation.id = binobf::EntityId{8};
    relocation.formatIndex = 0;
    relocation.formatTableIndex = format == binobf::BinaryFormat::ELF ? 5U : 1U;
    relocation.section = binobf::EntityId{1};
    relocation.offset = 1;
    relocation.kind = binobf::RelocationKind::PcRelative;
    relocation.rawType = format == binobf::BinaryFormat::ELF ? 2U : 0x14U;
    relocation.targetSymbol = binobf::EntityId{3};
    relocation.addend = format == binobf::BinaryFormat::ELF ? -4 : 0;
    image.relocations.push_back(relocation);
    return image;
}

auto next_byte(const std::uint8_t* data, std::size_t size, std::size_t& cursor) -> std::uint8_t {
    if (size == 0U) return 0;
    const auto value = data[cursor % size];
    ++cursor;
    return value;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0U) return 0;
    const auto format = data[0] == static_cast<std::uint8_t>('E')
        ? binobf::BinaryFormat::ELF : binobf::BinaryFormat::COFF;
    const auto image = seed_image(format);
    auto backend = binobf::make_architecture_backend(binobf::Architecture::X86);
    if (!backend.has_value()) fail();

    std::size_t cursor = 1;
    binobf::ObjectRewriteRequest request{};
    request.passName = "object-rewrite-fuzzer";
    request.transform = binobf::TransformId{UINT64_C(0xf022)};
    request.maxOutputGrowth = 64;
    const auto rangeCount = static_cast<std::size_t>(next_byte(data, size, cursor) % 5U) + 1U;
    for (std::size_t rangeIndex = 0; rangeIndex < rangeCount; ++rangeIndex) {
        auto begin = static_cast<std::uint64_t>(next_byte(data, size, cursor) % 17U);
        auto end = static_cast<std::uint64_t>(next_byte(data, size, cursor) % 17U);
        if (begin > end) std::swap(begin, end);
        binobf::ObjectRewriteRange range{};
        range.section = binobf::EntityId{1};
        range.oldBegin = begin;
        range.oldEnd = end;
        range.newBegin = static_cast<std::uint64_t>(next_byte(data, size, cursor) % 33U);
        const auto replacementSize = static_cast<std::size_t>(
            next_byte(data, size, cursor) % 9U);
        range.replacement.reserve(replacementSize);
        for (std::size_t index = 0; index < replacementSize; ++index) {
            range.replacement.push_back(static_cast<std::byte>(next_byte(data, size, cursor)));
        }
        request.ranges.push_back(std::move(range));
    }

    const auto first = binobf::ObjectRewritePlan::create(image, *backend.value(), request);
    const auto second = binobf::ObjectRewritePlan::create(image, *backend.value(), request);
    if (first.has_value() != second.has_value()) fail();
    if (!first.has_value()) {
        if (first.error().code.empty() || first.error().code != second.error().code
            || first.error().message != second.error().message) fail();
        return 0;
    }
    const auto validated = first.value().validate(image);
    const auto committed = first.value().commit(image);
    if (!validated.has_value() || !committed.has_value()) fail();
    const auto written = binobf::write_object(committed.value());
    if (!written.has_value()) fail();
    const auto reparsed = binobf::parse_object(written.value(), "fuzz-rewrite.o");
    if (!reparsed.has_value() || reparsed.value().architecture != binobf::Architecture::X86
        || reparsed.value().format != format) fail();
    return 0;
}

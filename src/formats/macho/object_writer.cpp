#include "../object_writer_internal.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>
#include <string>
#include <unordered_map>
#include <vector>

namespace binobf::formats::detail {
namespace {

constexpr std::uint32_t lcSegment64 = 0x19;
constexpr std::uint32_t lcSymtab = 0x2;
constexpr std::uint32_t nTypeSection = 0x0eU;
constexpr std::uint32_t nTypeAbsolute = 0x02U;
constexpr std::uint32_t nExt = 0x01U;

auto align_up(std::size_t value, std::size_t alignment) -> std::size_t {
    if (alignment <= 1U) return value;
    const auto remainder = value % alignment;
    return remainder == 0U ? value : value + alignment - remainder;
}

void put_u32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    if (bytes.size() < offset + 4U) bytes.resize(offset + 4U);
    for (std::size_t index = 0; index < 4U; ++index) {
        bytes[offset + index] = static_cast<std::byte>(value >> (index * 8U));
    }
}

void put_u16(std::vector<std::byte>& bytes, std::size_t offset, std::uint16_t value) {
    if (bytes.size() < offset + 2U) bytes.resize(offset + 2U);
    for (std::size_t index = 0; index < 2U; ++index) {
        bytes[offset + index] = static_cast<std::byte>(value >> (index * 8U));
    }
}

void put_u64(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value) {
    if (bytes.size() < offset + 8U) bytes.resize(offset + 8U);
    for (std::size_t index = 0; index < 8U; ++index) {
        bytes[offset + index] = static_cast<std::byte>(value >> (index * 8U));
    }
}

void put_name(std::vector<std::byte>& bytes, std::size_t offset, std::string_view name) {
    const auto count = std::min<std::size_t>(name.size(), 16U);
    for (std::size_t index = 0; index < count; ++index) {
        bytes[offset + index] = static_cast<std::byte>(name[index]);
    }
}

auto failure(std::string code, std::string message)
    -> Result<std::vector<std::byte>, Diagnostic> {
    return Result<std::vector<std::byte>, Diagnostic>::failure(
        Diagnostic{DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

} // namespace

auto write_macho_object(const BinaryImage& image)
    -> Result<std::vector<std::byte>, Diagnostic> {
    if (image.format != BinaryFormat::MachO || image.type != BinaryType::RelocatableObject) {
        return failure("macho.request", "Mach-O writer requires a relocatable Mach-O image");
    }
    if (image.sections.empty() || image.sections.size() > 4096U || image.symbols.size() > 1'000'000U) {
        return failure("macho.size", "Mach-O object exceeds supported section or symbol limits");
    }
    if (image.architecture != Architecture::X86_64 && image.architecture != Architecture::ARM64 &&
        image.architecture != Architecture::X86) {
        return failure("macho.architecture", "Mach-O writer requires a supported architecture");
    }

    const auto segmentCommandSize = 72U + image.sections.size() * 80U;
    const auto loadCommandBytes = segmentCommandSize + 24U;
    if (loadCommandBytes > std::numeric_limits<std::uint32_t>::max()) {
        return failure("macho.size", "Mach-O load commands exceed 32-bit limits");
    }
    const auto headerBytes = 32U + loadCommandBytes;
    std::vector<std::byte> output(headerBytes, std::byte{0});
    put_u32(output, 0, 0xfeedfacfU);
    const auto cpuType = image.architecture == Architecture::X86_64
        ? 0x01000007U : image.architecture == Architecture::ARM64 ? 0x0100000cU : 7U;
    put_u32(output, 4, cpuType);
    put_u32(output, 8, 3U);
    put_u32(output, 12, 1U);
    put_u32(output, 16, 2U);
    put_u32(output, 20, static_cast<std::uint32_t>(loadCommandBytes));
    put_u32(output, 24, static_cast<std::uint32_t>(image.objectMetadata.formatFlags));

    const auto segmentOffset = std::size_t{32};
    put_u32(output, segmentOffset, lcSegment64);
    put_u32(output, segmentOffset + 4U, static_cast<std::uint32_t>(segmentCommandSize));
    put_name(output, segmentOffset + 8U, "__TEXT");
    put_u64(output, segmentOffset + 24U, 0U);
    std::uint64_t virtualEnd = 0;
    for (const auto& section : image.sections) {
        if (section.address.value > std::numeric_limits<std::uint64_t>::max() - section.logicalSize) {
            return failure("macho.size", "Mach-O section address overflows");
        }
        virtualEnd = std::max(virtualEnd, section.address.value + section.logicalSize);
    }
    put_u64(output, segmentOffset + 32U, virtualEnd);
    put_u64(output, segmentOffset + 40U, headerBytes);
    put_u64(output, segmentOffset + 48U, 0U);
    put_u32(output, segmentOffset + 56U, 7U);
    put_u32(output, segmentOffset + 60U, 7U);
    put_u32(output, segmentOffset + 64U, static_cast<std::uint32_t>(image.sections.size()));
    put_u32(output, segmentOffset + 68U, 0U);

    std::vector<std::uint32_t> sectionOffsets(image.sections.size());
    std::size_t dataCursor = headerBytes;
    for (std::size_t index = 0; index < image.sections.size(); ++index) {
        const auto& section = image.sections[index];
        const auto alignment = section.alignment == 0U ? 1U : static_cast<std::size_t>(section.alignment);
        dataCursor = align_up(dataCursor, alignment);
        if (section.kind != SectionKind::UninitializedData) {
            if (section.contents.size() != section.logicalSize) {
                return failure("macho.section", "Mach-O section contents do not match logical size");
            }
            if (dataCursor > std::numeric_limits<std::uint32_t>::max() ||
                section.contents.size() > std::numeric_limits<std::size_t>::max() - dataCursor) {
                return failure("macho.size", "Mach-O section file offset overflows");
            }
            sectionOffsets[index] = static_cast<std::uint32_t>(dataCursor);
            if (output.size() < dataCursor + section.contents.size()) {
                output.resize(dataCursor + section.contents.size(), std::byte{0});
            }
            std::copy(section.contents.begin(), section.contents.end(),
                      output.begin() + static_cast<std::ptrdiff_t>(dataCursor));
            dataCursor += section.contents.size();
        }
        const auto sectionOffset = segmentOffset + 72U + index * 80U;
        put_name(output, sectionOffset, section.name);
        put_name(output, sectionOffset + 16U, "__TEXT");
        put_u64(output, sectionOffset + 32U, section.address.value);
        put_u64(output, sectionOffset + 40U, section.logicalSize);
        put_u32(output, sectionOffset + 48U, sectionOffsets[index]);
        std::uint32_t alignmentExponent = 0;
        auto alignmentValue = alignment;
        while (alignmentValue > 1U && alignmentExponent < 31U) {
            alignmentValue >>= 1U;
            ++alignmentExponent;
        }
        put_u32(output, sectionOffset + 52U, alignmentExponent);
        put_u32(output, sectionOffset + 64U,
                static_cast<std::uint32_t>(section.formatFlags != 0U ? section.formatFlags
                    : (section.kind == SectionKind::Code ? 0x80000400U : 0U)));
    }
    put_u64(output, segmentOffset + 48U, dataCursor - headerBytes);

    std::vector<std::uint32_t> relocationOffsets(image.sections.size());
    std::vector<std::uint32_t> relocationCounts(image.sections.size());
    std::unordered_map<std::uint64_t, std::uint32_t> symbolIndices;
    for (std::size_t index = 0; index < image.symbols.size(); ++index) {
        symbolIndices.emplace(image.symbols[index].id.value(), static_cast<std::uint32_t>(index));
    }
    for (const auto& relocation : image.relocations) {
        const auto sectionIt = std::find_if(image.sections.begin(), image.sections.end(),
            [&](const auto& section) { return section.id == relocation.section; });
        if (sectionIt == image.sections.end()) return failure("macho.relocation", "relocation section is missing");
        const auto sectionIndex = static_cast<std::size_t>(sectionIt - image.sections.begin());
        if (relocation.offset > std::numeric_limits<std::int32_t>::max()) {
            return failure("macho.relocation", "Mach-O relocation offset is out of range");
        }
        if (relocationCounts[sectionIndex] == 0U) relocationOffsets[sectionIndex] = static_cast<std::uint32_t>(dataCursor);
        const auto targetIt = relocation.targetSymbol.has_value()
            ? symbolIndices.find(relocation.targetSymbol->value()) : symbolIndices.end();
        const auto symbolNumber = targetIt == symbolIndices.end() ? 0U : targetIt->second;
        const auto width = relocation.rawType == 0U ? 3U : 2U;
        const auto pcrel = relocation.kind == RelocationKind::PcRelative ? 1U : 0U;
        const auto external = targetIt == symbolIndices.end() ? 0U : 1U;
        const auto info = (symbolNumber & 0x00ffffffU) | (pcrel << 24U) |
            (width << 25U) | (external << 27U) | ((static_cast<std::uint32_t>(relocation.rawType) & 0x0fU) << 28U);
        if (dataCursor > std::numeric_limits<std::uint32_t>::max()) return failure("macho.size", "Mach-O relocation table overflows");
        put_u32(output, dataCursor, static_cast<std::uint32_t>(relocation.offset));
        put_u32(output, dataCursor + 4U, info);
        dataCursor += 8U;
        ++relocationCounts[sectionIndex];
    }
    for (std::size_t index = 0; index < image.sections.size(); ++index) {
        const auto sectionOffset = segmentOffset + 72U + index * 80U;
        put_u32(output, sectionOffset + 56U, relocationOffsets[index]);
        put_u32(output, sectionOffset + 60U, relocationCounts[index]);
    }

    const auto symbolOffset = align_up(dataCursor, 8U);
    std::unordered_map<std::uint64_t, std::uint8_t> sectionIndices;
    for (std::size_t index = 0; index < image.sections.size(); ++index) {
        if (index >= std::numeric_limits<std::uint8_t>::max()) {
            return failure("macho.size", "Mach-O section index exceeds nlist limits");
        }
        sectionIndices.emplace(image.sections[index].id.value(), static_cast<std::uint8_t>(index + 1U));
    }
    const auto stringOffset = symbolOffset + image.symbols.size() * 16U;
    output.resize(stringOffset, std::byte{0});
    std::vector<std::byte> strings{std::byte{0}};
    std::vector<std::uint32_t> stringOffsets;
    stringOffsets.reserve(image.symbols.size());
    for (const auto& symbol : image.symbols) {
        stringOffsets.push_back(static_cast<std::uint32_t>(strings.size()));
        for (const auto character : symbol.name) strings.push_back(static_cast<std::byte>(character));
        strings.push_back(std::byte{0});
    }
    for (std::size_t index = 0; index < image.symbols.size(); ++index) {
        const auto& symbol = image.symbols[index];
        const auto offset = symbolOffset + index * 16U;
        put_u32(output, offset, stringOffsets[index]);
        std::uint8_t type = symbol.defined ? (symbol.section.has_value() ? nTypeSection : nTypeAbsolute) : 0U;
        if (symbol.visibility == SymbolVisibility::External) type = static_cast<std::uint8_t>(type | nExt);
        output[offset + 4U] = static_cast<std::byte>(type);
        const auto sectionIt = symbol.section.has_value()
            ? sectionIndices.find(symbol.section->value()) : sectionIndices.end();
        output[offset + 5U] = static_cast<std::byte>(
            sectionIt == sectionIndices.end() ? 0U : sectionIt->second);
        put_u16(output, offset + 6U, symbol.formatOther);
        put_u64(output, offset + 8U, symbol.address.value);
    }
    output.resize(stringOffset + strings.size(), std::byte{0});
    std::copy(strings.begin(), strings.end(),
              output.begin() + static_cast<std::ptrdiff_t>(stringOffset));
    const auto symtabOffset = segmentOffset + segmentCommandSize;
    put_u32(output, symtabOffset, lcSymtab);
    put_u32(output, symtabOffset + 4U, 24U);
    put_u32(output, symtabOffset + 8U, static_cast<std::uint32_t>(symbolOffset));
    put_u32(output, symtabOffset + 12U, static_cast<std::uint32_t>(image.symbols.size()));
    put_u32(output, symtabOffset + 16U, static_cast<std::uint32_t>(stringOffset));
    put_u32(output, symtabOffset + 20U, static_cast<std::uint32_t>(strings.size()));
    return Result<std::vector<std::byte>, Diagnostic>::success(std::move(output));
}

} // namespace binobf::formats::detail

#include <binobf/formats/linked_writer.hpp>
#include <binobf/verify/structural_verifier.hpp>

#include "object_parser_internal.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace binobf {
namespace {

auto failure(std::string code, std::string message)
    -> Result<LinkedRewriteReport, Diagnostic> {
    return Result<LinkedRewriteReport, Diagnostic>::failure(
        Diagnostic{DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

void put_u32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        bytes[offset + index] = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

void put_u64(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value) {
    for (std::size_t index = 0; index < 8; ++index) {
        bytes[offset + index] = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

void zero_range(std::vector<std::byte>& bytes, std::size_t offset, std::size_t size) {
    std::fill_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset), size, std::byte{0});
}

auto directory_of(const LinkedImage& image, LinkedDirectoryKind kind)
    -> const LinkedDirectory* {
    const auto found = std::find_if(
        image.directories.begin(), image.directories.end(),
        [kind](const LinkedDirectory& directory) { return directory.kind == kind; });
    return found == image.directories.end() ? nullptr : &*found;
}

auto pe_checksum(const std::vector<std::byte>& bytes, std::size_t checksumOffset)
    -> std::uint32_t {
    std::uint64_t checksum = 0;
    for (std::size_t offset = 0; offset < bytes.size(); offset += 2) {
        std::uint16_t word = 0;
        if (offset < checksumOffset || offset >= checksumOffset + 4) {
            word = std::to_integer<std::uint8_t>(bytes[offset]);
            if (offset + 1 < bytes.size()) {
                word |= static_cast<std::uint16_t>(
                    static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[offset + 1]))
                    << 8U);
            }
        }
        checksum += word;
        checksum = (checksum & UINT64_C(0xffff)) + (checksum >> 16U);
    }
    checksum = (checksum & UINT64_C(0xffff)) + (checksum >> 16U);
    checksum += bytes.size();
    return static_cast<std::uint32_t>(checksum);
}

auto rewrite_pe(
    const LinkedImage& image,
    const LinkedRewriteOptions& options,
    LinkedRewriteReport& report) -> std::optional<Diagnostic> {
    if (!options.stripDebug) return std::nullopt;
    const auto* debug = directory_of(image, LinkedDirectoryKind::Debug);
    if (debug == nullptr) return std::nullopt;
    if (image.signedImage && !options.allowSignatureInvalidation) {
        return Diagnostic{
            DiagnosticSeverity::Error,
            "linked.signature_intent_required",
            "rewriting this signed PE requires --allow-signature-invalidation",
        };
    }
    if (!debug->fileOffset.has_value() || debug->size % 28 != 0
        || !formats::detail::contains_range(
            static_cast<std::size_t>(*debug->fileOffset),
            static_cast<std::size_t>(debug->size),
            report.bytes.size())) {
        return Diagnostic{
            DiagnosticSeverity::Error, "linked.debug_range", "PE debug directory is invalid"};
    }
    const formats::detail::ByteReader reader(report.bytes);
    const auto count = static_cast<std::size_t>(debug->size / 28);
    for (std::size_t index = 0; index < count; ++index) {
        const auto record = static_cast<std::size_t>(*debug->fileOffset) + index * 28;
        const auto dataSize = reader.u32(record + 16).value();
        const auto dataOffset = reader.u32(record + 24).value();
        if (dataSize != 0) {
            if (!formats::detail::contains_range(dataOffset, dataSize, report.bytes.size())) {
                return Diagnostic{
                    DiagnosticSeverity::Error,
                    "linked.debug_range",
                    "PE debug raw-data range is invalid",
                };
            }
            zero_range(report.bytes, dataOffset, dataSize);
        }
        ++report.stats.debugRecordsRemoved;
    }
    zero_range(
        report.bytes,
        static_cast<std::size_t>(*debug->fileOffset),
        static_cast<std::size_t>(debug->size));
    zero_range(report.bytes, static_cast<std::size_t>(debug->headerOffset), 8);

    if (image.signedImage) {
        const auto* security = directory_of(image, LinkedDirectoryKind::SecurityCertificate);
        if (security == nullptr || !security->fileOffset.has_value()
            || !formats::detail::contains_range(
                static_cast<std::size_t>(*security->fileOffset),
                static_cast<std::size_t>(security->size),
                report.bytes.size())) {
            return Diagnostic{
                DiagnosticSeverity::Error,
                "linked.security_range",
                "PE certificate table is invalid",
            };
        }
        zero_range(
            report.bytes,
            static_cast<std::size_t>(*security->fileOffset),
            static_cast<std::size_t>(security->size));
        zero_range(report.bytes, static_cast<std::size_t>(security->headerOffset), 8);
        report.stats.signatureRemoved = true;
        report.diagnostics.push_back(Diagnostic{
            DiagnosticSeverity::Warning,
            "linked.signature_removed",
            "the PE Authenticode certificate was removed because the image changed",
        });
    }
    if (!formats::detail::contains_range(
            static_cast<std::size_t>(image.checksumOffset), 4, report.bytes.size())) {
        return Diagnostic{
            DiagnosticSeverity::Error, "linked.checksum_range", "PE checksum field is invalid"};
    }
    put_u32(report.bytes, static_cast<std::size_t>(image.checksumOffset), 0);
    put_u32(
        report.bytes,
        static_cast<std::size_t>(image.checksumOffset),
        pe_checksum(report.bytes, static_cast<std::size_t>(image.checksumOffset)));
    return std::nullopt;
}

auto rewrite_elf(
    const LinkedImage& image,
    const LinkedRewriteOptions& options,
    LinkedRewriteReport& report) -> std::optional<Diagnostic> {
    if (!options.stripDebug) return std::nullopt;
    if (report.bytes.size() < 5) {
        return Diagnostic{
            DiagnosticSeverity::Error, "linked.elf_header", "ELF header is truncated"};
    }
    const auto elfClass = std::to_integer<std::uint8_t>(report.bytes[4]);
    if (elfClass != 1 && elfClass != 2) {
        return Diagnostic{
            DiagnosticSeverity::Error, "linked.elf_header", "ELF class is unsupported"};
    }
    std::vector<std::uint32_t> removedIndices;
    for (const auto& section : image.image.sections) {
        if (section.kind != SectionKind::Debug) continue;
        if ((section.formatFlags & UINT64_C(0x2)) != 0) {
            return Diagnostic{
                DiagnosticSeverity::Error,
                "linked.allocated_debug",
                "allocated ELF debug sections cannot be stripped conservatively",
            };
        }
        removedIndices.push_back(section.formatIndex);
    }
    for (const auto& section : image.image.sections) {
        if (section.kind == SectionKind::Relocation && section.formatInfo != 0
            && std::find(
                   removedIndices.begin(), removedIndices.end(), section.formatInfo)
                != removedIndices.end()) {
            removedIndices.push_back(section.formatIndex);
        }
    }
    for (const auto formatIndex : removedIndices) {
        const auto section = std::find_if(
            image.image.sections.begin(), image.image.sections.end(),
            [formatIndex](const Section& candidate) {
                return candidate.formatIndex == formatIndex;
            });
        const auto layout = std::find_if(
            image.sectionLayout.begin(), image.sectionLayout.end(),
            [&](const LinkedSectionLayout& candidate) {
                return section != image.image.sections.end() && candidate.section == section->id;
            });
        if (section == image.image.sections.end() || layout == image.sectionLayout.end()) {
            return Diagnostic{
                DiagnosticSeverity::Error,
                "linked.section_range",
                "ELF debug section layout is missing",
            };
        }
        if (layout->fileSize != 0) {
            if (!formats::detail::contains_range(
                    static_cast<std::size_t>(layout->fileOffset),
                    static_cast<std::size_t>(layout->fileSize),
                    report.bytes.size())) {
                return Diagnostic{
                    DiagnosticSeverity::Error,
                    "linked.section_range",
                    "ELF debug section payload is outside the input",
                };
            }
            zero_range(
                report.bytes,
                static_cast<std::size_t>(layout->fileOffset),
                static_cast<std::size_t>(layout->fileSize));
        }
        const auto header = static_cast<std::size_t>(layout->headerOffset);
        const auto headerSize = elfClass == 2 ? std::size_t{64} : std::size_t{40};
        if (!formats::detail::contains_range(header, headerSize, report.bytes.size())) {
            return Diagnostic{
                DiagnosticSeverity::Error,
                "linked.section_range",
                "ELF debug section header is outside the input",
            };
        }
        put_u32(report.bytes, header + 4, 8);
        if (elfClass == 2) {
            put_u64(report.bytes, header + 8, 0);
            put_u64(report.bytes, header + 16, 0);
            put_u64(report.bytes, header + 24, 0);
            put_u64(report.bytes, header + 32, 0);
            put_u32(report.bytes, header + 40, 0);
            put_u32(report.bytes, header + 44, 0);
            put_u64(report.bytes, header + 48, 1);
            put_u64(report.bytes, header + 56, 0);
        } else {
            put_u32(report.bytes, header + 8, 0);
            put_u32(report.bytes, header + 12, 0);
            put_u32(report.bytes, header + 16, 0);
            put_u32(report.bytes, header + 20, 0);
            put_u32(report.bytes, header + 24, 0);
            put_u32(report.bytes, header + 28, 0);
            put_u32(report.bytes, header + 32, 1);
            put_u32(report.bytes, header + 36, 0);
        }
        if (section->kind == SectionKind::Debug) ++report.stats.debugSectionsRemoved;
    }
    return std::nullopt;
}

auto rewrite_macho(
    const LinkedImage& image,
    const LinkedRewriteOptions& options,
    LinkedRewriteReport& report) -> std::optional<Diagnostic> {
    // The current linked Mach-O parser intentionally exposes only structural
    // metadata.  A rewrite therefore has no bytes to mutate yet, but it is
    // still useful to run the same verify/reparse/contract checks as PE/ELF.
    // Refuse a future strip request if the parser ever starts reporting debug
    // records without a corresponding Mach-O rewrite implementation.
    if (options.stripDebug && !image.image.debugInfo.empty()) {
        return Diagnostic{
            DiagnosticSeverity::Error,
            "linked.macho_debug_unsupported",
            "Mach-O debug rewriting is not supported for the parsed image",
        };
    }
    (void)report;
    return std::nullopt;
}

} // namespace

auto rewrite_linked_image(
    const LinkedImage& image,
    const LinkedRewriteOptions& options) -> Result<LinkedRewriteReport, Diagnostic> {
    if (image.image.format != BinaryFormat::PE && image.image.format != BinaryFormat::ELF
        && image.image.format != BinaryFormat::MachO) {
        return failure("linked.unsupported_format", "linked rewrite supports PE, ELF, and Mach-O");
    }
    LinkedRewriteReport report{
        .image = {},
        .bytes = image.sourceBytes,
        .stats = {},
        .diagnostics = {},
    };
    std::optional<Diagnostic> error;
    if (image.image.format == BinaryFormat::PE) {
        error = rewrite_pe(image, options, report);
    } else if (image.image.format == BinaryFormat::ELF) {
        error = rewrite_elf(image, options, report);
    } else {
        error = rewrite_macho(image, options, report);
    }
    if (error.has_value()) {
        return Result<LinkedRewriteReport, Diagnostic>::failure(std::move(*error));
    }
    for (std::size_t index = 0; index < report.bytes.size(); ++index) {
        if (report.bytes[index] != image.sourceBytes[index]) ++report.stats.bytesChanged;
    }
    const auto verified = verify_linked_image(report.bytes, image.sourceName);
    if (!verified.has_value()) {
        return failure(
            "linked.verification_failed",
            "rewritten linked image failed structural verification: " + verified.error().code);
    }
    auto reparsed = parse_linked_image(report.bytes, image.sourceName);
    if (!reparsed.has_value()) {
        return failure(
            "linked.reparse_failed",
            "rewritten linked image failed to reparse: " + reparsed.error().code);
    }
    if (options.stripDebug && !reparsed.value().image.debugInfo.empty()) {
        return failure("linked.debug_preserved", "rewritten image still contains parsed debug metadata");
    }
    if (reparsed.value().image.imports.size() != image.image.imports.size()
        || reparsed.value().image.exports.size() != image.image.exports.size()) {
        return failure(
            "linked.dynamic_contract_changed",
            "linked rewrite changed the import or export contract");
    }
    report.image = std::move(reparsed).value();
    return Result<LinkedRewriteReport, Diagnostic>::success(std::move(report));
}

} // namespace binobf

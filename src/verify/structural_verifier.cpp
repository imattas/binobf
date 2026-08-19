#include <binobf/verify/structural_verifier.hpp>

#include "../formats/object_writer_internal.hpp"

#include <binobf/analysis/object_analyzer.hpp>
#include <binobf/formats/archive.hpp>
#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/linked_image.hpp>

#include <algorithm>
#include <cstddef>
#include <string>
#include <utility>

namespace binobf {
namespace {

auto add_source_context(Diagnostic diagnostic, std::string_view sourceName) -> Diagnostic {
    if (!sourceName.empty()) {
        diagnostic.message = std::string{sourceName} + ": " + diagnostic.message;
    }
    return diagnostic;
}

auto pe_checksum(std::span<const std::byte> bytes, std::size_t checksumOffset)
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

} // namespace

auto verification_status_name(VerificationStatus status) noexcept -> std::string_view {
    switch (status) {
    case VerificationStatus::Passed:
        return "passed";
    case VerificationStatus::NotApplicable:
        return "not-applicable";
    case VerificationStatus::Unsupported:
        return "unsupported";
    }
    return "unsupported";
}

auto verify_object(std::span<const std::byte> bytes, std::string_view sourceName)
    -> Result<StructuralVerificationReport, Diagnostic> {
    auto parsed = parse_object(bytes, sourceName);
    if (!parsed.has_value()) {
        return Result<StructuralVerificationReport, Diagnostic>::failure(
            add_source_context(std::move(parsed).error(), sourceName));
    }
    auto image = std::move(parsed).value();
    if (image.format != BinaryFormat::MachO) {
        if (auto invalid = formats::detail::validate_object_model(image); invalid.has_value()) {
            return Result<StructuralVerificationReport, Diagnostic>::failure(
                add_source_context(std::move(*invalid), sourceName));
        }
    }

    std::vector<VerificationCheck> checks;
    checks.reserve(8);
    checks.push_back(VerificationCheck{"headers", VerificationStatus::Passed, 1});
    checks.push_back(VerificationCheck{
        "section-ranges", VerificationStatus::Passed, image.sections.size()});
    checks.push_back(VerificationCheck{
        "symbols", VerificationStatus::Passed, image.symbols.size()});
    checks.push_back(VerificationCheck{
        "relocations", VerificationStatus::Passed, image.relocations.size()});
    checks.push_back(VerificationCheck{
        "entity-references", VerificationStatus::Passed,
        image.symbols.size() + image.relocations.size()});
    checks.push_back(VerificationCheck{
        "imports-exports", VerificationStatus::NotApplicable, 0});
    VerificationStatus branchStatus = VerificationStatus::Unsupported;
    std::size_t branchCount = 0;
    auto analyzed = analyze_object(image);
    if (analyzed.has_value()) {
        if (analyzed.value().image.functions.empty()) {
            branchStatus = VerificationStatus::NotApplicable;
        } else if (std::all_of(
                       analyzed.value().image.functions.begin(),
                       analyzed.value().image.functions.end(),
                       [](const auto& function) { return function.complete; })) {
            branchStatus = VerificationStatus::Passed;
            for (const auto& block : analyzed.value().image.basicBlocks) {
                branchCount += block.edges.size();
            }
        }
        image = std::move(analyzed).value().image;
    }
    checks.push_back(VerificationCheck{
        "branch-destinations", branchStatus, branchCount});
    checks.push_back(VerificationCheck{
        "unwind-semantics", VerificationStatus::Unsupported, 0});
    return Result<StructuralVerificationReport, Diagnostic>::success(
        StructuralVerificationReport{std::move(image), std::move(checks)});
}

auto verify_linked_image(std::span<const std::byte> bytes, std::string_view sourceName)
    -> Result<StructuralVerificationReport, Diagnostic> {
    auto parsed = parse_linked_image(bytes, sourceName);
    if (!parsed.has_value()) {
        return Result<StructuralVerificationReport, Diagnostic>::failure(
            add_source_context(std::move(parsed).error(), sourceName));
    }
    auto linked = std::move(parsed).value();
    auto& image = linked.image;
    std::vector<VerificationCheck> checks;
    checks.reserve(12);
    checks.push_back(VerificationCheck{"headers", VerificationStatus::Passed, 1});
    checks.push_back(VerificationCheck{
        "section-ranges", VerificationStatus::Passed, linked.sectionLayout.size()});
    checks.push_back(VerificationCheck{
        "segment-ranges", VerificationStatus::Passed, linked.segmentLayout.size()});
    checks.push_back(VerificationCheck{
        "entry-point",
        image.entryPoint.has_value() && image.entryPoint->value != 0
            ? VerificationStatus::Passed
            : VerificationStatus::NotApplicable,
        image.entryPoint.has_value() && image.entryPoint->value != 0 ? 1U : 0U,
    });
    checks.push_back(VerificationCheck{
        "symbols", image.symbols.empty() ? VerificationStatus::NotApplicable : VerificationStatus::Passed,
        image.symbols.size()});
    checks.push_back(VerificationCheck{
        "imports-exports",
        image.imports.empty() && image.exports.empty()
            ? VerificationStatus::NotApplicable
            : VerificationStatus::Passed,
        image.imports.size() + image.exports.size()});
    checks.push_back(VerificationCheck{
        "relocations",
        image.relocations.empty() ? VerificationStatus::NotApplicable : VerificationStatus::Passed,
        image.relocations.size()});
    checks.push_back(VerificationCheck{
        "format-directories",
        linked.directories.empty() ? VerificationStatus::NotApplicable : VerificationStatus::Passed,
        linked.directories.size()});
    const bool hasUnwindDirectory = std::any_of(
        linked.directories.begin(), linked.directories.end(),
        [](const LinkedDirectory& directory) {
            return directory.kind == LinkedDirectoryKind::Exception
                || directory.kind == LinkedDirectoryKind::Unwind;
        });
    checks.push_back(VerificationCheck{
        "unwind-records",
        image.unwindInfo.empty()
            ? (hasUnwindDirectory ? VerificationStatus::Unsupported
                                  : VerificationStatus::NotApplicable)
            : VerificationStatus::Passed,
        image.unwindInfo.size()});
    checks.push_back(VerificationCheck{
        "resources",
        image.resources.empty() ? VerificationStatus::NotApplicable : VerificationStatus::Passed,
        image.resources.size()});
    checks.push_back(VerificationCheck{
        "debug-records",
        image.debugInfo.empty() ? VerificationStatus::NotApplicable : VerificationStatus::Passed,
        image.debugInfo.size()});
    checks.push_back(VerificationCheck{
        "signature-state",
        image.format == BinaryFormat::PE ? VerificationStatus::Passed : VerificationStatus::NotApplicable,
        image.format == BinaryFormat::PE && linked.signedImage ? 1U : 0U,
    });
    if (image.format == BinaryFormat::PE && linked.checksum != 0
        && pe_checksum(bytes, static_cast<std::size_t>(linked.checksumOffset)) != linked.checksum) {
        return Result<StructuralVerificationReport, Diagnostic>::failure(add_source_context(
            Diagnostic{
                DiagnosticSeverity::Error,
                "linked.checksum_mismatch",
                "PE checksum does not match the linked image bytes",
            },
            sourceName));
    }
    checks.push_back(VerificationCheck{
        "pe-checksum",
        image.format != BinaryFormat::PE || linked.checksum == 0
            ? VerificationStatus::NotApplicable
            : VerificationStatus::Passed,
        image.format == BinaryFormat::PE && linked.checksum != 0 ? 1U : 0U,
    });
    return Result<StructuralVerificationReport, Diagnostic>::success(
        StructuralVerificationReport{std::move(image), std::move(checks)});
}

auto verify_archive(std::span<const std::byte> bytes, std::string_view sourceName)
    -> Result<ArchiveVerificationReport, Diagnostic> {
    auto parsed = parse_archive(bytes, sourceName);
    if (!parsed.has_value()) {
        return Result<ArchiveVerificationReport, Diagnostic>::failure(
            add_source_context(std::move(parsed).error(), sourceName));
    }
    auto archive = std::move(parsed).value();
    if (archive.members.size() != archive.layout.size()) {
        return Result<ArchiveVerificationReport, Diagnostic>::failure(add_source_context(
            Diagnostic{
                DiagnosticSeverity::Error,
                "archive.layout_mismatch",
                "archive member and layout counts differ",
            },
            sourceName));
    }
    std::size_t objectMembers = 0;
    std::size_t verifiedSymbols = 0;
    for (const auto& member : archive.members) {
        const auto layout = std::find_if(
            archive.layout.begin(), archive.layout.end(),
            [&](const ArchiveMemberLayout& candidate) { return candidate.member == member.id; });
        if (layout == archive.layout.end()) {
            return Result<ArchiveVerificationReport, Diagnostic>::failure(add_source_context(
                Diagnostic{
                    DiagnosticSeverity::Error,
                    "archive.layout_mismatch",
                    "archive member has no layout record: " + member.name,
                },
                sourceName));
        }
        if (member.kind != ArchiveMemberKind::Object) continue;
        ++objectMembers;
        const auto verified = verify_object(member.contents, member.name);
        if (!verified.has_value()) {
            return Result<ArchiveVerificationReport, Diagnostic>::failure(add_source_context(
                Diagnostic{
                    DiagnosticSeverity::Error,
                    "archive.member_invalid",
                    "object member failed verification: " + member.name + ": "
                        + verified.error().code,
                },
                sourceName));
        }
    }
    for (const auto& symbol : archive.symbols) {
        const auto member = std::find_if(
            archive.members.begin(), archive.members.end(),
            [&](const ArchiveMember& candidate) { return candidate.id == symbol.member; });
        if (member == archive.members.end()) {
            return Result<ArchiveVerificationReport, Diagnostic>::failure(add_source_context(
                Diagnostic{
                    DiagnosticSeverity::Error,
                    "archive.symbol_member",
                    "archive symbol references a missing member: " + symbol.name,
                },
                sourceName));
        }
        if (member->kind == ArchiveMemberKind::Object) {
            const auto object = parse_object(member->contents, member->name);
            if (!object.has_value()) {
                return Result<ArchiveVerificationReport, Diagnostic>::failure(add_source_context(
                    std::move(object).error(), sourceName));
            }
            const auto defined = std::find_if(
                object.value().symbols.begin(), object.value().symbols.end(),
                [&](const Symbol& candidate) {
                    return candidate.name == symbol.name && candidate.defined
                        && candidate.visibility == SymbolVisibility::External;
                });
            if (defined == object.value().symbols.end()) {
                return Result<ArchiveVerificationReport, Diagnostic>::failure(add_source_context(
                    Diagnostic{
                        DiagnosticSeverity::Error,
                        "archive.symbol_mismatch",
                        "archive index symbol does not match its object member: " + symbol.name,
                    },
                    sourceName));
            }
            ++verifiedSymbols;
        }
    }
    std::vector<VerificationCheck> checks;
    checks.reserve(5);
    checks.push_back(VerificationCheck{"archive-header", VerificationStatus::Passed, 1});
    checks.push_back(VerificationCheck{
        "member-layouts", VerificationStatus::Passed, archive.members.size()});
    checks.push_back(VerificationCheck{
        "object-members",
        objectMembers == 0 ? VerificationStatus::NotApplicable : VerificationStatus::Passed,
        objectMembers});
    checks.push_back(VerificationCheck{
        "symbol-index",
        archive.symbols.empty() ? VerificationStatus::NotApplicable : VerificationStatus::Passed,
        archive.symbols.size()});
    checks.push_back(VerificationCheck{
        "object-symbol-bindings",
        verifiedSymbols == 0 ? VerificationStatus::NotApplicable : VerificationStatus::Passed,
        verifiedSymbols});
    return Result<ArchiveVerificationReport, Diagnostic>::success(
        ArchiveVerificationReport{std::move(archive), std::move(checks)});
}

} // namespace binobf

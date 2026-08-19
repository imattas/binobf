#pragma once

#include "object_parser_internal.hpp"

#include <binobf/formats/linked_image.hpp>

#include <span>
#include <string>
#include <utility>

namespace binobf::formats::detail {

inline auto linked_failure(std::string code, std::string message)
    -> Result<LinkedImage, Diagnostic> {
    return Result<LinkedImage, Diagnostic>::failure(
        Diagnostic{DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

[[nodiscard]] auto parse_pe_linked(
    std::span<const std::byte> bytes,
    const DetectionResult& detection,
    const LinkedParseLimits& limits) -> Result<LinkedImage, Diagnostic>;

[[nodiscard]] auto parse_elf_linked(
    std::span<const std::byte> bytes,
    const DetectionResult& detection,
    const LinkedParseLimits& limits) -> Result<LinkedImage, Diagnostic>;

[[nodiscard]] auto parse_macho_linked(
    std::span<const std::byte> bytes,
    const DetectionResult& detection,
    const LinkedParseLimits& limits) -> Result<LinkedImage, Diagnostic>;

} // namespace binobf::formats::detail

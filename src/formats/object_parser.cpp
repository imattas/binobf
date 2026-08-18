#include <binobf/formats/object_parser.hpp>

#include "object_parser_internal.hpp"

#include <binobf/formats/detector.hpp>

#include <utility>

namespace binobf {

auto parse_object(std::span<const std::byte> bytes, std::string_view sourceName)
    -> Result<BinaryImage, Diagnostic> {
    auto detection = detect_binary(bytes, sourceName);
    if (!detection.has_value()) {
        return Result<BinaryImage, Diagnostic>::failure(std::move(detection).error());
    }
    if (detection.value().type != BinaryType::RelocatableObject) {
        return formats::detail::failure(
            "object.unsupported_type",
            "input is not a relocatable object");
    }
    if (detection.value().architecture == Architecture::Unknown) {
        return formats::detail::failure(
            "object.unsupported_architecture",
            "object machine architecture is unsupported");
    }
    if (detection.value().format == BinaryFormat::ELF) {
        return formats::detail::parse_elf_object(bytes, detection.value());
    }
    if (detection.value().format == BinaryFormat::COFF) {
        return formats::detail::parse_coff_object(bytes, detection.value());
    }
    return formats::detail::failure(
        "object.unsupported_format",
        "object format parser is not available");
}

} // namespace binobf

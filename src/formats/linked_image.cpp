#include <binobf/formats/linked_image.hpp>

#include "linked_parser_internal.hpp"

#include <binobf/formats/detector.hpp>

#include <utility>

namespace binobf {

auto parse_linked_image(
    std::span<const std::byte> bytes,
    std::string_view sourceName,
    const LinkedParseLimits& limits) -> Result<LinkedImage, Diagnostic> {
    if (bytes.size() > limits.maxInputBytes) {
        return formats::detail::linked_failure(
            "linked.input_limit", "linked image exceeds the configured byte limit");
    }
    auto detection = detect_binary(bytes, sourceName);
    if (!detection.has_value()) {
        return Result<LinkedImage, Diagnostic>::failure(std::move(detection).error());
    }
    if (detection.value().type != BinaryType::Executable
        && detection.value().type != BinaryType::SharedLibrary
        && detection.value().type != BinaryType::KernelDriver) {
        return formats::detail::linked_failure(
            "linked.unsupported_type", "input is not a linked executable or shared library");
    }
    if (detection.value().architecture == Architecture::Unknown) {
        return formats::detail::linked_failure(
            "linked.unsupported_architecture", "linked image architecture is unsupported");
    }
    Result<LinkedImage, Diagnostic> parsed = formats::detail::linked_failure(
        "linked.unsupported_format", "linked image format is unsupported");
    if (detection.value().format == BinaryFormat::PE) {
        parsed = formats::detail::parse_pe_linked(bytes, detection.value(), limits);
    } else if (detection.value().format == BinaryFormat::ELF) {
        parsed = formats::detail::parse_elf_linked(bytes, detection.value(), limits);
    }
    if (parsed.has_value()) parsed.value().sourceName = std::string{sourceName};
    return parsed;
}

} // namespace binobf

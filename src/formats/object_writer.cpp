#include "object_writer_internal.hpp"

#include <binobf/formats/object_writer.hpp>

#include <string>
#include <utility>

namespace binobf {
namespace {

auto failure(std::string code, std::string message)
    -> Result<std::vector<std::byte>, Diagnostic> {
    return Result<std::vector<std::byte>, Diagnostic>::failure(
        Diagnostic{DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

} // namespace

auto write_object(const BinaryImage& image)
    -> Result<std::vector<std::byte>, Diagnostic> {
    if (image.format != BinaryFormat::ELF && image.format != BinaryFormat::COFF) {
        return failure(
            "object.unsupported_format",
            "object writing supports only ELF and COFF relocatable objects");
    }
    if (const auto invalid = formats::detail::validate_object_model(image)) {
        return Result<std::vector<std::byte>, Diagnostic>::failure(*invalid);
    }
    if (image.format == BinaryFormat::ELF) {
        return formats::detail::write_elf_object(image);
    }
    return formats::detail::write_coff_object(image);
}

namespace formats::detail {

} // namespace formats::detail
} // namespace binobf

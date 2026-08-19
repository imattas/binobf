#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/model.hpp>
#include <binobf/core/result.hpp>

#include <cstddef>
#include <optional>
#include <vector>

namespace binobf::formats::detail {

[[nodiscard]] auto validate_object_model(const BinaryImage& image)
    -> std::optional<Diagnostic>;

[[nodiscard]] auto write_elf_object(const BinaryImage& image)
    -> Result<std::vector<std::byte>, Diagnostic>;

[[nodiscard]] auto write_coff_object(const BinaryImage& image)
    -> Result<std::vector<std::byte>, Diagnostic>;

[[nodiscard]] auto write_macho_object(const BinaryImage& image)
    -> Result<std::vector<std::byte>, Diagnostic>;

} // namespace binobf::formats::detail

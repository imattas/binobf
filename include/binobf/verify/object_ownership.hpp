#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/model.hpp>
#include <binobf/core/result.hpp>

#include <cstddef>

namespace binobf {

[[nodiscard]] auto validate_object_ownership(const BinaryImage& image)
    -> Result<std::size_t, Diagnostic>;

} // namespace binobf

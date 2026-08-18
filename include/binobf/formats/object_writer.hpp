#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/model.hpp>
#include <binobf/core/result.hpp>

#include <cstddef>
#include <vector>

namespace binobf {

[[nodiscard]] auto write_object(const BinaryImage& image)
    -> Result<std::vector<std::byte>, Diagnostic>;

} // namespace binobf

#pragma once

#include <binobf/formats/archive.hpp>

#include <vector>

namespace binobf {

[[nodiscard]] auto write_archive(const ArchiveImage& image)
    -> Result<std::vector<std::byte>, Diagnostic>;

} // namespace binobf

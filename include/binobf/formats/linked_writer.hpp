#pragma once

#include <binobf/formats/linked_image.hpp>

#include <cstddef>
#include <vector>

namespace binobf {

struct LinkedRewriteOptions {
    bool stripDebug{false};
    bool allowSignatureInvalidation{false};
};

struct LinkedRewriteStatistics {
    std::size_t bytesChanged{0};
    std::size_t debugRecordsRemoved{0};
    std::size_t debugSectionsRemoved{0};
    bool signatureRemoved{false};
};

struct LinkedRewriteReport {
    LinkedImage image;
    std::vector<std::byte> bytes;
    LinkedRewriteStatistics stats;
    std::vector<Diagnostic> diagnostics;
};

[[nodiscard]] auto rewrite_linked_image(
    const LinkedImage& image,
    const LinkedRewriteOptions& options = {}) -> Result<LinkedRewriteReport, Diagnostic>;

} // namespace binobf

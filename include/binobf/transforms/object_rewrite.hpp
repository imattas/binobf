#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/model.hpp>
#include <binobf/core/result.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace binobf {

class ArchitectureBackend;

struct ObjectRewriteRange {
    EntityId section;
    std::uint64_t oldBegin{0};
    std::uint64_t oldEnd{0};
    std::uint64_t newBegin{0};
    std::vector<std::byte> replacement;
};

struct ObjectRewriteRequest {
    std::vector<ObjectRewriteRange> ranges;
    std::string passName;
    TransformId transform;
    std::uint64_t maxOutputGrowth{16U << 20U};
};

class ObjectRewritePlan {
public:
    [[nodiscard]] static auto create(
        const BinaryImage& image,
        const ArchitectureBackend& backend,
        const ObjectRewriteRequest& request) -> Result<ObjectRewritePlan, Diagnostic>;

    [[nodiscard]] auto validate(const BinaryImage& image) const
        -> Result<std::size_t, Diagnostic>;
    [[nodiscard]] auto commit(const BinaryImage& image) const
        -> Result<BinaryImage, Diagnostic>;

private:
    std::uint64_t sourceFingerprint_{0};
    std::size_t validationCount_{0};
    BinaryImage output_;
};

} // namespace binobf

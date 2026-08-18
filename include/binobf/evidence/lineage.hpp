#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/model.hpp>
#include <binobf/core/result.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace binobf::evidence {

struct LineageParseLimits {
    std::size_t maxInputBytes{16U << 20U};
    std::size_t maxStringBytes{4096};
    std::size_t maxEntities{100000};
    std::size_t maxTransforms{1000000};
    std::size_t maxDepth{64};
};

struct LineageTransform {
    std::uint64_t id{0};
    std::uint64_t sourceEntity{0};
    std::string pass;

    auto operator==(const LineageTransform&) const -> bool = default;
};

struct LineageEntity {
    std::string id;
    std::string domain;
    std::string kind;
    std::string name;
    std::string section;
    std::uint64_t address{0};
    std::uint64_t size{0};
    std::string addressKind;
    std::optional<std::string> origin;
    std::vector<LineageTransform> transforms;

    auto operator==(const LineageEntity&) const -> bool = default;
};

struct LineageDocument {
    std::uint32_t schemaVersion{1};
    std::string toolVersion;
    std::string inputSha256;
    std::string outputSha256;
    std::string format;
    std::string architecture;
    std::vector<LineageEntity> entities;

    auto operator==(const LineageDocument&) const -> bool = default;
};

struct LineageQueryResult {
    LineageEntity protectedEntity;
    LineageEntity originalEntity;
    std::vector<LineageTransform> transforms;
};

[[nodiscard]] auto serialize_lineage(const LineageDocument& document) -> std::string;
[[nodiscard]] auto parse_lineage(
    std::span<const std::byte> bytes,
    const LineageParseLimits& limits = {}) -> Result<LineageDocument, Diagnostic>;
[[nodiscard]] auto query_lineage(const LineageDocument& document, std::uint64_t address)
    -> Result<LineageQueryResult, Diagnostic>;
[[nodiscard]] auto make_object_lineage(
    const BinaryImage& original,
    const BinaryImage& protectedImage,
    const BinaryImage& protectedProvenance,
    std::string inputSha256,
    std::string outputSha256) -> Result<LineageDocument, Diagnostic>;

} // namespace binobf::evidence

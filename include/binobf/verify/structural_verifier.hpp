#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/model.hpp>
#include <binobf/core/result.hpp>
#include <binobf/formats/archive.hpp>

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace binobf {

enum class VerificationStatus {
    Passed,
    NotApplicable,
    Unsupported,
};

struct VerificationCheck {
    std::string name;
    VerificationStatus status{VerificationStatus::Unsupported};
    std::size_t examined{0};
};

struct StructuralVerificationReport {
    BinaryImage image;
    std::vector<VerificationCheck> checks;
};

struct ArchiveVerificationReport {
    ArchiveImage image;
    std::vector<VerificationCheck> checks;
};

[[nodiscard]] auto verification_status_name(VerificationStatus status) noexcept
    -> std::string_view;

[[nodiscard]] auto verify_object(
    std::span<const std::byte> bytes,
    std::string_view sourceName = {}) -> Result<StructuralVerificationReport, Diagnostic>;

[[nodiscard]] auto verify_linked_image(
    std::span<const std::byte> bytes,
    std::string_view sourceName = {}) -> Result<StructuralVerificationReport, Diagnostic>;

[[nodiscard]] auto verify_archive(
    std::span<const std::byte> bytes,
    std::string_view sourceName = {}) -> Result<ArchiveVerificationReport, Diagnostic>;

} // namespace binobf

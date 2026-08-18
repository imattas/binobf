#include <binobf/capabilities/evidence.hpp>

#include <algorithm>
#include <array>
#include <string>
#include <utility>
#include <vector>

namespace binobf {
namespace {

constexpr std::array kBuiltinEvidence{
    AcceptanceEvidence{"archive", "archive_integration", true},
    AcceptanceEvidence{"baseline_transforms", "baseline_transforms", true},
    AcceptanceEvidence{"coff_object_parser", "object_parser_integration", true},
    AcceptanceEvidence{"elf_object_parser", "object_parser_integration", true},
    AcceptanceEvidence{"format_detector", "format_detector", true},
    AcceptanceEvidence{"instruction_decoder", "instruction_decoder", true},
    AcceptanceEvidence{"instruction_transforms", "instruction_transform_integration", true},
    AcceptanceEvidence{"linked_image", "linked_image_integration", true},
    AcceptanceEvidence{"object_analyzer", "object_analyzer", true},
    AcceptanceEvidence{"object_writer", "object_writer_integration", true},
    AcceptanceEvidence{"structural_verifier", "structural_verifier", true},
    AcceptanceEvidence{"x86_abi_adapter", "x86_abi_native_differential", true},
    AcceptanceEvidence{"x86_codegen", "x86_native_differential", true},
    AcceptanceEvidence{"x86_object_backend", "x86_object_backend", true},
    AcceptanceEvidence{"x86_unwind", "x86_unwind_semantics", true},
    AcceptanceEvidence{"arm64_abi_adapter", "arm64_abi_native_differential", true},
    AcceptanceEvidence{"arm64_codegen", "arm64_native_differential", true},
    AcceptanceEvidence{"arm64_object_backend", "arm64_object_backend", true},
    AcceptanceEvidence{"arm64_unwind", "arm64_unwind_semantics", true},
};

auto failure(std::string code, std::string message)
    -> Result<std::size_t, Diagnostic> {
    return Result<std::size_t, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error,
        std::move(code),
        std::move(message),
    });
}

} // namespace

auto builtin_acceptance_evidence() -> std::span<const AcceptanceEvidence> {
    return kBuiltinEvidence;
}

auto validate_capability_evidence(
    const CapabilityRegistry& registry,
    std::span<const AcceptanceEvidence> evidence)
    -> Result<std::size_t, Diagnostic> {
    std::vector<const AcceptanceEvidence*> sorted;
    sorted.reserve(evidence.size());
    for (const auto& item : evidence) {
        sorted.push_back(&item);
    }
    std::ranges::sort(sorted, {}, [](const AcceptanceEvidence* item) {
        return item->id;
    });

    const auto duplicate = std::adjacent_find(
        sorted.begin(), sorted.end(),
        [](const AcceptanceEvidence* left, const AcceptanceEvidence* right) {
            return left->id == right->id;
        });
    if (duplicate != sorted.end()) {
        return failure("capability.duplicate_evidence",
                       "acceptance evidence catalog contains duplicate id: " +
                           std::string((*duplicate)->id));
    }

    for (const auto* item : sorted) {
        if (item->id.empty() || item->ctestName.empty()) {
            return failure("capability.invalid_evidence",
                           "acceptance evidence requires non-empty id and CTest name");
        }
    }

    std::size_t validatedSupportedRecords = 0;
    for (const auto& record : registry.records()) {
        if (record.support == SupportLevel::Supported && record.evidence.empty()) {
            return failure("capability.missing_evidence",
                           "supported capability has no acceptance evidence: " +
                               std::string(to_string(record.key.capability)));
        }

        for (const auto referencedId : record.evidence) {
            const auto found = std::ranges::lower_bound(
                sorted, referencedId, {}, [](const AcceptanceEvidence* item) {
                    return item->id;
                });
            if (found == sorted.end() || (*found)->id != referencedId) {
                return failure("capability.unknown_evidence",
                               "capability references unknown evidence id: " +
                                   std::string(referencedId));
            }
            if (record.support == SupportLevel::Supported && !(*found)->releaseGate) {
                return failure("capability.disabled_evidence",
                               "supported capability references disabled evidence id: " +
                                   std::string(referencedId));
            }
        }

        if (record.support == SupportLevel::Supported) {
            ++validatedSupportedRecords;
        }
    }

    return Result<std::size_t, Diagnostic>::success(validatedSupportedRecords);
}

} // namespace binobf

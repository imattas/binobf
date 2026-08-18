#include <binobf/evidence/manifest.hpp>

#include <nlohmann/json.hpp>

#include <string>

#ifndef BINOBF_VERSION
#define BINOBF_VERSION "unknown"
#endif

namespace binobf::evidence {

auto tool_version() noexcept -> std::string_view {
    return BINOBF_VERSION;
}

auto serialize_manifest(const BuildManifest& manifest) -> std::string {
    nlohmann::json reports = nlohmann::json::array();
    for (const auto& report : manifest.reports) {
        reports.push_back(nlohmann::json{
            {"changed", report.changed},
            {"examined", report.examined},
            {"name", report.name},
            {"skipped", report.skipped},
            {"status", report.status},
        });
    }

    const nlohmann::json json{
        {"architecture", manifest.architecture},
        {"config_sha256", manifest.configSha256},
        {"format", manifest.format},
        {"input", nlohmann::json{{"name", manifest.inputName},
                                  {"sha256", manifest.inputSha256},
                                  {"size", manifest.inputSize}}},
        {"output", nlohmann::json{{"name", manifest.outputName},
                                   {"sha256", manifest.outputSha256},
                                   {"size", manifest.outputSize}}},
        {"passes", manifest.passes},
        {"reports", std::move(reports)},
        {"schema_version", manifest.schemaVersion},
        {"seed", manifest.seed},
        {"tool", nlohmann::json{{"name", "binobf"},
                                 {"version", manifest.toolVersion}}},
        {"verification", manifest.verification},
    };
    return json.dump() + '\n';
}

} // namespace binobf::evidence

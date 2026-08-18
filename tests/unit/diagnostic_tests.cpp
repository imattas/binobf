#include "../test_support.hpp"

#include <binobf/core/diagnostic.hpp>

#include <string>

TEST_CASE(text_diagnostic_contains_actionable_context) {
    binobf::Diagnostic diagnostic{
        binobf::DiagnosticSeverity::Error,
        "format.truncated",
        "input ended before the COFF header",
    };
    diagnostic.pass = "format-detection";
    diagnostic.function = "fixture";
    diagnostic.originalAddress = binobf::BinaryAddress{0x40, binobf::AddressKind::FileOffset};
    diagnostic.transformedEntity = binobf::EntityId{9};

    const auto rendered = binobf::render_text(diagnostic);
    REQUIRE(rendered.find("error[format.truncated]") != std::string::npos);
    REQUIRE(rendered.find("input ended before the COFF header") != std::string::npos);
    REQUIRE(rendered.find("pass=format-detection") != std::string::npos);
    REQUIRE(rendered.find("address=0x40") != std::string::npos);
    REQUIRE(rendered.find("entity=9") != std::string::npos);
}

TEST_CASE(json_diagnostic_escapes_all_json_control_characters) {
    const binobf::Diagnostic diagnostic{
        binobf::DiagnosticSeverity::Warning,
        "format.\"odd\"",
        "line 1\nline 2\t\\end\x01",
    };

    REQUIRE_EQ(
        binobf::render_json(diagnostic),
        "{\"severity\":\"warning\",\"code\":\"format.\\\"odd\\\"\","
        "\"message\":\"line 1\\nline 2\\t\\\\end\\u0001\"}");
}

TEST_CASE(diagnostic_severity_names_are_stable) {
    REQUIRE_EQ(binobf::to_string(binobf::DiagnosticSeverity::Info), "info");
    REQUIRE_EQ(binobf::to_string(binobf::DiagnosticSeverity::Warning), "warning");
    REQUIRE_EQ(binobf::to_string(binobf::DiagnosticSeverity::Error), "error");
}

TEST_CASE(diagnostics_render_explanation_remediation_and_lineage_deterministically) {
    binobf::Diagnostic diagnostic{
        binobf::DiagnosticSeverity::Warning,
        "transform.skipped",
        "selected transformation was skipped",
    };
    diagnostic.explanation = "an indirect branch was not resolved safely";
    diagnostic.remediation = "provide complete relocation metadata";
    diagnostic.lineage.push_back(binobf::DiagnosticLineageEntry{
        .transform = binobf::TransformId{7},
        .source = binobf::EntityId{3},
        .pass = "branch-inversion",
    });

    REQUIRE_EQ(
        binobf::render_text(diagnostic),
        "warning[transform.skipped]: selected transformation was skipped"
        " explanation=an indirect branch was not resolved safely"
        " remediation=provide complete relocation metadata"
        " lineage=[7:3:branch-inversion]");
    REQUIRE_EQ(
        binobf::render_json(diagnostic),
        "{\"severity\":\"warning\",\"code\":\"transform.skipped\","
        "\"message\":\"selected transformation was skipped\","
        "\"explanation\":\"an indirect branch was not resolved safely\","
        "\"remediation\":\"provide complete relocation metadata\","
        "\"lineage\":[{\"transform\":7,\"source\":3,\"pass\":\"branch-inversion\"}]}" );
}

int main() {
    return binobf::test::run_all();
}

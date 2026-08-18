#include <binobf/core/diagnostic.hpp>

#include <iomanip>
#include <sstream>

namespace binobf {
namespace {

auto escape_json(std::string_view input) -> std::string {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const char rawCharacter : input) {
        const auto character = static_cast<unsigned char>(rawCharacter);
        switch (character) {
        case '"': output << "\\\""; break;
        case '\\': output << "\\\\"; break;
        case '\b': output << "\\b"; break;
        case '\f': output << "\\f"; break;
        case '\n': output << "\\n"; break;
        case '\r': output << "\\r"; break;
        case '\t': output << "\\t"; break;
        default:
            if (character < 0x20U) {
                output << "\\u" << std::setw(4) << static_cast<unsigned int>(character);
            } else {
                output << static_cast<char>(character);
            }
            break;
        }
    }
    return output.str();
}

void append_json_string(std::ostringstream& output, std::string_view key, std::string_view value) {
    output << ",\"" << key << "\":\"" << escape_json(value) << '"';
}

} // namespace

auto to_string(DiagnosticSeverity severity) noexcept -> std::string_view {
    switch (severity) {
    case DiagnosticSeverity::Info: return "info";
    case DiagnosticSeverity::Warning: return "warning";
    case DiagnosticSeverity::Error: return "error";
    }
    return "error";
}

auto render_text(const Diagnostic& diagnostic) -> std::string {
    std::ostringstream output;
    output << to_string(diagnostic.severity) << '[' << diagnostic.code << "]: "
           << diagnostic.message;
    if (diagnostic.pass.has_value()) {
        output << " pass=" << *diagnostic.pass;
    }
    if (diagnostic.function.has_value()) {
        output << " function=" << *diagnostic.function;
    }
    if (diagnostic.originalAddress.has_value()) {
        output << " address=0x" << std::hex << diagnostic.originalAddress->value << std::dec;
    }
    if (diagnostic.transformedEntity.has_value()) {
        output << " entity=" << diagnostic.transformedEntity->value();
    }
    if (diagnostic.explanation.has_value()) {
        output << " explanation=" << *diagnostic.explanation;
    }
    if (diagnostic.remediation.has_value()) {
        output << " remediation=" << *diagnostic.remediation;
    }
    if (!diagnostic.lineage.empty()) {
        output << " lineage=[";
        for (std::size_t index = 0; index < diagnostic.lineage.size(); ++index) {
            if (index != 0) output << ',';
            const auto& entry = diagnostic.lineage[index];
            output << entry.transform.value() << ':' << entry.source.value()
                   << ':' << entry.pass;
        }
        output << ']';
    }
    return output.str();
}

auto render_json(const Diagnostic& diagnostic) -> std::string {
    std::ostringstream output;
    output << "{\"severity\":\"" << to_string(diagnostic.severity) << '"';
    append_json_string(output, "code", diagnostic.code);
    append_json_string(output, "message", diagnostic.message);
    if (diagnostic.explanation.has_value()) {
        append_json_string(output, "explanation", *diagnostic.explanation);
    }
    if (diagnostic.remediation.has_value()) {
        append_json_string(output, "remediation", *diagnostic.remediation);
    }
    if (diagnostic.pass.has_value()) {
        append_json_string(output, "pass", *diagnostic.pass);
    }
    if (diagnostic.function.has_value()) {
        append_json_string(output, "function", *diagnostic.function);
    }
    if (diagnostic.originalAddress.has_value()) {
        output << ",\"original_address\":" << diagnostic.originalAddress->value;
    }
    if (diagnostic.transformedEntity.has_value()) {
        output << ",\"transformed_entity\":" << diagnostic.transformedEntity->value();
    }
    if (!diagnostic.lineage.empty()) {
        output << ",\"lineage\":[";
        for (std::size_t index = 0; index < diagnostic.lineage.size(); ++index) {
            if (index != 0) output << ',';
            const auto& entry = diagnostic.lineage[index];
            output << "{\"transform\":" << entry.transform.value()
                   << ",\"source\":" << entry.source.value();
            append_json_string(output, "pass", entry.pass);
            output << '}';
        }
        output << ']';
    }
    output << '}';
    return output.str();
}

} // namespace binobf

#include <binobf/capabilities/evidence.hpp>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

namespace {

constexpr std::uintmax_t kMaximumCTestFileSize = 16U * 1024U * 1024U;

} // namespace

auto main(int argc, char** argv) -> int {
    if (argc != 2) {
        std::cerr << "usage: capability_evidence_tests <CTestTestfile.cmake>\n";
        return 2;
    }

    std::ifstream input(argv[1], std::ios::binary | std::ios::ate);
    if (!input) {
        std::cerr << "cannot open generated CTest file: " << argv[1] << '\n';
        return 2;
    }
    const auto end = input.tellg();
    if (end < 0 || static_cast<std::uintmax_t>(end) > kMaximumCTestFileSize) {
        std::cerr << "generated CTest file is invalid or exceeds the bounded read limit\n";
        return 2;
    }
    input.seekg(0);
    const std::string contents(std::istreambuf_iterator<char>{input},
                               std::istreambuf_iterator<char>{});
    if (input.bad()) {
        std::cerr << "failed while reading generated CTest file\n";
        return 2;
    }

    const auto validated = binobf::validate_capability_evidence(
        binobf::builtin_capability_registry(),
        binobf::builtin_acceptance_evidence());
    if (!validated.has_value()) {
        std::cerr << validated.error().code << ": " << validated.error().message << '\n';
        return 1;
    }

    for (const auto& evidence : binobf::builtin_acceptance_evidence()) {
        if (!evidence.releaseGate) {
            continue;
        }
        const std::string declaration =
            "add_test(\"" + std::string(evidence.ctestName) + "\"";
        if (contents.find(declaration) == std::string::npos) {
            std::cerr << "missing registered release-gate CTest: "
                      << evidence.ctestName << '\n';
            return 1;
        }
    }

    return 0;
}

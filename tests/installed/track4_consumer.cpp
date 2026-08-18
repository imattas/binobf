#include <binobf/analysis/object_analyzer.hpp>
#include <binobf/architecture/backend.hpp>
#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/transforms/instruction.hpp>
#include <binobf/transforms/pass_manager.hpp>

#include <fstream>
#include <cstring>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

auto read(const char* path) -> std::vector<std::byte> {
    std::ifstream input(path, std::ios::binary);
    const std::vector<char> raw{std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
    std::vector<std::byte> result(raw.size());
    std::memcpy(result.data(), raw.data(), raw.size());
    return result;
}

auto pass(std::size_t index) -> std::unique_ptr<binobf::TransformPass> {
    switch (index) {
    case 0: return binobf::make_instruction_substitution_pass();
    case 1: return binobf::make_constant_rewriting_pass();
    case 2: return binobf::make_branch_inversion_pass();
    case 3: return binobf::make_block_splitting_pass();
    case 4: return binobf::make_dead_code_insertion_pass();
    case 5: return binobf::make_block_reordering_pass();
    default: return binobf::make_function_reordering_pass();
    }
}

int main(int argc, char** argv) {
    if (argc != 3) return 2;
    auto backend = binobf::make_architecture_backend(binobf::Architecture::ARM64);
    if (!backend.has_value()) return 3;
    for (const auto service : {binobf::BackendService::AnalyzeObject,
                               binobf::BackendService::EmitCode,
                               binobf::BackendService::EncodeFixups,
                               binobf::BackendService::BuildAbiAdapter,
                               binobf::BackendService::BuildUnwind}) {
        const auto* record = backend.value()->find_service(service);
        if (record == nullptr || record->support != binobf::SupportLevel::Supported
            || record->evidence.empty()) return 4;
    }
    binobf::MachineTransformRequest request{};
    request.architecture = binobf::Architecture::ARM64;
    request.format = binobf::BinaryFormat::ELF;
    request.kind = binobf::MachineTransformKind::DeadCodeFill;
    request.exactSize = 4;
    if (!backend.value()->emit_transform(request).has_value()) return 5;
    for (int file = 1; file <= 2; ++file) {
        const auto parsed = binobf::parse_object(read(argv[file]), "installed-arm64.o");
        if (!parsed.has_value() || parsed.value().architecture != binobf::Architecture::ARM64) return 6;
        if (!binobf::analyze_object(parsed.value()).has_value()) return 7;
        for (std::size_t index = 0; index < 7; ++index) {
            binobf::PassManager manager;
            if (!manager.add(pass(index)).has_value()) return 8;
            binobf::TransformContext context{UINT64_C(0x4a64), false};
            const auto outcome = manager.run(context, parsed.value());
            if (!outcome.has_value() || outcome.value().reports.size() != 1) return 9;
            const auto written = binobf::write_object(outcome.value().image);
            if (!written.has_value() || !binobf::parse_object(written.value(), "roundtrip.o").has_value()) return 10;
        }
    }
    return 0;
}

#include <binobf/formats/archive.hpp>
#include <binobf/formats/archive_writer.hpp>
#include <binobf/formats/detector.hpp>
#include <binobf/formats/linked_image.hpp>
#include <binobf/formats/linked_writer.hpp>
#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/verify/structural_verifier.hpp>
#include <binobf/vm/bytecode.hpp>
#include <binobf/vm/runtime.hpp>

#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

struct Options {
    std::size_t iterations{100};
    std::vector<std::filesystem::path> fixtures;
};

auto parse_options(int argc, char** argv) -> Options {
    Options options;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument{argv[index]};
        if (argument.starts_with("--iterations=")) {
            const auto value = argument.substr(std::string_view{"--iterations="}.size());
            const auto parsed = std::from_chars(
                value.data(), value.data() + value.size(), options.iterations, 10);
            if (value.empty() || parsed.ec != std::errc{}
                || parsed.ptr != value.data() + value.size()
                || options.iterations == 0 || options.iterations > 1'000'000) {
                throw std::runtime_error("iterations must be an integer from 1 through 1000000");
            }
        } else {
            options.fixtures.emplace_back(argument);
        }
    }
    if (options.fixtures.empty()) {
        throw std::runtime_error("usage: binobf-benchmarks [--iterations=N] <fixture>...");
    }
    return options;
}

auto read_file(const std::filesystem::path& path) -> std::vector<std::byte> {
    std::error_code sizeError;
    const auto size = std::filesystem::file_size(path, sizeError);
    if (sizeError || size > 512U * 1024U * 1024U) {
        throw std::runtime_error("could not size benchmark fixture: " + path.string());
    }
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    std::ifstream stream(path, std::ios::binary);
    stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!stream) throw std::runtime_error("could not read benchmark fixture: " + path.string());
    return bytes;
}

auto is_linked(binobf::BinaryType type) -> bool {
    return type == binobf::BinaryType::Executable
        || type == binobf::BinaryType::SharedLibrary
        || type == binobf::BinaryType::KernelDriver;
}

auto run_pipeline(
    std::span<const std::byte> bytes,
    std::string_view name,
    const binobf::DetectionResult& detection) -> std::size_t {
    if (detection.format == binobf::BinaryFormat::Archive) {
        const auto parsed = binobf::parse_archive(bytes, name);
        if (!parsed.has_value()) throw std::runtime_error(parsed.error().message);
        const auto written = binobf::write_archive(parsed.value());
        if (!written.has_value()) throw std::runtime_error(written.error().message);
        const auto verified = binobf::verify_archive(written.value(), name);
        if (!verified.has_value()) throw std::runtime_error(verified.error().message);
        return verified.value().image.members.size() + verified.value().image.symbols.size();
    }
    if (is_linked(detection.type)) {
        const auto parsed = binobf::parse_linked_image(bytes, name);
        if (!parsed.has_value()) throw std::runtime_error(parsed.error().message);
        const auto written = binobf::rewrite_linked_image(parsed.value());
        if (!written.has_value()) throw std::runtime_error(written.error().message);
        const auto verified = binobf::verify_linked_image(written.value().bytes, name);
        if (!verified.has_value()) throw std::runtime_error(verified.error().message);
        return verified.value().image.sections.size() + verified.value().checks.size();
    }
    const auto parsed = binobf::parse_object(bytes, name);
    if (!parsed.has_value()) throw std::runtime_error(parsed.error().message);
    const auto written = binobf::write_object(parsed.value());
    if (!written.has_value()) throw std::runtime_error(written.error().message);
    const auto verified = binobf::verify_object(written.value(), name);
    if (!verified.has_value()) throw std::runtime_error(verified.error().message);
    return verified.value().image.sections.size() + verified.value().image.symbols.size();
}

auto nanoseconds(Clock::duration duration) -> std::uint64_t {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count());
}

void benchmark_fixture(const std::filesystem::path& path, std::size_t iterations) {
    const auto bytes = read_file(path);
    const auto name = path.filename().string();
    const auto detection = binobf::detect_binary(bytes, name);
    if (!detection.has_value()) throw std::runtime_error(detection.error().message);
    for (std::size_t warmup = 0; warmup < 3; ++warmup) {
        static_cast<void>(run_pipeline(bytes, name, detection.value()));
    }

    std::size_t digest = 0;
    const auto detectStart = Clock::now();
    for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
        const auto detected = binobf::detect_binary(bytes, name);
        if (!detected.has_value()) throw std::runtime_error(detected.error().message);
        digest += static_cast<std::size_t>(detected.value().format);
    }
    const auto detectElapsed = Clock::now() - detectStart;
    const auto pipelineStart = Clock::now();
    for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
        digest += run_pipeline(bytes, name, detection.value());
    }
    const auto pipelineElapsed = Clock::now() - pipelineStart;
    const auto detectNs = nanoseconds(detectElapsed);
    const auto pipelineNs = nanoseconds(pipelineElapsed);
    const auto operationsPerSecond = pipelineNs == 0 ? 0.0
        : static_cast<double>(iterations) * 1'000'000'000.0
            / static_cast<double>(pipelineNs);
    const auto mebibytesPerSecond = pipelineNs == 0 ? 0.0
        : static_cast<double>(bytes.size()) * static_cast<double>(iterations)
            * 1'000'000'000.0 / static_cast<double>(pipelineNs)
            / (1024.0 * 1024.0);
    std::cout << "fixture: " << path.string() << '\n'
              << "format: " << binobf::to_string(detection.value().format) << '\n'
              << "bytes: " << bytes.size() << '\n'
              << "iterations: " << iterations << '\n'
              << "detect-ns-total: " << detectNs << '\n'
              << "pipeline-ns-total: " << pipelineNs << '\n'
              << std::fixed << std::setprecision(2)
              << "pipeline-ops-per-second: " << operationsPerSecond << '\n'
              << "pipeline-mib-per-second: " << mebibytesPerSecond << '\n'
              << "digest: " << digest << "\n\n";
}

void benchmark_vm(std::size_t iterations) {
    using namespace binobf::vm;
    const VmProgram program{
        .version = currentVmVersion,
        .registerCount = 3,
        .slotCount = 0,
        .localMemorySize = 0,
        .instructions = {
            VmLoadConstant{VmRegister{0}, VmValue::from_bits(VmWidth::U32, 20)},
            VmLoadConstant{VmRegister{1}, VmValue::from_bits(VmWidth::U32, 22)},
            VmBinaryOperation{
                VmBinaryOpcode::Add, VmWidth::U32,
                VmRegister{2}, VmRegister{0}, VmRegister{1}},
            VmReturn{VmRegister{2}},
        },
    };
    const auto bytecode = assemble_program(program, VmAssemblyOptions{12012});
    if (!bytecode.has_value()) throw std::runtime_error(bytecode.error().message);
    std::uint64_t digest = 0;
    const auto start = Clock::now();
    for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
        const auto decoded = decode_program(bytecode.value());
        if (!decoded.has_value()) throw std::runtime_error(decoded.error().message);
        LinearVmMemory memory{0};
        RejectingVmNativeCallBridge bridge;
        const auto executed = execute_program(decoded.value().program, memory, bridge);
        if (!executed.has_value()) throw std::runtime_error(executed.error().message);
        digest += executed.value().returnValue.bits();
    }
    const auto elapsed = nanoseconds(Clock::now() - start);
    const auto operationsPerSecond = elapsed == 0 ? 0.0
        : static_cast<double>(iterations) * 1'000'000'000.0
            / static_cast<double>(elapsed);
    std::cout << "fixture: internal-vm-decode-execute\n"
              << "iterations: " << iterations << '\n'
              << "pipeline-ns-total: " << elapsed << '\n'
              << std::fixed << std::setprecision(2)
              << "pipeline-ops-per-second: " << operationsPerSecond << '\n'
              << "digest: " << digest << '\n';
}

} // namespace

int main(int argc, char** argv) {
    try {
        const auto options = parse_options(argc, argv);
        for (const auto& fixture : options.fixtures) {
            benchmark_fixture(fixture, options.iterations);
        }
        benchmark_vm(options.iterations);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "benchmark error: " << error.what() << '\n';
        return 2;
    }
}

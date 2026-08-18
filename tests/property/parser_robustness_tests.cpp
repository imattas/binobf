#include "../test_support.hpp"

#include <binobf/formats/archive.hpp>
#include <binobf/formats/archive_writer.hpp>
#include <binobf/formats/detector.hpp>
#include <binobf/formats/linked_image.hpp>
#include <binobf/formats/linked_writer.hpp>
#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/support/deterministic_rng.hpp>
#include <binobf/verify/structural_verifier.hpp>
#include <binobf/vm/bytecode.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#if defined(_WIN32) && defined(_DEBUG)
#include <crtdbg.h>
#endif

namespace {

std::vector<std::filesystem::path> objectFixtures;
std::vector<std::filesystem::path> linkedFixtures;
std::filesystem::path archiveFixture;

auto read_file(const std::filesystem::path& path) -> std::vector<std::byte> {
    std::error_code sizeError;
    const auto size = std::filesystem::file_size(path, sizeError);
    if (sizeError) throw std::runtime_error("could not size robustness fixture");
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    std::ifstream stream(path, std::ios::binary);
    stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!stream) throw std::runtime_error("could not read robustness fixture");
    return bytes;
}

auto mutate(
    const std::vector<std::byte>& seed,
    binobf::DeterministicRng& rng) -> std::vector<std::byte> {
    auto bytes = seed;
    if (bytes.empty()) bytes.push_back(std::byte{0});
    switch (rng.uniform(4)) {
    case 0: {
        const auto offset = static_cast<std::size_t>(rng.uniform(bytes.size()));
        const auto bit = static_cast<unsigned int>(rng.uniform(8));
        bytes[offset] ^= static_cast<std::byte>(1U << bit);
        break;
    }
    case 1:
        bytes.resize(static_cast<std::size_t>(rng.uniform(bytes.size() + 1U)));
        break;
    case 2: {
        const auto offset = static_cast<std::size_t>(rng.uniform(bytes.size()));
        const auto count = std::min<std::size_t>(
            bytes.size() - offset, static_cast<std::size_t>(rng.uniform(8) + 1U));
        for (std::size_t index = 0; index < count; ++index) {
            bytes[offset + index] = static_cast<std::byte>(rng.next_u64() & 0xffU);
        }
        break;
    }
    default: {
        const auto offset = static_cast<std::size_t>(rng.uniform(bytes.size() + 1U));
        const auto count = static_cast<std::size_t>(rng.uniform(8) + 1U);
        std::vector<std::byte> inserted(count);
        for (auto& byte : inserted) byte = static_cast<std::byte>(rng.next_u64() & 0xffU);
        bytes.insert(
            bytes.begin() + static_cast<std::ptrdiff_t>(offset),
            inserted.begin(), inserted.end());
        break;
    }
    }
    return bytes;
}

template <typename ResultType>
auto stable_outcome(const ResultType& result) -> std::string {
    return result.has_value()
        ? std::string{"ok"}
        : result.error().code + "\n" + result.error().message;
}

void exercise_object(std::span<const std::byte> bytes, std::string_view name) {
    const auto first = binobf::parse_object(bytes, name);
    const auto second = binobf::parse_object(bytes, name);
    REQUIRE_EQ(stable_outcome(first), stable_outcome(second));
    if (!first.has_value()) return;
    const auto written = binobf::write_object(first.value());
    if (written.has_value()) {
        static_cast<void>(binobf::verify_object(written.value(), name));
    }
}

void exercise_linked(std::span<const std::byte> bytes, std::string_view name) {
    auto limits = binobf::LinkedParseLimits{};
    limits.maxInputBytes = 1U << 20U;
    limits.maxSections = 512;
    limits.maxSegments = 512;
    limits.maxSymbols = 65536;
    limits.maxImports = 65536;
    limits.maxExports = 65536;
    limits.maxRelocations = 262144;
    limits.maxStringBytes = 1U << 20U;
    const auto first = binobf::parse_linked_image(bytes, name, limits);
    const auto second = binobf::parse_linked_image(bytes, name, limits);
    REQUIRE_EQ(stable_outcome(first), stable_outcome(second));
    if (!first.has_value()) return;
    const auto written = binobf::rewrite_linked_image(first.value());
    if (written.has_value()) {
        static_cast<void>(binobf::verify_linked_image(written.value().bytes, name));
    }
}

void exercise_archive(std::span<const std::byte> bytes) {
    auto limits = binobf::ArchiveParseLimits{};
    limits.maxInputBytes = 1U << 20U;
    limits.maxMembers = 4096;
    limits.maxSymbols = 65536;
    limits.maxNameBytes = 1U << 20U;
    const auto first = binobf::parse_archive(bytes, "mutated.a", limits);
    const auto second = binobf::parse_archive(bytes, "mutated.a", limits);
    REQUIRE_EQ(stable_outcome(first), stable_outcome(second));
    if (!first.has_value()) return;
    const auto written = binobf::write_archive(first.value());
    if (written.has_value()) {
        static_cast<void>(binobf::verify_archive(written.value(), "mutated.a"));
    }
}

void exercise_bytecode(std::span<const std::byte> bytes) {
    auto limits = binobf::vm::VmLimits{};
    limits.maxBytecodeBytes = 1U << 20U;
    limits.maxInstructions = 65536;
    limits.maxRegisters = 1024;
    limits.maxSlots = 1024;
    limits.maxMemoryBytes = 1U << 20U;
    limits.maxSteps = 100000;
    const auto first = binobf::vm::decode_program(bytes, limits);
    const auto second = binobf::vm::decode_program(bytes, limits);
    REQUIRE_EQ(stable_outcome(first), stable_outcome(second));
    if (!first.has_value()) return;
    static_cast<void>(binobf::vm::assemble_program(
        first.value().program,
        binobf::vm::VmAssemblyOptions{first.value().encodingSeed},
        limits));
}

} // namespace

TEST_CASE(deterministic_mutations_of_real_binary_fixtures_never_escape_structured_results) {
    binobf::DeterministicRng rng{UINT64_C(0x435241534850524f)};
    for (const auto& path : objectFixtures) {
        const auto seed = read_file(path);
        for (std::size_t iteration = 0; iteration < 768; ++iteration) {
            const auto bytes = mutate(seed, rng);
            static_cast<void>(binobf::detect_binary(bytes, path.filename().string()));
            exercise_object(bytes, path.filename().string());
        }
    }
    for (const auto& path : linkedFixtures) {
        const auto seed = read_file(path);
        for (std::size_t iteration = 0; iteration < 768; ++iteration) {
            const auto bytes = mutate(seed, rng);
            static_cast<void>(binobf::detect_binary(bytes, path.filename().string()));
            exercise_linked(bytes, path.filename().string());
        }
    }
    const auto archiveSeed = read_file(archiveFixture);
    for (std::size_t iteration = 0; iteration < 1024; ++iteration) {
        const auto bytes = mutate(archiveSeed, rng);
        static_cast<void>(binobf::detect_binary(bytes, "mutated.a"));
        exercise_archive(bytes);
    }
}

TEST_CASE(deterministic_mutations_of_valid_vm_bytecode_fail_or_round_trip_cleanly) {
    const binobf::vm::VmProgram program{
        .version = binobf::vm::currentVmVersion,
        .registerCount = 3,
        .slotCount = 1,
        .localMemorySize = 16,
        .instructions = {
            binobf::vm::VmLoadConstant{
                binobf::vm::VmRegister{0},
                binobf::vm::VmValue::from_bits(binobf::vm::VmWidth::U32, 17)},
            binobf::vm::VmStoreSlot{
                binobf::vm::VmWidth::U32,
                binobf::vm::VmSlot{0},
                binobf::vm::VmRegister{0}},
            binobf::vm::VmLoadSlot{
                binobf::vm::VmWidth::U32,
                binobf::vm::VmRegister{1},
                binobf::vm::VmSlot{0}},
            binobf::vm::VmLoadConstant{
                binobf::vm::VmRegister{2},
                binobf::vm::VmValue::from_bits(binobf::vm::VmWidth::U32, 25)},
            binobf::vm::VmBinaryOperation{
                binobf::vm::VmBinaryOpcode::Add,
                binobf::vm::VmWidth::U32,
                binobf::vm::VmRegister{0},
                binobf::vm::VmRegister{1},
                binobf::vm::VmRegister{2}},
            binobf::vm::VmReturn{binobf::vm::VmRegister{0}},
        },
    };
    const auto assembled = binobf::vm::assemble_program(
        program, binobf::vm::VmAssemblyOptions{5519});
    REQUIRE(assembled.has_value());
    binobf::DeterministicRng rng{UINT64_C(0x42595445434f4445)};
    for (std::size_t iteration = 0; iteration < 4096; ++iteration) {
        exercise_bytecode(mutate(assembled.value(), rng));
    }
}

int main(int argc, char** argv) {
    if (argc != 7) return 2;
#if defined(_WIN32) && defined(_DEBUG)
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_DEBUG);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
    objectFixtures = {argv[1], argv[2]};
    linkedFixtures = {argv[3], argv[4], argv[5]};
    archiveFixture = argv[6];
    return binobf::test::run_all();
}

#include "../test_support.hpp"

#include <binobf/formats/archive.hpp>
#include <binobf/formats/linked_image.hpp>
#include <binobf/formats/linked_writer.hpp>
#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/transforms/instruction.hpp>
#include <binobf/transforms/pass_manager.hpp>
#include <binobf/verify/structural_verifier.hpp>
#include <binobf/vm/bytecode.hpp>
#include <binobf/vm/runtime.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::filesystem::path coffFixture;
std::filesystem::path elfObjectFixture;
std::filesystem::path peFixture;
std::filesystem::path elfLinkedFixture;
std::filesystem::path archiveFixture;

auto read_file(const std::filesystem::path& path) -> std::vector<std::byte> {
    std::error_code sizeError;
    const auto size = std::filesystem::file_size(path, sizeError);
    if (sizeError) throw std::runtime_error("could not size mutation fixture");
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    std::ifstream stream(path, std::ios::binary);
    stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!stream) throw std::runtime_error("could not read mutation fixture");
    return bytes;
}

void put_le16(std::vector<std::byte>& bytes, std::size_t offset, std::uint16_t value) {
    bytes.at(offset) = static_cast<std::byte>(value & 0xffU);
    bytes.at(offset + 1) = static_cast<std::byte>((value >> 8U) & 0xffU);
}

void put_le32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        bytes.at(offset + index) = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

void put_le64(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value) {
    for (std::size_t index = 0; index < 8; ++index) {
        bytes.at(offset + index) = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

void put_be32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        bytes.at(offset + index) = static_cast<std::byte>(
            (value >> ((3U - index) * 8U)) & 0xffU);
    }
}

struct MutationScore {
    std::size_t killed{0};
    std::size_t total{0};
    std::vector<std::string> survivors;

    void record(std::string_view name, bool wasKilled) {
        ++total;
        if (wasKilled) {
            ++killed;
        } else {
            survivors.emplace_back(name);
        }
    }
};

auto simple_vm_program() -> binobf::vm::VmProgram {
    using namespace binobf::vm;
    return VmProgram{
        .version = currentVmVersion,
        .registerCount = 3,
        .slotCount = 0,
        .localMemorySize = 0,
        .instructions = {
            VmLoadConstant{VmRegister{0}, VmValue::from_bits(VmWidth::U32, 19)},
            VmLoadConstant{VmRegister{1}, VmValue::from_bits(VmWidth::U32, 23)},
            VmBinaryOperation{
                VmBinaryOpcode::Add, VmWidth::U32,
                VmRegister{2}, VmRegister{0}, VmRegister{1}},
            VmReturn{VmRegister{2}},
        },
    };
}

} // namespace

TEST_CASE(required_artifact_and_model_mutations_are_all_killed) {
    MutationScore score;

    auto coffBadSection = read_file(coffFixture);
    put_le32(coffBadSection, 20 + 20, UINT32_C(0xfffffff0));
    score.record(
        "coff-section-range",
        !binobf::verify_object(coffBadSection, "mutant.obj").has_value());

    auto coffBadSymbols = read_file(coffFixture);
    put_le32(coffBadSymbols, 8, UINT32_C(0xfffffff0));
    put_le32(coffBadSymbols, 12, 1);
    score.record(
        "coff-symbol-range",
        !binobf::verify_object(coffBadSymbols, "mutant.obj").has_value());

    auto elfBadSections = read_file(elfObjectFixture);
    put_le64(elfBadSections, 40, UINT64_C(0xfffffffffffffff0));
    score.record(
        "elf-section-table-range",
        !binobf::verify_object(elfBadSections, "mutant.o").has_value());

    auto elfBadCount = read_file(elfObjectFixture);
    put_le16(elfBadCount, 60, UINT16_MAX);
    score.record(
        "elf-section-count",
        !binobf::verify_object(elfBadCount, "mutant.o").has_value());

    auto peBadHeader = read_file(peFixture);
    put_le32(peBadHeader, 0x3c, UINT32_C(0xfffffff0));
    score.record(
        "pe-header-range",
        !binobf::verify_linked_image(peBadHeader, "mutant.exe").has_value());

    const auto parsedPe = binobf::parse_linked_image(read_file(peFixture), "fixture.exe");
    REQUIRE(parsedPe.has_value());
    const auto checksummedPe = binobf::rewrite_linked_image(
        parsedPe.value(), binobf::LinkedRewriteOptions{.stripDebug = true});
    REQUIRE(checksummedPe.has_value());
    auto peBadChecksum = checksummedPe.value().bytes;
    REQUIRE(checksummedPe.value().image.checksum != 0);
    peBadChecksum.back() ^= std::byte{1};
    score.record(
        "pe-checksum",
        !binobf::verify_linked_image(peBadChecksum, "mutant.exe").has_value());

    auto elfBadProgramHeaders = read_file(elfLinkedFixture);
    put_le64(elfBadProgramHeaders, 32, UINT64_C(0xfffffffffffffff0));
    score.record(
        "elf-program-header-range",
        !binobf::verify_linked_image(elfBadProgramHeaders, "mutant.elf").has_value());

    auto elfBadEntry = read_file(elfLinkedFixture);
    put_le64(elfBadEntry, 24, UINT64_C(0xfffffffffffffff0));
    score.record(
        "elf-entry-mapping",
        !binobf::verify_linked_image(elfBadEntry, "mutant.elf").has_value());

    auto archiveBadTrailer = read_file(archiveFixture);
    archiveBadTrailer.at(8 + 58) = std::byte{'x'};
    score.record(
        "archive-member-trailer",
        !binobf::verify_archive(archiveBadTrailer, "mutant.a").has_value());

    auto archiveBadIndex = read_file(archiveFixture);
    const auto parsedArchive = binobf::parse_archive(archiveBadIndex, "fixture.a");
    REQUIRE(parsedArchive.has_value());
    const auto indexLayout = parsedArchive.value().layout.front();
    put_be32(
        archiveBadIndex,
        static_cast<std::size_t>(indexLayout.dataOffset) + 4,
        UINT32_C(0xfffffff0));
    score.record(
        "archive-symbol-member-offset",
        !binobf::verify_archive(archiveBadIndex, "mutant.a").has_value());

    const auto program = simple_vm_program();
    const auto assembled = binobf::vm::assemble_program(
        program, binobf::vm::VmAssemblyOptions{917});
    REQUIRE(assembled.has_value());
    auto bytecodeBadMagic = assembled.value();
    bytecodeBadMagic.front() ^= std::byte{1};
    score.record(
        "vm-bytecode-magic",
        !binobf::vm::decode_program(bytecodeBadMagic).has_value());

    auto bytecodeBadVersion = assembled.value();
    put_le16(bytecodeBadVersion, 4, UINT16_MAX);
    score.record(
        "vm-bytecode-version",
        !binobf::vm::decode_program(bytecodeBadVersion).has_value());

    auto bytecodeTruncated = assembled.value();
    bytecodeTruncated.pop_back();
    score.record(
        "vm-bytecode-truncation",
        !binobf::vm::decode_program(bytecodeTruncated).has_value());

    auto bytecodeLimits = binobf::vm::VmLimits{};
    bytecodeLimits.maxInstructions = 1;
    score.record(
        "vm-bytecode-instruction-limit",
        !binobf::vm::decode_program(assembled.value(), bytecodeLimits).has_value());

    auto badBranch = program;
    badBranch.instructions.insert(
        badBranch.instructions.end() - 1,
        binobf::vm::VmJump{UINT32_MAX});
    score.record(
        "vm-branch-target",
        !binobf::vm::validate_program(badBranch).has_value());

    auto uninitialized = program;
    uninitialized.instructions = {
        binobf::vm::VmReturn{binobf::vm::VmRegister{2}}};
    binobf::vm::LinearVmMemory emptyMemory{0};
    binobf::vm::RejectingVmNativeCallBridge bridge;
    score.record(
        "vm-uninitialized-register",
        !binobf::vm::execute_program(uninitialized, emptyMemory, bridge).has_value());

    auto divisionByZero = program;
    divisionByZero.instructions[2] = binobf::vm::VmBinaryOperation{
        binobf::vm::VmBinaryOpcode::Divide,
        binobf::vm::VmWidth::U32,
        binobf::vm::VmRegister{2},
        binobf::vm::VmRegister{0},
        binobf::vm::VmRegister{1}};
    divisionByZero.instructions[1] = binobf::vm::VmLoadConstant{
        binobf::vm::VmRegister{1},
        binobf::vm::VmValue::from_bits(binobf::vm::VmWidth::U32, 0)};
    score.record(
        "vm-division-precondition",
        !binobf::vm::execute_program(divisionByZero, emptyMemory, bridge).has_value());

    const auto parsedObject = binobf::parse_object(read_file(coffFixture), "fixture.obj");
    REQUIRE(parsedObject.has_value());
    auto wrongArchitecture = parsedObject.value();
    wrongArchitecture.architecture = binobf::Architecture::ARM64;
    binobf::PassManager manager;
    REQUIRE(manager.add(binobf::make_instruction_substitution_pass()).has_value());
    binobf::TransformContext context{77, false};
    const auto unsupported = manager.run(context, wrongArchitecture);
    score.record(
        "pass-architecture-precondition",
        unsupported.has_value() && unsupported.value().reports.size() == 1
            && unsupported.value().reports.front().status == binobf::PassStatus::Unsupported);

    auto danglingModel = parsedObject.value();
    const auto defined = std::find_if(
        danglingModel.symbols.begin(), danglingModel.symbols.end(),
        [](const binobf::Symbol& symbol) { return symbol.defined; });
    REQUIRE(defined != danglingModel.symbols.end());
    defined->section = binobf::EntityId{UINT64_C(0xffff)};
    score.record(
        "object-dangling-entity",
        !binobf::write_object(danglingModel).has_value());

    for (const auto& survivor : score.survivors) {
        std::cerr << "[SURVIVED] " << survivor << '\n';
    }
    std::cout << "mutation-score: " << score.killed << '/' << score.total << '\n';
    REQUIRE_EQ(score.killed, score.total);
}

int main(int argc, char** argv) {
    if (argc != 6) return 2;
    coffFixture = argv[1];
    elfObjectFixture = argv[2];
    peFixture = argv[3];
    elfLinkedFixture = argv[4];
    archiveFixture = argv[5];
    return binobf::test::run_all();
}

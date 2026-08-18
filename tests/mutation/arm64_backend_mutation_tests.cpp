#include "../test_support.hpp"

#include <binobf/architecture/backend.hpp>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <utility>

namespace {

auto backend() -> binobf::ArchitectureBackend& {
    static auto instance = [] {
        auto result = binobf::make_architecture_backend(binobf::Architecture::ARM64);
        if (!result.has_value()) throw std::runtime_error(result.error().message);
        return std::move(result).value();
    }();
    return *instance;
}

auto source(std::uint64_t address) -> binobf::Instruction {
    binobf::Instruction value{};
    value.id = binobf::EntityId{1};
    value.address = {address, binobf::AddressKind::Virtual};
    value.section = binobf::EntityId{1};
    value.sectionOffset = 0;
    value.mnemonic = "mov";
    value.operands = "x0, x1";
    value.encoding = {std::byte{0xe0}, std::byte{0x03}, std::byte{0x01}, std::byte{0xaa}};
    value.registersRead.push_back({1, "x1"});
    value.registersWritten.push_back({0, "x0"});
    return value;
}

} // namespace

TEST_CASE(arm64_backend_mutations_are_rejected_by_alignment_and_range_guards) {
    std::size_t killed = 0;
    auto unaligned = binobf::MachineTransformRequest{};
    unaligned.architecture = binobf::Architecture::ARM64;
    unaligned.format = binobf::BinaryFormat::ELF;
    unaligned.kind = binobf::MachineTransformKind::InstructionEquivalent;
    unaligned.source = source(0x1002);
    unaligned.exactSize = 4;
    if (!backend().emit_transform(unaligned).has_value()) ++killed;

    auto outOfRange = binobf::MachineTransformRequest{};
    outOfRange.architecture = binobf::Architecture::ARM64;
    outOfRange.format = binobf::BinaryFormat::ELF;
    outOfRange.kind = binobf::MachineTransformKind::DirectJump;
    outOfRange.source = source(0x1000);
    outOfRange.targetAddress = UINT64_C(0x900000000);
    outOfRange.exactSize = 4;
    if (!backend().emit_transform(outOfRange).has_value()) ++killed;

    auto valid = binobf::MachineTransformRequest{};
    valid.architecture = binobf::Architecture::ARM64;
    valid.format = binobf::BinaryFormat::ELF;
    valid.kind = binobf::MachineTransformKind::InstructionEquivalent;
    valid.source = source(0x1000);
    valid.exactSize = 4;
    if (backend().emit_transform(valid).has_value()) ++killed;
    REQUIRE_EQ(killed, std::size_t{3});
    std::cout << "mutation-score: " << killed << "/3\n";
}

int main() { return binobf::test::run_all(); }

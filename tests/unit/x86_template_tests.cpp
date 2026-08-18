#include <binobf/architecture/backend.hpp>

#include "../test_support.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

namespace {

auto backend() -> std::unique_ptr<binobf::ArchitectureBackend> {
    auto result = binobf::make_architecture_backend(binobf::Architecture::X86);
    if (!result.has_value()) throw std::runtime_error(result.error().message);
    return std::move(result).value();
}

auto source_instruction(std::uint64_t address = 0x1000U) -> binobf::Instruction {
    binobf::Instruction result{};
    result.id = binobf::EntityId{1};
    result.section = binobf::EntityId{1};
    result.address = binobf::BinaryAddress{address, binobf::AddressKind::Virtual};
    result.encoding = {std::byte{0x90}};
    result.mnemonic = "nop";
    result.kind = binobf::InstructionKind::Normal;
    result.hasFallthrough = true;
    return result;
}

auto decode_all(
    const binobf::ArchitectureBackend& decoder,
    const std::vector<std::byte>& bytes,
    std::uint64_t address) -> std::vector<binobf::Instruction> {
    std::vector<binobf::Instruction> result;
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto decoded = decoder.decode(binobf::DecodeRequest{
            .architecture = binobf::Architecture::X86,
            .bytes = std::span<const std::byte>{bytes}.subspan(offset),
            .address = binobf::BinaryAddress{address + offset, binobf::AddressKind::Virtual},
            .instructionId = binobf::EntityId{result.size() + 1U},
            .sectionId = binobf::EntityId{1},
            .sectionOffset = offset,
        });
        REQUIRE(decoded.has_value());
        REQUIRE(!decoded.value().encoding.empty());
        offset += decoded.value().encoding.size();
        result.push_back(decoded.value());
    }
    REQUIRE_EQ(offset, bytes.size());
    return result;
}

} // namespace

TEST_CASE(x86_instruction_equivalents_are_exact_and_fully_decodable) {
    auto fixed = backend();
    for (std::size_t size = 2; size <= 9; ++size) {
        binobf::MachineTransformRequest request{};
        request.architecture = binobf::Architecture::X86;
        request.format = binobf::BinaryFormat::COFF;
        request.kind = binobf::MachineTransformKind::InstructionEquivalent;
        request.source = source_instruction();
        request.exactSize = size;
        const auto emitted = fixed->emit_transform(request);
        REQUIRE(emitted.has_value());
        REQUIRE_EQ(emitted.value().emission.bytes.size(), size);
        const auto decoded = decode_all(*fixed, emitted.value().emission.bytes, 0x1000U);
        REQUIRE_EQ(decoded.size(), emitted.value().instructionCount);
        for (const auto& instruction : decoded) {
            REQUIRE(instruction.registersRead.empty());
            REQUIRE(instruction.registersWritten.empty());
        }
        REQUIRE_EQ(emitted.value().controlFlow, binobf::MachineControlFlow::Fallthrough);
        REQUIRE(!emitted.value().readsFlags);
        REQUIRE(!emitted.value().writesFlags);
    }
}

TEST_CASE(x86_constant_templates_materialize_eax_and_ecx) {
    auto fixed = backend();
    for (const auto name : {std::string_view{"eax"}, std::string_view{"ecx"}}) {
        for (const auto size : {std::size_t{5}, std::size_t{6}}) {
            binobf::MachineTransformRequest request{};
            request.architecture = binobf::Architecture::X86;
            request.format = binobf::BinaryFormat::ELF;
            request.kind = binobf::MachineTransformKind::ConstantMaterialization;
            request.constantBits = UINT64_C(0x78563412);
            request.condition = name;
            request.exactSize = size;
            const auto emitted = fixed->emit_transform(request);
            REQUIRE(emitted.has_value());
            REQUIRE_EQ(emitted.value().emission.bytes.size(), size);
            REQUIRE_EQ(emitted.value().emission.bytes.front(),
                       size == 5U
                           ? (name == "eax" ? std::byte{0xb8} : std::byte{0xb9})
                           : std::byte{0xc7});
            const auto decoded = decode_all(*fixed, emitted.value().emission.bytes, 0x2000U);
            REQUIRE_EQ(decoded.size(), std::size_t{1});
            REQUIRE_EQ(decoded.front().mnemonic, "mov");
            REQUIRE(std::ranges::find(decoded.front().registersWritten, name,
                                      &binobf::RegisterAccess::name)
                    != decoded.front().registersWritten.end());
        }
    }
}

TEST_CASE(x86_condition_inversions_cover_every_normalized_condition_and_width) {
    auto fixed = backend();
    constexpr std::array conditions{
        "equal", "not-equal", "zero", "nonzero",
        "unsigned-below", "unsigned-above-or-equal",
        "signed-less", "signed-greater-or-equal"};
    for (const auto condition : conditions) {
        for (const auto size : {std::size_t{2}, std::size_t{6}}) {
            binobf::MachineTransformRequest request{};
            request.architecture = binobf::Architecture::X86;
            request.format = binobf::BinaryFormat::COFF;
            request.kind = binobf::MachineTransformKind::ConditionalInversion;
            request.source = source_instruction(0x3000U);
            request.targetAddress = 0x3040U;
            request.condition = condition;
            request.exactSize = size;
            const auto emitted = fixed->emit_transform(request);
            REQUIRE(emitted.has_value());
            REQUIRE_EQ(emitted.value().emission.bytes.size(), size);
            REQUIRE_EQ(emitted.value().controlFlow, binobf::MachineControlFlow::Conditional);
            REQUIRE(emitted.value().readsFlags);
            const auto decoded = decode_all(*fixed, emitted.value().emission.bytes, 0x3000U);
            REQUIRE_EQ(decoded.size(), std::size_t{1});
            REQUIRE_EQ(decoded.front().kind, binobf::InstructionKind::ConditionalBranch);
            REQUIRE_EQ(decoded.front().directTarget->value, UINT64_C(0x3040));
        }
    }
}

TEST_CASE(x86_direct_jumps_choose_and_honor_short_and_near_encodings) {
    auto fixed = backend();
    for (const auto size : {std::size_t{2}, std::size_t{5}}) {
        binobf::MachineTransformRequest request{};
        request.architecture = binobf::Architecture::X86;
        request.format = binobf::BinaryFormat::ELF;
        request.kind = binobf::MachineTransformKind::DirectJump;
        request.source = source_instruction(0x4000U);
        request.targetAddress = 0x4040U;
        request.exactSize = size;
        const auto emitted = fixed->emit_transform(request);
        REQUIRE(emitted.has_value());
        REQUIRE_EQ(emitted.value().emission.bytes.size(), size);
        REQUIRE_EQ(emitted.value().controlFlow, binobf::MachineControlFlow::Direct);
        const auto decoded = decode_all(*fixed, emitted.value().emission.bytes, 0x4000U);
        REQUIRE_EQ(decoded.front().directTarget->value, UINT64_C(0x4040));
    }
}

TEST_CASE(x86_dead_code_fill_covers_every_supported_exact_size) {
    auto fixed = backend();
    for (std::size_t size = 1; size <= 15; ++size) {
        binobf::MachineTransformRequest request{};
        request.architecture = binobf::Architecture::X86;
        request.format = binobf::BinaryFormat::COFF;
        request.kind = binobf::MachineTransformKind::DeadCodeFill;
        request.exactSize = size;
        const auto emitted = fixed->emit_transform(request);
        REQUIRE(emitted.has_value());
        REQUIRE_EQ(emitted.value().emission.bytes.size(), size);
        REQUIRE_EQ(decode_all(*fixed, emitted.value().emission.bytes, 0x5000U).size(), size);
    }
}

TEST_CASE(x86_templates_refuse_impossible_sizes_and_targets) {
    auto fixed = backend();
    binobf::MachineTransformRequest request{};
    request.architecture = binobf::Architecture::X86;
    request.format = binobf::BinaryFormat::COFF;
    request.kind = binobf::MachineTransformKind::ConstantMaterialization;
    request.constantBits = 1U;
    request.condition = "eax";
    request.exactSize = 4;
    auto result = fixed->emit_transform(request);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "architecture.exact_size_unavailable");

    request.kind = binobf::MachineTransformKind::DirectJump;
    request.source = source_instruction(0x6000U);
    request.targetAddress = 0x6040U;
    request.exactSize = 3;
    result = fixed->emit_transform(request);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "architecture.exact_size_unavailable");

    request.exactSize = 2;
    request.targetAddress = 0x7000U;
    result = fixed->emit_transform(request);
    REQUIRE(!result.has_value());
    REQUIRE_EQ(result.error().code, "architecture.target_out_of_range");
}

int main() { return binobf::test::run_all(); }

#include <binobf/architecture/backend.hpp>

#include "../test_support.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

auto backend() -> std::unique_ptr<binobf::ArchitectureBackend> {
    auto result = binobf::make_architecture_backend(binobf::Architecture::ARM64);
    if (!result.has_value())
        throw std::runtime_error(result.error().message);
    return std::move(result).value();
}

auto bytes(std::initializer_list<unsigned int> values) -> std::vector<std::byte> {
    std::vector<std::byte> result;
    result.reserve(values.size());
    for (const auto value : values)
        result.push_back(static_cast<std::byte>(value));
    return result;
}

auto source_instruction(std::uint64_t address = 0x1000U) -> binobf::Instruction {
    binobf::Instruction result{};
    result.id = binobf::EntityId{1};
    result.section = binobf::EntityId{1};
    result.address = binobf::BinaryAddress{address, binobf::AddressKind::Virtual};
    result.encoding = bytes({0x1f, 0x20, 0x03, 0xd5});
    result.mnemonic = "nop";
    result.kind = binobf::InstructionKind::Normal;
    result.hasFallthrough = true;
    return result;
}

auto base_request(binobf::MachineTransformKind kind) -> binobf::MachineTransformRequest {
    binobf::MachineTransformRequest request{};
    request.architecture = binobf::Architecture::ARM64;
    request.format = binobf::BinaryFormat::ELF;
    request.kind = kind;
    request.source = source_instruction();
    return request;
}

auto decode_all(const binobf::ArchitectureBackend &decoder, const std::vector<std::byte> &encoded,
                std::uint64_t address = 0x1000U) -> std::vector<binobf::Instruction> {
    std::vector<binobf::Instruction> result;
    std::size_t offset = 0;
    while (offset < encoded.size()) {
        const auto decoded = decoder.decode(binobf::DecodeRequest{
            .architecture = binobf::Architecture::ARM64,
            .bytes = std::span<const std::byte>{encoded}.subspan(offset),
            .address = {address + offset, binobf::AddressKind::Virtual},
            .instructionId = binobf::EntityId{result.size() + 1U},
            .sectionId = binobf::EntityId{1},
            .sectionOffset = offset,
        });
        REQUIRE(decoded.has_value());
        REQUIRE_EQ(decoded.value().encoding.size(), std::size_t{4});
        offset += decoded.value().encoding.size();
        result.push_back(decoded.value());
    }
    REQUIRE_EQ(offset, encoded.size());
    return result;
}

auto word_at(const std::vector<std::byte> &encoded, std::size_t offset) -> std::uint32_t {
    return std::to_integer<std::uint32_t>(encoded[offset]) |
           (std::to_integer<std::uint32_t>(encoded[offset + 1U]) << 8U) |
           (std::to_integer<std::uint32_t>(encoded[offset + 2U]) << 16U) |
           (std::to_integer<std::uint32_t>(encoded[offset + 3U]) << 24U);
}

} // namespace

TEST_CASE(arm64_dead_code_is_exact_aligned_and_decodable) {
    auto fixed = backend();
    auto request = base_request(binobf::MachineTransformKind::DeadCodeFill);
    request.exactSize = 12;
    const auto emitted = fixed->emit_transform(request);
    REQUIRE(emitted.has_value());
    REQUIRE_EQ(emitted.value().emission.bytes,
               bytes({0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5}));
    REQUIRE_EQ(decode_all(*fixed, emitted.value().emission.bytes).size(), std::size_t{3});
}

TEST_CASE(arm64_register_copy_uses_flag_preserving_orr) {
    auto fixed = backend();
    auto request = base_request(binobf::MachineTransformKind::InstructionEquivalent);
    request.exactSize = 4;
    request.source->mnemonic = "mov";
    request.source->registersRead = {{2U, "x1"}};
    request.source->registersWritten = {{1U, "x0"}};
    const auto emitted = fixed->emit_transform(request);
    REQUIRE(emitted.has_value());
    REQUIRE_EQ(emitted.value().emission.bytes, bytes({0xe0, 0x03, 0x01, 0xaa}));
    REQUIRE(!emitted.value().readsFlags);
    REQUIRE(!emitted.value().writesFlags);
    const auto decoded = decode_all(*fixed, emitted.value().emission.bytes);
    REQUIRE_EQ(decoded.front().mnemonic, "mov");
    REQUIRE(std::ranges::find(decoded.front().registersRead, "x1", &binobf::RegisterAccess::name) !=
            decoded.front().registersRead.end());
    REQUIRE(
        std::ranges::find(decoded.front().registersWritten, "x0", &binobf::RegisterAccess::name) !=
        decoded.front().registersWritten.end());
}

TEST_CASE(arm64_constants_choose_shortest_movz_or_movn_then_low_to_high_movk) {
    auto fixed = backend();
    struct Golden {
        std::uint64_t value;
        std::size_t instructionCount;
        bool startsWithMovn;
    };
    constexpr std::array goldens{
        Golden{0, 1, false},
        Golden{UINT64_MAX, 1, true},
        Golden{UINT64_C(0x0000000012345678), 2, false},
        Golden{UINT64_C(0xffff0000ffff1234), 2, true},
        Golden{UINT64_C(0xffff0000ffff0000), 2, false},
        Golden{UINT64_C(0x1111222233334444), 4, false},
    };
    for (const auto &golden : goldens) {
        auto request = base_request(binobf::MachineTransformKind::ConstantMaterialization);
        request.source.reset();
        request.condition = "x9";
        request.constantBits = golden.value;
        const auto emitted = fixed->emit_transform(request);
        REQUIRE(emitted.has_value());
        REQUIRE_EQ(emitted.value().instructionCount, golden.instructionCount);
        REQUIRE_EQ(emitted.value().emission.bytes.size(), golden.instructionCount * 4U);
        const auto first = word_at(emitted.value().emission.bytes, 0);
        REQUIRE_EQ((first & 0x7f800000U) == 0x12800000U, golden.startsWithMovn);
        const auto decoded = decode_all(*fixed, emitted.value().emission.bytes, 0);
        REQUIRE_EQ(decoded.size(), golden.instructionCount);
        if (golden.value == UINT64_C(0x1111222233334444)) {
            for (std::size_t index = 0; index < decoded.size(); ++index) {
                REQUIRE_EQ((word_at(emitted.value().emission.bytes, index * 4U) >> 21U) & 3U,
                           static_cast<std::uint32_t>(index));
            }
        }
    }
}

TEST_CASE(arm64_condition_inversions_cover_all_fourteen_ordinary_conditions) {
    auto fixed = backend();
    struct Pair {
        std::string_view source;
        std::string_view inverseMnemonic;
    };
    constexpr std::array conditions{Pair{"eq", "b.ne"}, Pair{"ne", "b.eq"}, Pair{"hs", "b.lo"},
                                    Pair{"lo", "b.hs"}, Pair{"mi", "b.pl"}, Pair{"pl", "b.mi"},
                                    Pair{"vs", "b.vc"}, Pair{"vc", "b.vs"}, Pair{"hi", "b.ls"},
                                    Pair{"ls", "b.hi"}, Pair{"ge", "b.lt"}, Pair{"lt", "b.ge"},
                                    Pair{"gt", "b.le"}, Pair{"le", "b.gt"}};
    for (const auto &condition : conditions) {
        auto request = base_request(binobf::MachineTransformKind::ConditionalInversion);
        request.condition = condition.source;
        request.targetAddress = 0x1100U;
        request.exactSize = 4;
        const auto emitted = fixed->emit_transform(request);
        if (!emitted.has_value()) {
            throw std::runtime_error(std::string{condition.source} + ": " + emitted.error().code +
                                     ": " + emitted.error().message);
        }
        REQUIRE(emitted.has_value());
        REQUIRE_EQ(emitted.value().controlFlow, binobf::MachineControlFlow::Conditional);
        REQUIRE(emitted.value().readsFlags);
        REQUIRE_EQ(emitted.value().emission.bytes.size(), std::size_t{4});
        const auto decoded = decode_all(*fixed, emitted.value().emission.bytes);
        REQUIRE_EQ(decoded.front().kind, binobf::InstructionKind::ConditionalBranch);
        REQUIRE_EQ(decoded.front().mnemonic, condition.inverseMnemonic);
        REQUIRE(decoded.front().directTarget.has_value());
        REQUIRE_EQ(decoded.front().directTarget->value, UINT64_C(0x1100));
    }
}

TEST_CASE(arm64_direct_branch_and_call_emit_typed_symbol_fixups) {
    auto fixed = backend();
    for (const auto format : {binobf::BinaryFormat::COFF, binobf::BinaryFormat::ELF}) {
        for (const auto call : {false, true}) {
            auto request = base_request(binobf::MachineTransformKind::DirectJump);
            request.format = format;
            request.condition = "external_target";
            request.targetAddress.reset();
            request.exactSize = 4;
            if (call) {
                request.source->kind = binobf::InstructionKind::DirectCall;
                request.source->mnemonic = "bl";
            }
            const auto emitted = fixed->emit_transform(request);
            REQUIRE(emitted.has_value());
            REQUIRE_EQ(emitted.value().emission.fixups.size(), std::size_t{1});
            REQUIRE_EQ(emitted.value().emission.fixups.front().offset, UINT64_C(0));
            REQUIRE_EQ(emitted.value().emission.fixups.front().symbol, "external_target");
            REQUIRE_EQ(emitted.value().emission.fixups.front().kind,
                       call ? binobf::MachineFixupKind::AArch64Call26
                            : binobf::MachineFixupKind::AArch64Branch26);
            REQUIRE_EQ(emitted.value().controlFlow, call ? binobf::MachineControlFlow::Call
                                                         : binobf::MachineControlFlow::Direct);
        }
    }
}

TEST_CASE(arm64_templates_reject_unaligned_oversized_and_untrusted_inputs) {
    auto fixed = backend();
    auto request = base_request(binobf::MachineTransformKind::DeadCodeFill);
    request.exactSize = 6;
    REQUIRE(!fixed->emit_transform(request).has_value());

    request.exactSize = request.limits.maxEmittedBytes;
    request.exactSize += 4U;
    const auto excessiveFill = fixed->emit_transform(request);
    REQUIRE(!excessiveFill.has_value());
    REQUIRE_EQ(excessiveFill.error().code, "architecture.resource_limit");

    request = base_request(binobf::MachineTransformKind::DirectJump);
    request.condition = "target\nret";
    request.targetAddress.reset();
    request.exactSize = 4;
    REQUIRE(!fixed->emit_transform(request).has_value());

    request = base_request(binobf::MachineTransformKind::ConditionalInversion);
    request.source->address.value = 0x1002;
    request.targetAddress = 0x1100;
    request.condition = "eq";
    request.exactSize = 4;
    REQUIRE(!fixed->emit_transform(request).has_value());

    request = base_request(binobf::MachineTransformKind::ConstantMaterialization);
    request.source.reset();
    request.condition = "x0";
    request.constantBits = UINT64_C(0x12345678);
    request.exactSize = 4;
    REQUIRE(!fixed->emit_transform(request).has_value());

    request = base_request(binobf::MachineTransformKind::DirectJump);
    request.targetAddress = UINT64_C(0x80000000);
    request.exactSize = 4;
    const auto distant = fixed->emit_transform(request);
    REQUIRE(!distant.has_value());
    REQUIRE_EQ(distant.error().code, "architecture.target_out_of_range");
}

int main() { return binobf::test::run_all(); }

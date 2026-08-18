#include "../test_support.hpp"

#include <binobf/analysis/instruction_decoder.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <string_view>

namespace {

auto has_register(const std::vector<binobf::RegisterAccess>& registers, std::string_view name)
    -> bool {
    return std::any_of(registers.begin(), registers.end(), [name](const auto& value) {
        return value.name == name;
    });
}

auto make_decoder() -> std::unique_ptr<binobf::InstructionDecoder> {
    auto decoder = binobf::make_instruction_decoder();
    if (!decoder.has_value()) throw std::runtime_error(decoder.error().message);
    return std::move(decoder).value();
}

} // namespace

TEST_CASE(decoder_normalizes_x86_64_register_access_and_direct_calls) {
    auto decoder = make_decoder();
    constexpr std::array addBytes{std::byte{0x48}, std::byte{0x01}, std::byte{0xd8}};
    const auto add = decoder->decode(binobf::DecodeRequest{
        .architecture = binobf::Architecture::X86_64,
        .bytes = addBytes,
        .address = binobf::BinaryAddress{0x1000, binobf::AddressKind::Virtual},
        .instructionId = binobf::EntityId{10},
        .sectionId = binobf::EntityId{1},
        .sectionOffset = 4,
    });
    REQUIRE(add.has_value());
    REQUIRE_EQ(add.value().mnemonic, "add");
    REQUIRE_EQ(add.value().kind, binobf::InstructionKind::Normal);
    REQUIRE_EQ(add.value().encoding.size(), std::size_t{3});
    REQUIRE(has_register(add.value().registersRead, "rax"));
    REQUIRE(has_register(add.value().registersRead, "rbx"));
    REQUIRE(has_register(add.value().registersWritten, "rax"));
    REQUIRE(add.value().hasFallthrough);

    constexpr std::array callBytes{
        std::byte{0xe8}, std::byte{0x05}, std::byte{0}, std::byte{0}, std::byte{0}};
    const auto call = decoder->decode(binobf::DecodeRequest{
        .architecture = binobf::Architecture::X86_64,
        .bytes = callBytes,
        .address = binobf::BinaryAddress{0x1000, binobf::AddressKind::Virtual},
        .instructionId = binobf::EntityId{11},
        .sectionId = binobf::EntityId{1},
    });
    REQUIRE(call.has_value());
    REQUIRE_EQ(call.value().kind, binobf::InstructionKind::DirectCall);
    REQUIRE(call.value().directTarget.has_value());
    REQUIRE_EQ(call.value().directTarget->value, UINT64_C(0x100a));
    REQUIRE(call.value().hasFallthrough);
}

TEST_CASE(decoder_distinguishes_conditional_and_unconditional_x86_flow) {
    auto decoder = make_decoder();
    constexpr std::array conditionalBytes{std::byte{0x75}, std::byte{0x05}};
    const auto conditional = decoder->decode(binobf::DecodeRequest{
        .architecture = binobf::Architecture::X86_64,
        .bytes = conditionalBytes,
        .address = binobf::BinaryAddress{0x2000, binobf::AddressKind::Virtual},
        .instructionId = binobf::EntityId{20}, .sectionId = binobf::EntityId{1},
    });
    REQUIRE(conditional.has_value());
    REQUIRE_EQ(conditional.value().kind, binobf::InstructionKind::ConditionalBranch);
    REQUIRE_EQ(conditional.value().directTarget->value, UINT64_C(0x2007));
    REQUIRE(conditional.value().hasFallthrough);

    constexpr std::array jumpBytes{std::byte{0xeb}, std::byte{0xfe}};
    const auto jump = decoder->decode(binobf::DecodeRequest{
        .architecture = binobf::Architecture::X86,
        .bytes = jumpBytes,
        .address = binobf::BinaryAddress{0x3000, binobf::AddressKind::Virtual},
        .instructionId = binobf::EntityId{21}, .sectionId = binobf::EntityId{1},
    });
    REQUIRE(jump.has_value());
    REQUIRE_EQ(jump.value().kind, binobf::InstructionKind::DirectBranch);
    REQUIRE_EQ(jump.value().directTarget->value, UINT64_C(0x3000));
    REQUIRE(!jump.value().hasFallthrough);
}

TEST_CASE(decoder_supports_arm64_direct_branches_and_returns) {
    auto decoder = make_decoder();
    constexpr std::array branchBytes{
        std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x14}};
    const auto branch = decoder->decode(binobf::DecodeRequest{
        .architecture = binobf::Architecture::ARM64,
        .bytes = branchBytes,
        .address = binobf::BinaryAddress{0x4000, binobf::AddressKind::Virtual},
        .instructionId = binobf::EntityId{30}, .sectionId = binobf::EntityId{1},
    });
    REQUIRE(branch.has_value());
    REQUIRE_EQ(branch.value().kind, binobf::InstructionKind::DirectBranch);
    REQUIRE_EQ(branch.value().directTarget->value, UINT64_C(0x4008));
    REQUIRE(!branch.value().hasFallthrough);

    constexpr std::array returnBytes{
        std::byte{0xc0}, std::byte{0x03}, std::byte{0x5f}, std::byte{0xd6}};
    const auto returned = decoder->decode(binobf::DecodeRequest{
        .architecture = binobf::Architecture::ARM64,
        .bytes = returnBytes,
        .address = binobf::BinaryAddress{0x5000, binobf::AddressKind::Virtual},
        .instructionId = binobf::EntityId{31}, .sectionId = binobf::EntityId{1},
    });
    REQUIRE(returned.has_value());
    REQUIRE_EQ(returned.value().kind, binobf::InstructionKind::Return);
    REQUIRE(!returned.value().hasFallthrough);
}

TEST_CASE(decoder_rejects_empty_unsupported_and_truncated_inputs) {
    auto decoder = make_decoder();
    const auto empty = decoder->decode(binobf::DecodeRequest{
        .architecture = binobf::Architecture::X86_64,
        .bytes = {}, .address = {},
        .instructionId = binobf::EntityId{40}, .sectionId = binobf::EntityId{1},
    });
    REQUIRE(!empty.has_value());
    REQUIRE_EQ(empty.error().code, "analysis.empty_input");

    constexpr std::array oneByte{std::byte{0x90}};
    const auto unsupported = decoder->decode(binobf::DecodeRequest{
        .architecture = binobf::Architecture::Unknown,
        .bytes = oneByte, .address = {},
        .instructionId = binobf::EntityId{41}, .sectionId = binobf::EntityId{1},
    });
    REQUIRE(!unsupported.has_value());
    REQUIRE_EQ(unsupported.error().code, "analysis.unsupported_architecture");

    constexpr std::array truncatedBytes{std::byte{0x0f}};
    const auto truncated = decoder->decode(binobf::DecodeRequest{
        .architecture = binobf::Architecture::X86_64,
        .bytes = truncatedBytes, .address = {},
        .instructionId = binobf::EntityId{42}, .sectionId = binobf::EntityId{1},
    });
    REQUIRE(!truncated.has_value());
    REQUIRE_EQ(truncated.error().code, "analysis.decode_failed");
}

int main() {
    return binobf::test::run_all();
}

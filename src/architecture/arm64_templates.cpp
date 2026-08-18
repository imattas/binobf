#include "arm64_templates.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace binobf::detail {
namespace {

template <typename T> auto failure(std::string code, std::string message) -> Result<T, Diagnostic> {
    return Result<T, Diagnostic>::failure(
        Diagnostic{DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

struct RegisterName {
    std::string text;
    std::uint8_t index{0};
    bool is64Bit{false};
};

auto parse_register(std::string_view text) -> std::optional<RegisterName> {
    if (text.size() < 2U || (text.front() != 'x' && text.front() != 'w')) {
        return std::nullopt;
    }
    unsigned int index = 0;
    for (std::size_t position = 1; position < text.size(); ++position) {
        const auto character = static_cast<unsigned char>(text[position]);
        if (std::isdigit(character) == 0)
            return std::nullopt;
        index = index * 10U + static_cast<unsigned int>(character - '0');
        if (index > 30U)
            return std::nullopt;
    }
    if (text.size() > 2U && text[1] == '0')
        return std::nullopt;
    return RegisterName{std::string{text}, static_cast<std::uint8_t>(index), text.front() == 'x'};
}

auto valid_symbol(std::string_view symbol) noexcept -> bool {
    if (symbol.empty())
        return false;
    const auto first = static_cast<unsigned char>(symbol.front());
    if (std::isalpha(first) == 0 && symbol.front() != '_' && symbol.front() != '.' &&
        symbol.front() != '$') {
        return false;
    }
    return std::ranges::all_of(symbol.substr(1U), [](char character) {
        const auto value = static_cast<unsigned char>(character);
        return std::isalnum(value) != 0 || character == '_' || character == '.' || character == '$';
    });
}

auto append_word(std::vector<std::byte> &bytes, std::uint32_t word) -> void {
    for (unsigned int shift = 0; shift < 32U; shift += 8U) {
        bytes.push_back(static_cast<std::byte>((word >> shift) & 0xffU));
    }
}

auto byte_assembly(std::span<const std::byte> bytes) -> std::string {
    constexpr char digits[] = "0123456789abcdef";
    std::string result{".byte "};
    result.reserve(7U + bytes.size() * 6U);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index != 0U)
            result += ", ";
        const auto value = std::to_integer<unsigned int>(bytes[index]);
        result += "0x";
        result += digits[(value >> 4U) & 0xfU];
        result += digits[value & 0xfU];
    }
    result += '\n';
    return result;
}

auto assembly_request(const MachineTransformRequest &request, std::string assembly,
                      std::size_t instructionCount) -> MachineAssemblyRequest {
    MachineAssemblyRequest result{};
    result.architecture = Architecture::ARM64;
    result.format = request.format;
    result.triple = request.format == BinaryFormat::COFF ? "aarch64-pc-windows-msvc"
                                                         : "aarch64-unknown-linux-gnu";
    result.syntax = MachineSyntax::GNU;
    result.baseAddress = request.source.has_value() ? request.source->address : BinaryAddress{};
    result.limits = request.limits;
    result.expectedInstructionCount = instructionCount;
    result.assembly = std::move(assembly);
    return result;
}

auto emit_words(const MachineTransformRequest &request, const CodegenProvider &codegen,
                std::span<const std::uint32_t> words, MachineControlFlow controlFlow,
                bool readsFlags, std::vector<std::string> clobbers = {})
    -> Result<MachineTransformEmission, Diagnostic> {
    std::vector<std::byte> bytes;
    bytes.reserve(words.size() * 4U);
    for (const auto word : words)
        append_word(bytes, word);
    const auto assembly = byte_assembly(bytes);
    if (bytes.empty() || bytes.size() > request.limits.maxEmittedBytes ||
        words.size() > request.limits.maxInstructions ||
        assembly.size() > request.limits.maxAssemblyBytes || request.limits.maxLines == 0U) {
        return failure<MachineTransformEmission>("architecture.resource_limit",
                                                 "ARM64 template exceeds the request limits");
    }
    auto emission = codegen.emit(assembly_request(request, assembly, words.size()));
    if (!emission.has_value()) {
        return failure<MachineTransformEmission>(emission.error().code, emission.error().message);
    }
    if (emission.value().bytes != bytes || !emission.value().fixups.empty()) {
        return failure<MachineTransformEmission>(
            "architecture.exact_size_unavailable",
            "assembler changed the exact ARM64 instruction template");
    }
    emission.value().clobberedRegisters = std::move(clobbers);
    return Result<MachineTransformEmission, Diagnostic>::success(MachineTransformEmission{
        .emission = std::move(emission).value(),
        .instructionCount = words.size(),
        .controlFlow = controlFlow,
        .stackDelta = 0,
        .readsFlags = readsFlags,
        .writesFlags = false,
    });
}

auto checked_displacement(const MachineTransformRequest &request, std::int64_t minimum,
                          std::int64_t maximum) -> Result<std::int64_t, Diagnostic> {
    if (!request.source.has_value() || !request.targetAddress.has_value()) {
        return failure<std::int64_t>("architecture.invalid_template",
                                     "direct control flow requires source and target");
    }
    const auto source = request.source->address.value;
    const auto target = *request.targetAddress;
    if ((source & 3U) != 0U || (target & 3U) != 0U) {
        return failure<std::int64_t>("architecture.invalid_alignment",
                                     "ARM64 control-flow addresses must be aligned");
    }
    std::int64_t displacement = 0;
    if (target >= source) {
        const auto distance = target - source;
        if (distance > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            return failure<std::int64_t>("architecture.target_out_of_range",
                                         "ARM64 branch displacement overflows");
        }
        displacement = static_cast<std::int64_t>(distance);
    } else {
        const auto distance = source - target;
        constexpr auto minimumMagnitude = UINT64_C(1) << 63U;
        if (distance > minimumMagnitude) {
            return failure<std::int64_t>("architecture.target_out_of_range",
                                         "ARM64 branch displacement overflows");
        }
        displacement = distance == minimumMagnitude ? std::numeric_limits<std::int64_t>::min()
                                                    : -static_cast<std::int64_t>(distance);
    }
    if (displacement < minimum || displacement > maximum) {
        return failure<std::int64_t>("architecture.target_out_of_range",
                                     "ARM64 branch displacement is out of range");
    }
    return Result<std::int64_t, Diagnostic>::success(displacement);
}

auto inverted_condition(std::string_view condition) -> std::optional<std::uint8_t> {
    struct Entry {
        std::string_view name;
        std::uint8_t inverse;
    };
    constexpr std::array entries{
        Entry{"eq", 0x1},
        Entry{"ne", 0x0},
        Entry{"hs", 0x3},
        Entry{"lo", 0x2},
        Entry{"mi", 0x5},
        Entry{"pl", 0x4},
        Entry{"vs", 0x7},
        Entry{"vc", 0x6},
        Entry{"hi", 0x9},
        Entry{"ls", 0x8},
        Entry{"ge", 0xb},
        Entry{"lt", 0xa},
        Entry{"gt", 0xd},
        Entry{"le", 0xc},
        Entry{"equal", 0x1},
        Entry{"not-equal", 0x0},
        Entry{"unsigned-above-or-equal", 0x3},
        Entry{"unsigned-below", 0x2},
        Entry{"minus", 0x5},
        Entry{"plus", 0x4},
        Entry{"overflow", 0x7},
        Entry{"no-overflow", 0x6},
        Entry{"unsigned-above", 0x9},
        Entry{"unsigned-below-or-equal", 0x8},
        Entry{"signed-greater-or-equal", 0xb},
        Entry{"signed-less", 0xa},
        Entry{"signed-greater", 0xd},
        Entry{"signed-less-or-equal", 0xc},
    };
    const auto found = std::ranges::find(entries, condition, &Entry::name);
    return found == entries.end() ? std::nullopt : std::optional<std::uint8_t>{found->inverse};
}

auto move_wide_words(const RegisterName &destination, std::uint64_t value)
    -> std::vector<std::uint32_t> {
    const auto laneCount = destination.is64Bit ? std::size_t{4} : std::size_t{2};
    std::array<std::uint16_t, 4> lanes{};
    for (std::size_t lane = 0; lane < laneCount; ++lane) {
        lanes[lane] = static_cast<std::uint16_t>((value >> (lane * 16U)) & 0xffffU);
    }
    const auto nonzero = static_cast<std::size_t>(
        std::count_if(lanes.begin(), lanes.begin() + static_cast<std::ptrdiff_t>(laneCount),
                      [](std::uint16_t lane) { return lane != 0U; }));
    const auto nonones = static_cast<std::size_t>(
        std::count_if(lanes.begin(), lanes.begin() + static_cast<std::ptrdiff_t>(laneCount),
                      [](std::uint16_t lane) { return lane != 0xffffU; }));
    const bool useMovn = std::max(std::size_t{1}, nonones) < std::max(std::size_t{1}, nonzero);
    const auto defaultLane = useMovn ? UINT16_C(0xffff) : UINT16_C(0);
    std::size_t seedLane = 0;
    for (std::size_t lane = 0; lane < laneCount; ++lane) {
        if (lanes[lane] != defaultLane) {
            seedLane = lane;
            break;
        }
    }
    const auto widthBase = destination.is64Bit ? UINT32_C(0x80000000) : UINT32_C(0);
    const auto seedBase = useMovn ? UINT32_C(0x12800000) : UINT32_C(0x52800000);
    const auto seedImmediate =
        useMovn ? static_cast<std::uint16_t>(~lanes[seedLane]) : lanes[seedLane];
    std::vector<std::uint32_t> result;
    result.push_back(widthBase | seedBase | (static_cast<std::uint32_t>(seedLane) << 21U) |
                     (static_cast<std::uint32_t>(seedImmediate) << 5U) | destination.index);
    const auto movkBase = widthBase | UINT32_C(0x72800000);
    for (std::size_t lane = 0; lane < laneCount; ++lane) {
        if (lane == seedLane || lanes[lane] == defaultLane)
            continue;
        result.push_back(movkBase | (static_cast<std::uint32_t>(lane) << 21U) |
                         (static_cast<std::uint32_t>(lanes[lane]) << 5U) | destination.index);
    }
    return result;
}

auto emit_symbol_branch(const MachineTransformRequest &request, const CodegenProvider &codegen,
                        bool call) -> Result<MachineTransformEmission, Diagnostic> {
    if (!valid_symbol(request.condition)) {
        return failure<MachineTransformEmission>("architecture.invalid_template",
                                                 "ARM64 branch symbol is not an allowlisted token");
    }
    const std::string assembly = std::string{call ? "bl " : "b "} + request.condition + "\n";
    if (assembly.size() > request.limits.maxAssemblyBytes || request.limits.maxLines == 0U ||
        request.limits.maxInstructions == 0U || request.limits.maxFixups == 0U) {
        return failure<MachineTransformEmission>("architecture.resource_limit",
                                                 "ARM64 branch template exceeds request limits");
    }
    auto emission = codegen.emit(assembly_request(request, assembly, 1U));
    if (!emission.has_value()) {
        return failure<MachineTransformEmission>(emission.error().code, emission.error().message);
    }
    const auto expectedKind =
        call ? MachineFixupKind::AArch64Call26 : MachineFixupKind::AArch64Branch26;
    if (emission.value().bytes.size() != 4U || emission.value().fixups.size() != 1U ||
        emission.value().fixups.front().offset != 0U ||
        emission.value().fixups.front().kind != expectedKind ||
        emission.value().fixups.front().symbol != request.condition) {
        return failure<MachineTransformEmission>(
            "architecture.template_verification_failed",
            "ARM64 symbolic branch did not emit its exact typed fixup");
    }
    if (call)
        emission.value().clobberedRegisters = {"x30"};
    return Result<MachineTransformEmission, Diagnostic>::success(MachineTransformEmission{
        .emission = std::move(emission).value(),
        .instructionCount = 1,
        .controlFlow = call ? MachineControlFlow::Call : MachineControlFlow::Direct,
        .stackDelta = 0,
        .readsFlags = false,
        .writesFlags = false,
    });
}

} // namespace

auto emit_arm64_transform(const MachineTransformRequest &request, const CodegenProvider &codegen)
    -> Result<MachineTransformEmission, Diagnostic> {
    if (request.architecture != Architecture::ARM64) {
        return failure<MachineTransformEmission>(
            "architecture.request_mismatch", "ARM64 template request has the wrong architecture");
    }
    if (request.format != BinaryFormat::COFF && request.format != BinaryFormat::ELF) {
        return failure<MachineTransformEmission>("architecture.unsupported_format",
                                                 "ARM64 templates require COFF or ELF");
    }
    if (request.source.has_value() && (request.source->address.value & 3U) != 0U) {
        return failure<MachineTransformEmission>("architecture.invalid_alignment",
                                                 "ARM64 template source must be four-byte aligned");
    }

    if (request.kind == MachineTransformKind::DeadCodeFill) {
        if (request.exactSize == 0U || (request.exactSize & 3U) != 0U) {
            return failure<MachineTransformEmission>(
                "architecture.exact_size_unavailable",
                "ARM64 dead-code fill requires a positive four-byte multiple");
        }
        if (request.exactSize > request.limits.maxEmittedBytes ||
            request.exactSize / 4U > request.limits.maxInstructions) {
            return failure<MachineTransformEmission>("architecture.resource_limit",
                                                     "ARM64 dead-code fill exceeds request limits");
        }
        return emit_words(request, codegen,
                          std::vector<std::uint32_t>(request.exactSize / 4U, UINT32_C(0xd503201f)),
                          MachineControlFlow::Fallthrough, false);
    }

    if (request.kind == MachineTransformKind::InstructionEquivalent) {
        const auto exactSize = request.exactSize == 0U ? 4U : request.exactSize;
        if (exactSize != 4U || !request.source.has_value()) {
            return failure<MachineTransformEmission>(
                "architecture.exact_size_unavailable",
                "ARM64 register-copy equivalence requires exactly four bytes");
        }
        if (request.source->mnemonic == "nop") {
            constexpr std::array words{UINT32_C(0xd503201f)};
            return emit_words(request, codegen, words, MachineControlFlow::Fallthrough, false);
        }
        if ((request.source->mnemonic != "mov" && request.source->mnemonic != "orr") ||
            request.source->registersRead.size() != 1U ||
            request.source->registersWritten.size() != 1U) {
            return failure<MachineTransformEmission>(
                "architecture.invalid_template",
                "ARM64 copy equivalence requires one explicit source and destination");
        }
        const auto source = parse_register(request.source->registersRead.front().name);
        const auto destination = parse_register(request.source->registersWritten.front().name);
        if (!source.has_value() || !destination.has_value() ||
            source->is64Bit != destination->is64Bit) {
            return failure<MachineTransformEmission>(
                "architecture.invalid_template", "ARM64 copy registers are invalid or mismatched");
        }
        const auto base = destination->is64Bit ? UINT32_C(0xaa0003e0) : UINT32_C(0x2a0003e0);
        const std::array words{base | (static_cast<std::uint32_t>(source->index) << 16U) |
                               destination->index};
        return emit_words(request, codegen, words, MachineControlFlow::Fallthrough, false,
                          {destination->text});
    }

    if (request.kind == MachineTransformKind::ConstantMaterialization) {
        const auto destination = parse_register(request.condition);
        if (!destination.has_value() || !request.constantBits.has_value() ||
            (!destination->is64Bit &&
             *request.constantBits > std::numeric_limits<std::uint32_t>::max())) {
            return failure<MachineTransformEmission>(
                "architecture.invalid_template",
                "ARM64 constant template requires x0-x30 or w0-w30 and a fitting value");
        }
        const auto words = move_wide_words(*destination, *request.constantBits);
        const auto exactSize = words.size() * 4U;
        if (request.exactSize != 0U && request.exactSize != exactSize) {
            return failure<MachineTransformEmission>(
                "architecture.exact_size_unavailable",
                "ARM64 constant template size must match its shortest sequence");
        }
        return emit_words(request, codegen, words, MachineControlFlow::Fallthrough, false,
                          {destination->text});
    }

    if (request.kind == MachineTransformKind::ConditionalInversion) {
        const auto exactSize = request.exactSize == 0U ? 4U : request.exactSize;
        const auto condition = inverted_condition(request.condition);
        if (exactSize != 4U) {
            return failure<MachineTransformEmission>(
                "architecture.exact_size_unavailable",
                "ARM64 conditional branches are exactly four bytes");
        }
        if (!condition.has_value()) {
            return failure<MachineTransformEmission>(
                "architecture.invalid_condition", "ARM64 condition is not ordinarily invertible");
        }
        const auto displacement =
            checked_displacement(request, -(INT64_C(1) << 20U), (INT64_C(1) << 20U) - 4);
        if (!displacement.has_value()) {
            return failure<MachineTransformEmission>(displacement.error().code,
                                                     displacement.error().message);
        }
        const auto immediate =
            static_cast<std::uint32_t>(displacement.value() / 4) & UINT32_C(0x7ffff);
        const std::array words{UINT32_C(0x54000000) | (immediate << 5U) | *condition};
        return emit_words(request, codegen, words, MachineControlFlow::Conditional, true);
    }

    if (request.kind == MachineTransformKind::DirectJump) {
        const auto exactSize = request.exactSize == 0U ? 4U : request.exactSize;
        if (exactSize != 4U) {
            return failure<MachineTransformEmission>("architecture.exact_size_unavailable",
                                                     "ARM64 direct branches are four bytes");
        }
        const bool call =
            request.source.has_value() && (request.source->kind == InstructionKind::DirectCall ||
                                           request.source->mnemonic == "bl");
        if (!request.targetAddress.has_value()) {
            return emit_symbol_branch(request, codegen, call);
        }
        const auto displacement =
            checked_displacement(request, -(INT64_C(1) << 27U), (INT64_C(1) << 27U) - 4);
        if (!displacement.has_value()) {
            return failure<MachineTransformEmission>(displacement.error().code,
                                                     displacement.error().message);
        }
        const auto immediate =
            static_cast<std::uint32_t>(displacement.value() / 4) & UINT32_C(0x03ffffff);
        const std::array words{(call ? UINT32_C(0x94000000) : UINT32_C(0x14000000)) | immediate};
        return emit_words(request, codegen, words,
                          call ? MachineControlFlow::Call : MachineControlFlow::Direct, false,
                          call ? std::vector<std::string>{"x30"} : std::vector<std::string>{});
    }

    return failure<MachineTransformEmission>("architecture.service_unsupported",
                                             "unsupported ARM64 template kind");
}

} // namespace binobf::detail

#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/model.hpp>
#include <binobf/core/result.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace binobf {

struct DecodeRequest {
    Architecture architecture{Architecture::Unknown};
    std::span<const std::byte> bytes;
    BinaryAddress address;
    EntityId instructionId;
    EntityId sectionId;
    std::uint64_t sectionOffset{0};
};

class InstructionDecoder {
public:
    virtual ~InstructionDecoder() = default;

    [[nodiscard]] virtual auto decode(const DecodeRequest& request) const
        -> Result<Instruction, Diagnostic> = 0;
};

[[nodiscard]] auto make_instruction_decoder()
    -> Result<std::unique_ptr<InstructionDecoder>, Diagnostic>;

} // namespace binobf

#pragma once

#include <binobf/vm/ir.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace binobf::vm {

enum class VmOpcode : std::uint8_t {
    Move,
    LoadConstant,
    LoadSlot,
    StoreSlot,
    LoadMemory,
    StoreMemory,
    Add,
    Subtract,
    Multiply,
    Divide,
    And,
    Or,
    Xor,
    Not,
    ShiftLeft,
    ShiftRight,
    Compare,
    Test,
    Jump,
    ConditionalJump,
    Call,
    NativeCall,
    Return,
};

inline constexpr std::size_t vmOpcodeCount = 23;

struct VmAssemblyOptions {
    std::uint64_t seed{0};
};

struct VmDecodedProgram {
    VmProgram program;
    std::uint64_t encodingSeed{0};
};

[[nodiscard]] auto assemble_program(
    const VmProgram& program,
    const VmAssemblyOptions& options = {},
    const VmLimits& limits = {}) -> Result<std::vector<std::byte>, Diagnostic>;

[[nodiscard]] auto decode_program(
    std::span<const std::byte> bytecode,
    const VmLimits& limits = {}) -> Result<VmDecodedProgram, Diagnostic>;

[[nodiscard]] auto disassemble_program(const VmProgram& program)
    -> Result<std::string, Diagnostic>;

[[nodiscard]] auto disassemble_bytecode(
    std::span<const std::byte> bytecode,
    const VmLimits& limits = {}) -> Result<std::string, Diagnostic>;

} // namespace binobf::vm

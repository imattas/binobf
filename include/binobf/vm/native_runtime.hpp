#pragma once

#include <cstddef>
#include <cstdint>

extern "C" {

[[nodiscard]] auto
binobf_vm_execute_embedded_u32(const std::uint8_t* bytecode, std::size_t bytecodeSize,
                               const std::uint32_t* arguments, std::size_t argumentCount) noexcept
    -> std::uint32_t;

[[nodiscard]] auto binobf_vm_embedded_last_error() noexcept -> const char*;
}

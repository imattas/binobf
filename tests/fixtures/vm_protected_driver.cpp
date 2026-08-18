#include <cstdint>

extern "C" auto binobf_vm_add(std::uint32_t left, std::uint32_t right) -> std::uint32_t;

auto main() -> int { return binobf_vm_add(20, 22) == 42 ? 0 : 1; }

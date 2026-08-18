#include <binobf/support/deterministic_rng.hpp>

#include <limits>

namespace binobf {

auto DeterministicRng::next_u64() noexcept -> std::uint64_t {
    state_ += UINT64_C(0x9e3779b97f4a7c15);
    auto value = state_;
    value = (value ^ (value >> 30U)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27U)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31U);
}

auto DeterministicRng::uniform(std::uint64_t exclusiveBound) noexcept -> std::uint64_t {
    if (exclusiveBound < 2) {
        return 0;
    }

    const auto threshold = (std::numeric_limits<std::uint64_t>::max() - exclusiveBound + 1U)
        % exclusiveBound;
    for (;;) {
        const auto value = next_u64();
        if (value >= threshold) {
            return value % exclusiveBound;
        }
    }
}

} // namespace binobf

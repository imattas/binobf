#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <ranges>
#include <utility>

namespace binobf {

class DeterministicRng {
public:
    explicit constexpr DeterministicRng(std::uint64_t seed) noexcept : state_(seed) {}

    [[nodiscard]] auto next_u64() noexcept -> std::uint64_t;
    [[nodiscard]] auto uniform(std::uint64_t exclusiveBound) noexcept -> std::uint64_t;

    template <std::ranges::random_access_range Range>
        requires std::ranges::sized_range<Range>
    void shuffle(Range&& range) noexcept(noexcept(std::ranges::iter_swap(
        std::ranges::begin(range), std::ranges::begin(range)))) {
        const auto size = std::ranges::size(range);
        if (size < 2) {
            return;
        }

        for (auto remaining = size; remaining > 1; --remaining) {
            const auto index = uniform(static_cast<std::uint64_t>(remaining));
            std::ranges::iter_swap(
                std::ranges::begin(range) + static_cast<std::ptrdiff_t>(remaining - 1),
                std::ranges::begin(range) + static_cast<std::ptrdiff_t>(index));
        }
    }

private:
    std::uint64_t state_;
};

} // namespace binobf

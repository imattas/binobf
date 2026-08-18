#include "../test_support.hpp"

#include <binobf/support/deterministic_rng.hpp>

#include <algorithm>
#include <array>
#include <cstdint>

TEST_CASE(splitmix64_matches_published_golden_sequence) {
    binobf::DeterministicRng rng{0};
    REQUIRE_EQ(rng.next_u64(), UINT64_C(0xe220a8397b1dcdaf));
    REQUIRE_EQ(rng.next_u64(), UINT64_C(0x6e789e6aa1b965f4));
    REQUIRE_EQ(rng.next_u64(), UINT64_C(0x06c45d188009454f));
}

TEST_CASE(equal_seeds_produce_equal_sequences) {
    binobf::DeterministicRng first{8675309};
    binobf::DeterministicRng second{8675309};
    for (int index = 0; index < 32; ++index) {
        REQUIRE_EQ(first.next_u64(), second.next_u64());
    }
}

TEST_CASE(uniform_values_never_reach_the_exclusive_bound) {
    binobf::DeterministicRng rng{123456};
    for (int index = 0; index < 512; ++index) {
        REQUIRE(rng.uniform(7) < 7);
    }
    REQUIRE_EQ(rng.uniform(1), UINT64_C(0));
}

TEST_CASE(shuffle_is_deterministic_and_preserves_values) {
    std::array<int, 8> first{0, 1, 2, 3, 4, 5, 6, 7};
    std::array<int, 8> second = first;
    binobf::DeterministicRng rngA{44};
    binobf::DeterministicRng rngB{44};

    rngA.shuffle(first);
    rngB.shuffle(second);

    REQUIRE(first == second);
    auto sorted = first;
    std::sort(sorted.begin(), sorted.end());
    REQUIRE_EQ(sorted, (std::array<int, 8>{0, 1, 2, 3, 4, 5, 6, 7}));
}

int main() {
    return binobf::test::run_all();
}

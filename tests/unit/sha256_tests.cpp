#include "../test_support.hpp"

#include <binobf/support/sha256.hpp>

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

auto bytes_of(std::string_view value) -> std::span<const std::byte> {
    return std::as_bytes(std::span{value.data(), value.size()});
}

auto digest_of(std::string_view value) -> std::string {
    const auto digest = binobf::sha256(bytes_of(value));
    REQUIRE(digest.has_value());
    return binobf::sha256_hex(*digest);
}

} // namespace

TEST_CASE(sha256_matches_nist_known_vectors) {
    REQUIRE_EQ(
        digest_of(""),
        std::string{"e3b0c44298fc1c149afbf4c8996fb924"
                    "27ae41e4649b934ca495991b7852b855"});
    REQUIRE_EQ(
        digest_of("abc"),
        std::string{"ba7816bf8f01cfea414140de5dae2223"
                    "b00361a396177a9cb410ff61f20015ad"});
    REQUIRE_EQ(
        digest_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        std::string{"248d6a61d20638b8e5c026930c3e6039"
                    "a33ce45964ff2167f6ecedd419db06c1"});
}

TEST_CASE(sha256_incremental_chunks_match_single_update_and_finish_is_repeatable) {
    const std::string value(1000, 'a');
    binobf::Sha256 incremental;
    for (std::size_t offset = 0; offset < value.size(); offset += 7) {
        const auto count = std::min<std::size_t>(7, value.size() - offset);
        REQUIRE(incremental.update(bytes_of(std::string_view{value}.substr(offset, count))));
    }
    const auto expected = binobf::sha256(bytes_of(value));
    REQUIRE(expected.has_value());
    REQUIRE_EQ(incremental.finish(), *expected);
    REQUIRE_EQ(incremental.finish(), *expected);
    REQUIRE_EQ(
        binobf::sha256_hex(*expected),
        std::string{"41edece42d63e8d9bf515a9ba6932e1c"
                    "20cbc9f5a5d134645adb5db1b9737ea3"});
}

TEST_CASE(sha256_hex_is_fixed_width_lowercase) {
    binobf::Sha256Digest digest{};
    digest.front() = std::byte{0x01};
    digest.back() = std::byte{0xab};
    const auto rendered = binobf::sha256_hex(digest);
    REQUIRE_EQ(rendered.size(), std::size_t{64});
    REQUIRE_EQ(rendered.substr(0, 4), std::string{"0100"});
    REQUIRE_EQ(rendered.substr(60), std::string{"00ab"});
}

int main() {
    return binobf::test::run_all();
}

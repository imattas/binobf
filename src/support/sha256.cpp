#include <binobf/support/sha256.hpp>

#include <algorithm>
#include <bit>
#include <limits>

namespace binobf {
namespace {

constexpr std::array<std::uint32_t, 64> roundConstants{
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

auto load_u32_be(const std::byte* bytes) noexcept -> std::uint32_t {
    return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[0])) << 24U)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[1])) << 16U)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[2])) << 8U)
        | static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[3]));
}

void store_u32_be(std::uint32_t value, std::byte* bytes) noexcept {
    bytes[0] = static_cast<std::byte>((value >> 24U) & 0xffU);
    bytes[1] = static_cast<std::byte>((value >> 16U) & 0xffU);
    bytes[2] = static_cast<std::byte>((value >> 8U) & 0xffU);
    bytes[3] = static_cast<std::byte>(value & 0xffU);
}

} // namespace

Sha256::Sha256() noexcept
    : state_{
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U} {}

void Sha256::compress(std::span<const std::byte, 64> block) noexcept {
    std::array<std::uint32_t, 64> words{};
    for (std::size_t index = 0; index < 16; ++index) {
        words[index] = load_u32_be(block.data() + index * 4U);
    }
    for (std::size_t index = 16; index < words.size(); ++index) {
        const auto s0 = std::rotr(words[index - 15], 7)
            ^ std::rotr(words[index - 15], 18) ^ (words[index - 15] >> 3U);
        const auto s1 = std::rotr(words[index - 2], 17)
            ^ std::rotr(words[index - 2], 19) ^ (words[index - 2] >> 10U);
        words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }

    auto a = state_[0];
    auto b = state_[1];
    auto c = state_[2];
    auto d = state_[3];
    auto e = state_[4];
    auto f = state_[5];
    auto g = state_[6];
    auto h = state_[7];
    for (std::size_t index = 0; index < words.size(); ++index) {
        const auto sum1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
        const auto choose = (e & f) ^ (~e & g);
        const auto temporary1 = h + sum1 + choose + roundConstants[index] + words[index];
        const auto sum0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
        const auto majority = (a & b) ^ (a & c) ^ (b & c);
        const auto temporary2 = sum0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + temporary1;
        d = c;
        c = b;
        b = a;
        a = temporary1 + temporary2;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

auto Sha256::update(std::span<const std::byte> bytes) noexcept -> bool {
    constexpr auto maximumBytes = std::numeric_limits<std::uint64_t>::max() / 8U;
    if (bytes.size() > maximumBytes - byteCount_) return false;
    byteCount_ += static_cast<std::uint64_t>(bytes.size());

    std::size_t offset = 0;
    if (bufferSize_ != 0) {
        const auto count = std::min(buffer_.size() - bufferSize_, bytes.size());
        std::copy_n(bytes.begin(), count, buffer_.begin() + static_cast<std::ptrdiff_t>(bufferSize_));
        bufferSize_ += count;
        offset += count;
        if (bufferSize_ == buffer_.size()) {
            compress(std::span<const std::byte, 64>{buffer_});
            bufferSize_ = 0;
        }
    }
    while (bytes.size() - offset >= buffer_.size()) {
        compress(std::span<const std::byte, 64>{bytes.data() + offset, buffer_.size()});
        offset += buffer_.size();
    }
    if (offset < bytes.size()) {
        bufferSize_ = bytes.size() - offset;
        std::copy(bytes.begin() + static_cast<std::ptrdiff_t>(offset), bytes.end(), buffer_.begin());
    }
    return true;
}

auto Sha256::finish() const noexcept -> Sha256Digest {
    auto final = *this;
    const auto bitCount = final.byteCount_ * 8U;
    final.buffer_[final.bufferSize_++] = std::byte{0x80};
    if (final.bufferSize_ > 56U) {
        std::fill(final.buffer_.begin() + static_cast<std::ptrdiff_t>(final.bufferSize_),
                  final.buffer_.end(), std::byte{0});
        final.compress(std::span<const std::byte, 64>{final.buffer_});
        final.bufferSize_ = 0;
    }
    std::fill(final.buffer_.begin() + static_cast<std::ptrdiff_t>(final.bufferSize_),
              final.buffer_.begin() + 56, std::byte{0});
    for (std::size_t index = 0; index < 8; ++index) {
        const auto shift = static_cast<unsigned int>((7U - index) * 8U);
        final.buffer_[56U + index] = static_cast<std::byte>((bitCount >> shift) & 0xffU);
    }
    final.compress(std::span<const std::byte, 64>{final.buffer_});

    Sha256Digest digest{};
    for (std::size_t index = 0; index < final.state_.size(); ++index) {
        store_u32_be(final.state_[index], digest.data() + index * 4U);
    }
    return digest;
}

auto sha256(std::span<const std::byte> bytes) noexcept -> std::optional<Sha256Digest> {
    Sha256 hash;
    if (!hash.update(bytes)) return std::nullopt;
    return hash.finish();
}

auto sha256_hex(const Sha256Digest& digest) -> std::string {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string output;
    output.resize(digest.size() * 2U);
    for (std::size_t index = 0; index < digest.size(); ++index) {
        const auto value = std::to_integer<std::uint8_t>(digest[index]);
        output[index * 2U] = digits[(value >> 4U) & 0x0fU];
        output[index * 2U + 1U] = digits[value & 0x0fU];
    }
    return output;
}

} // namespace binobf

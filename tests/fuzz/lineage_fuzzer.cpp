#include <binobf/evidence/lineage.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto bytes = std::span{
        reinterpret_cast<const std::byte*>(data), size};
    const auto parsed = binobf::evidence::parse_lineage(bytes);
    if (parsed.has_value()) {
        std::uint64_t address = 0;
        for (std::size_t index = 0; index < size && index < 8; ++index) {
            address |= static_cast<std::uint64_t>(data[index]) << (index * 8U);
        }
        static_cast<void>(binobf::evidence::query_lineage(parsed.value(), address));
    }
    return 0;
}

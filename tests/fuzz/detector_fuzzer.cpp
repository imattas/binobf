#include <binobf/formats/detector.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto bytes = std::span<const std::byte>{
        reinterpret_cast<const std::byte*>(data), size};
    static_cast<void>(binobf::detect_binary(bytes, "fuzz.bin"));
    return 0;
}

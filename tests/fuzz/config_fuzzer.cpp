#include <binobf/config/config.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto bytes = std::span{
        reinterpret_cast<const std::byte*>(data), size};
    static_cast<void>(binobf::config::parse_transform_config(
        bytes, std::filesystem::path{"fuzz.toml"}));
    return 0;
}

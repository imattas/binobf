#include <binobf/formats/linked_image.hpp>
#include <binobf/formats/linked_writer.hpp>
#include <binobf/verify/structural_verifier.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > 65536) return 0;
    const auto bytes = std::span<const std::byte>{
        reinterpret_cast<const std::byte*>(data), size};
    auto limits = binobf::LinkedParseLimits{};
    limits.maxInputBytes = 65536;
    limits.maxSections = 256;
    limits.maxSegments = 256;
    limits.maxSymbols = 4096;
    limits.maxImports = 4096;
    limits.maxExports = 4096;
    limits.maxRelocations = 16384;
    limits.maxStringBytes = 65536;
    const auto parsed = binobf::parse_linked_image(bytes, "fuzz.bin", limits);
    if (!parsed.has_value()) return 0;
    const auto rewritten = binobf::rewrite_linked_image(parsed.value());
    if (rewritten.has_value()) {
        static_cast<void>(
            binobf::verify_linked_image(rewritten.value().bytes, "fuzz-roundtrip.bin"));
    }
    return 0;
}

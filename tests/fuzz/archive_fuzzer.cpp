#include <binobf/formats/archive.hpp>
#include <binobf/formats/archive_writer.hpp>
#include <binobf/verify/structural_verifier.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > 65536) return 0;
    const auto bytes = std::span<const std::byte>{
        reinterpret_cast<const std::byte*>(data), size};
    auto limits = binobf::ArchiveParseLimits{};
    limits.maxInputBytes = 65536;
    limits.maxMembers = 512;
    limits.maxSymbols = 4096;
    limits.maxNameBytes = 65536;
    const auto parsed = binobf::parse_archive(bytes, "fuzz.a", limits);
    if (!parsed.has_value()) return 0;
    const auto written = binobf::write_archive(parsed.value());
    if (written.has_value()) {
        static_cast<void>(binobf::verify_archive(written.value(), "fuzz-roundtrip.a"));
    }
    return 0;
}

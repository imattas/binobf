#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/transforms/baseline.hpp>
#include <binobf/transforms/pass_manager.hpp>
#include <binobf/verify/structural_verifier.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > 65536) return 0;
    const auto bytes = std::span<const std::byte>{
        reinterpret_cast<const std::byte*>(data), size};
    const auto parsed = binobf::parse_object(bytes, "fuzz.o");
    if (!parsed.has_value()) return 0;
    const auto written = binobf::write_object(parsed.value());
    if (written.has_value()) {
        static_cast<void>(binobf::verify_object(written.value(), "fuzz-roundtrip.o"));
    }
    binobf::PassManager manager;
    if (!manager.add(binobf::make_strip_debug_pass()).has_value()) return 0;
    if (!manager.add(binobf::make_metadata_cleanup_pass()).has_value()) return 0;
    if (!manager.add(binobf::make_rename_private_symbols_pass()).has_value()) return 0;
    binobf::TransformContext context{0x62696e6f6266, false};
    static_cast<void>(manager.run(context, parsed.value()));
    return 0;
}

#include <binobf/c_api.h>

#include <binobf/evidence/manifest.hpp>
#include <binobf/formats/detector.hpp>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

namespace {

void copy_string(char* destination, std::size_t capacity, std::string_view value) noexcept {
    if (destination == nullptr || capacity == 0U) return;
    const auto count = std::min(capacity - 1U, value.size());
    std::memcpy(destination, value.data(), count);
    destination[count] = '\0';
}

void set_error(binobf_error* error, std::string_view code, std::string_view message) noexcept {
    if (error == nullptr || error->struct_size < sizeof(binobf_error)) return;
    copy_string(error->code, error->code_capacity, code);
    copy_string(error->message, error->message_capacity, message);
}

} // namespace

extern "C" {

const char* binobf_version(void) {
    static const std::string version{binobf::evidence::tool_version()};
    return version.c_str();
}

binobf_status binobf_detect(
    const void* bytes,
    std::size_t size,
    const char* source_name,
    binobf_detection* output,
    binobf_error* error) {
    if (output == nullptr || output->struct_size < sizeof(binobf_detection)
        || (bytes == nullptr && size != 0U)) {
        set_error(error, "c_api.invalid_argument", "output, struct_size, or input bytes are invalid");
        return BINOBF_STATUS_INVALID_ARGUMENT;
    }
    const auto input = std::span<const std::byte>{
        static_cast<const std::byte*>(bytes), size};
    const auto detected = binobf::detect_binary(input, source_name == nullptr ? "" : source_name);
    if (!detected.has_value()) {
        set_error(error, detected.error().code, detected.error().message);
        return BINOBF_STATUS_FAILURE;
    }
    output->format = static_cast<uint32_t>(detected.value().format);
    output->type = static_cast<uint32_t>(detected.value().type);
    output->architecture = static_cast<uint32_t>(detected.value().architecture);
    output->entry_point = detected.value().entryPoint;
    set_error(error, {}, {});
    return BINOBF_STATUS_OK;
}

} // extern "C"

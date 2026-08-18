#include <binobf/c_api.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <string>

#include "../test_support.hpp"

TEST_CASE(c_api_reports_version_and_detects_elf) {
    REQUIRE(std::strlen(binobf_version()) > 0U);
    std::array<std::byte, 64> elf{
        std::byte{0x7f}, std::byte{'E'}, std::byte{'L'}, std::byte{'F'},
        std::byte{2}, std::byte{1}, std::byte{1}};
    elf[18] = std::byte{62};
    elf[16] = std::byte{1};
    elf[52] = std::byte{64};
    binobf_detection detection{sizeof(binobf_detection), 0, 0, 0, 0};
    char code[64]{};
    char message[256]{};
    binobf_error error{
        .struct_size = sizeof(binobf_error),
        .code = code,
        .code_capacity = sizeof(code),
        .message = message,
        .message_capacity = sizeof(message)};
    REQUIRE_EQ(binobf_detect(
                   elf.data(), elf.size(), "fixture.o", &detection, &error),
               BINOBF_STATUS_OK);
    REQUIRE_EQ(detection.format, 2U);
    REQUIRE_EQ(detection.type, 3U);
    REQUIRE_EQ(detection.architecture, 1U);
    REQUIRE(std::strlen(code) == 0U);
    REQUIRE(std::strlen(message) == 0U);
}

TEST_CASE(c_api_rejects_invalid_arguments_with_bounded_error_output) {
    char code[8]{};
    char message[8]{};
    binobf_error error{
        .struct_size = sizeof(binobf_error),
        .code = code,
        .code_capacity = sizeof(code),
        .message = message,
        .message_capacity = sizeof(message)};
    binobf_detection detection{sizeof(binobf_detection), 0, 0, 0, 0};
    REQUIRE_EQ(binobf_detect(nullptr, 1U, nullptr, &detection, &error),
               BINOBF_STATUS_INVALID_ARGUMENT);
    REQUIRE_EQ(std::string{code}, "c_api.i");
    REQUIRE_EQ(std::string{message}, "output,");
}

int main() {
    return binobf::test::run_all();
}

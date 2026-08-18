#pragma once

#include <exception>
#include <functional>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace binobf::test {

struct TestCase {
    std::string_view name;
    std::function<void()> body;
};

inline auto registry() -> std::vector<TestCase>& {
    static std::vector<TestCase> tests;
    return tests;
}

class Registrar {
public:
    Registrar(std::string_view name, std::function<void()> body) {
        registry().push_back(TestCase{name, std::move(body)});
    }
};

[[noreturn]] inline void fail(
    std::string_view expression,
    std::string_view file,
    int line,
    std::string_view detail = {}) {
    std::ostringstream message;
    message << file << ':' << line << ": assertion failed: " << expression;
    if (!detail.empty()) {
        message << " (" << detail << ')';
    }
    throw std::runtime_error(message.str());
}

inline auto run_all() -> int {
    std::size_t failures = 0;
    for (const auto& test : registry()) {
        try {
            test.body();
            std::cout << "[PASS] " << test.name << '\n';
        } catch (const std::exception& error) {
            ++failures;
            std::cerr << "[FAIL] " << test.name << ": " << error.what() << '\n';
        } catch (...) {
            ++failures;
            std::cerr << "[FAIL] " << test.name << ": unknown exception\n";
        }
    }
    std::cout << (registry().size() - failures) << '/' << registry().size()
              << " tests passed\n";
    return failures == 0 ? 0 : 1;
}

} // namespace binobf::test

#define BINOBF_TEST_CONCAT_INNER(left, right) left##right
#define BINOBF_TEST_CONCAT(left, right) BINOBF_TEST_CONCAT_INNER(left, right)
#define TEST_CASE(name)                                                                    \
    static void BINOBF_TEST_CONCAT(binobf_test_body_, __LINE__)();                         \
    static ::binobf::test::Registrar BINOBF_TEST_CONCAT(binobf_test_registrar_, __LINE__){ \
        #name, BINOBF_TEST_CONCAT(binobf_test_body_, __LINE__)};                           \
    static void BINOBF_TEST_CONCAT(binobf_test_body_, __LINE__)()

#define REQUIRE(expression)                                                        \
    do {                                                                           \
        if (!(expression)) {                                                       \
            ::binobf::test::fail(#expression, __FILE__, __LINE__);                \
        }                                                                          \
    } while (false)

#define REQUIRE_EQ(actual, expected)                                                \
    do {                                                                            \
        const auto& binobf_actual = (actual);                                       \
        const auto& binobf_expected = (expected);                                   \
        if (!(binobf_actual == binobf_expected)) {                                  \
            ::binobf::test::fail(#actual " == " #expected, __FILE__, __LINE__);    \
        }                                                                           \
    } while (false)

#define REQUIRE_CONTAINS(haystack, needle)                                          \
    do {                                                                            \
        const auto binobf_haystack_owner = (haystack);                              \
        const auto binobf_needle_owner = (needle);                                  \
        const std::string_view binobf_haystack = binobf_haystack_owner;             \
        const std::string_view binobf_needle = binobf_needle_owner;                 \
        if (binobf_haystack.find(binobf_needle) == std::string_view::npos) {        \
            ::binobf::test::fail(#haystack " contains " #needle, __FILE__, __LINE__); \
        }                                                                           \
    } while (false)

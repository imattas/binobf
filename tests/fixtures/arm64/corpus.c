#if defined(_WIN32)
#define BINOBF_EXPORT __declspec(dllexport)
#define BINOBF_TLS __declspec(thread)
#else
#define BINOBF_EXPORT __attribute__((visibility("default")))
#define BINOBF_TLS _Thread_local
#endif

typedef float binobf_v4f __attribute__((vector_size(16)));
typedef long long (*binobf_binary_fn)(long long, long long);

long long binobf_arm64_common;
BINOBF_TLS long long binobf_arm64_tls;
BINOBF_EXPORT long long binobf_arm64_global = 17;
static const long long binobf_arm64_table[] = {3, 5, 11, 17, 23, 31, 43, 59};

BINOBF_EXPORT long long binobf_arm64_add(long long left, long long right) {
    return left + right + binobf_arm64_global;
}

BINOBF_EXPORT long long binobf_arm64_nine_args(
    long long a, long long b, long long c, long long d, long long e,
    long long f, long long g, long long h, long long i) {
    return a - b + c - d + e - f + g - h + i;
}

BINOBF_EXPORT long long binobf_arm64_loop(const long long* values, unsigned count) {
    long long result = 0;
    for (unsigned index = 0; index < count; ++index) {
        result += values[index] * (long long)(index + 1U);
    }
    return result;
}

BINOBF_EXPORT long long binobf_arm64_switch(unsigned value) {
    return binobf_arm64_table[value & 7U];
}

BINOBF_EXPORT long long binobf_arm64_recursive(unsigned value) {
    if (value < 2U) return (long long)value;
    return binobf_arm64_recursive(value - 1U) + binobf_arm64_recursive(value - 2U);
}

BINOBF_EXPORT long long binobf_arm64_tail(unsigned value, long long accumulator) {
    if (value == 0U) return accumulator;
    return binobf_arm64_tail(value - 1U, accumulator + (long long)value);
}

BINOBF_EXPORT long long binobf_arm64_indirect(
    binobf_binary_fn function, long long left, long long right) {
    return function(left, right);
}

BINOBF_EXPORT binobf_v4f binobf_arm64_vector(binobf_v4f left, binobf_v4f right) {
    return left * right + left;
}

BINOBF_EXPORT long long binobf_arm64_storage(void) {
    ++binobf_arm64_tls;
    binobf_arm64_common += binobf_arm64_tls;
    return binobf_arm64_common;
}

BINOBF_EXPORT binobf_binary_fn binobf_arm64_function_pointer = binobf_arm64_add;

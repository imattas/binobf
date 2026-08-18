#if defined(_WIN32)
#define BINOBF_EXPORT __declspec(dllexport)
#define BINOBF_CDECL __cdecl
#define BINOBF_STDCALL __stdcall
#define BINOBF_FASTCALL __fastcall
#define BINOBF_VECTORCALL __vectorcall
#define BINOBF_TLS __declspec(thread)
#else
#define BINOBF_EXPORT __attribute__((visibility("default")))
#define BINOBF_CDECL
#define BINOBF_STDCALL
#define BINOBF_FASTCALL
#define BINOBF_VECTORCALL
#define BINOBF_TLS _Thread_local
#endif

typedef float binobf_v4f __attribute__((vector_size(16)));
typedef int (*binobf_binary_fn)(int, int);

int binobf_c_common;
BINOBF_TLS int binobf_c_tls;
BINOBF_EXPORT int binobf_c_global = 17;

BINOBF_EXPORT int BINOBF_CDECL binobf_c_add(int left, int right) {
    return left + right + binobf_c_global;
}

BINOBF_EXPORT int BINOBF_STDCALL binobf_c_stack_args(
    int a, int b, int c, int d, int e, int f) {
    return a - b + c - d + e - f;
}

BINOBF_EXPORT int BINOBF_FASTCALL binobf_c_register_args(int left, int right) {
    return (left * 3) ^ (right + 11);
}

BINOBF_EXPORT int BINOBF_VECTORCALL binobf_c_vector_args(
    binobf_v4f left, binobf_v4f right) {
    binobf_v4f sum = left + right;
    return (int)(sum[0] + sum[1] + sum[2] + sum[3]);
}

BINOBF_EXPORT int binobf_c_loop(const int* values, unsigned count) {
    int result = 0;
    for (unsigned index = 0; index < count; ++index) {
        result += values[index] * (int)(index + 1U);
    }
    return result;
}

BINOBF_EXPORT int binobf_c_switch(unsigned value) {
    switch (value & 7U) {
    case 0: return 3;
    case 1: return 5;
    case 2: return 11;
    case 3: return 17;
    case 4: return 23;
    case 5: return 31;
    case 6: return 43;
    default: return 59;
    }
}

BINOBF_EXPORT int binobf_c_recursive(unsigned value) {
    if (value < 2U) return (int)value;
    return binobf_c_recursive(value - 1U) + binobf_c_recursive(value - 2U);
}

BINOBF_EXPORT int binobf_c_tail(unsigned value, int accumulator) {
    if (value == 0U) return accumulator;
    return binobf_c_tail(value - 1U, accumulator + (int)value);
}

BINOBF_EXPORT int binobf_c_indirect(binobf_binary_fn function, int left, int right) {
    return function(left, right);
}

BINOBF_EXPORT float binobf_c_f32(float left, float right) {
    return left * 1.5f + right;
}

BINOBF_EXPORT double binobf_c_f64(double left, double right) {
    return left / 3.0 + right * 2.0;
}

BINOBF_EXPORT binobf_v4f binobf_c_sse2(binobf_v4f left, binobf_v4f right) {
    return left * right + left;
}

BINOBF_EXPORT int binobf_c_storage(void) {
    ++binobf_c_tls;
    binobf_c_common += binobf_c_tls;
    return binobf_c_common;
}

BINOBF_EXPORT binobf_binary_fn binobf_c_function_pointer = binobf_c_add;

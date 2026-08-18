#if defined(_WIN32)
#define BINOBF_EXPORT __declspec(dllexport)
#else
#define BINOBF_EXPORT __attribute__((visibility("default")))
#endif

template <typename T>
__attribute__((noinline)) T binobf_cpp_template(T value) {
    return value * static_cast<T>(5) + static_cast<T>(9);
}

template int binobf_cpp_template<int>(int);
template float binobf_cpp_template<float>(float);

struct BinobfAccumulator {
    int bias;
    __attribute__((noinline)) int apply(int value) const { return value + bias; }
};

extern "C" BINOBF_EXPORT int binobf_cpp_comdat_int(int value) {
    return binobf_cpp_template(value);
}

extern "C" BINOBF_EXPORT float binobf_cpp_comdat_float(float value) {
    return binobf_cpp_template(value);
}

extern "C" BINOBF_EXPORT int binobf_cpp_member(int value) {
    BinobfAccumulator accumulator{13};
    return accumulator.apply(value);
}

extern "C" BINOBF_EXPORT int binobf_cpp_exception(int value) {
    try {
        if (value < 0) throw value;
        return value * 2;
    } catch (int thrown) {
        return -thrown + 1;
    }
}

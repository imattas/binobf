#if defined(_WIN32)
#define BINOBF_EXPORT __declspec(dllexport)
#else
#define BINOBF_EXPORT __attribute__((visibility("default")))
#endif

template <typename T>
__attribute__((noinline)) T binobf_arm64_template(T value) {
    return value * static_cast<T>(5) + static_cast<T>(9);
}

template int binobf_arm64_template<int>(int);
template double binobf_arm64_template<double>(double);

struct BinobfArm64Accumulator {
    long long bias;
    __attribute__((noinline)) long long apply(long long value) const {
        return value + bias;
    }
};

struct BinobfArm64Base {
    virtual ~BinobfArm64Base() = default;
    virtual long long apply(long long value) const = 0;
};

struct BinobfArm64Derived final : BinobfArm64Base {
    long long bias;
    explicit BinobfArm64Derived(long long value) : bias(value) {}
    long long apply(long long value) const override { return value * 3 + bias; }
};

extern "C" BINOBF_EXPORT int binobf_arm64_cpp_comdat(int value) {
    return binobf_arm64_template(value);
}

extern "C" BINOBF_EXPORT long long binobf_arm64_cpp_member(long long value) {
    BinobfArm64Accumulator accumulator{13};
    return accumulator.apply(value);
}

extern "C" BINOBF_EXPORT long long binobf_arm64_cpp_virtual(
    const BinobfArm64Base* object, long long value) {
    return object->apply(value);
}

extern "C" BINOBF_EXPORT long long binobf_arm64_cpp_exception(long long value) {
    try {
        if (value < 0) throw value;
        return value * 2;
    } catch (long long thrown) {
        return -thrown + 1;
    }
}

extern "C" BINOBF_EXPORT long long binobf_arm64_cpp_local(long long value) {
    BinobfArm64Derived object{7};
    return object.apply(value);
}

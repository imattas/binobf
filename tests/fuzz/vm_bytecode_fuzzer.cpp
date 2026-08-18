#include <binobf/vm/bytecode.hpp>
#include <binobf/vm/runtime.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > 65536) return 0;
    const auto bytes = std::span<const std::byte>{
        reinterpret_cast<const std::byte*>(data), size};
    auto limits = binobf::vm::VmLimits{};
    limits.maxBytecodeBytes = 65536;
    limits.maxInstructions = 4096;
    limits.maxRegisters = 256;
    limits.maxSlots = 256;
    limits.maxMemoryBytes = 65536;
    limits.maxNativeArguments = 16;
    limits.maxInternalArguments = 16;
    limits.maxFrameDepth = 16;
    limits.maxSteps = 10000;
    const auto decoded = binobf::vm::decode_program(bytes, limits);
    if (!decoded.has_value()) return 0;
    const auto assembled = binobf::vm::assemble_program(
        decoded.value().program,
        binobf::vm::VmAssemblyOptions{decoded.value().encodingSeed},
        limits);
    if (assembled.has_value()) {
        static_cast<void>(binobf::vm::decode_program(assembled.value(), limits));
    }
    binobf::vm::LinearVmMemory memory{decoded.value().program.localMemorySize};
    binobf::vm::RejectingVmNativeCallBridge bridge;
    static_cast<void>(binobf::vm::execute_program(
        decoded.value().program, memory, bridge, {}, limits));
    return 0;
}

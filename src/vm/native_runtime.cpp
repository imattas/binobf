#include <binobf/vm/native_runtime.hpp>

#include <binobf/vm/bytecode.hpp>
#include <binobf/vm/runtime.hpp>

#include <cstddef>
#include <exception>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

thread_local std::string lastError;

void set_error(const binobf::Diagnostic& diagnostic) {
    lastError = diagnostic.code + ": " + diagnostic.message;
}

void set_error(std::string message) { lastError = std::move(message); }

} // namespace

extern "C" auto
binobf_vm_execute_embedded_u32(const std::uint8_t* bytecode, std::size_t bytecodeSize,
                               const std::uint32_t* arguments, std::size_t argumentCount) noexcept
    -> std::uint32_t {
    try {
        lastError.clear();
        if (bytecode == nullptr && bytecodeSize != 0) {
            set_error("vm.native_bytecode: embedded bytecode pointer is null");
            return 0;
        }
        if (arguments == nullptr && argumentCount != 0) {
            set_error("vm.native_arguments: embedded argument pointer is null");
            return 0;
        }
        if (argumentCount > 4) {
            set_error("vm.native_arguments: embedded argument count exceeds four");
            return 0;
        }

        const auto bytes =
            std::span<const std::byte>{reinterpret_cast<const std::byte*>(bytecode), bytecodeSize};
        const auto decoded = binobf::vm::decode_program(bytes);
        if (!decoded.has_value()) {
            set_error(decoded.error());
            return 0;
        }

        binobf::vm::VmExecutionInput input;
        input.arguments.reserve(argumentCount);
        for (std::size_t index = 0; index < argumentCount; ++index) {
            input.arguments.push_back(
                binobf::vm::VmValue::from_bits(binobf::vm::VmWidth::U32, arguments[index]));
        }
        binobf::vm::LinearVmMemory memory{decoded.value().program.localMemorySize};
        binobf::vm::RejectingVmNativeCallBridge bridge;
        const auto result =
            binobf::vm::execute_program(decoded.value().program, memory, bridge, input);
        if (!result.has_value()) {
            set_error(result.error());
            return 0;
        }
        if (result.value().returnValue.width() != binobf::vm::VmWidth::U32) {
            set_error("vm.native_return_width: embedded program did not return u32");
            return 0;
        }
        return static_cast<std::uint32_t>(result.value().returnValue.bits());
    } catch (const std::exception& exception) {
        set_error(std::string{"vm.native_exception: "} + exception.what());
        return 0;
    } catch (...) {
        set_error("vm.native_exception: unknown embedded runtime failure");
        return 0;
    }
}

extern "C" auto binobf_vm_embedded_last_error() noexcept -> const char* {
    return lastError.c_str();
}

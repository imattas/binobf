#pragma once

#include <binobf/vm/ir.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace binobf::vm {

struct VmFlags {
    bool zero{false};
    bool sign{false};
    bool carry{false};
    bool overflow{false};

    auto operator==(const VmFlags&) const -> bool = default;
};

class VmRegisterFile {
public:
    explicit VmRegisterFile(std::size_t count);

    [[nodiscard]] auto read(VmRegister index) const -> Result<VmValue, Diagnostic>;
    [[nodiscard]] auto write(VmRegister index, VmValue value)
        -> Result<std::size_t, Diagnostic>;
    [[nodiscard]] auto size() const noexcept -> std::size_t { return values_.size(); }

private:
    std::vector<std::optional<VmValue>> values_;
};

class VmFrameStack {
public:
    VmFrameStack(std::size_t slotCount, std::size_t maxDepth);

    [[nodiscard]] auto load(VmSlot slot) const -> Result<VmValue, Diagnostic>;
    [[nodiscard]] auto store(VmSlot slot, VmValue value)
        -> Result<std::size_t, Diagnostic>;
    [[nodiscard]] auto push_frame() -> Result<std::size_t, Diagnostic>;
    [[nodiscard]] auto pop_frame() -> Result<std::size_t, Diagnostic>;
    [[nodiscard]] auto depth() const noexcept -> std::size_t { return frames_.size(); }

private:
    std::size_t slotCount_{0};
    std::size_t maxDepth_{0};
    std::vector<std::vector<std::optional<VmValue>>> frames_;
};

class VmMemory {
public:
    virtual ~VmMemory() = default;
    [[nodiscard]] virtual auto size() const noexcept -> std::size_t = 0;
    [[nodiscard]] virtual auto load(std::uint64_t offset, VmWidth width) const
        -> Result<VmValue, Diagnostic> = 0;
    [[nodiscard]] virtual auto store(std::uint64_t offset, VmValue value)
        -> Result<std::size_t, Diagnostic> = 0;
};

class LinearVmMemory final : public VmMemory {
public:
    explicit LinearVmMemory(std::size_t size);

    [[nodiscard]] auto size() const noexcept -> std::size_t override { return bytes_.size(); }
    [[nodiscard]] auto load(std::uint64_t offset, VmWidth width) const
        -> Result<VmValue, Diagnostic> override;
    [[nodiscard]] auto store(std::uint64_t offset, VmValue value)
        -> Result<std::size_t, Diagnostic> override;
    [[nodiscard]] auto bytes() const noexcept -> std::span<const std::byte> { return bytes_; }

private:
    std::vector<std::byte> bytes_;
};

class VmNativeCallBridge {
public:
    virtual ~VmNativeCallBridge() = default;
    [[nodiscard]] virtual auto invoke(
        std::uint32_t functionId,
        std::span<const VmValue> arguments) -> Result<VmValue, Diagnostic> = 0;
};

class RejectingVmNativeCallBridge final : public VmNativeCallBridge {
public:
    [[nodiscard]] auto invoke(
        std::uint32_t functionId,
        std::span<const VmValue> arguments) -> Result<VmValue, Diagnostic> override;
};

struct VmExecutionInput {
    std::vector<VmValue> arguments;
};

struct VmExecutionResult {
    VmValue returnValue{VmValue::from_bits(VmWidth::U64, 0)};
    std::uint64_t steps{0};
    VmFlags flags;
};

[[nodiscard]] auto execute_program(
    const VmProgram& program,
    VmMemory& memory,
    VmNativeCallBridge& nativeCalls,
    const VmExecutionInput& input = {},
    const VmLimits& limits = {}) -> Result<VmExecutionResult, Diagnostic>;

} // namespace binobf::vm

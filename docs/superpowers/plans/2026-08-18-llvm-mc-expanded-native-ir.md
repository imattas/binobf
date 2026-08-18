# LLVM MC Provider and Expanded Native IR Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a pinned in-process LLVM 22.1.8 X86/AArch64 MC provider and migrate native IR to a validated type, memory, call, control-flow, fallback-effect, and unwind model without changing current capability levels.

**Architecture:** LLVM is a private static dependency that assembles bounded backend-generated text into an in-memory relocatable object; binobf extracts section bytes and typed fixups, then independently re-decodes the bytes. The canonical native IR uses `IrType` and `IrValue`, while checked integer-width helpers preserve existing VM behavior during the migration.

**Tech Stack:** C++20, CMake 3.25+, Ninja, LLVM `llvmorg-22.1.8` (X86 and AArch64 only), Capstone 5.0.9, existing `Result<T, Diagnostic>` and local test harness.

**Spec:** `docs/superpowers/specs/2026-08-18-llvm-mc-expanded-native-ir-design.md`

## Global Constraints

- Fetch only the official `llvm-project-22.1.8.src.tar.xz` archive with SHA-256 `922f1817a0df7b1489272d18134ee0087a8b068828f87ac63b9861b1a9965888`.
- Build only LLVM X86 and AArch64 static-library components; build no LLVM tools, projects, runtimes, tests, examples, benchmarks, docs, or bindings.
- LLVM types, headers, definitions, and link dependencies remain private to `binobf_core`.
- Preserve current decoder, x86-64 transform, VM bytecode, VM runtime, and installed-consumer behavior.
- Reject file-reading, macro, conditional, custom-section, debug, visibility, target-option, and binary-include assembler directives before LLVM parsing.
- Bound assembly bytes, lines, symbols, emitted bytes, fixups, instructions, IR values, blocks, storage locations, calls, memory operations, aggregate bytes, and unwind regions.
- Keep capability statuses unchanged throughout this track.
- Follow red-green-refactor TDD, warning-as-error builds, focused commits, and the safety boundary in `docs/security-boundaries.md`.

---

### Task 1: Provider-neutral code-generation contract

**Files:**
- Create: `include/binobf/architecture/codegen.hpp`
- Create: `src/architecture/codegen_provider.cpp`
- Create: `tests/unit/codegen_provider_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `Architecture`, `BinaryFormat`, `BinaryAddress`, `Result<T, Diagnostic>`.
- Produces: `MachineAssemblyRequest`, `MachineFixup`, `MachineEmission`, `CodegenProvider`, and `make_codegen_provider()`.

- [ ] **Step 1: Write the missing-contract test**

Create `tests/unit/codegen_provider_tests.cpp`:

```cpp
#include <binobf/architecture/codegen.hpp>
#include "../test_support.hpp"

#include <array>

TEST_CASE(codegen_provider_is_fixed_to_each_supported_architecture) {
    for (const auto architecture : std::array{
             binobf::Architecture::X86,
             binobf::Architecture::X86_64,
             binobf::Architecture::ARM64}) {
        auto provider = binobf::make_codegen_provider(architecture);
        REQUIRE(provider.has_value());
        REQUIRE_EQ(provider.value()->architecture(), architecture);
        REQUIRE_EQ(provider.value()->provider_version(), "LLVM 22.1.8");
    }
    const auto unknown = binobf::make_codegen_provider(binobf::Architecture::Unknown);
    REQUIRE(!unknown.has_value());
    REQUIRE_EQ(unknown.error().code, "codegen.unsupported_architecture");
}

TEST_CASE(codegen_request_defaults_are_bounded_and_provider_neutral) {
    const binobf::MachineAssemblyRequest request{};
    REQUIRE(request.limits.maxAssemblyBytes > 0U);
    REQUIRE(request.limits.maxAssemblyBytes <= (1U << 20U));
    REQUIRE(request.limits.maxEmittedBytes <= (16U << 20U));
    REQUIRE_EQ(request.sectionName, ".text");
}

int main() { return binobf::test::run_all(); }
```

- [ ] **Step 2: Register the test and prove the header is absent**

Add the unit target using the existing warning/test pattern, then run:

```powershell
cmake --build build\m12-verify-debug --target binobf_codegen_provider_tests
```

Expected: compilation fails on missing `binobf/architecture/codegen.hpp`.

- [ ] **Step 3: Add the complete public value contract**

Define these public types without forward-declaring an LLVM type:

```cpp
enum class MachineSyntax : std::uint8_t { Intel, GNU };
enum class RelocationModel : std::uint8_t { Static, PositionIndependent, DynamicNoPic };
enum class CodeModel : std::uint8_t { Small, Kernel, Medium, Large };
enum class MachineFixupKind : std::uint8_t {
    Absolute8, Absolute16, Absolute32, Absolute64,
    PcRelative8, PcRelative16, PcRelative32, PcRelative64,
    GotRelative32, PltRelative32, SectionRelative32,
    AArch64Branch26, AArch64Call26, AArch64Page21, AArch64PageOffset12,
};
struct MachineCodeLimits {
    std::size_t maxAssemblyBytes{1U << 20U};
    std::size_t maxLines{65536};
    std::size_t maxSymbols{65536};
    std::size_t maxEmittedBytes{16U << 20U};
    std::size_t maxFixups{1U << 20U};
    std::size_t maxInstructions{1U << 20U};
};
struct MachineAssemblyRequest {
    Architecture architecture{Architecture::Unknown};
    BinaryFormat format{BinaryFormat::Unknown};
    std::string triple;
    std::string cpu;
    std::string features;
    std::string assembly;
    std::string sectionName{".text"};
    BinaryAddress baseAddress{};
    MachineSyntax syntax{MachineSyntax::Intel};
    RelocationModel relocationModel{RelocationModel::Static};
    CodeModel codeModel{CodeModel::Small};
    MachineCodeLimits limits{};
    std::optional<std::size_t> expectedInstructionCount;
};
struct MachineFixup {
    std::uint64_t offset{0};
    std::uint8_t bitWidth{0};
    bool isSigned{false};
    bool pcRelative{false};
    std::int64_t addend{0};
    std::string symbol;
    MachineFixupKind kind{MachineFixupKind::Absolute32};
    auto operator==(const MachineFixup&) const -> bool = default;
};
struct MachineEmission {
    std::vector<std::byte> bytes;
    std::uint64_t alignment{1};
    std::vector<MachineFixup> fixups;
    std::vector<std::string> clobberedRegisters;
    std::vector<std::string> unwindActions;
    std::string provider;
};
class CodegenProvider {
public:
    virtual ~CodegenProvider() = default;
    virtual auto architecture() const noexcept -> Architecture = 0;
    virtual auto provider_version() const noexcept -> std::string_view = 0;
    virtual auto emit(const MachineAssemblyRequest&) const
        -> Result<MachineEmission, Diagnostic> = 0;
};
auto make_codegen_provider(Architecture)
    -> Result<std::unique_ptr<CodegenProvider>, Diagnostic>;
```

Implement a contract-only fixed-architecture provider in
`src/architecture/codegen_provider.cpp`. Its factory returns a provider for x86, x86-64, and ARM64,
rejects `Unknown` with `codegen.unsupported_architecture`, reports version `LLVM 22.1.8`, and returns
`codegen.not_implemented` from `emit()`. Task 2 replaces only that emission body after the pinned
private dependency exists.

- [ ] **Step 4: Run the contract test to green**

```powershell
cmake --build build\m12-verify-debug --target binobf_codegen_provider_tests
ctest --test-dir build\m12-verify-debug -R '^codegen_provider$' --output-on-failure
```

- [ ] **Step 5: Commit the public contract**

```powershell
git add CMakeLists.txt include/binobf/architecture/codegen.hpp `
  src/architecture/codegen_provider.cpp tests/unit/codegen_provider_tests.cpp
git commit -m "test: define machine code provider contract"
```

---

### Task 2: Pinned minimal LLVM dependency

**Files:**
- Create: `cmake/BinobfLLVM.cmake`
- Modify: `src/architecture/codegen_provider.cpp`
- Modify: `CMakeLists.txt`
- Modify: `THIRD_PARTY_NOTICES.md`
- Create: `licenses/LLVM_LICENSE.txt`
- Modify: `tests/unit/codegen_provider_tests.cpp`

**Interfaces:**
- Consumes: the Task 1 public contract.
- Produces: private LLVM targets and fixed-architecture provider instances.

- [ ] **Step 1: Add a failing provider identity test**

Append a test requiring non-empty provider identity and a structured empty-input failure:

```cpp
TEST_CASE(codegen_provider_rejects_empty_and_mismatched_requests) {
    auto provider = binobf::make_codegen_provider(binobf::Architecture::X86_64);
    REQUIRE(provider.has_value());
    const auto empty = provider.value()->emit(binobf::MachineAssemblyRequest{
        .architecture = binobf::Architecture::X86_64,
        .format = binobf::BinaryFormat::COFF,
        .triple = "x86_64-pc-windows-msvc",
    });
    REQUIRE(!empty.has_value());
    REQUIRE_EQ(empty.error().code, "codegen.empty_input");
    const auto mismatch = provider.value()->emit(binobf::MachineAssemblyRequest{
        .architecture = binobf::Architecture::ARM64,
        .format = binobf::BinaryFormat::COFF,
        .triple = "aarch64-pc-windows-msvc",
        .assembly = "ret",
    });
    REQUIRE(!mismatch.has_value());
    REQUIRE_EQ(mismatch.error().code, "codegen.request_mismatch");
}
```

- [ ] **Step 2: Configure the official archive privately**

In `cmake/BinobfLLVM.cmake`, set cache values before adding LLVM:

```cmake
set(LLVM_TARGETS_TO_BUILD "X86;AArch64" CACHE STRING "" FORCE)
set(LLVM_ENABLE_PROJECTS "" CACHE STRING "" FORCE)
set(LLVM_ENABLE_RUNTIMES "" CACHE STRING "" FORCE)
set(LLVM_INCLUDE_TESTS OFF CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_DOCS OFF CACHE BOOL "" FORCE)
set(LLVM_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(LLVM_BUILD_UTILS OFF CACHE BOOL "" FORCE)
set(LLVM_ENABLE_BINDINGS OFF CACHE BOOL "" FORCE)
set(LLVM_ENABLE_TERMINFO OFF CACHE BOOL "" FORCE)
set(LLVM_ENABLE_ZLIB OFF CACHE BOOL "" FORCE)
set(LLVM_ENABLE_ZSTD OFF CACHE BOOL "" FORCE)
set(LLVM_ENABLE_LIBXML2 OFF CACHE BOOL "" FORCE)
set(LLVM_ENABLE_CURL OFF CACHE BOOL "" FORCE)
FetchContent_Declare(llvm_dependency
    URL https://github.com/llvm/llvm-project/releases/download/llvmorg-22.1.8/llvm-project-22.1.8.src.tar.xz
    URL_HASH SHA256=922f1817a0df7b1489272d18134ee0087a8b068828f87ac63b9861b1a9965888
    DOWNLOAD_EXTRACT_TIMESTAMP FALSE)
FetchContent_GetProperties(llvm_dependency)
if(NOT llvm_dependency_POPULATED)
    FetchContent_Populate(llvm_dependency)
    add_subdirectory("${llvm_dependency_SOURCE_DIR}/llvm"
                     "${llvm_dependency_BINARY_DIR}" EXCLUDE_FROM_ALL)
endif()
```

Map only `Support;Target;MC;MCParser;Object;BinaryFormat;X86Info;X86Desc;X86AsmParser;AArch64Info;AArch64Desc;AArch64AsmParser` and link them privately. Add only LLVM source/generated include directories privately.

- [ ] **Step 3: Add the minimal provider shell**

Implement fixed architecture, version, request mismatch, empty assembly, unsupported format/triple,
and resource-limit checks in `src/architecture/codegen_provider.cpp`. Initialize X86 and AArch64
target info/MC/parser registrations exactly once with `std::once_flag`. Return
`codegen.not_implemented` only for non-empty valid assembly until Task 3.

- [ ] **Step 4: Add dependency license evidence**

Copy LLVM's Apache-2.0-with-LLVM-exception license text from the fetched release into
`licenses/LLVM_LICENSE.txt`, install it beside existing licenses, and add LLVM 22.1.8 plus the
archive hash to `THIRD_PARTY_NOTICES.md`.

- [ ] **Step 5: Build the provider target and run identity tests**

```powershell
cmake --build build\m12-verify-debug --target binobf_codegen_provider_tests
ctest --test-dir build\m12-verify-debug -R '^codegen_provider$' --output-on-failure
```

- [ ] **Step 6: Commit the pinned provider foundation**

```powershell
git add CMakeLists.txt cmake/BinobfLLVM.cmake src/architecture/codegen_provider.cpp `
  THIRD_PARTY_NOTICES.md licenses/LLVM_LICENSE.txt tests/unit/codegen_provider_tests.cpp
git commit -m "build: add pinned minimal LLVM MC provider"
```

---

### Task 3: In-memory assembly, extraction, and independent re-decoding

**Files:**
- Modify: `src/architecture/codegen_provider.cpp`
- Create: `src/architecture/llvm_mc_assembler.hpp`
- Create: `src/architecture/llvm_mc_assembler.cpp`
- Modify: `tests/unit/codegen_provider_tests.cpp`

**Interfaces:**
- Consumes: LLVM MC/Object private APIs and the fixed architecture decoder.
- Produces: deterministic section bytes and provider diagnostics for x86, x86-64, and ARM64.

- [ ] **Step 1: Write golden no-fixup emission tests**

Add exact cases:

```cpp
struct Golden { Architecture architecture; BinaryFormat format; std::string triple;
                MachineSyntax syntax; std::string assembly; std::vector<std::byte> bytes; };
const std::array goldens{
    Golden{Architecture::X86, BinaryFormat::COFF, "i686-pc-windows-msvc",
           MachineSyntax::Intel, "nop\nret\n", {std::byte{0x90}, std::byte{0xc3}}},
    Golden{Architecture::X86_64, BinaryFormat::ELF, "x86_64-unknown-linux-gnu",
           MachineSyntax::Intel, "nop\nret\n", {std::byte{0x90}, std::byte{0xc3}}},
    Golden{Architecture::ARM64, BinaryFormat::ELF, "aarch64-unknown-linux-gnu",
           MachineSyntax::GNU, "nop\nret\n",
           {std::byte{0x1f}, std::byte{0x20}, std::byte{0x03}, std::byte{0xd5},
            std::byte{0xc0}, std::byte{0x03}, std::byte{0x5f}, std::byte{0xd6}}},
};
```

Require exact bytes, no fixups, deterministic repeated results, provider `LLVM 22.1.8`, and
successful decode of every emitted instruction.

- [ ] **Step 2: Confirm `codegen.not_implemented` RED**

Run the focused test and require failure on the first golden emission.

- [ ] **Step 3: Implement bounded directive screening**

Tokenize lines before LLVM parsing. Allow labels, instructions, `.text`, `.intel_syntax`,
`.att_syntax`, `.p2align`, `.balign`, `.byte`, `.short`, `.long`, `.quad`, and `.globl` only.
Reject every other leading-dot directive with `codegen.directive_rejected`; reject `#include`,
`.include`, `.incbin`, `.macro`, `.if`, `.section`, `.pushsection`, `.debug`, and `.file` by exact
case-insensitive token. Enforce byte/line/symbol limits before allocation.

- [ ] **Step 4: Assemble to an in-memory object**

In `llvm_mc_assembler.cpp`, create `Triple`, lookup `Target`, construct `MCRegisterInfo`,
`MCAsmInfo`, `MCSubtargetInfo`, `MCInstrInfo`, `MCContext`, `MCObjectFileInfo`, object streamer,
`MCAsmParser`, and target parser. Write with `raw_svector_ostream` and return an owning byte vector.
Capture `SourceMgr` diagnostics into `codegen.assembly_failed` with bounded line/column/message.

- [ ] **Step 5: Extract the requested text section**

Use `object::ObjectFile::createObjectFile`, require exactly one matching section, enforce alignment
and emitted-byte limits, copy contents, reject defined executable sections other than the requested
section, and sort all results deterministically.

- [ ] **Step 6: Re-decode emitted bytes**

Walk the bytes with `make_architecture_backend(request.architecture)`, allocate stable temporary
entity IDs, and require complete decoding until the section ends. Enforce
`expectedInstructionCount`; return `codegen.verification_failed` for a mismatch.

- [ ] **Step 7: Run provider goldens**

```powershell
cmake --build build\m12-verify-debug --target binobf_codegen_provider_tests
ctest --test-dir build\m12-verify-debug -R '^codegen_provider$' --output-on-failure
```

- [ ] **Step 8: Commit deterministic in-process emission**

```powershell
git add src/architecture/codegen_provider.cpp src/architecture/llvm_mc_assembler.* `
  tests/unit/codegen_provider_tests.cpp
git commit -m "feat: emit machine code through LLVM MC"
```

---

### Task 4: COFF and ELF fixup normalization

**Files:**
- Modify: `src/architecture/llvm_mc_assembler.cpp`
- Create: `src/architecture/llvm_fixups.hpp`
- Create: `src/architecture/llvm_fixups.cpp`
- Modify: `tests/unit/codegen_provider_tests.cpp`

**Interfaces:**
- Consumes: LLVM Object relocations in the in-memory object.
- Produces: sorted architecture-neutral `MachineFixup` records.

- [ ] **Step 1: Add exact external-symbol fixup tests**

Test x86/x86-64 COFF `call external_symbol`, x86/x86-64 ELF `call external_symbol`, ARM64 COFF
`bl external_symbol`, and ARM64 ELF `bl external_symbol`. Require symbol, section offset, addend,
bit width, PC-relative state, and normalized kind (`PcRelative32` or `AArch64Call26`). Add x86-64
absolute `.quad external_symbol`, GOT/PLT, and ARM64 page/page-offset pairs.

- [ ] **Step 2: Observe missing-fixup RED**

Run the focused test; emission succeeds but `fixups` is empty.

- [ ] **Step 3: Map supported relocation families**

Implement exhaustive switches for the COFF and ELF relocation numbers used by i386, AMD64, and
AArch64. Reject any unrecognized relocation with `codegen.unsupported_fixup`, including the numeric
type and architecture. Obtain symbol names and explicit/implicit addends without truncation.

- [ ] **Step 4: Validate and sort fixups**

Reject offsets outside the emitted section, duplicate incompatible fixups, empty external symbols,
and counts above `maxFixups`. Sort by offset, kind, then symbol.

- [ ] **Step 5: Run fixup and determinism tests**

Run `codegen_provider` and repeat every request twice.

- [ ] **Step 6: Commit fixup normalization**

```powershell
git add src/architecture/llvm_fixups.* src/architecture/llvm_mc_assembler.cpp `
  tests/unit/codegen_provider_tests.cpp
git commit -m "feat: normalize LLVM MC fixups"
```

---

### Task 5: Canonical native IR types, values, storage, and memory

**Files:**
- Modify: `include/binobf/ir/native.hpp`
- Modify: `src/ir/native.cpp`
- Modify: `tests/unit/native_ir_tests.cpp`

**Interfaces:**
- Consumes: existing integer IR and validation.
- Produces: `IrType`, `IrValue`, storage/address types, memory/cast instructions, and checked width helpers.

- [ ] **Step 1: Add failing type/value/storage validation cases**

Cover valid integer/pointer/f32/f64/vector types and reject invalid integer widths, vector lanes,
pointer widths, alignments, address scales, address spaces, readonly stores, type-mismatched loads,
illegal casts, invalid atomics, symbol/addend overflow, and resource ceilings. Require stable codes:
`ir.invalid_type`, `ir.invalid_alignment`, `ir.invalid_address`, `ir.readonly_store`,
`ir.type_mismatch`, `ir.invalid_cast`, and `ir.memory_operation_limit`.

- [ ] **Step 2: Add canonical public types**

Add exact enums/records:

```cpp
enum class IrTypeKind : std::uint8_t { Void, Integer, Pointer, FloatingPoint, Vector };
enum class IrByteOrder : std::uint8_t { Little, Big };
struct IrType { IrTypeKind kind; std::uint16_t bits; std::uint16_t lanes{1};
                std::uint16_t addressSpace{0}; IrByteOrder byteOrder{IrByteOrder::Little}; };
enum class IrStorageKind : std::uint8_t { Register, Argument, Stack, Local, Global, ThreadLocal };
struct IrStorageLocation { IrStorageKind kind; IrType type; std::string name;
    std::int64_t offset{0}; std::uint64_t size{0}; std::uint32_t alignment{1};
    std::uint16_t index{0}; bool readonly{false}; };
struct IrAddress { IrVariable base; std::optional<IrVariable> index; std::uint8_t scale{1};
    std::int64_t displacement{0}; std::uint16_t addressSpace{0}; std::uint32_t alignment{1}; };
```

Define typed constant variants, `IrLoad`, `IrStore`, `IrAddressOf`, `IrPointerOffset`, and `IrCast`.
Add them to `IrInstruction`.

- [ ] **Step 3: Migrate function canonical tables**

Replace `variableWidths` with `variableTypes`, `returnWidth` with `returnType`, and width fields in
argument/internal-call bindings with types. Keep `integer_type(IrWidth)` and
`integer_width(const IrType&) -> Result<IrWidth, Diagnostic>` helpers.

- [ ] **Step 4: Extend validation and dataflow**

Validate every new record before graph/dataflow validation. Add reads/writes for address bases,
indices, loads, stores, casts, and address results. Enforce definite assignment and immutable
variable type exactly as for current integer instructions.

- [ ] **Step 5: Run native IR tests**

```powershell
cmake --build build\m12-verify-debug --target binobf_native_ir_tests
ctest --test-dir build\m12-verify-debug -R '^native_ir$' --output-on-failure
```

- [ ] **Step 6: Commit typed memory IR**

```powershell
git add include/binobf/ir/native.hpp src/ir/native.cpp tests/unit/native_ir_tests.cpp
git commit -m "feat: expand native IR type and memory model"
```

---

### Task 6: Calls, advanced control flow, fallback effects, and unwind plans

**Files:**
- Modify: `include/binobf/ir/native.hpp`
- Modify: `src/ir/native.cpp`
- Modify: `tests/unit/native_ir_tests.cpp`
- Modify: `tests/unit/ir_module_tests.cpp`

**Interfaces:**
- Consumes: Task 5 canonical types and storage.
- Produces: signatures/declarations, external/tail calls, switch/indirect flow, fallback effects, and unwind regions.

- [ ] **Step 1: Add failing semantic validation tests**

Cover duplicate/missing switch targets, empty indirect target sets, undeclared external symbols,
signature mismatch, invalid ABI bindings, illegal tail calls, incomplete fallback effects, unwind
cycles, missing landing blocks, overlapping protected ownership, and all new limits.

- [ ] **Step 2: Add the public records**

Define `IrCallingConvention`, `IrFunctionSignature`, `IrExternalDeclaration`, `IrCallClobbers`,
`IrExternalCall`, `IrTailCall`, `IrSwitchCase`, `IrSwitch`, `IrIndirectJump`, `IrFallbackEffects`,
`IrUnwindRegionKind`, and `IrUnwindRegion`. Store declarations on `IrModule`, signatures and unwind
regions on `IrFunction`, and optional unwind-region IDs on effectful instructions.

- [ ] **Step 3: Extend terminator and graph validation**

Treat switch, indirect jump, and tail call as terminators; add all proven targets to predecessor
dataflow. Require unique sorted switch values and indirect targets, signature equality for internal
and tail calls, declared external calls, and acyclic unwind parents.

- [ ] **Step 4: Make fallback boundaries explicit**

Require non-empty reason plus complete read/write/clobber/control-flow effect declarations.
`function_contains_fallback` remains true; add `fallback_blocks_rewrite(function, block-set)` for
later transforms.

- [ ] **Step 5: Run function/module validation suites**

Run `native_ir` and `ir_module` focused CTests.

- [ ] **Step 6: Commit advanced semantic IR**

```powershell
git add include/binobf/ir/native.hpp src/ir/native.cpp `
  tests/unit/native_ir_tests.cpp tests/unit/ir_module_tests.cpp
git commit -m "feat: model native calls control flow and unwind"
```

---

### Task 7: Migrate lifter, IR transforms, and VM lowering

**Files:**
- Modify: `include/binobf/ir/native_lifter.hpp`
- Modify: `src/ir/native_lifter.cpp`
- Modify: `src/ir/control_flow.cpp`
- Modify: `src/ir/outlining.cpp`
- Modify: `src/ir/vm_lowering.cpp`
- Modify: `src/cli/command.cpp`
- Modify: affected unit/differential tests under `tests/unit` and `tests/differential`

**Interfaces:**
- Consumes: canonical Task 5/6 IR.
- Produces: unchanged existing integer lifting/transform/lowering semantics using canonical types.

- [ ] **Step 1: Compile all affected targets to expose migration failures**

Build native lifter, control-flow, outlining, VM lowering, CLI, and differential targets. Preserve
the compiler error list as the migration checklist; do not add compatibility duplicate fields.

- [ ] **Step 2: Migrate construction and type checks**

Replace every `variableWidths`/`returnWidth`/call `resultWidth` construction with canonical
`IrType`. Use `integer_width()` only at the VM boundary and propagate its diagnostic. Keep all
existing golden functions structurally equal after converting widths to types.

- [ ] **Step 3: Add explicit unsupported-node lowering diagnostics**

For new memory, floating, vector, external-call, switch, indirect, tail, and unwind nodes that Track
5 has not yet lowered, return `vm.unsupported_native_ir` naming the exact node/source instruction.
Never reinterpret one as fallback or silently skip it.

- [ ] **Step 4: Preserve transform fallback boundaries**

Control-flow flattening, outlining, and splitting must reject regions blocked by incomplete
fallback effects with `ir.fallback_blocks_transform`. Byte-preserving existing cases remain green.

- [ ] **Step 5: Run all IR/VM regression targets**

```powershell
cmake --build build\m12-verify-debug --target binobf_native_lifter_tests `
  binobf_control_flow_transform_tests binobf_outlining_tests `
  binobf_vm_lowering_tests binobf_vm_lowering_differential_tests binobf_cli_tests
ctest --test-dir build\m12-verify-debug `
  -R '^(native_lifter|control_flow_transforms|outlining|vm_lowering|vm_lowering_differential|cli)$' `
  --output-on-failure
```

- [ ] **Step 6: Commit canonical IR migration**

```powershell
git add include/binobf/ir/native_lifter.hpp src/ir src/cli/command.cpp tests
git commit -m "refactor: migrate native pipeline to canonical IR types"
```

---

### Task 8: Architecture backend provider ownership and emission verification

**Files:**
- Modify: `include/binobf/architecture/backend.hpp`
- Modify: `src/architecture/capstone_backend.cpp`
- Modify: `tests/unit/architecture_backend_tests.cpp`
- Modify: `tests/integration/capability_consistency_tests.cpp`

**Interfaces:**
- Consumes: fixed decode backend and Task 1 provider.
- Produces: backend-owned `codegen()` service with service/capability consistency.

- [ ] **Step 1: Add failing backend-provider ownership tests**

For all architectures require `backend->codegen() != nullptr`, matching architecture/provider
identity, deterministic `nop; ret` emission, and independent backend decode. Keep `EmitCode`
service states equal to the capability registry rather than promoting them.

- [ ] **Step 2: Extend `ArchitectureBackend`**

Add:

```cpp
virtual auto codegen() const noexcept -> const CodegenProvider* = 0;
```

Include `codegen.hpp`; own one `std::unique_ptr<CodegenProvider>` inside each Capstone backend.
Factory construction fails if either decoder or provider initialization fails.

- [ ] **Step 3: Cross-check service evidence**

Extend consistency tests so every supported backend service has a known acceptance-evidence ID,
and decode/analyze/emit service levels equal their capability records. Provider availability alone
must not alter `EmitCode` support.

- [ ] **Step 4: Run backend, provider, registry, and consistency tests**

Run the four focused CTests with output on failure.

- [ ] **Step 5: Commit backend provider ownership**

```powershell
git add include/binobf/architecture/backend.hpp src/architecture/capstone_backend.cpp `
  tests/unit/architecture_backend_tests.cpp tests/integration/capability_consistency_tests.cpp
git commit -m "refactor: attach LLVM codegen providers to backends"
```

---

### Task 9: Fuzzing, packaging, documentation, and full Track 2 gates

**Files:**
- Create: `tests/fuzz/codegen_fuzzer.cpp`
- Modify: `CMakeLists.txt`
- Modify: `docs/architecture.md`
- Modify: `docs/developer-guide.md`
- Modify: `docs/verification.md`
- Modify: `docs/superpowers/specs/2026-08-17-full-feature-matrix-program-design.md`

**Interfaces:**
- Consumes: complete Track 2 provider and IR.
- Produces: release evidence without matrix promotion.

- [ ] **Step 1: Add bounded provider fuzzing**

Map arbitrary input to one of three architectures, two formats, and an allowlisted token stream;
cap assembly at 64 KiB and provider limits below production defaults. Emit or return a diagnostic,
repeat the request for deterministic equality, and never execute emitted bytes. Add 2,000 runs to
`fuzz-smoke` with a seed corpus for all six architecture/format pairs.

- [ ] **Step 2: Document provider and IR contracts**

Document the pinned hash, private component boundary, directive allowlist, independent re-decode,
canonical IR types/storage/memory/calls/control flow/unwind, fallback transform boundary, and the
rule that provider presence does not promote codegen support.

- [ ] **Step 3: Run standalone headers and installed consumer**

Compile every public header standalone. Install to fresh `build/track18-install`; compile a consumer
that creates all providers/backends, emits and verifies one golden per architecture, constructs and
validates a typed memory/call/unwind module, validates capability evidence, and exits zero.

- [ ] **Step 4: Run complete project gates**

Run full Debug, Release, and UBSan builds/CTest; `fuzz-smoke`; 47-plus whole-production analyzer
units including new provider sources; `git diff --check`; tracked-artifact and unfinished-marker
checks; and the installed consumer. Confirm README/CLI matrices retain current statuses.

- [ ] **Step 5: Commit Track 2 release evidence**

```powershell
git add CMakeLists.txt docs tests/fuzz/codegen_fuzzer.cpp
git commit -m "test: gate LLVM provider and expanded native IR"
```

- [ ] **Step 6: Record Track 2 completion**

Mark this plan complete and check only Track 2 in the umbrella program checklist. Confirm a clean
`main` worktree. Track 3 is the full x86 object backend; do not claim overall completion.

# Full ARM64 Object Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Promote little-endian ARM64 COFF/ELF object analysis and code generation to supported with complete fixup, template, ABI, unwind, compiler-corpus, linker, and QEMU execution evidence.

**Architecture:** Extend the existing fixed-architecture backend and immutable object rewrite transaction. Capstone decodes, the pinned LLVM MC provider emits A64 code and normalized fixups, format adapters preserve ARM64 metadata, and QEMU's `virt` machine executes freestanding differential fixtures through documented semihosting.

**Tech Stack:** C++20, CMake/CTest, Capstone 5.0.6, LLVM/Clang/LLD 22.1.8 AArch64, Windows ARM64 COFF, AArch64 ELF64, QEMU system emulation, libFuzzer, UBSan, Clang Static Analyzer.

**Spec:** `docs/superpowers/specs/2026-08-18-full-arm64-object-backend-design.md`

## Global Constraints

- Supported baseline is little-endian Armv8-A user-mode A64 with scalar FP and Advanced SIMD.
- COFF target is `aarch64-pc-windows-msvc`; ELF target is `aarch64-unknown-linux-gnu`.
- Supported ABIs are Windows ARM64 and AAPCS64 with 16-byte stack alignment.
- LLVM remains pinned to `llvmorg-22.1.8`, archive SHA-256 `922f1817a0df7b1489272d18134ee0087a8b068828f87ac63b9861b1a9965888`, private to `binobf_core`.
- Every A64 instruction boundary and emitted size is a multiple of four.
- Unknown relocation/unwind metadata may round-trip unchanged but blocks movement of anything it owns.
- Every transformation is complete-source-snapshot, plan, verify, and commit; a failure leaves input and existing output unchanged.
- Runtime evidence uses only checked-in freestanding fixtures under `qemu-system-aarch64`; no guest OS image or network is involved.
- No debugger/VM/security-product detection, injection, reflective loading, persistence, payload download, dynamic API discovery, malformed/overlapping instruction stream, exception abuse, or signing bypass.
- Capability promotion occurs only with enabled acceptance evidence and every fresh gate green.

---

### Task 1: Public ARM64 ABI, unwind, and fixup-field contracts

**Files:**
- Modify: `include/binobf/architecture/codegen.hpp`
- Modify: `include/binobf/architecture/object_backend.hpp`
- Modify: `include/binobf/core/model.hpp`
- Modify: `include/binobf/ir/native.hpp`
- Modify: `include/binobf/ir/native_lifter.hpp`
- Modify: `src/ir/native_lifter.cpp`
- Modify: `tests/unit/core_types_tests.cpp`
- Modify: `tests/unit/object_backend_contract_tests.cpp`
- Modify: `tests/unit/native_lifter_tests.cpp`

**Interfaces:**
- Consumes: existing fixup, unwind, ABI, and IR calling-convention records.
- Produces: `ObjectFixupFieldEncoding`, masked fixup writes, `WindowsARM64`, `AAPCS64`, `WindowsARM64` unwind, and `DwarfCfi64` unwind values used by later tasks.

- [x] **Step 1: Write failing public-contract tests**

```cpp
TEST_CASE(arm64_public_contracts_expose_masked_fields_and_platform_abis) {
    binobf::ObjectFixupSemantics semantics{};
    semantics.fieldEncoding = binobf::ObjectFixupFieldEncoding::AArch64Branch26;
    semantics.storageBytes = 4;
    semantics.rightShift = 2;
    REQUIRE_EQ(semantics.storageBytes, std::uint8_t{4});

    binobf::ObjectFixupEncoding encoding{};
    encoding.fieldBytes.resize(4);
    encoding.writeMask.resize(4);
    REQUIRE_EQ(encoding.fieldBytes.size(), encoding.writeMask.size());
    REQUIRE(binobf::ir::NativeAbi::WindowsARM64 != binobf::ir::NativeAbi::AAPCS64);
    REQUIRE(binobf::UnwindEncoding::WindowsARM64 != binobf::UnwindEncoding::DwarfCfi64);
    REQUIRE(binobf::UnwindFormat::WindowsARM64 != binobf::UnwindFormat::DwarfCfi64);
}
```

Add native-lifter cases mapping `WindowsARM64` to `IrCallingConvention::MicrosoftARM64` and
`AAPCS64` to `IrCallingConvention::AAPCS64`, while the x86-only lifter rejects both with
`ir.unsupported_architecture`.

- [x] **Step 2: Run the focused targets and prove RED**

```powershell
cmake --build build\m13-verify-debug --target binobf_core_types_tests binobf_object_backend_contract_tests binobf_native_lifter_tests
```

Expected: compilation fails because the new enums and masked encoding fields do not exist.

- [x] **Step 3: Add the minimal public model**

Append this enum without renumbering any existing member:

```cpp
enum class ObjectFixupFieldEncoding : std::uint8_t {
    ScalarLittleEndian,
    AArch64Branch26,
    AArch64Branch19,
    AArch64Branch14,
    AArch64Adr21,
    AArch64Adrp21,
    AArch64Low12,
    AArch64MoveWide16,
};
```

Extend `ObjectFixupSemantics` with `fieldEncoding`, `storageBytes`, `rightShift`, and
`valueShift`; extend `ObjectFixupEncoding` with `writeMask`. Add `AArch64Branch19`,
`AArch64Branch14`, `AArch64Adr21`, `AArch64Low12`, `AArch64MoveWide16`,
`AArch64GotPage21`, `AArch64GotLow12`, `AArch64TlsPage21`, `AArch64TlsLow12`, and
`AArch64TlsDescriptor` fixup kinds. Append the two ABI, calling-convention, encoding, and format
values named above. Preserve existing numeric values and equality behavior.

- [x] **Step 4: Run focused tests and all public headers**

```powershell
cmake --build build\m13-verify-debug --target binobf_core_types_tests binobf_object_backend_contract_tests binobf_native_lifter_tests
ctest --test-dir build\m13-verify-debug -C Debug -R "^(core_types|object_backend_contract|native_lifter)$" --output-on-failure
```

Compile every `include/binobf/**/*.hpp` standalone with Clang C++20 warnings-as-errors. Expected:
all focused tests and headers pass.

- [x] **Step 5: Commit the public contract**

```powershell
git add include/binobf src/ir/native_lifter.cpp tests/unit/core_types_tests.cpp tests/unit/object_backend_contract_tests.cpp tests/unit/native_lifter_tests.cpp
git commit -m "feat: define ARM64 object backend contracts"
```

---

### Task 2: ARM64 COFF and ELF fixup semantics

**Files:**
- Create: `src/architecture/arm64_fixups.hpp`
- Create: `src/architecture/arm64_fixups.cpp`
- Modify: `src/architecture/capstone_backend.cpp`
- Modify: `src/transforms/object_rewrite.cpp`
- Create: `tests/unit/arm64_fixup_tests.cpp`
- Modify: `tests/unit/object_rewrite_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: masked field contracts from Task 1 and normalized raw relocation types.
- Produces: `arm64_fixup_semantics`, `encode_arm64_fixup`, `decode_arm64_fixup`, and masked instruction-field merging.

- [ ] **Step 1: Add failing golden field tests**

Cover every defined COFF type `0x0000` through `0x0011` and ELF `NONE`, `ABS64/32/16`,
`PREL64/32/16`, move-wide groups, `LD_PREL_LO19`, `ADR_PREL_LO21`,
`ADR_PREL_PG_HI21(_NC)`, `ADD_ABS_LO12_NC`, `LDST*_ABS_LO12_NC`, `TSTBR14`, `CONDBR19`,
`JUMP26`, `CALL26`, GOT page/low12, TLS GD/IE/LE, and TLSDESC.

```cpp
TEST_CASE(arm64_branch26_encoding_preserves_opcode_and_scales_displacement) {
    const auto semantics = require_semantics(binobf::BinaryFormat::ELF, 283);
    const auto encoded = binobf::detail::encode_arm64_fixup(semantics, 0x100);
    REQUIRE(encoded.has_value());
    REQUIRE_EQ(encoded.value().writeMask, bytes({0xff, 0xff, 0xff, 0x03}));
    REQUIRE_EQ(apply_mask(bytes({0x00, 0x00, 0x00, 0x94}), encoded.value()),
               bytes({0x40, 0x00, 0x00, 0x94}));
}
```

Add failures for misalignment, signed endpoints, ADR split fields, ADRP page scaling, load/store
low12 scaling, move-wide shifts, `INT64_MIN`, invalid masks, and unsupported raw types.

- [ ] **Step 2: Prove the fixup tests fail**

```powershell
cmake --build build\m13-verify-debug --target binobf_arm64_fixup_tests
```

Expected: target or header is missing.

- [ ] **Step 3: Implement sorted format tables and checked encoders**

Define strictly sorted format tables recording logical width, signedness, PC-relative status,
implicit addend, field encoding, storage bytes, scaling, and group shift. Use unsigned intermediate
masks, explicit sign extension, checked arithmetic, and a dedicated encoder for each non-contiguous
field. Never shift a negative signed value or by its type width.

Instruction encodings return four bytes plus a four-byte write mask; scalar data encodings return
full `0xff` masks. Decode reverses the field and scale exactly. Dispatch ARM64 backend fixup calls to
these functions.

- [ ] **Step 4: Merge masked fields transactionally**

```cpp
output[index] = static_cast<std::byte>(
    (std::to_integer<std::uint8_t>(output[index]) &
     ~std::to_integer<std::uint8_t>(encoding.writeMask[index])) |
    (std::to_integer<std::uint8_t>(encoding.fieldBytes[index]) &
     std::to_integer<std::uint8_t>(encoding.writeMask[index])));
```

Require equal nonzero lengths, section bounds, and unchanged opcode bits. Keep x86 encodings on
full-byte masks so their output is identical.

- [ ] **Step 5: Run Debug and UBSan focused tests**

```powershell
cmake --build build\m13-verify-debug --target binobf_arm64_fixup_tests binobf_object_rewrite_tests
ctest --test-dir build\m13-verify-debug -C Debug -R "^(arm64_fixup|object_rewrite)$" --output-on-failure
cmake --build build\m13-ubsan --target binobf_arm64_fixup_tests binobf_object_rewrite_tests
ctest --test-dir build\m13-ubsan -C RelWithDebInfo -R "^(arm64_fixup|object_rewrite)$" --output-on-failure
```

- [ ] **Step 6: Commit ARM64 fixups**

```powershell
git add CMakeLists.txt src/architecture/arm64_fixups.* src/architecture/capstone_backend.cpp src/transforms/object_rewrite.cpp tests/unit/arm64_fixup_tests.cpp tests/unit/object_rewrite_tests.cpp
git commit -m "feat: encode ARM64 object fixups"
```

---

### Task 3: Verified ARM64 transformation templates

**Files:**
- Create: `src/architecture/arm64_templates.hpp`
- Create: `src/architecture/arm64_templates.cpp`
- Modify: `src/architecture/capstone_backend.cpp`
- Modify: `src/architecture/codegen_provider.cpp`
- Create: `tests/unit/arm64_template_tests.cpp`
- Modify: `tests/unit/architecture_backend_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `MachineTransformRequest`, LLVM MC emission, ARM64 fixups, and Capstone decode.
- Produces: `emit_arm64_transform(const MachineTransformRequest&, const CodegenProvider&)` for all template kinds.

- [ ] **Step 1: Add RED golden-template cases**

Require register-copy equivalence using `orr`, shortest deterministic `movz/movn/movk` constant
synthesis, all 14 ordinary conditional inversions, direct `b`/`bl` fixups, and exact A64 NOP fill.

```cpp
TEST_CASE(arm64_dead_code_is_exact_aligned_and_decodable) {
    auto request = base_request(binobf::MachineTransformKind::DeadCodeFill);
    request.exactSize = 12;
    const auto emitted = backend().emit_transform(request);
    REQUIRE(emitted.has_value());
    REQUIRE_EQ(emitted.value().emission.bytes,
               bytes({0x1f,0x20,0x03,0xd5, 0x1f,0x20,0x03,0xd5,
                      0x1f,0x20,0x03,0xd5}));
}
```

- [ ] **Step 2: Run and prove unsupported-service failure**

```powershell
cmake --build build\m13-verify-debug --target binobf_arm64_template_tests
```

Expected: ARM64 `emit_transform` returns `architecture.service_unsupported`.

- [ ] **Step 3: Implement fixed-width templates**

Build assembly only from allowlisted register, condition, constant, and symbol tokens. Require every
address and exact size to be four-byte aligned. Normalize LLVM MC fixups through Task 2. Constant
synthesis chooses `movz` or `movn` by fewer lane updates, breaks ties for `movz`, and orders `movk`
low-to-high. Conditional inversion uses a fixed table; branches never truncate.

- [ ] **Step 4: Generalize backend self-verification**

Extract the x86 post-emission decode loop into a fixed-architecture verifier. ARM64 requires
four-byte progress, complete coverage, expected control flow, flags, destination writes, no
unexpected SP access, and exact fixup offsets. Preserve x86 checks unchanged.

- [ ] **Step 5: Run template, backend, provider, and codegen fuzz tests**

```powershell
cmake --build build\m13-verify-debug --target binobf_arm64_template_tests binobf_architecture_backend_tests binobf_codegen_provider_tests
ctest --test-dir build\m13-verify-debug -C Debug -R "^(arm64_template|architecture_backend|codegen_provider)$" --output-on-failure
cmake --build build\m13-fuzz-final --target binobf_fuzz_codegen
build\m13-fuzz-final\binobf_fuzz_codegen.exe -runs=2000 -seed=14003 -max_len=65536 -timeout=5 build\m13-fuzz-final\fuzz-corpus\codegen
```

- [ ] **Step 6: Commit ARM64 templates**

```powershell
git add CMakeLists.txt src/architecture/arm64_templates.* src/architecture/capstone_backend.cpp src/architecture/codegen_provider.cpp tests/unit/arm64_template_tests.cpp tests/unit/architecture_backend_tests.cpp
git commit -m "feat: emit verified ARM64 transform templates"
```

---

### Task 4: ARM64 object metadata and relocation preservation

**Files:**
- Modify: `src/formats/coff/object_parser.cpp`
- Modify: `src/formats/coff/object_writer.cpp`
- Modify: `src/formats/elf/object_parser.cpp`
- Modify: `src/formats/elf/object_writer.cpp`
- Modify: `src/verify/object_model_validator.cpp`
- Create: `tests/unit/coff_arm64_extended_tests.cpp`
- Create: `tests/unit/elf64_arm64_extended_tests.cpp`
- Modify: `tests/unit/object_writer_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: ARM64 raw relocation tables and existing normalized object records.
- Produces: complete ARM64 COFF/ELF models with known field ownership and byte-exact unknown records.

- [ ] **Step 1: Add malformed and round-trip fixtures**

Generate minimal valid ARM64 COFF and ELF64 objects. Require defined COFF relocations, Task 2 ELF
families, section symbols with addends, associative COMDAT/groups, TLS, common symbols, function
sizes, and debug relocations to survive parse/write/reparse. Add failures for truncated arrays,
cumulative limits, invalid `r_info`, missing tables, bad section indexes, invalid group signatures,
addend overflow, and overlapping tables.

- [ ] **Step 2: Run parser tests and prove missing ownership**

```powershell
cmake --build build\m13-verify-debug --target binobf_coff_arm64_extended_tests binobf_elf64_arm64_extended_tests
```

Expected: source/targets are missing, then ARM64 field ownership is incomplete.

- [ ] **Step 3: Normalize complete format metadata**

Use Task 2 semantics to populate kind, width, signedness, addend ownership, and association identity.
Preserve raw type/entry bytes. Recognize COFF `.pdata/.xdata`, ELF `.eh_frame`, TLS, groups, and
AArch64 mapping symbols without treating mapping symbols as functions. Unknown types remain
architecture-specific. Apply the 4,000,000 relocation ceiling and checked table arithmetic.

- [ ] **Step 4: Validate and reconstruct deterministically**

Known ARM64 instruction relocations must be four-byte aligned, within the section, and compatible
with their field encoding. Validate group identity without requiring adjacency where the ABI allows
independent members. Preserve section order, alignment, symbol indexes, addends, and associations.

- [ ] **Step 5: Run parser/writer and LLVM inspection gates**

```powershell
cmake --build build\m13-verify-debug --target binobf_coff_arm64_extended_tests binobf_elf64_arm64_extended_tests binobf_object_writer_tests
ctest --test-dir build\m13-verify-debug -C Debug -R "^(coff_arm64_extended|elf64_arm64_extended|object_writer)$" --output-on-failure
```

Require `llvm-readobj --file-headers --sections --symbols --relocations` to accept representative
original and reconstructed files.

- [ ] **Step 6: Commit ARM64 object metadata**

```powershell
git add CMakeLists.txt src/formats src/verify/object_model_validator.cpp tests/unit/coff_arm64_extended_tests.cpp tests/unit/elf64_arm64_extended_tests.cpp tests/unit/object_writer_tests.cpp
git commit -m "feat: normalize ARM64 object metadata"
```

---

### Task 5: Complete ARM64 object analysis

**Files:**
- Modify: `src/architecture/capstone_backend.cpp`
- Modify: `src/analysis/object_analyzer.cpp`
- Create: `tests/unit/arm64_object_analyzer_tests.cpp`
- Create: `tests/fixtures/arm64/corpus.c`
- Create: `tests/fixtures/arm64/corpus.cpp`
- Create: `cmake/RunArm64CompilerCorpus.cmake`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: normalized ARM64 objects, Capstone detail, and four-byte boundaries.
- Produces: complete functions, instructions, blocks, CFG edges, calls, register effects, and stable refusal reasons.

- [ ] **Step 1: Add RED decoder and analyzer cases**

Require classification and targets for `b`, `bl`, every `b.cond`, `cbz/cbnz`, `tbz/tbnz`, `br`,
`blr`, and `ret`; SP/FP/LR and NZCV effects; literal/PC-relative references; and incomplete results
for indirect branches without proven targets.

```cpp
TEST_CASE(arm64_analyzer_builds_fixed_width_cfg_and_calls) {
    const auto report = analyze_fixture(make_arm64_loop_and_call_object());
    REQUIRE(report.has_value());
    REQUIRE(report.value().complete);
    REQUIRE(std::ranges::all_of(report.value().image.instructions,
        [](const auto& instruction) { return instruction.encoding.size() == 4; }));
    REQUIRE(has_edge(report.value().image, binobf::ControlFlowKind::Conditional));
    REQUIRE(has_edge(report.value().image, binobf::ControlFlowKind::Call));
}
```

- [ ] **Step 2: Prove analyzer gaps on real Clang objects**

Compile the C/C++ fixtures at `-O0` for both targets and run the new tests. Expected: failures for
missing call/conditional classification, function-size recovery, or completeness.

- [ ] **Step 3: Implement conservative A64 semantics**

Use Capstone groups/operands, not mnemonic substrings. Normalize `nzcv`, `sp`, `x29`, `x30`,
integer/vector reads/writes, targets, fallthrough, calls, and returns. Reject targets outside owned
code or inside an instruction; never invent `br/blr` targets. Prefer exact function symbols/sizes,
then relocation/unwind evidence. Mapping symbols refine spans but never create functions. Preserve
stable IDs across reanalysis.

- [ ] **Step 4: Build the six-optimization corpus**

`RunArm64CompilerCorpus.cmake` compiles both languages and formats with
`-O0/-O1/-O2/-O3/-Os/-Oz`, function/data sections, debug, unwind, PIC where valid, and Armv8-A
baseline flags. It writes a manifest consumed by integration tests.

- [ ] **Step 5: Run analyzer and corpus gates**

```powershell
cmake --build build\m13-verify-debug --target binobf_arm64_object_analyzer_tests arm64_compiler_corpus
ctest --test-dir build\m13-verify-debug -C Debug -R "^(arm64_object_analyzer|arm64_compiler_corpus)$" --output-on-failure
```

- [ ] **Step 6: Commit ARM64 analysis**

```powershell
git add CMakeLists.txt cmake/RunArm64CompilerCorpus.cmake src/analysis/object_analyzer.cpp src/architecture/capstone_backend.cpp tests/unit/arm64_object_analyzer_tests.cpp tests/fixtures/arm64
git commit -m "feat: analyze ARM64 compiler objects"
```

---

### Task 6: Windows ARM64 and AAPCS64 adapters

**Files:**
- Create: `src/architecture/arm64_abi.hpp`
- Create: `src/architecture/arm64_abi.cpp`
- Modify: `src/architecture/capstone_backend.cpp`
- Create: `tests/unit/arm64_abi_unwind_tests.cpp`
- Create: `tests/differential/arm64_service_artifact_generator.cpp`
- Create: `tests/fixtures/arm64/abi_native_entry.S`
- Create: `tests/fixtures/arm64/semihosting.S`
- Create: `tests/fixtures/arm64/qemu.ld`
- Create: `cmake/RunArm64AbiNativeDifferential.cmake`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `AbiAdapterRequest`, `IrType`, explicit bindings, and ARM64 LLVM MC emission.
- Produces: `build_arm64_abi_adapter` with moves, stack usage, clobbers, call fixup, return binding, and unwind actions.

- [ ] **Step 1: Add RED binding and rejection tests**

Cover integer/pointer `x0-x7`, FP/vector `v0-v7`, aligned stack overflow, `x8` indirect results,
`x0/x1` wide integer results, `v0` FP/vector results, register cycles, binding overlap, huge offsets,
wrong pointer width, unsupported aggregates, cross-ABI variadics, tail calls, and mismatches.

```cpp
TEST_CASE(arm64_adapter_moves_register_and_stack_arguments_without_clobber) {
    auto request = arm64_request(binobf::ir::NativeAbi::WindowsARM64,
                                 binobf::ir::NativeAbi::AAPCS64,
                                 nine_u64_parameters());
    const auto plan = backend().build_abi_adapter(request);
    REQUIRE(plan.has_value());
    REQUIRE_EQ(plan.value().stackArgumentBytes, std::uint64_t{16});
    REQUIRE_EQ(plan.value().stackDelta, std::int64_t{0});
    REQUIRE(plan.value().emission.bytes.size() % 4 == 0);
}
```

- [ ] **Step 2: Prove ARM64 ABI service is unsupported**

```powershell
cmake --build build\m13-verify-debug --target binobf_arm64_abi_unwind_tests
```

Expected: source/target missing, then `architecture.service_unsupported`.

- [ ] **Step 3: Implement ABI layout and move planning**

Validate the complete signature before emission. Derive integer/vector sequences independently,
place exhausted arguments in aligned 8/16-byte slots, and use `x8` for indirect results. Explicit
bindings must match type, size, alignment, index, class, and non-overlap rules.

Build a move graph; save all live sources before writes; resolve cycles with owned `x16/x17` or
`v16/v17`; reserve a 16-byte-aligned frame; save `x29/x30` and used nonvolatile scratch; emit stack
arguments and `bl`; restore and `ret`. Reject unrepresentable frames/displacements.

- [ ] **Step 4: Emit and verify ABI instructions**

Populate exact moves, stack bytes, clobbers, call26 fixup, and code-offset unwind actions. Decode
every instruction and prove SP returns to its entry value on each exit.

- [ ] **Step 5: Add QEMU ABI evidence**

The service artifact generator writes checked ARM64 adapter/unwind objects into a verified build-local
directory. The fixture invokes same/cross-ABI adapters with register exhaustion, FP/vector values,
indirect results, a cycle, and two valid incoming SP positions. `semihosting.S` provides the A64
`HLT #0xF000` write/exit helpers and `qemu.ld` supplies the `virt` RAM/stack layout. Enforce a
15-second timeout.

- [ ] **Step 6: Run unit and ABI-native gates**

```powershell
cmake --build build\m13-verify-debug --target binobf_arm64_abi_unwind_tests binobf_arm64_service_artifact_generator
ctest --test-dir build\m13-verify-debug -C Debug -R "^(arm64_abi_unwind|arm64_abi_native_differential)$" --output-on-failure
```

- [ ] **Step 7: Commit ARM64 ABI support**

```powershell
git add CMakeLists.txt cmake/RunArm64AbiNativeDifferential.cmake src/architecture/arm64_abi.* src/architecture/capstone_backend.cpp tests/unit/arm64_abi_unwind_tests.cpp tests/differential/arm64_service_artifact_generator.cpp tests/fixtures/arm64/abi_native_entry.S tests/fixtures/arm64/semihosting.S tests/fixtures/arm64/qemu.ld
git commit -m "feat: generate ARM64 ABI adapters"
```

---

### Task 7: Windows ARM64 and ELF64 unwind ownership

**Files:**
- Create: `src/architecture/arm64_unwind.hpp`
- Create: `src/architecture/arm64_unwind.cpp`
- Modify: `src/architecture/capstone_backend.cpp`
- Modify: `src/formats/coff/object_parser.cpp`
- Modify: `src/formats/elf/object_parser.cpp`
- Modify: `src/verify/object_model_validator.cpp`
- Modify: `tests/unit/arm64_abi_unwind_tests.cpp`
- Modify: `tests/unit/coff_arm64_extended_tests.cpp`
- Modify: `tests/unit/elf64_arm64_extended_tests.cpp`
- Create: `cmake/RunArm64UnwindSemantics.cmake`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: ordered unwind actions and function-owned relocations.
- Produces: `build_arm64_unwind_plan`, normalized Windows/DWARF64 records, and opaque/unknown refusal states.

- [ ] **Step 1: Add RED Windows packed-unwind tests**

Require no record for a leaf and exact 8-byte `.pdata` for canonical frames. Validate four-byte
function length, frame size, integer/vector saves, frame-chain bits, `ADDR32NB` relocation, and
refusal of handlers/noncanonical prologues. Include every field boundary and overflow.

- [ ] **Step 2: Add RED ELF64 CFI tests**

Require a version-1 `zR` CIE with alignments 1/-8, return register 30, nonzero FDE back-pointer,
ordered PC advances, signed CFA offsets, function relocation, and padding. Link at a nonzero text
offset and assert LLVM reports the FDE initial location equal to the symbol.

- [ ] **Step 3: Prove unwind tests fail**

```powershell
cmake --build build\m13-verify-debug --target binobf_arm64_abi_unwind_tests binobf_coff_arm64_extended_tests binobf_elf64_arm64_extended_tests
```

Expected: build-unwind is unsupported and frame records remain unknown.

- [ ] **Step 4: Implement bounded unwind emission**

Validate architecture, format, symbol, action ordering, code offsets, registers, alignment, length,
and arithmetic. Emit only canonical Windows packed records; refuse `.xdata` generation. Emit ELF64
CIE/FDE with guarded ULEB/SLEB helpers including `INT64_MIN` and size limits.

- [ ] **Step 5: Normalize compiler unwind records**

COFF associates `.pdata` through function-start relocations, parses packed words, and retains owned
`.xdata` as opaque. ELF generalizes CIE/FDE parsing to ELF64, follows function or section-symbol plus
addend relocations, and requires one unique function range. Unknown records use `Unknown`; recognized
unmodeled records use `Opaque`.

- [ ] **Step 6: Run unwind unit/link/inspection gates**

```powershell
cmake --build build\m13-verify-debug --target binobf_arm64_abi_unwind_tests binobf_coff_arm64_extended_tests binobf_elf64_arm64_extended_tests binobf_arm64_service_artifact_generator
ctest --test-dir build\m13-verify-debug -C Debug -R "^(arm64_abi_unwind|coff_arm64_extended|elf64_arm64_extended|arm64_unwind_semantics)$" --output-on-failure
```

- [ ] **Step 7: Commit ARM64 unwind support**

```powershell
git add CMakeLists.txt cmake/RunArm64UnwindSemantics.cmake src/architecture/arm64_unwind.* src/architecture/capstone_backend.cpp src/formats src/verify/object_model_validator.cpp tests/unit/arm64_abi_unwind_tests.cpp tests/unit/coff_arm64_extended_tests.cpp tests/unit/elf64_arm64_extended_tests.cpp
git commit -m "feat: own ARM64 object unwind metadata"
```

---

### Task 8: Run all seven transformations on ARM64

**Files:**
- Modify: `src/transforms/instruction.cpp`
- Modify: `src/transforms/object_rewrite.cpp`
- Modify: `src/transforms/pass_manager.cpp`
- Modify: `tests/unit/instruction_transform_tests.cpp`
- Create: `tests/integration/arm64_transform_integration_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: complete ARM64 analysis, templates, fixups, unwind ownership, and rewrite plans.
- Produces: all seven eligible transformations on ARM64 COFF/ELF.

- [ ] **Step 1: Add RED per-pass integration cases**

For both formats, require `Applied`, nonzero exact statistics, deterministic seeded bytes, successful
reparse/reanalysis, and semantic preservation. Add `Unchanged` for no candidate and `Unsupported`
for unknown metadata, misalignment, incomplete CFG, indirect control flow, optional ISA, and
out-of-range branch repair.

- [ ] **Step 2: Prove architecture gating**

```powershell
cmake --build build\m13-verify-debug --target binobf_arm64_transform_integration_tests
```

Expected: target missing, then ARM64 declines on x86-only pass logic.

- [ ] **Step 3: Remove x86 assumptions from exact passes**

Select by decoded semantics/backend support. Require four-byte windows, fixed source coverage,
relocation non-overlap, unchanged address/size, and decoded-effect equality. Use normalized register
and condition names.

- [ ] **Step 4: Generalize layout passes**

Build orders from CFG entities; request A64 direct branches; remap branch26/19/14 and ADR/ADRP/low12
groups; update symbols, groups, unwind, and lineage; then run the shared verifier. Reject branches
requiring a veneer inside the object transaction.

- [ ] **Step 5: Run transform and rewrite tests**

```powershell
cmake --build build\m13-verify-debug --target binobf_instruction_transform_tests binobf_arm64_transform_integration_tests binobf_object_rewrite_tests
ctest --test-dir build\m13-verify-debug -C Debug -R "^(instruction_transforms|arm64_transform_integration|object_rewrite)$" --output-on-failure
```

- [ ] **Step 6: Commit ARM64 transformations**

```powershell
git add CMakeLists.txt src/transforms tests/unit/instruction_transform_tests.cpp tests/integration/arm64_transform_integration_tests.cpp
git commit -m "feat: run all object transforms on ARM64"
```

---

### Task 9: Compiler-corpus transformation and linker proof

**Files:**
- Modify: `tests/fixtures/arm64/corpus.c`
- Modify: `tests/fixtures/arm64/corpus.cpp`
- Create: `tests/fixtures/arm64/link_entry.S`
- Create: `tests/integration/arm64_object_backend_integration_tests.cpp`
- Modify: `cmake/RunArm64CompilerCorpus.cmake`
- Create: `cmake/RunArm64ObjectLink.cmake`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: the six-optimization, two-format corpus and seven passes.
- Produces: standard-tool/linker acceptance for every original/transformed object with coverage counters.

- [ ] **Step 1: Add RED corpus-coverage assertions**

Require all six modes and both formats, function/data sections, debug, unwind, PIC, calls, globals,
loops, switches, FP/vector, COMDAT/groups, TLS, and section-symbol fixups. Each pass must apply to at
least one COFF and ELF object; each object must transform or return an allowlisted per-function
refusal.

- [ ] **Step 2: Prove missing corpus/link gate**

```powershell
cmake --build build\m13-verify-debug --target binobf_arm64_object_backend_integration_tests
```

Expected: target missing or coverage below the matrix.

- [ ] **Step 3: Complete fixtures and transform driver**

Use harmless pure functions with stable inputs and no OS calls. Load the manifest, parse/analyze
every object, run each eligible pass with fixed seeds, write unique build-local outputs, reparse,
verify, and record totals by format, optimization, and pass.

- [ ] **Step 4: Link and inspect every artifact**

Compile `link_entry.S` separately for Windows ARM64 COFF and AArch64 ELF. COFF uses
`lld-link /machine:arm64 /entry:entry /subsystem:console /nodefaultlib`; ELF uses
`ld.lld -m aarch64elf -e _start` with the freestanding entry and Task 6 linker script. Run
`llvm-readobj --file-headers --sections --symbols --relocations --unwind` and `llvm-objdump -d` on
all originals and outputs. Any command failure fails.

- [ ] **Step 5: Run the complete compiler-object gate**

```powershell
cmake --build build\m13-verify-debug --target binobf_arm64_object_backend_integration_tests
ctest --test-dir build\m13-verify-debug -C Debug -R "^arm64_object_backend$" --output-on-failure
```

- [ ] **Step 6: Commit corpus/link evidence**

```powershell
git add CMakeLists.txt cmake/RunArm64CompilerCorpus.cmake cmake/RunArm64ObjectLink.cmake tests/fixtures/arm64 tests/integration/arm64_object_backend_integration_tests.cpp
git commit -m "test: validate the ARM64 compiler object corpus"
```

---

### Task 10: QEMU native differential execution

**Files:**
- Create: `tests/fixtures/arm64/native_entry.S`
- Modify: `tests/fixtures/arm64/semihosting.S`
- Modify: `tests/fixtures/arm64/qemu.ld`
- Create: `tests/differential/arm64_native_differential_tests.cpp`
- Create: `cmake/RunArm64NativeDifferential.cmake`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: runtime-safe corpus objects and transformed counterparts.
- Produces: original/transformed A64 behavior under bounded system emulation.

- [ ] **Step 1: Add a hard QEMU host probe**

Compile `_start` for `aarch64-none-elf`, link at `virt` RAM with an aligned stack, and call
`SYS_EXIT_EXTENDED` through `hlt #0xf000`. Run:

```powershell
qemu-system-aarch64 -M virt -cpu cortex-a57 -nographic -monitor none -serial none -semihosting-config enable=on,target=native -kernel build\m14-arm64-probe\probe.elf
```

Require a designed nonzero exit code. Missing QEMU, timeout, trap, or wrong status fails; no skip.

- [ ] **Step 2: Prove the probe target is RED**

```powershell
cmake --build build\m13-verify-debug --target binobf_arm64_native_differential_tests
```

Expected: target/source is absent.

- [ ] **Step 3: Build deterministic result reporting**

Expose `binobf_semihost_write0` and `binobf_semihost_exit`. The entry prints a fixed record with
magic, function ID, return value, selected global bytes, and checksum. No host path comes from
transformed code. Capture output and enforce a 15-second timeout.

- [ ] **Step 4: Compare every runtime-safe pass**

Link original/transformed objects with the same entry, execute fresh QEMU processes, and require
identical exit/result records. Every pass must execute at least once. Crash, timeout, unexpected
output, or checksum mismatch fails.

- [ ] **Step 5: Run the differential target twice**

```powershell
cmake --build build\m13-verify-debug --target binobf_arm64_native_differential_tests
ctest --test-dir build\m13-verify-debug -C Debug -R "^arm64_native_differential$" --output-on-failure
ctest --test-dir build\m13-verify-debug -C Debug -R "^arm64_native_differential$" --output-on-failure
```

Require identical hashes and totals.

- [ ] **Step 6: Commit QEMU evidence**

```powershell
git add CMakeLists.txt cmake/RunArm64NativeDifferential.cmake tests/fixtures/arm64/native_entry.S tests/fixtures/arm64/semihosting.S tests/fixtures/arm64/qemu.ld tests/differential/arm64_native_differential_tests.cpp
git commit -m "test: prove ARM64 behavior under QEMU"
```

---

### Task 11: ARM64 fuzz and mutation evidence

**Files:**
- Modify: `tests/fuzz/codegen_fuzzer.cpp`
- Modify: `tests/fuzz/object_rewrite_fuzzer.cpp`
- Create: `tests/fuzz/corpus/object-rewrite/arm64-coff.seed`
- Create: `tests/fuzz/corpus/object-rewrite/arm64-elf.seed`
- Create: `tests/mutation/arm64_backend_mutation_tests.cpp`
- Modify: `tests/fuzz/README.md`
- Modify: `docs/hardening.md`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: ARM64 template, fixup, parser, unwind, and transaction boundaries.
- Produces: deterministic fuzz coverage and required mutation kills.

- [ ] **Step 1: Add RED mutation counterexamples**

Mutants omit four-byte alignment, branch scale/range, ADR mapping, ADRP page bias, low12 access
scale, group ownership, packed-unwind length, CFI ownership, unknown-section identity, and source
snapshot comparison. Each golden input passes production and kills its mutant.

- [ ] **Step 2: Extend bounded fuzz mapping**

Map bytes to ARM64 COFF/ELF seeds, known/unknown relocations, masked fields, aligned windows, unwind
mutations, and resource limits. Successful plans write/reparse/verify but never execute. Repeated
refusals require the same nonempty diagnostic.

- [ ] **Step 3: Prove the mutation target is RED**

```powershell
cmake --build build\m13-verify-debug --target binobf_arm64_backend_mutation_tests
```

Expected: target/source absent.

- [ ] **Step 4: Run mutation and all nine fuzz surfaces**

```powershell
cmake --build build\m13-verify-debug --target binobf_arm64_backend_mutation_tests
ctest --test-dir build\m13-verify-debug -C Debug -R "^arm64_backend_mutation$" --output-on-failure
cmake --build build\m13-fuzz-final --target fuzz-smoke
```

Require all mutants killed and nine surfaces times 2,000 UBSan runs without crash/timeout/instability.

- [ ] **Step 5: Commit robustness evidence**

```powershell
git add CMakeLists.txt docs/hardening.md tests/fuzz tests/mutation/arm64_backend_mutation_tests.cpp
git commit -m "test: harden the ARM64 object backend"
```

---

### Task 12: Capability promotion, packaging, review, and push

**Files:**
- Modify: `src/architecture/capstone_backend.cpp`
- Modify: `src/capabilities/evidence.cpp`
- Modify: `src/capabilities/registry.cpp`
- Modify: `src/capabilities/render.cpp`
- Modify: `tests/integration/capability_evidence_tests.cpp`
- Modify: `tests/integration/capability_consistency_tests.cpp`
- Modify: `tests/integration/cli_tests.cpp`
- Create: `tests/installed/track4_consumer.cpp`
- Modify: `cmake/RunInstalledConsumer.cmake`
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/developer-guide.md`
- Modify: `docs/ir.md`
- Modify: `docs/verification.md`
- Modify: `docs/superpowers/specs/2026-08-17-full-feature-matrix-program-design.md`
- Modify: `docs/superpowers/plans/2026-08-18-full-arm64-object-backend.md`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: all Track 4 implementation and evidence.
- Produces: supported ARM64 object capabilities, installed proof, reviewed commits, and a public milestone.

- [ ] **Step 1: Bind enabled acceptance evidence**

```cpp
AcceptanceEvidence{"arm64_abi_adapter", "arm64_abi_native_differential", true},
AcceptanceEvidence{"arm64_codegen", "arm64_native_differential", true},
AcceptanceEvidence{"arm64_object_backend", "arm64_object_backend", true},
AcceptanceEvidence{"arm64_unwind", "arm64_unwind_semantics", true},
```

Validation fails for missing, duplicate, disabled, or absent-CTest evidence.

- [ ] **Step 2: Promote ARM64 records and services**

Set ARM64 ObjectAnalysis/CodeGeneration and AnalyzeObject/EmitCode/EncodeFixups/BuildAbiAdapter/
BuildUnwind to supported with split evidence. Preserve x86/x86-64 and later-track states.

- [ ] **Step 3: Add installed-only Track 4 consumption**

The consumer compiles ARM64 COFF/ELF fixtures, parses/analyzes, emits every template, encodes
scalar/split/scaled fixups, builds both adapters/unwind plans, runs seven transforms on eligible
inputs, writes/reparses, and validates evidence. It uses installed headers and exact archives only.

- [ ] **Step 4: Update documentation from the registry**

Render ARM64 object analysis/codegen supported. Document fixed-width transforms, relocations,
ABI/unwind limits, corpus/linker/QEMU evidence, and safety. Do not promote Tracks 5-10.

- [ ] **Step 5: Run complete matrices**

```powershell
cmake -S . -B build\m14-verify-debug -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBINOBF_BUILD_TESTS=ON
cmake --build build\m14-verify-debug
ctest --test-dir build\m14-verify-debug -C Debug --output-on-failure
cmake -S . -B build\m14-verify-release -G Ninja -DCMAKE_BUILD_TYPE=Release -DBINOBF_BUILD_TESTS=ON
cmake --build build\m14-verify-release
ctest --test-dir build\m14-verify-release -C Release --output-on-failure
cmake -S . -B build\m14-ubsan -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBINOBF_BUILD_TESTS=ON -DBINOBF_ENABLE_UNDEFINED_SANITIZER=ON
cmake --build build\m14-ubsan
ctest --test-dir build\m14-ubsan -C RelWithDebInfo --output-on-failure
cmake --build build\m13-fuzz-final --target fuzz-smoke
```

- [ ] **Step 6: Run non-CTest release gates**

Run analyzer on exact production units, supported ASan, standalone headers, installed consumer,
`git diff --check`, artifact/unfinished-marker scans, LLVM license/hash checks, registry/render
consistency, and two QEMU runs. Record Windows ASan unsupported only if the current MSVC STL lacks
its integration library, preserving the exact error.

- [ ] **Step 7: Obtain and resolve independent review**

Use `superpowers:requesting-code-review` over `53645ae..HEAD`. Resolve every Critical/Important
finding with regression tests, rerun affected gates, then all complete matrices, fuzz, analyzer,
and QEMU.

- [ ] **Step 8: Record and commit Track 4 completion**

Check Steps 1-8 and Track 4 only after fresh evidence passes.

```powershell
git add CMakeLists.txt README.md cmake docs include src tests
git commit -m "feat: promote the full ARM64 object backend"
```

- [ ] **Step 9: Push and verify the public milestone**

```powershell
gh auth status
git push origin main
git status -sb
gh repo view imattas/binobf --json isPrivate,url,defaultBranchRef,latestRelease
```

Require local/remote `main` hashes equal and public visibility. Do not tag/release because Track 4
does not advance the version. Mark Step 9 in a follow-up docs commit and push it.

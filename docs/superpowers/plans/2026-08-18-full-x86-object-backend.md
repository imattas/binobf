# Full x86 Object Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Promote 32-bit x86 object analysis and code generation to supported with architecture-neutral transforms, complete i386 COFF/ELF metadata and fixups, ABI/unwind services, compiler corpora, and native execution evidence.

**Architecture:** Extend the composed architecture backend with provider-neutral transform, fixup, ABI, and unwind contracts. Normalize the object metadata that rewrites must own, build immutable object rewrite plans, and make the seven machine passes consume backend services instead of x86-64 byte constants. Capstone decodes, the pinned in-process LLVM MC provider emits, and binobf writers transactionally rebuild COFF/ELF objects.

**Tech Stack:** C++20, CMake/CTest, Capstone 5.0.6, LLVM 22.1.8 MC/Object, Clang/LLD 22.1.8, Windows i686 native execution, libFuzzer, UBSan, clang-tidy/Clang Static Analyzer.

**Spec:** `docs/superpowers/specs/2026-08-18-full-x86-object-backend-design.md`

## Global Constraints

- Supported baseline is 32-bit x86 user-mode i686 with SSE2.
- COFF uses `i686-pc-windows-msvc`; ELF uses `i386-unknown-linux-gnu`.
- Windows i386 cdecl, stdcall, fastcall, and thiscall plus System V i386 are explicit ABIs.
- LLVM remains pinned to `llvmorg-22.1.8`, archive SHA-256 `922f1817a0df7b1489272d18134ee0087a8b068828f87ac63b9861b1a9965888`, private to `binobf_core`.
- No LLVM or Capstone type appears in an installed header.
- Unknown relocation/unwind metadata may round-trip unchanged but blocks movement of anything it owns.
- Every transformation is copy-plan-verify-commit and leaves input/existing output unchanged on failure.
- No debugger/VM/security-product detection, injection, reflective loading, persistence, payload download, dynamic API discovery, malformed/overlapping instruction stream, exception abuse, or signing bypass.
- Capability promotion occurs only with enabled acceptance evidence and all gates green.

---

### Task 1: Callable object-backend service contracts

**Files:**
- Create: `include/binobf/architecture/object_backend.hpp`
- Modify: `include/binobf/architecture/backend.hpp`
- Modify: `src/architecture/capstone_backend.cpp`
- Create: `tests/unit/object_backend_contract_tests.cpp`
- Modify: `tests/unit/architecture_backend_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `MachineEmission`, `MachineFixupKind`, `Instruction`, `IrFunctionSignature`, and existing backend service records.
- Produces: `MachineTransformRequest`, `MachineTransformEmission`, `ObjectFixupSemantics`, `ObjectFixupEncoding`, `AbiAdapterRequest`, `AbiAdapterPlan`, `UnwindRequest`, `UnwindPlan`, and callable `ArchitectureBackend` methods.

- [x] **Step 1: Add a failing service-contract target**

Create tests that instantiate all three backends and require callable methods whose result architecture matches the fixed backend. The first test uses these exact public shapes:

```cpp
auto backend = binobf::make_architecture_backend(binobf::Architecture::X86);
REQUIRE(backend.has_value());
auto emitted = backend.value()->emit_transform(binobf::MachineTransformRequest{
    .architecture = binobf::Architecture::X86,
    .format = binobf::BinaryFormat::COFF,
    .kind = binobf::MachineTransformKind::DeadCodeFill,
    .exactSize = 3,
});
REQUIRE(emitted.has_value());
REQUIRE_EQ(emitted.value().emission.bytes.size(), std::size_t{3});
```

Also require architecture mismatch diagnostics for all four services, unique sorted service records, and non-empty evidence for a service advertised as `Supported`.

- [x] **Step 2: Register the target and prove the contract is RED**

Run:

```powershell
cmake -S . -B build\m13-dev -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBINOBF_BUILD_TESTS=ON
cmake --build build\m13-dev --target binobf_object_backend_contract_tests
```

Expected: compile failure because `object_backend.hpp` and callable methods do not exist.

- [x] **Step 3: Add the provider-neutral public values**

Define the stable enums and records in `object_backend.hpp`:

```cpp
enum class MachineTransformKind : std::uint8_t {
    InstructionEquivalent, ConstantMaterialization, ConditionalInversion,
    DirectJump, DeadCodeFill, AbiCallAdapter,
};
enum class MachineControlFlow : std::uint8_t {
    Fallthrough, Conditional, Direct, Call, Return,
};
enum class UnwindDisposition : std::uint8_t { NotRequired, Preserve, Emit };
enum class UnwindEncoding : std::uint8_t { None, WindowsI386, DwarfCfi32 };

struct MachineTransformRequest {
    Architecture architecture{Architecture::Unknown};
    BinaryFormat format{BinaryFormat::Unknown};
    MachineTransformKind kind{MachineTransformKind::InstructionEquivalent};
    std::optional<Instruction> source;
    std::optional<std::uint64_t> targetAddress;
    std::optional<std::uint64_t> constantBits;
    std::string condition;
    std::size_t exactSize{0};
    MachineCodeLimits limits{};
};
struct MachineTransformEmission {
    MachineEmission emission;
    std::size_t instructionCount{0};
    MachineControlFlow controlFlow{MachineControlFlow::Fallthrough};
    std::int64_t stackDelta{0};
    bool readsFlags{false};
    bool writesFlags{false};
};
struct ObjectFixupSemantics {
    MachineFixupKind kind{MachineFixupKind::Absolute32};
    std::uint64_t rawType{0};
    std::uint8_t bitWidth{0};
    bool isSigned{false};
    bool pcRelative{false};
    bool implicitAddend{false};
    std::int8_t pcBias{0};
};
struct ObjectFixupEncoding {
    ObjectFixupSemantics semantics;
    std::vector<std::byte> fieldBytes;
};
```

Define ABI/unwind records using `ir::NativeAbi`, `ir::IrFunctionSignature`, typed register/CFA actions, code range, symbol, clobbers, and resource bounds exactly as the design specifies.

- [x] **Step 4: Make every service callable and fail narrowly when unsupported**

Add virtual methods:

```cpp
virtual auto emit_transform(const MachineTransformRequest&) const
    -> Result<MachineTransformEmission, Diagnostic> = 0;
virtual auto fixup_semantics(BinaryFormat, std::uint64_t rawType) const
    -> Result<ObjectFixupSemantics, Diagnostic> = 0;
virtual auto encode_fixup(const ObjectFixupSemantics&, std::int64_t value) const
    -> Result<ObjectFixupEncoding, Diagnostic> = 0;
virtual auto build_abi_adapter(const AbiAdapterRequest&) const
    -> Result<AbiAdapterPlan, Diagnostic> = 0;
virtual auto build_unwind(const UnwindRequest&) const
    -> Result<UnwindPlan, Diagnostic> = 0;
```

Use shared validators for architecture/format/size/resource fields. Temporary unsupported paths return stable `architecture.service_unsupported`; do not mark those records supported.

- [x] **Step 5: Run contract and backend regressions**

```powershell
cmake --build build\m13-dev --target binobf_object_backend_contract_tests binobf_architecture_backend_tests
ctest --test-dir build\m13-dev -R "object_backend_contract|architecture_backend" --output-on-failure
```

Expected: both CTests pass and installed headers contain neither `llvm::` nor `cs_`.

- [x] **Step 6: Commit callable service contracts**

```powershell
git add CMakeLists.txt include/binobf/architecture src/architecture/capstone_backend.cpp tests/unit/object_backend_contract_tests.cpp tests/unit/architecture_backend_tests.cpp
git commit -m "feat: define callable object backend services"
```

---

### Task 2: i386 ABI declarations, analysis, and native lifting

**Files:**
- Modify: `include/binobf/ir/native.hpp`
- Modify: `include/binobf/ir/native_lifter.hpp`
- Modify: `src/ir/native.cpp`
- Modify: `src/ir/native_lifter.cpp`
- Modify: `src/analysis/object_analyzer.cpp`
- Create: `tests/unit/x86_object_analyzer_tests.cpp`
- Modify: `tests/unit/native_lifter_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: canonical Track 2 types/storage/calls/fallbacks and 32-bit Capstone decode results.
- Produces: five i386 ABI enum values, validated 32-bit bindings, complete x86 analysis, and x86 native lift reports.

- [x] **Step 1: Add failing ABI and x86-lifter cases**

Cover each ABI with a signature containing register and stack arguments, a 64-bit return, and a variadic rejection for non-cdecl conventions. Add a real x86 function fixture containing prologue, stack argument load, arithmetic, conditional branch, external relocation-backed call, SSE2 scalar operation, epilogue, and return. Require pointer types to be 32-bit and require fallback effects for an unsupported instruction.

- [x] **Step 2: Prove current x64-only behavior is RED**

```powershell
cmake --build build\m13-dev --target binobf_x86_object_analyzer_tests binobf_native_lifter_tests
ctest --test-dir build\m13-dev -R "x86_object_analyzer|native_lifter" --output-on-failure
```

Expected: x86 lift fails with `ir.unsupported_architecture`, and i386 ABI enum cases do not compile.

- [x] **Step 3: Extend the ABI enums and validation**

Add:

```cpp
enum class NativeAbi : std::uint8_t {
    WindowsX64, SystemVAMD64,
    WindowsI386Cdecl, WindowsI386Stdcall,
    WindowsI386Fastcall, WindowsI386Thiscall, SystemVI386,
};
```

Add matching `IrCallingConvention` values. Validate ECX/EDX fastcall, ECX thiscall, stack-only cdecl/stdcall/System V, caller-versus-callee cleanup, variadic-only cdecl/System V, EAX/EDX integer returns, x87/SSE scalar returns, hidden aggregate-return pointers, and 16-byte System V call-site alignment.

- [x] **Step 4: Parameterize the lifter by architecture and ABI**

Open Capstone with `CS_MODE_32` for x86 and `CS_MODE_64` for x86-64. Build 32-bit register/pointer storage, decode EBP/ESP addressing, attach complete relocation references, and map ordinary MOV/LEA/PUSH/POP/arithmetic/compare/branch/call/return plus SSE2 scalar operations. Keep unsupported instructions as complete-effect `IrFallback` nodes and set `report.complete = false`.

- [x] **Step 5: Harden x86 function discovery and CFG recovery**

Require function symbols to be bounded by their exact symbol/auxiliary size or the next owned symbol. Prevent inference across section-association boundaries. Resolve relocation-backed calls/branches, keep indirect edges unresolved without a proven target set, and compute deterministic live-in/live-out sets for 32-bit register names.

- [x] **Step 6: Run analyzer/lifter and x64 regression suites**

```powershell
cmake --build build\m13-dev --target binobf_x86_object_analyzer_tests binobf_object_analyzer_tests binobf_native_lifter_tests
ctest --test-dir build\m13-dev -R "x86_object_analyzer|object_analyzer|native_lifter" --output-on-failure
```

- [x] **Step 7: Commit x86 analysis and lifting**

```powershell
git add CMakeLists.txt include/binobf/ir src/analysis/object_analyzer.cpp src/ir tests/unit/x86_object_analyzer_tests.cpp tests/unit/native_lifter_tests.cpp
git commit -m "feat: analyze and lift i386 object code"
```

---

### Task 3: Normalized object ownership model

**Files:**
- Modify: `include/binobf/core/model.hpp`
- Modify: `src/verify/object_model_validator.cpp`
- Create: `tests/unit/object_ownership_tests.cpp`
- Modify: `tests/unit/core_types_tests.cpp`
- Modify: `tests/unit/structural_verifier_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: stable entity IDs, raw format fields, symbols, sections, relocations, and unwind records.
- Produces: normalized definition, association, relocation-table, extended-index, TLS, and unwind ownership records.

- [x] **Step 1: Write invalid-ownership tests first**

Require rejection of duplicate association membership, missing COMDAT/group signature, association cycles, a relocation table targeting an absent section, SHN_XINDEX without a companion entry, a common symbol with zero alignment, overlapping unwind ranges, and an unwind relocation outside its encoded record. Require a valid COFF associative COMDAT and valid ELF group to pass.

- [x] **Step 2: Run the new target to RED**

```powershell
cmake --build build\m13-dev --target binobf_object_ownership_tests
```

Expected compile failure because normalized ownership types do not exist.

- [x] **Step 3: Add exact normalized records**

Add these model values:

```cpp
enum class SymbolDefinitionKind : std::uint8_t {
    Undefined, SectionRelative, Absolute, Common,
};
enum class SectionAssociationKind : std::uint8_t {
    Ordinary, CoffComdat, CoffAssociativeComdat, ElfGroup,
};
enum class CoffComdatSelection : std::uint8_t {
    None, NoDuplicates, Any, SameSize, ExactMatch, Associative, Largest, Newest,
};
struct SectionAssociation {
    EntityId section;
    SectionAssociationKind kind{SectionAssociationKind::Ordinary};
    CoffComdatSelection coffSelection{CoffComdatSelection::None};
    std::optional<EntityId> signatureSymbol;
    std::optional<EntityId> parentSection;
    std::vector<EntityId> members;
};
struct RelocationTableEncoding {
    EntityId section;
    bool coffOverflow{false};
    std::uint64_t declaredCount{0};
};
enum class UnwindFormat : std::uint8_t { Unknown, WindowsI386, DwarfCfi32 };
```

Extend symbols with definition kind/common alignment/TLS model, unwind records with section/range/format/relocation IDs/rewrite state, and `BinaryImage` with association/table-encoding collections. Preserve raw fields.

- [x] **Step 4: Validate ownership independently of a writer**

Index all entity IDs once, enforce unique membership and acyclic parents, validate association signature/selection rules, verify normalized/raw index agreement, and prove unwind ranges and referenced relocations lie in owned sections. Return `object.ownership_*` diagnostics with entity context.

- [x] **Step 5: Run model, ownership, and structural tests**

```powershell
cmake --build build\m13-dev --target binobf_object_ownership_tests binobf_core_types_tests binobf_structural_verifier_tests
ctest --test-dir build\m13-dev -R "object_ownership|core_types|structural_verifier" --output-on-failure
```

- [x] **Step 6: Commit normalized ownership**

```powershell
git add CMakeLists.txt include/binobf/core/model.hpp src/verify/object_model_validator.cpp tests/unit/object_ownership_tests.cpp tests/unit/core_types_tests.cpp tests/unit/structural_verifier_tests.cpp
git commit -m "feat: normalize object metadata ownership"
```

---

### Task 4: Complete i386 COFF parsing and writing

**Files:**
- Modify: `src/formats/detector.cpp`
- Modify: `src/formats/coff/object_parser.cpp`
- Modify: `src/formats/coff/object_writer.cpp`
- Create: `tests/unit/coff_x86_extended_tests.cpp`
- Modify: `tests/unit/coff_object_parser_tests.cpp`
- Modify: `tests/unit/object_writer_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: normalized object ownership and raw COFF records.
- Produces: classic/bigobj parse-write-parse, overflow relocation tables, COMDAT/SafeSEH ownership, and stable symbol identities.

- [x] **Step 1: Add exact boundary fixtures and failing goldens**

Construct minimal byte fixtures for i386 classic COFF, bigobj with 32-bit section numbers, a 65,536-entry relocation-overflow table, each COMDAT selection, associative COMDAT, common symbol, `.sxdata` SafeSEH index, long names, and unknown auxiliary bytes. Exercise `ABSOLUTE`, `DIR16`, `REL16`, `DIR32`, `DIR32NB`, `SEG12`, `SECTION`, `SECREL`, `TOKEN`, `SECREL7`, and `REL32`. Add malformed count/index/association variants and require stable diagnostic codes.

- [x] **Step 2: Confirm current unsupported paths are RED**

```powershell
cmake --build build\m13-dev --target binobf_coff_x86_extended_tests
ctest --test-dir build\m13-dev -R coff_x86_extended --output-on-failure
```

Expected: bigobj is not detected and relocation overflow returns `coff.unsupported`.

- [x] **Step 3: Parse classic and bigobj through one bounded view**

Introduce a private `CoffObjectLayout` containing header size, section count, symbol offset/count,
symbol entry size (18 or 20), and section-number width. Recognize the bigobj UUID and version,
cap section/symbol/relocation counts before allocation, and normalize symbol IDs before resolving
auxiliary references.

- [x] **Step 4: Normalize COMDAT, SafeSEH, common, and relocation overflow**

Decode section-definition auxiliary records into `SectionAssociation`; resolve associative section
numbers after every section exists. Decode common symbols from external/undefined symbols with
nonzero value. Decode `.sxdata` entries as symbol-index ownership. For overflow tables, require
header count `0xffff`, overflow flag, and first relocation record containing the real count; expose
only real relocations in `BinaryImage`.

- [x] **Step 5: Rebuild tables with repaired indices**

Choose classic COFF unless the source is bigobj or section indices exceed 16-bit signed range.
Recalculate section/symbol indices, auxiliary associations, SafeSEH entries, section-symbol
checksums, long-name offsets, and overflow sentinel/count records. Preserve unknown auxiliary data
byte-for-byte after updating only proven index/checksum fields.

- [x] **Step 6: Run COFF round-trip and writer regressions**

```powershell
cmake --build build\m13-dev --target binobf_coff_x86_extended_tests binobf_coff_object_parser_tests binobf_object_writer_tests
ctest --test-dir build\m13-dev -R "coff_x86_extended|coff_object_parser|object_writer" --output-on-failure
```

- [x] **Step 7: Commit complete i386 COFF metadata**

```powershell
git add CMakeLists.txt src/formats/detector.cpp src/formats/coff tests/unit/coff_x86_extended_tests.cpp tests/unit/coff_object_parser_tests.cpp tests/unit/object_writer_tests.cpp
git commit -m "feat: support extended i386 COFF objects"
```

---

### Task 5: Complete ELF32 parsing and writing

**Files:**
- Modify: `src/formats/elf/object_parser.cpp`
- Modify: `src/formats/elf/object_writer.cpp`
- Create: `tests/unit/elf32_extended_tests.cpp`
- Modify: `tests/unit/elf_object_parser_tests.cpp`
- Modify: `tests/unit/object_writer_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: normalized ownership plus ELF32 raw section/symbol/relocation fields.
- Produces: extended numbering/indices, groups, common/TLS symbols, REL/RELA, and exact ELF32 reconstruction.

- [x] **Step 1: Add synthetic ELF32 boundary fixtures**

Cover `e_shnum == 0` with section-zero count, `e_shstrndx == SHN_XINDEX`, symbol `SHN_XINDEX` through `SHT_SYMTAB_SHNDX`, `SHN_COMMON`, `STT_TLS`, `SHT_GROUP` with COMDAT flag/signature, REL implicit addends, RELA explicit addends, and i386 GOT/PLT/GOTOFF/GOTPC/TLS relocations. Add missing companion tables, invalid group member, truncated extended header, and out-of-range symbol index.

- [x] **Step 2: Prove extended paths are RED**

```powershell
cmake --build build\m13-dev --target binobf_elf32_extended_tests
ctest --test-dir build\m13-dev -R elf32_extended --output-on-failure
```

Expected: current parser returns `elf.unsupported` for extended numbering and extended symbol indices.

- [x] **Step 3: Resolve extended counts and symbol indices before allocation**

Read section zero first using the declared entry size. Resolve actual section count from `sh_size`,
actual name-table index from `sh_link`, and per-symbol extended indices from a single correctly linked
`SHT_SYMTAB_SHNDX` table. Apply existing 16,384-section and 1,000,000-symbol resource ceilings after
resolution.

- [x] **Step 4: Normalize groups, common/TLS, and i386 relocations**

Parse group word zero as flags and remaining words as section indices; bind the signature through
`sh_info` in the linked symbol table. Map `SHN_COMMON` value to alignment and size to allocation
size. Preserve TLS binding/model. For REL records, read the field bytes using backend fixup semantics
and store the normalized signed addend without changing the raw section bytes.

- [x] **Step 5: Emit direct or extended encodings deterministically**

Use direct header/index forms when values fit and preserve extended source form for unchanged
objects. Emit section-zero extended fields, `SHT_SYMTAB_SHNDX`, local-symbol boundary `sh_info`,
group member indices/signature, common/TLS symbols, and REL field addends. Require every referenced
section/symbol to have a rebuilt index.

- [x] **Step 6: Run ELF32 and existing writer/parser suites**

```powershell
cmake --build build\m13-dev --target binobf_elf32_extended_tests binobf_elf_object_parser_tests binobf_object_writer_tests
ctest --test-dir build\m13-dev -R "elf32_extended|elf_object_parser|object_writer" --output-on-failure
```

- [x] **Step 7: Commit complete ELF32 metadata**

```powershell
git add CMakeLists.txt src/formats/elf tests/unit/elf32_extended_tests.cpp tests/unit/elf_object_parser_tests.cpp tests/unit/object_writer_tests.cpp
git commit -m "feat: support extended i386 ELF objects"
```

---

### Task 6: x86 fixup normalization and range-checked encoding

**Files:**
- Modify: `include/binobf/architecture/codegen.hpp`
- Create: `src/architecture/x86_fixups.hpp`
- Create: `src/architecture/x86_fixups.cpp`
- Modify: `src/architecture/capstone_backend.cpp`
- Modify: `src/architecture/llvm_fixups.cpp`
- Create: `tests/unit/x86_fixup_tests.cpp`
- Modify: `tests/unit/codegen_provider_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: COFF i386 and ELF i386 raw relocation numbers plus normalized addends.
- Produces: inverse `fixup_semantics()`/`encode_fixup()` services for all declared x86 families.

- [x] **Step 1: Write table-driven fixup goldens**

For COFF cover `ABSOLUTE`, `DIR16`, `REL16`, `DIR32`, `DIR32NB`, `SEG12`, `SECTION`, `SECREL`,
`TOKEN`, `SECREL7`, and `REL32`. For ELF cover `R_386_NONE`, `32`, `PC32`, `GOT32`, `PLT32`,
`GOTOFF`, `GOTPC`, `16`, `PC16`, `8`, `PC8`, `SIZE32`, `GOT32X`, and the `TLS_TPOFF`, `TLS_IE`,
`TLS_GOTIE`, `TLS_LE`, `TLS_GD`, `TLS_LDM`, `TLS_LDO_32`, `TLS_IE_32`, `TLS_LE_32`, `TLS_DTPMOD32`,
`TLS_DTPOFF32`, `TLS_TPOFF32`, `TLS_GOTDESC`, `TLS_DESC_CALL`, and `TLS_DESC` families. Each row
asserts stable kind, width, signedness, PC-relative flag/bias, implicit-addend
state, zero/nonzero addend bytes, signed boundaries, and one-step overflow rejection.

- [x] **Step 2: Extend stable fixup kinds**

Add only provider-neutral kinds required by the tables:

```cpp
Segment12, MetadataToken32, SectionIndex16, SectionRelative7,
GotOffset32, GotPcRelative32, Size32,
TlsOffset32, TlsGot32, TlsGeneralDynamic32, TlsLocalDynamic32,
```

Update all exhaustive switches and `operator<=>` tests.

- [x] **Step 3: Implement constexpr semantics tables**

Use sorted private rows keyed by format/raw type. Reject duplicate table keys in a static assertion.
Unknown values return `architecture.unsupported_fixup` naming architecture, format, and raw number.
Encode with checked signed/unsigned bounds and little-endian bytes of exactly `bitWidth / 8`.

- [x] **Step 4: Cross-check LLVM normalization and object writers**

For each LLVM-emitted x86 external reference, normalize the object relocation, encode its addend,
and require equality with the extracted section field. Add a parse-write-parse test proving REL
implicit addends and COFF PC bias survive unchanged.

- [x] **Step 5: Run fixup/provider tests**

```powershell
cmake --build build\m13-dev --target binobf_x86_fixup_tests binobf_codegen_provider_tests
ctest --test-dir build\m13-dev -R "x86_fixup|codegen_provider" --output-on-failure
```

- [x] **Step 6: Commit x86 fixup services**

```powershell
git add CMakeLists.txt include/binobf/architecture/codegen.hpp src/architecture tests/unit/x86_fixup_tests.cpp tests/unit/codegen_provider_tests.cpp
git commit -m "feat: encode complete i386 object fixups"
```

---

### Task 7: Backend-owned x86 templates, ABI adapters, and unwind plans

**Files:**
- Create: `src/architecture/x86_templates.hpp`
- Create: `src/architecture/x86_templates.cpp`
- Create: `src/architecture/x86_abi.hpp`
- Create: `src/architecture/x86_abi.cpp`
- Create: `src/architecture/x86_unwind.hpp`
- Create: `src/architecture/x86_unwind.cpp`
- Modify: `src/architecture/capstone_backend.cpp`
- Create: `tests/unit/x86_template_tests.cpp`
- Create: `tests/unit/x86_abi_unwind_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: callable service contracts, i386 ABI declarations, LLVM MC provider, and x86 fixups.
- Produces: verified exact-size transform emissions, convention adapters, and Windows/DWARF unwind plans.

- [x] **Step 1: Add transform-template goldens**

Require same-size x86 equivalents for multi-byte NOP substitution, EAX/ECX constant materialization,
all normalized condition inversions, short/near direct jumps, and dead-code fill sizes 1 through 15.
Require emitted bytes to re-decode completely and effects to match. Add impossible exact-size and
out-of-range target refusals.

- [x] **Step 2: Add ABI/unwind goldens**

For each five i386 ABIs assert argument moves, cleanup owner, 16-byte alignment, external call
fixup, return binding, clobbers, and net stack delta. Require Windows leaf plans to return
`NotRequired/WindowsI386` with zero encoded records and System V EBP-frame plans to return
`Emit/DwarfCfi32` with CFA actions for EIP/EBP and a bounded code range.

- [x] **Step 3: Implement typed template-to-assembly lowering**

Translate requests to internal Intel assembly using fixed register/condition tables. Emit with
the request format triple, enforce exact byte count, and re-decode every byte. Compare decoded
control-flow class, instruction count, flags access, register effects, and stack delta to the typed
request before returning.

- [x] **Step 4: Implement i386 convention adapters**

Build a deterministic argument-move schedule that handles register cycles through EAX, emits stack
arguments right-to-left, inserts alignment padding, emits one external call fixup, applies
caller/callee cleanup exactly once, and moves EAX/EDX/x87/SSE return values to the requested binding.
Reject variadic stdcall/fastcall/thiscall and incompatible aggregate layouts.

- [x] **Step 5: Encode bounded DWARF CFI and Windows dispositions**

Encode CIE/FDE length/version/augmentation/code alignment/data alignment/return register plus typed
CFA opcodes using checked 32-bit offsets. Windows ordinary leaf/frame adapters return
`NotRequired`; handler-bearing requests require `Preserve` with an owned SafeSEH symbol or fail
`architecture.unwind_unowned`.

- [x] **Step 6: Run template, ABI, unwind, and backend suites**

```powershell
cmake --build build\m13-dev --target binobf_x86_template_tests binobf_x86_abi_unwind_tests binobf_architecture_backend_tests
ctest --test-dir build\m13-dev -R "x86_template|x86_abi_unwind|architecture_backend" --output-on-failure
```

- [x] **Step 7: Commit x86 code generation services**

```powershell
git add CMakeLists.txt src/architecture tests/unit/x86_template_tests.cpp tests/unit/x86_abi_unwind_tests.cpp
git commit -m "feat: emit i386 templates ABI and unwind"
```

---

### Task 8: Immutable object rewrite plans

**Files:**
- Create: `include/binobf/transforms/object_rewrite.hpp`
- Create: `src/transforms/object_rewrite.cpp`
- Create: `tests/unit/object_rewrite_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: normalized ownership, backend fixup services, section-local replacements, and lineage.
- Produces: `ObjectRewritePlan::create()`, `validate()`, and `commit()` with total old-to-new mapping.

- [x] **Step 1: Write plan invariant and transaction tests**

Cover overlapping replacements, mapping gaps, expansion overflow, unmapped symbol, moved relocation
site/target, implicit addend repair, unowned association/unwind metadata, branch range overflow,
duplicate lineage, deterministic order, and a valid two-function reorder. Snapshot the input and
require exact equality after every failed plan/commit.

- [x] **Step 2: Define focused public plan values**

```cpp
struct ObjectRewriteRange {
    EntityId section;
    std::uint64_t oldBegin{0}, oldEnd{0}, newBegin{0};
    std::vector<std::byte> replacement;
};
struct ObjectRewriteRequest {
    std::vector<ObjectRewriteRange> ranges;
    std::string passName;
    TransformId transform;
    std::uint64_t maxOutputGrowth{16U << 20U};
};
class ObjectRewritePlan {
public:
    static auto create(const BinaryImage&, const ArchitectureBackend&,
                       const ObjectRewriteRequest&)
        -> Result<ObjectRewritePlan, Diagnostic>;
    auto commit(const BinaryImage&) const -> Result<BinaryImage, Diagnostic>;
};
```

Keep indexes and implementation maps private.

- [x] **Step 3: Build and freeze a total mapping**

Sort by section/old begin, reject overlap/overflow, derive unchanged gaps, and map every symbol,
relocation site/target, section-symbol addend, association, and unwind range. Use backend fixup
semantics to repair explicit and implicit addends. Store only immutable vectors after `create()`.

- [x] **Step 4: Commit to a copy and validate the result**

Apply bytes, normalized addresses, raw addend fields, association indices, unwind ranges, and one
lineage record to a copy. Run object-model validation before returning. Do not write files or mutate
the source.

- [x] **Step 5: Run rewrite/model suites**

```powershell
cmake --build build\m13-dev --target binobf_object_rewrite_tests binobf_structural_verifier_tests
ctest --test-dir build\m13-dev -R "object_rewrite|structural_verifier" --output-on-failure
```

- [x] **Step 6: Commit transactional rewrite plans**

```powershell
git add CMakeLists.txt include/binobf/transforms/object_rewrite.hpp src/transforms/object_rewrite.cpp tests/unit/object_rewrite_tests.cpp
git commit -m "feat: add transactional object rewrite plans"
```

---

### Task 9: Architecture-neutral machine transforms with x86 support

**Files:**
- Modify: `src/transforms/instruction.cpp`
- Modify: `tests/unit/instruction_transform_tests.cpp`
- Modify: `tests/integration/instruction_transform_integration_tests.cpp`
- Create: `tests/integration/x86_transform_integration_tests.cpp`
- Modify: `tests/differential/differential_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: backend templates and `ObjectRewritePlan`.
- Produces: all seven machine transforms for x86 COFF/ELF while preserving x86-64 results.

- [x] **Step 1: Add x86 tests for every pass before changing support**

For COFF and ELF require a real deterministic change from instruction substitution, constant
rewriting, branch inversion, block splitting, dead-code insertion, block reordering, and function
reordering. Include relocations, section symbols, COMDAT/group membership, common/TLS references,
and unwind records. Add per-function skips for exact-size failure, opaque-crossing, unowned metadata,
and out-of-range branches.

- [x] **Step 2: Prove current x86 support is RED**

```powershell
cmake --build build\m13-dev --target binobf_x86_transform_integration_tests
ctest --test-dir build\m13-dev -R x86_transform_integration --output-on-failure
```

Expected: every pass reports unsupported because `supports_machine_pass` accepts x86-64 only.

- [x] **Step 3: Remove architecture byte logic from pass algorithms**

Replace raw opcode construction/patching with `emit_transform()` requests. Replace local
`FunctionChunk`/branch patching with `ObjectRewriteRequest`. Passes select proven semantic candidates,
ask for exact-size backend output, assemble the complete plan, commit to a candidate, reanalyze, and
only then replace the working image.

- [x] **Step 4: Enable x86 and keep narrow skip diagnostics**

Accept x86/x86-64 relocatable COFF/ELF when the backend advertises all required services. A failed
candidate increments `skipped` and records its contextual diagnostic; a plan invariant failure
fails the pass transaction. Require `changed > 0` for an applied status.

- [x] **Step 5: Run unit/integration/differential regressions**

```powershell
cmake --build build\m13-dev --target binobf_instruction_transform_tests binobf_instruction_transform_integration_tests binobf_x86_transform_integration_tests binobf_differential_tests
ctest --test-dir build\m13-dev -R "instruction_transform|x86_transform|differential" --output-on-failure
```

- [x] **Step 6: Commit architecture-neutral transforms**

```powershell
git add CMakeLists.txt src/transforms/instruction.cpp tests/unit/instruction_transform_tests.cpp tests/integration tests/differential/differential_tests.cpp
git commit -m "feat: run all object transforms on i386"
```

---

### Task 10: i386 compiler corpus and standard-tool acceptance

**Files:**
- Create: `tests/fixtures/x86/corpus.c`
- Create: `tests/fixtures/x86/corpus.cpp`
- Create: `tests/fixtures/x86/corpus.S`
- Create: `cmake/RunX86ObjectCorpus.cmake`
- Create: `tests/integration/x86_object_backend_integration_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: Clang/LLD 22.1.8, both x86 triples, parsers/writers/analyzer/transforms.
- Produces: `x86_object_backend` acceptance CTest covering six optimization levels and two formats.

- [x] **Step 1: Add self-contained compiler fixtures**

Define exported functions for stack/register arguments, all Windows conventions under target
guards, loops, switches, recursion, tail calls, globals, common storage, TLS, function pointers,
integer/f32/f64/SSE2 vector operations, COMDAT/group templates, debug locations, and exception
metadata. Use compiler builtins and local typedefs only; include no host headers.

- [x] **Step 2: Generate the full object matrix deterministically**

For each `-O0 -O1 -O2 -O3 -Os -Oz`, compile C/C++/assembly with:

```powershell
clang --target=i686-pc-windows-msvc -m32 -msse2 -ffunction-sections -fdata-sections -c
clang --target=i386-unknown-linux-gnu -m32 -msse2 -fPIC -ffunction-sections -fdata-sections -c
```

Use build-local output directories and explicit source/output arguments. Record compiler version
and command lines in a build-local manifest.

- [x] **Step 3: Parse, analyze, transform, write, and reparse each object**

The integration executable loads every matrix member, requires x86 detection and complete ordinary
functions, runs every pass separately with a fixed seed, requires at least one applied function per
pass across the corpus, writes/reparses, and validates deterministic repeated bytes and lineage.

- [x] **Step 4: Gate LLVM inspection and linking**

Run `llvm-readobj --file-headers --sections --symbols --relocations --unwind`, `llvm-objdump -dr`,
and `llvm-nm` on originals and outputs. Link COFF objects relocatably with `lld-link /lib` plus a
consumer link, and ELF objects with `ld.lld -m elf_i386 -r`. Any nonzero tool exit fails the CTest
with captured command/output.

- [x] **Step 5: Run the acceptance CTest**

```powershell
cmake --build build\m13-dev --target binobf_x86_object_backend_integration_tests
ctest --test-dir build\m13-dev -R x86_object_backend --output-on-failure
```

- [x] **Step 6: Commit compiler-corpus acceptance**

```powershell
git add CMakeLists.txt cmake/RunX86ObjectCorpus.cmake tests/fixtures/x86 tests/integration/x86_object_backend_integration_tests.cpp
git commit -m "test: validate the i386 compiler object corpus"
```

---

### Task 11: Native x86 differential, fuzz, and mutation evidence

**Files:**
- Create: `tests/differential/x86_native_differential_tests.cpp`
- Create: `tests/fixtures/x86/native_entry.S`
- Create: `cmake/RunX86NativeDifferential.cmake`
- Create: `tests/fuzz/object_rewrite_fuzzer.cpp`
- Create: `tests/fuzz/corpus/object-rewrite/x86-coff.seed`
- Create: `tests/fuzz/corpus/object-rewrite/x86-elf.seed`
- Modify: `tests/fuzz/README.md`
- Create: `tests/mutation/x86_backend_mutation_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: transformed x86 COFF objects and all validation/range/ownership checks.
- Produces: native original-versus-transformed behavior, rewrite fuzzing, and mutation-kill evidence.

- [ ] **Step 1: Add a hard native-x86 host probe**

Compile/link a freestanding i386 COFF executable with `lld-link /machine:x86 /entry:entry
/subsystem:console /nodefaultlib`, run it, and require the designed exit code. Check the PE machine
field before execution. A launch failure or wrong code fails `x86_native_differential`; do not skip.

- [ ] **Step 2: Compare original and transformed programs**

For each runtime-safe corpus function and every pass, link original and transformed objects with the
same entry fixture. Run bounded child processes, compare exit code and fixed result-file bytes, and
require no timeout/crash. Use build-local unique paths and remove only verified build-local outputs.

- [ ] **Step 3: Add bounded rewrite-plan fuzzing**

Map input bytes to x86 COFF/ELF seed selection, bounded replacement ranges, target/addend changes,
and resource limits. Parse, attempt plan creation/commit, and if successful write/reparse/validate;
otherwise require a nonempty stable diagnostic. Never execute fuzz output.

- [ ] **Step 4: Add mutation-kill assertions**

Introduce test-local mutant functions that omit each critical check: signed fixup range, PC bias,
implicit addend rewrite, association ownership, unwind ownership, mapping overlap, and transactional
copy. Require the golden counterexample to pass the production checker and fail the mutant.

- [ ] **Step 5: Run native, fuzz-smoke, and mutation gates**

```powershell
cmake --build build\m13-dev --target binobf_x86_native_differential_tests binobf_x86_backend_mutation_tests
ctest --test-dir build\m13-dev -R "x86_native_differential|x86_backend_mutation" --output-on-failure
cmake -S . -B build\m13-fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBINOBF_BUILD_FUZZERS=ON -DBINOBF_BUILD_TESTS=OFF
cmake --build build\m13-fuzz --target fuzz-smoke
```

- [ ] **Step 6: Commit runtime and robustness evidence**

```powershell
git add CMakeLists.txt cmake/RunX86NativeDifferential.cmake tests/differential tests/fixtures/x86/native_entry.S tests/fuzz tests/mutation/x86_backend_mutation_tests.cpp
git commit -m "test: prove native and adversarial i386 behavior"
```

---

### Task 12: Capability promotion, packaging, documentation, and full gates

**Files:**
- Modify: `src/architecture/capstone_backend.cpp`
- Modify: `src/capabilities/registry.cpp`
- Modify: `src/capabilities/evidence.cpp`
- Modify: `src/capabilities/render.cpp`
- Modify: `tests/integration/capability_evidence_tests.cpp`
- Modify: `tests/integration/capability_consistency_tests.cpp`
- Modify: `tests/integration/cli_tests.cpp`
- Create: `tests/installed/track3_consumer.cpp`
- Modify: `cmake/RunInstalledConsumer.cmake`
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/developer-guide.md`
- Modify: `docs/hardening.md`
- Modify: `docs/ir.md`
- Modify: `docs/verification.md`
- Modify: `docs/superpowers/specs/2026-08-17-full-feature-matrix-program-design.md`
- Modify: `docs/superpowers/plans/2026-08-18-full-x86-object-backend.md`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: all Track 3 implementation/evidence and installed static-library closure.
- Produces: supported x86 object-analysis/codegen records, installed-consumer proof, and a clean pushed milestone.

- [ ] **Step 1: Bind enabled acceptance evidence before promotion**

Add `AcceptanceEvidence{"x86_object_backend", "x86_object_backend", true}` and
`AcceptanceEvidence{"x86_codegen", "x86_native_differential", true}` in sorted order. Require the
evidence validator to fail when either group is absent/disabled.

- [ ] **Step 2: Promote x86 records and backend services**

Set x86 `ObjectAnalysis` and `CodeGeneration` to `Supported` with their evidence IDs. Set x86
AnalyzeObject/EmitCode/EncodeFixups/BuildAbiAdapter/BuildUnwind service records to supported and
evidence-bound. Keep ARM64 states unchanged and preserve x86-64 advertised behavior.

- [ ] **Step 3: Extend installed-only verification**

The Track 3 consumer parses checked-in x86 COFF/ELF fixtures, analyzes a function, emits a template
and ABI adapter, normalizes/encodes representative fixups, builds Windows/System V unwind plans,
runs all seven transforms across the two images, writes/reparses, and validates capability evidence.
Compile/link it only against installed headers and the exact declared archive closure.

- [ ] **Step 4: Update public documentation from evidence**

Render x86 architecture status as supported for object analysis/codegen. Document ABI conventions,
metadata ownership, supported relocation families, rewrite-plan transaction, unwind limitations,
compiler corpus, native probe, per-function refusal, and safety boundary. Do not promote ARM64, VM,
archive VM, linked PE/ELF transform, or overall-program completion.

- [ ] **Step 5: Run complete Debug, Release, and UBSan gates**

```powershell
cmake -S . -B build\m13-verify-debug -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBINOBF_BUILD_TESTS=ON
cmake --build build\m13-verify-debug
ctest --test-dir build\m13-verify-debug --output-on-failure
cmake -S . -B build\m13-verify-release -G Ninja -DCMAKE_BUILD_TYPE=Release -DBINOBF_BUILD_TESTS=ON
cmake --build build\m13-verify-release
ctest --test-dir build\m13-verify-release --output-on-failure
cmake -S . -B build\m13-ubsan -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBINOBF_BUILD_TESTS=ON -DBINOBF_ENABLE_UNDEFINED_SANITIZER=ON
cmake --build build\m13-ubsan
ctest --test-dir build\m13-ubsan --output-on-failure
```

- [ ] **Step 6: Run analyzer, headers, installed consumer, fuzz, and hygiene**

Run whole-production clang-tidy/Clang Static Analyzer over every production translation unit,
supported ASan tests, 2,000 deterministic runs for every fuzz surface, standalone compilation of
every public header, installed-only consumer CTest, `git diff --check`, tracked-artifact scan,
unfinished-marker scan outside plan/spec history, and README/CLI/capability consistency diff.

- [ ] **Step 7: Obtain independent code review and fix findings**

Use `superpowers:requesting-code-review` over the Track 3 commit range. Resolve every Critical and
Important finding with a focused regression and rerun the affected gate plus final full gates.

- [ ] **Step 8: Record and commit Track 3 completion**

Check Task 12 and Track 3 only after all fresh evidence passes. Commit:

```powershell
git add CMakeLists.txt README.md cmake docs include src tests
git commit -m "feat: promote the full x86 object backend"
```

- [ ] **Step 9: Push the verified milestone**

```powershell
gh auth status
git push origin main
git status -sb
gh repo view imattas/binobf --json isPrivate,url,defaultBranchRef
```

Do not create a tag or GitHub release unless the project version is advanced. If it is advanced,
push the commit and tag before `gh release create`, then verify the public release and asset hash.

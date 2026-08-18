# LLVM MC Provider and Expanded Native IR Design

## Status and scope

This is Track 2 of the approved full-feature-matrix program. It provides the private machine-code
emission/fixup provider and the architecture-neutral semantic model required by the x86, ARM64,
VM, archive, and linked-layout tracks. It does not promote a feature-matrix cell. Existing x86-64
object transforms and VM behavior must remain byte- and semantics-compatible.

The track is complete only when the pinned LLVM provider, expanded IR, compatibility migrations,
public packaging, and all Debug, Release, UBSan, fuzz, analyzer, standalone-header, and installed-
consumer gates pass together.

## Dependency decision

LLVM is built in process from the official `llvm-project-22.1.8.src.tar.xz` release asset:

- tag: `llvmorg-22.1.8`;
- archive SHA-256: `922f1817a0df7b1489272d18134ee0087a8b068828f87ac63b9861b1a9965888`;
- enabled targets: `X86;AArch64`;
- enabled projects/runtimes: none;
- assertions, tests, examples, benchmarks, documentation, bindings, and command-line tools: off;
- static libraries only, using the active C++ runtime.

CMake fetches the archive into the build tree and adds only `llvm/` as an excluded subdirectory.
LLVM headers, generated headers, compile definitions, and link libraries remain private to
`binobf_core`. Installed binobf headers expose no LLVM namespace, handle, enum, or container.

The provider is linked from the components needed for target lookup, MC parsing, object streaming,
object inspection, X86/AArch64 target descriptions, and support. It never invokes `llvm-mc`, Clang,
or another process at runtime.

## Provider contract

`include/binobf/architecture/codegen.hpp` exposes provider-neutral value types:

- `MachineSyntax`: Intel or GNU;
- `RelocationModel`: static, position independent, or dynamic-no-pic;
- `CodeModel`: small, kernel, medium, or large;
- `MachineAssemblyRequest`: fixed architecture, ABI triple, CPU/features, assembly, section name,
  base address, syntax, relocation model, code model, and resource limits;
- `MachineFixup`: section offset, bit width, signedness, PC-relative flag, addend, symbol, and a
  stable architecture-neutral fixup kind;
- `MachineEmission`: emitted bytes, alignment, fixups, declared register clobbers, unwind actions,
  and provider identity;
- `CodegenProvider`: fixed-architecture `emit()` interface;
- `make_codegen_provider(Architecture)`.

Assembly text is an internal interchange accepted by the provider so architecture backends can
use LLVM's complete parser and encoder without exposing LLVM opcodes. Public callers can use the
interface, but input remains bounded, contains one ordinary text section, cannot define custom
sections, and cannot use assembler directives outside an allowlist. The provider rejects include,
macro, conditional, binary-include, debug, section-switch, symbol-visibility, and target-option
directives. Later backends generate text from typed templates; user-controlled assembly is not
needed by the CLI.

The implementation creates an LLVM target/MC context, parses the bounded text into an in-memory
relocatable object, then extracts the requested section bytes and relocations through LLVM Object.
Every relocation maps to a stable `MachineFixupKind`; an unknown relocation is a structured error,
never silently dropped. The provider returns no file and performs no ambient I/O.

After emission, binobf re-decodes every byte range with the fixed architecture backend. The request
can supply expected instruction count, control-flow class, and clobbers. A mismatch returns
`codegen.verification_failed`. Provider diagnostics use stable `codegen.*` codes and include LLVM's
line/column text without leaking LLVM types.

## Expanded native type and value model

`IrWidth` remains as an integer-width compatibility helper, but canonical values use `IrType`:

- kind: void, integer, pointer, floating point, or vector;
- integer widths: 8, 16, 32, or 64 bits;
- floating widths: 32 or 64 bits;
- vector lanes: 2, 4, 8, or 16 with integer or floating scalar elements;
- pointer width: 32 or 64 bits with explicit address space;
- byte order: little or big for memory interpretation.

`IrValue` is a variable or a typed constant. Constants support integer bits, floating-point raw
bits, null pointers, symbol addresses plus addends, and zero vector values. No host floating-point
rounding is used to store constants.

Each function owns a `variableTypes` table. Existing width-based instructions migrate to canonical
types while retaining source-compatible construction helpers for integer-only call sites. A
variable has one immutable type for its lifetime.

## Storage and memory model

`IrStorageLocation` is a variant of:

- physical register name and register class;
- argument index;
- stack slot with size, alignment, and signed frame offset;
- function local slot;
- global symbol plus addend;
- thread-local symbol plus TLS model.

`IrAddress` contains a pointer-typed base, optional integer index, scale of 1/2/4/8, signed
displacement, address space, and explicit alignment. `IrLoad` and `IrStore` carry the accessed type,
byte order, volatility, atomic ordering, and source instruction. `IrAddressOf`, `IrPointerOffset`,
and `IrCast` model address creation, pointer arithmetic, bitcasts, integer extension/truncation,
integer-pointer conversion, and supported floating conversions.

Validation rejects zero/oversized alignments, invalid scales, type/width disagreement, illegal
address-space conversion, stores to readonly locations, unsupported atomic orderings, and address
arithmetic overflow. Resource limits bound storage locations, memory operations, aggregate bytes,
symbols, and external declarations.

## Operations, calls, and control flow

Arithmetic keeps explicit integer signedness and adds floating add/subtract/multiply/divide,
select, flag-producing operations, and named intrinsic calls. Unsupported flags remain explicit;
no backend infers flag liveness from textual mnemonics.

Control-flow instructions include direct jump, conditional jump, switch, indirect jump with a
non-empty proven target set, tail call, and return. Switch cases are unique and bounded. Indirect
targets must exist in the function. An empty or incomplete target proof becomes `IrFallback`.

Calls use a declared signature containing calling convention, parameter/return types, variadic
state, register/stack bindings, clobbers, and unwind behavior. Internal and external calls share the
signature model. External calls name a declared symbol; dynamic symbol lookup is not represented.
Tail calls require signature and ABI compatibility.

Each instruction can name an unwind-region ID and source lineage. A function owns bounded unwind
regions with parent nesting, protected blocks, landing block, cleanup/catch kind, and provider-
neutral unwind actions. This track validates and preserves plans; architecture-specific emission
is completed in later backend tracks.

## Fallback and transform boundary

`IrFallback` gains explicit read/write locations, clobbers, control-flow effects, and unwind-region
membership. It remains legal for analysis and byte-preserving movement. Validation marks a
function non-rewritable when a transformation would cross, resize, reorder, or synthesize around a
fallback whose effects are incomplete. VM lowering and machine-code emission reject unsupported
new nodes with a precise instruction and remediation diagnostic.

## Migration and compatibility

Current lifter, control-flow transforms, outlining, VM lowering, CLI, bytecode, and tests migrate to
canonical `IrType`/`IrValue` storage in this track. Convenience functions convert `IrWidth` to an
integer `IrType` and back with checked failure. Existing serialized bytecode is unchanged.

The architecture backend gains a `codegen()` accessor. Decode remains Capstone-owned; emission is
LLVM-owned. X86, x86-64, and ARM64 backends expose provider instances, but the capability registry
keeps current code-generation states (`planned`, `restricted`, `planned`) because full backend and
runtime corpora belong to Tracks 3 and 4.

## Error handling and determinism

All provider and IR operations return `Result<T, Diagnostic>`. Input length, line count, symbol
count, emitted bytes, fixups, instruction count, variable count, blocks, calls, memory operations,
and unwind regions have explicit defaults and caller-overridable lower ceilings.

LLVM initialization occurs once without mutable user-visible global state. Given the same request,
LLVM version, and target, emission bytes/fixups and diagnostic ordering are identical. Maps exposed
in results are sorted by offset, kind, and symbol.

## Verification

The track adds:

- dependency identity and no-public-LLVM-header checks;
- x86, x86-64, and ARM64 golden emission/re-decoding;
- external symbol and PC-relative fixup extraction for COFF and ELF triples;
- directive/resource/malformed-input rejection;
- exact deterministic repeated emission;
- type, storage, memory, cast, call, switch, indirect-target, fallback, and unwind validation;
- migration regression tests for every existing native IR, VM-lowering, control-flow, and outlining
  path;
- provider fuzzing using bounded assembly tokens without executing emitted native code;
- Debug, Release, UBSan, analyzer, standalone-header, install-consumer, and license gates.

Provider tests use LLVM's in-memory APIs and independently inspect the output through Capstone and
LLVM Object. Later architecture tracks add compiler-corpus native execution before capability
promotion.

## Safety boundary

The provider emits conventional documented instructions and relocatable objects. It does not add
anti-debugging, VM or sandbox detection, security-product detection, process injection, reflective
loading, persistence, payload downloading, malformed/overlapping instructions, exception abuse,
or signing bypass. Assembly directives that could read files or alter ambient build state are
rejected before LLVM parsing.

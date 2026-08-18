# Full x86 Object Backend Design

## Status and scope

This is Track 3 of the approved full-feature-matrix program. It promotes 32-bit x86 object
analysis and code generation from experimental/planned to supported for ordinary i686 user-mode
code using the Windows i386 and System V i386 ABIs with an SSE2 baseline. COFF and ELF
relocatable objects, all seven machine-code transforms, ABI adapter generation, relocation
encoding, and unwind ownership are in scope. VM protection, archives, linked PE/ELF rewriting,
and ARM64 promotion remain in later tracks.

The track is complete only when generated x86 code and transformed compiler objects pass binobf
reparse/verification, LLVM inspection and linking, deterministic differential execution on
32-bit Windows, negative transactional tests, and every project-wide release gate. Capability
records are promoted only in the same commit as their enabled acceptance evidence.

## Chosen architecture

The x86 implementation extends the existing composed architecture backend. Capstone remains the
bounded decoder, LLVM MC remains the private emitter, and binobf owns provider-neutral transform,
relocation, ABI, unwind, and object-metadata contracts. Transform passes ask a backend to describe
or emit a typed operation; they do not contain x86 opcodes, register IDs, relocation numbers, or
assembly text.

Two alternatives are rejected. Adding `Architecture::X86` branches and byte constants to each
pass would duplicate semantics and block the ARM64 track. Replacing binobf's object layer with
LLVM object types would leak the pinned dependency into installed contracts and surrender the
transactional model. The composed design keeps the dependency boundary established in Track 2
and makes the x86 work reusable by later backends.

Implementation is divided into focused units:

- stable backend transform, fixup, ABI, and unwind value contracts;
- x86 semantic classification and native lifting;
- normalized COFF/ELF object associations and relocation encodings;
- backend-owned x86 templates and range-checked fixup encoding;
- architecture-neutral transforms applied through an object rewrite plan;
- i386 ABI adapters and unwind plans;
- compiler corpora, native execution, and capability evidence.

## Backend service contracts

`ArchitectureBackend` gains callable services corresponding to the existing service records. The
public value types contain no LLVM or Capstone values.

`MachineTransformKind` identifies instruction substitution, constant materialization,
conditional inversion, direct jump, dead-code fill, and ABI call adapter emission.
`MachineTransformRequest` contains the architecture, binary format, source instruction when one
exists, normalized condition/constant/target values, exact output-size constraint, ABI, and
resource limits. `MachineTransformEmission` contains a `MachineEmission`, the semantic instruction
count, fallthrough/control-flow class, stack delta, and normalized flags/register effects.

`ObjectFixupRequest` describes a stable `MachineFixupKind`, architecture, format, field address,
target address or symbol, addend, and available field width. `ObjectFixupEncoding` contains the
raw relocation number, encoded addend bytes when the format uses implicit addends, field width,
signedness, PC bias, and range. Normalization and encoding are inverse for every declared x86
relocation. Out-of-range values return `architecture.fixup_out_of_range`; unknown raw relocation
numbers remain byte-preservable but block a rewrite that would move their site or target.

`AbiAdapterRequest` names source and destination calling conventions, exact signature, external
symbol, tail-call state, and stack-alignment requirement. `AbiAdapterPlan` contains machine code,
fixups, argument moves, caller/callee stack cleanup, clobbers, stack delta, and an unwind request.
`UnwindPlan` contains a disposition (`NotRequired`, `Preserve`, or `Emit`), typed CFA/register
actions, code range, personality/handler references, and encoded-format selection. A supported
backend service means the method is callable and acceptance-tested, not merely advertised.

## i386 ABI model

`NativeAbi` adds `WindowsI386Cdecl`, `WindowsI386Stdcall`, `WindowsI386Fastcall`,
`WindowsI386Thiscall`, and `SystemVI386`. Signatures use the canonical Track 2 `IrType` model and
explicit register/stack bindings. The supported baseline covers integer/pointer values through 64
bits, scalar `f32`/`f64`, SSE2 vector values used by ordinary compilers, hidden aggregate-return
pointers, variadic cdecl/System V calls, and declared external calls. Aggregate layout itself is
represented as an exact sequence of typed argument bindings; this track does not add a general
source-language type system.

Windows cdecl/thiscall/stdcall/fastcall stack cleanup and ECX/EDX bindings are explicit. System V
i386 stack arguments, return registers, direction-flag requirement, x87/SSE return rules, and
16-byte call-site stack alignment are validated. Unsupported convention combinations fail before
emission with `architecture.abi_unsupported`; adapters never guess a declaration or discover an
API dynamically.

The x86 lifter opens Capstone in 32-bit mode, creates 32-bit pointer/register storage, and maps
ordinary integer, flag, stack, global, TLS, call, branch, switch, and SSE2 operations into the
canonical native IR. Complete relocation-backed references become declared symbol values.
Instructions outside the modeled baseline remain explicit fallbacks with complete effects. A
fallback permits analysis and byte-preserving movement but blocks a transform crossing or
rewriting it.

## Object metadata and relocation ownership

The current raw format fields remain available for exact round trips, but normalized records are
added for properties that transforms must understand:

- symbol definition: undefined, section-relative, absolute, or common with alignment;
- section association: ordinary, COFF COMDAT with selection/key, or ELF group with signature;
- section relocation encoding: ordinary or COFF overflow-count form;
- symbol section index: direct or ELF `SHN_XINDEX` through `SHT_SYMTAB_SHNDX`;
- unwind record: code range, owning function/section, format, relocations, and rewrite state;
- TLS model and stable relocation semantics.

COFF parsing/writing supports classic objects and bigobj, long section/symbol names, section
symbols and auxiliary records, all defined i386 relocation numbers, COMDAT/associative COMDAT,
common symbols, `.sxdata` SafeSEH indices, and `IMAGE_SCN_LNK_NRELOC_OVFL`. Unknown auxiliary
records are preserved exactly. Rebuilding a table preserves symbol identities even when raw
indices change and repairs every index-bearing record.

ELF32 parsing/writing supports REL and RELA, i386 absolute/PC/GOT/PLT/GOTOFF/GOTPC and compiler
TLS relocation families, common and TLS symbols, `SHT_GROUP`, COMDAT signatures, extended section
counts, extended section-name indices, and `SHN_XINDEX`. REL implicit addends are decoded from and
re-encoded into the relocation field with backend-supplied width, signedness, and PC bias. A
relocation whose semantics are not normalized may round-trip unchanged but prevents movement of
its site, addend base, target, or containing association.

`.eh_frame` CIE/FDE records are bounded and correlated with their relocations and functions. The
implementation preserves unknown augmentation payloads while adjusting proven FDE locations and
ranges through the rewrite map. Windows x86 objects normalize SafeSEH and compiler exception
sections conservatively; a function-reordering candidate is refused unless every associated
record is owned. Ordinary leaf adapters on Windows use `NotRequired` because i386 has no x64-style
mandatory function table. System V adapters receive typed DWARF CFI encoded into a proven
`.eh_frame` record.

## Analysis and rewrite planning

Object analysis is promoted only after x86 function discovery, relocation-backed reference
resolution, instruction semantics, CFG recovery, liveness, and fallback boundaries work on the
compiler corpus. Function sizes are obtained from exact symbols/auxiliary records where available;
inference never crosses a section association, relocation-owned entry point, or another symbol.
Indirect control flow remains unresolved unless a bounded target set is proven.

Machine-code passes build an immutable `ObjectRewritePlan` before changing a `BinaryImage`. The
plan contains section-local old-to-new ranges, replacement bytes, symbol/address updates,
relocation-site/addend updates, unwind updates, association ownership, and lineage. Validation
requires non-overlapping ranges, total mapping for every moved reference, architecture-encoded
branch ranges, stable section membership, and bounded output growth. Commit applies the plan to a
copy; reparse, reanalysis, structural verification, and standard-tool checks occur before an
artifact is accepted.

The seven existing machine transforms become architecture-neutral:

- instruction substitution requests a same-size semantic equivalent with identical effects;
- constant rewriting requests an equal-size materialization, using harmless backend padding;
- branch inversion requests the opposite normalized condition and repaired direct targets;
- block splitting emits a direct jump to an existing boundary;
- dead-code insertion emits unreachable, side-effect-free backend padding;
- block reordering maps all direct branches, symbols, relocations, and unwind ranges;
- function reordering maps whole owned chunks plus section-symbol addends and associated metadata.

An exact-size request that cannot be satisfied is a per-candidate skip, not an unsafe widening.
Opaque instructions are retained byte-for-byte outside changed ranges. X86-64 behavior must remain
unchanged while it migrates to the same template and rewrite-plan contracts.

## Code generation and verification

The x86 backend produces ordinary i686/SSE2 assembly internally and sends it to the pinned LLVM MC
provider using `i686-pc-windows-msvc` for COFF or `i386-unknown-linux-gnu` for ELF. Backend-generated
text uses only the existing directive allowlist. Returned bytes are independently re-decoded by
Capstone in 32-bit mode. Semantic class, instruction count, exact size, stack delta, control flow,
clobbers, and fixups must match the typed request.

Every fixup is normalized from the LLVM object then re-encoded through the backend and compared
with the writer's output. Relocation tests cover zero, minimum, maximum, overflow, nonzero addend,
section-symbol, GOT/PLT, TLS, and implicit-addend cases. Output is deterministic for a fixed seed
and toolchain.

## Compiler corpus and runtime evidence

Self-contained C, C++, and assembly fixtures are compiled for `i686-pc-windows-msvc` COFF and
`i386-unknown-linux-gnu` ELF at `-O0`, `-O1`, `-O2`, `-O3`, `-Os`, and `-Oz`. The corpus covers
register and stack arguments, all declared i386 conventions, loops, switches, recursion, tail
calls, globals, common symbols, TLS, PIC/GOT/PLT, function pointers with proven targets, integer,
floating-point and SSE2 vector operations, COMDAT/groups, debug data, and exception/unwind
sections. Fixtures avoid host headers and runtimes so both triples are reproducible.

Each original and transformed object is inspected by `llvm-readobj`, `llvm-objdump`, and
`llvm-nm`. COFF objects link through `lld-link`; ELF objects link relocatably through `ld.lld -m
elf_i386 -r`. Parse-write-parse equality and repeated-output hashes cover unchanged and changed
objects.

The native differential harness links freestanding 32-bit Windows executables with `lld-link`,
runs them under Windows' native x86 compatibility environment, and compares exit status and a
bounded shared result buffer for original versus each transformed corpus case. It first proves
that the host can execute a known x86 probe. Failure of that probe is a hard unmet release gate,
not a skipped test or emulation claim.

Negative evidence includes malformed bigobj/extended-numbering inputs, relocation overflow,
unowned COMDAT/group references, incomplete unwind ownership, out-of-range branches/addends,
ambiguous functions, fallback-crossing transforms, ABI mismatch, and resource ceilings. Every
failure leaves the input image and any existing output unchanged.

## Capability promotion and packaging

The acceptance catalog adds enabled `x86_object_backend` and `x86_codegen` groups. The x86
architecture records for object analysis and code generation become `Supported` only after those
CTest groups exist and pass. X86 backend service records for analyze, emit, encode fixups, build an
ABI adapter, and build unwind become supported with the same evidence. CLI architecture and pass
output is rendered from those records; no hand-written status string is changed independently.

Installed consumers parse and transform both x86 COFF and ELF fixtures, emit one template and one
ABI adapter, encode representative fixups, build both unwind dispositions, write/reparse the
objects, and verify service/evidence consistency using only installed headers and archives.

## Release gates

Track completion requires:

- focused unit goldens for every x86 semantic/template/fixup/ABI/unwind contract and refusal;
- COFF/ELF parser-writer boundary fixtures for bigobj, overflow, groups, extended indices, TLS,
  common symbols, and unwind ownership;
- all seven transform integrations over both formats and all optimization levels;
- 32-bit native original-versus-transformed differential execution;
- LLVM standard-tool inspection/linking and exact deterministic hashes;
- object, decoder, codegen, and rewrite-plan fuzzing with x86 seeds;
- mutation gates for range, ownership, and transactional checks;
- full Debug, Release, UBSan, supported ASan, whole-production analyzer, standalone-header,
  installed-consumer, license, artifact-hygiene, and unfinished-marker gates;
- capability documentation and registry promotion in the final evidence commit.

## Safety boundary

All output is conventional compiler/linker-compatible relocatable code. The backend does not add
debugger, VM, sandbox, or security-product detection; injection; reflective loading; persistence;
payload downloading; dynamic API discovery; malformed/overlapping instructions; exception abuse;
or signing bypass. Exact ownership and range checks fail closed, and per-function refusal is
reported with format, section, symbol, relocation, instruction, ABI, pass, and remediation context.

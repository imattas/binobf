# Full Feature-Matrix Program Design

**Status:** Approved in chat on 2026-08-17.

## Objective

Every applicable cell in the public format and architecture feature matrices must become
`supported`. A cell may be promoted only when its public API, CLI path, format reconstruction,
native or emulated behavior, and negative safety cases are independently verified. Status text is
an output of evidence, never the implementation.

Relationships that have no coherent meaning remain `n/a`. A PE linked image is not a relocatable
object, a COFF object is not a linked image, and the standalone VM is not owned by a container
format. These are type-system relationships, not missing features.

## Target matrices

The final format matrix is:

| Capability | PE | COFF object | ELF | Archive |
|---|---:|---:|---:|---:|
| Header/container detection | supported | supported | supported | supported |
| Relocatable-object parsing | n/a | supported | supported | supported members |
| Linked-image detailed parsing | supported | n/a | supported | n/a |
| Structural verification | supported | supported | supported | supported |
| Exact linked/object emission | supported | supported | supported | supported |
| Baseline metadata transformations | supported | supported | supported | supported per member |
| x86-64 instruction/CFG/layout transformations | supported | supported | supported | supported per member |
| Selected-function VM lowering | n/a | supported | supported | supported per member |
| Embedded selected-function VM protection | n/a | supported | supported | supported per member |
| Standalone architecture-neutral VM core | n/a | n/a | n/a | n/a |

The final architecture matrix is:

| Architecture | Detection | Decoder | Object analysis | Code generation |
|---|---:|---:|---:|---:|
| x86 | supported | supported | supported | supported |
| x86-64 | supported | supported | supported | supported |
| ARM64 | supported | supported | supported | supported |

PE covers `.exe`, `.dll`, and `.sys`. ELF covers relocatable objects, executables, PIEs, and shared
objects. Archives cover GNU/BSD `.a`, Microsoft `.lib`, long-name members, linker indexes, and
recognized ELF/COFF members. Import-library records remain data rather than executable functions,
but their containers and indexes remain fully supported and byte-preserved when unchanged.

## Meaning of fully supported

`supported` requires all of the following:

1. A documented public-library API and CLI route exist for the capability.
2. Mainstream compiler-generated input for the declared architecture baseline is parsed and
   analyzed without an architecture-wide experimental qualifier.
3. Applicable transformations produce a real semantic or layout change. A no-op implementation or
   unconditional skip cannot satisfy the cell.
4. Changed output reparses through binobf, passes structural verification, and is accepted by the
   platform's standard object, linker, loader, and inspection tools.
5. Executable output has differential native or emulated behavior evidence across ordinary,
   boundary, error, and relocation-sensitive cases.
6. Unsupported per-function constructs produce a narrow, contextual diagnostic and leave the
   artifact transactional. A safe per-function refusal does not demote an otherwise supported
   architecture, but broad compiler-corpus refusal does.
7. Determinism, lineage, configuration, manifests, statistics, fuzzing, mutation testing,
   sanitizers, packaging, and standalone-header gates cover the new path.
8. Capability output and documentation are promoted only in the same change that adds the evidence.

The supported architecture baselines are 32-bit x86 user-mode code using the platform i686 ABI and
SSE2 baseline, x86-64 user-mode code using Windows x64 and System V AMD64 ABIs, and ARM64 user-mode
code using Windows ARM64 and AAPCS64 ABIs. Privileged instructions, deliberately malformed input,
and optional ISA extensions unavailable on the selected target may still fail closed with a precise
diagnostic. The code generator must nonetheless preserve opaque instructions outside a changed
region and repair every moved reference.

## Safety boundary

The existing safety boundary remains mandatory. This program does not add debugger, VM, sandbox,
or security-product detection; process injection; remote-process manipulation; reflective loading;
payload downloading; persistence; direct-syscall concealment; malformed instruction streams;
overlapping instructions; exception abuse; parser differentials; or code-signing bypasses.

VM execution remains a conventional documented interpreter. Native calls use explicit link-time
thunks and declared signatures, never dynamic API discovery or hidden imports. PE signatures are
preserved when bytes do not change and explicitly invalidated before an authorized rewrite; no
output claims a stale signature is valid. `.sys` code transformation is opt-in, requires complete
function, relocation, unwind, and load-configuration evidence, and uses ordinary kernel ABI code.

## Architecture

### Capability registry

Replace hard-coded capability prose in the CLI with a typed registry keyed by operation, format,
binary type, architecture, and policy. Each entry names its required analyses, metadata ownership,
verification gates, and supported state. README tables, `formats`, `architectures`, `passes`, and
matrix tests render from this registry so status cannot drift among code and documentation.

The registry never upgrades itself because a parser returned success. Each supported entry has a
named acceptance-test group, and release verification fails if that group is absent or disabled.

### Architecture backends

Introduce an `ArchitectureBackend` interface with five focused services:

- instruction decoding and semantic classification;
- native-to-IR lifting with explicit ABI state;
- IR and transformation-template machine-code emission;
- relocation/fixup encoding and range calculation;
- ABI adapter plus unwind-plan generation.

Backends exist for x86, x86-64, and ARM64. The current Capstone adapter remains the bounded decoder.
Emission uses LLVM MC from official release `llvmorg-22.1.8`, pinned by archive hash and built only
for X86 and AArch64 targets. LLVM types stay behind a private provider boundary and never leak into
installed headers. A provider result contains bytes, typed fixups, alignment, clobbers, and unwind
operations; the core rejects an emission whose declared effects disagree with re-decoding.

### Native IR

Extend the native IR rather than adding architecture conditions to transformations. It must model:

- 8/16/32/64-bit integers, pointers, scalar floating point, and baseline vector values;
- explicit register, argument, stack, local, global, and thread-local storage locations;
- loads, stores, address calculation, casts, extensions, truncation, and byte order;
- arithmetic, bitwise, comparisons, flag-producing operations, and selected intrinsic semantics;
- direct, conditional, switch, indirect-with-proven-target-set, tail, and return control flow;
- internal calls, declared external calls, call clobbers, and ABI return values;
- exception/unwind region membership and source-to-protected lineage.

Unknown semantics remain explicit fallback nodes. A fallback can coexist with analysis and
byte-preserving movement, but any transform that would cross or rewrite it must decline that region.

### Object code generation

COFF and ELF writers consume backend fixups rather than embedding x86-64 relocation constants in
passes. They support x86, x86-64, and ARM64 relocation families, section symbols, addends, COMDAT and
group membership, common symbols, TLS, unwind sections, bigobj, COFF relocation overflow, ELF
extended section numbering, and `SHN_XINDEX`. Size-changing passes rebuild symbol values, relocation
sites and addends, section metadata, and source lineage before the existing write/reparse/verify
transaction commits.

All current instruction, CFG, and layout transformations become architecture-neutral algorithms
with backend-owned templates. Each backend provides real equivalents for substitution, constant
rewriting, branch rewriting, harmless dead-code insertion, block splitting, block reordering, and
function reordering.

### Linked-image reconstruction

Add a normalized linked-layout editor above the PE and ELF adapters. A layout plan owns old-to-new
address maps, moved ranges, inserted executable/data ranges, symbol and export identities, relocation
fixups, unwind records, debug mappings, and lineage. The plan is immutable once verified; writers
commit it transactionally.

The PE writer rebuilds section layout, base relocations, imports/exports, exception data, resources,
TLS, debug directories, load configuration including CFG/CET-relevant tables, checksum, and explicit
signature state. The ELF writer rebuilds program/section headers, dynamic tables, symbols,
REL/RELA, GOT/PLT relationships, init/fini arrays, notes, TLS, and `.eh_frame`/`.eh_frame_hdr`.
Address-space growth is page/alignment checked and never overlays an unknown range.

Post-link transformations require complete ownership of every moved reference. When original call
sites cannot be safely resized, the editor uses ordinary in-range entry trampolines and places the
new body in a validated executable range. It never relies on overlapping decoding or malformed
control flow.

### VM lowering and embedding

Lift the full native IR value and memory model into VM IR. Selected functions support ABI register
and stack arguments, scalar and aggregate returns, frame locals, bounded pointer capabilities,
global/TLS references, declared native calls, and internal calls. Bytecode retains exact type,
relocation, ABI, resource-limit, and lineage metadata.

Native-call bridges are generated as ordinary link-time thunks with an allowlisted symbol and exact
signature. Embedded runtimes validate bytecode and thunk tables before execution. COFF and ELF
adapters emit x86, x86-64, and ARM64 wrappers through the backend; repeated protection reuses runtime
symbols and metadata.

Archive selection uses an unambiguous `member::function` identity. VM lowering or protection edits
the selected member through the same public object API, rebuilds long names and linker indexes, and
commits the entire archive only if every changed member and the reconstructed container verify.

### Configuration and CLI

Configuration gains typed architecture, binary-type, ABI, signature, member-selection, linked
rewrite, signature-invalidation, and `.sys` opt-in policies. CLI overrides remain deterministic and
schema-validated. The strong profile becomes real and selects CFG plus VM transformations only where
the configuration supplies an exact function signature.

CLI output reports applied, skipped-per-function, and failed operations separately. A supported
capability is not presented as successful merely because all candidate functions were skipped.

## Data flow and transaction

```text
input bytes
  -> bounded format parse
  -> normalized image and metadata ownership graph
  -> architecture backend analysis and native IR
  -> selected transform or VM lowering
  -> backend emission plus typed fixups and unwind plan
  -> object or linked layout plan
  -> deterministic reconstruction
  -> reparse, reanalysis, structural verification, standard-tool validation
  -> atomic artifact, manifest, and lineage commit
```

Every stage returns structured diagnostics. No stage mutates the user's input or an existing output.
An error retains format, architecture, member, section, function, address, pass, and remediation
context. Resource ceilings cover decoded instructions, IR nodes, fixups, relocation growth, layout
iterations, VM steps, archive members, and total output expansion.

## Program decomposition

The work is implemented as separately designed and gated tracks in dependency order:

1. **Capability contract and backend interfaces.** Typed registry, acceptance-test binding,
   architecture provider contracts, and migration of existing x86-64 behavior without regressions.
2. **LLVM MC provider and expanded native IR.** Private pinned dependency, types, validation,
   emission/fixup round trips, and independent re-decoding.
3. **Full x86 object backend.** Analysis, code generation, ABI/unwind, all object transforms, COFF and
   ELF compiler corpora, native 32-bit execution, and matrix promotion.
4. **Full ARM64 object backend.** Analysis, code generation, ABI/unwind, all object transforms,
   COFF and ELF compiler corpora, native or emulated execution, and matrix promotion.
5. **Full VM semantics and multi-architecture embedding.** Broadened IR/bytecode/runtime, native-call
   thunks, x86/x86-64/ARM64 adapters, compiler corpora, and differential execution.
6. **Archive VM operations.** Member-qualified selection, lowering/protection, index rebuilding,
   runtime linking, and `.a`/`.lib` promotion.
7. **Linked-layout engine.** Address mapping, fixup ownership, inserted ranges, unwind/debug lineage,
   and format-neutral plan validation.
8. **PE transformations.** Full baseline and x86-64 code/CFG/layout transformations for `.exe`,
   `.dll`, and opt-in `.sys`, with Windows loader and runtime evidence.
9. **ELF linked transformations.** Full baseline and x86-64 code/CFG/layout transformations for
   executables, PIEs, and shared objects, with dynamic-loader and runtime evidence.
10. **Matrix completion and release.** Cross-product corpus, fuzz/mutation/sanitizer/analyzer gates,
    installed consumers, package verification, capability-table promotion, and public release.

Each track receives its own focused design and implementation plan. Completing an early track does
not redefine the program as complete.

## Verification strategy

The corpus compiles C and C++ fixtures at `-O0`, `-O1`, `-O2`, `-O3`, `-Os`, and `-Oz` for every
supported ABI and both relocatable and linked forms. It covers register and stack arguments,
recursion, loops, switches, tail calls, globals, TLS, function pointers with proven target sets,
integer/FP/vector arithmetic, exceptions/unwind, PIC, imports/exports, COMDAT/groups, and debug data.

Required evidence includes:

- unit golden tests for every IR operation, encoding template, fixup kind, range boundary, and
  refusal rule;
- parse-write-parse and emit-decode semantic round trips for all architectures and formats;
- standard LLVM, Microsoft, and GNU inspection/linker acceptance where applicable;
- native x86/x86-64 execution and native or QEMU-backed ARM64 execution;
- executable, DLL/shared-library, archive-consumer, and selected `.sys` structural/load tests;
- original-versus-transformed differential observables, including returns, output, files, globals,
  callbacks, and expected faults;
- generated properties, parser and emitter fuzzing, required mutation-kill matrices, UBSan and
  supported ASan runs, whole-production static analysis, standalone public headers, and installed
  consumer builds;
- deterministic repeated builds with identical artifacts, manifests, and lineage for the same seed.

The final audit enumerates every matrix cell and links it to its implementation, positive evidence,
negative evidence, standard-tool evidence, runtime evidence, documentation, and capability-registry
test. Any missing link keeps that cell and the overall goal incomplete.

## Documentation and release policy

Architecture, IR, formats, passes, virtualization, configuration, verification, hardening, plugin,
and developer documentation change with their owning track. README and CLI matrices remain generated
from the capability registry. Releases include source, platform binaries, public headers, static
libraries, project and dependency licenses, hashes, and exact supported-target declarations.

The next release version is chosen only after the final matrix audit; intermediate tracks remain
unreleased development commits unless the user requests preview releases.

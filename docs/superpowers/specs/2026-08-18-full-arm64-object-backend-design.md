# Full ARM64 Object Backend Design

## Scope and acceptance

Track 4 promotes ARM64 relocatable-object analysis and code generation from experimental/planned
to supported for COFF and ELF. It completes the same five backend services and seven object
transformations already proved for i386, but uses A64 fixed-width instruction semantics, Windows
ARM64 and AAPCS64 calling conventions, ARM64 relocation families, and native-format unwind data.

The supported baseline is little-endian AArch64 user-mode code using Armv8-A integer, scalar
floating-point, and Advanced SIMD instructions. SVE, SME, Morello, privileged instructions,
platform authentication requirements, and Arm64EC remain outside this track. Inputs using an
unsupported optional extension may still be analyzed byte-preservingly, but a transformation that
would rewrite or move such an instruction or its metadata fails with a precise diagnostic.

Promotion requires all of the following in one change:

- both COFF and ELF compiler corpora at `-O0`, `-O1`, `-O2`, `-O3`, `-Os`, and `-Oz`;
- all seven object transformations applied wherever their declared preconditions hold;
- every transformed object accepted by the corresponding standard linker and LLVM inspection
  tools;
- deterministic bare-metal ARM64 execution under QEMU for runtime-safe original/transformed pairs;
- Windows ARM64 and AAPCS64 ABI adapter evidence;
- Windows ARM64 packed unwind and ELF64 DWARF CFI evidence;
- mutation, fuzz, UBSan, static-analysis, installed-consumer, and standalone-header gates;
- enabled acceptance evidence bound to every promoted capability and backend service.

This track does not promote VM semantics, archive VM operations, linked-image code transformation,
PE/ELF layout rewriting, Arm64EC, or overall-program completion.

## Chosen architecture

The implementation extends the existing architecture-neutral object rewrite transaction. It does
not create an ARM64-only pass manager or bypass normalized objects. Capstone remains the bounded
decoder, the pinned in-process LLVM MC 22.1.8 provider emits ordinary A64 instructions and typed
fixups, and the existing writers commit verified object models.

Three alternatives were rejected:

1. Structural-only ARM64 tests cannot justify supported code-generation status because they do not
   prove executable behavior.
2. A second ARM64 transformation pipeline would duplicate mapping, relocation, transaction, and
   validation rules and would drift from the i386 implementation.
3. Booting a guest operating system for every differential case would add unrelated images and
   nondeterminism. The installed `qemu-system-aarch64` can execute freestanding ELF images directly
   and report results through the documented A64 semihosting trap.

## Backend templates and decoded effects

`ArchitectureBackend::emit_transform` dispatches ARM64 requests to a focused
`arm64_templates.cpp` implementation. Each instruction is four bytes. Templates therefore reject
unaligned addresses and exact-size requests that are not multiples of four.

The backend provides ordinary encodings for:

- register-copy equivalence through `mov`/`orr` aliases without changing flags;
- bounded constant materialization through `movz`/`movn`/`movk` sequences;
- conditional inversion for the complete A64 condition-code pairs;
- direct `b` and `bl` control flow with typed relocations;
- harmless `nop` dead-code fill;
- block-split jumps and relocation-aware layout repair;
- canonical ABI adapter prologues, calls, epilogues, and returns.

Every emitted stream is decoded again through the fixed ARM64 backend. Byte coverage, instruction
count, control-flow kind, flags, stack effects, written registers, alignment, and fixup positions
must agree with the template declaration. Templates never emit privileged, malformed, overlapping,
environment-querying, or self-modifying instruction sequences.

## Relocation and object metadata ownership

The public provider-neutral fixup model gains the A64 field shapes needed by COFF and ELF while raw
format numbers remain private. It distinguishes branch26/call26, conditional branch19, test
branch14, ADR21, ADRP page21, add/load/store low12 fields, move-wide groups, absolute and PC-relative
data, GOT, PLT, TLS, section-relative, and section-index fixups.

COFF normalization covers the defined ARM64 family from `IMAGE_REL_ARM64_ABSOLUTE` through
`IMAGE_REL_ARM64_REL32`, including `ADDR32`, `ADDR32NB`, `BRANCH26`, `PAGEBASE_REL21`, `REL21`,
`PAGEOFFSET_12A`, `PAGEOFFSET_12L`, `SECREL`, the section-relative low/high fields, `TOKEN`,
`SECTION`, `ADDR64`, `BRANCH19`, and `BRANCH14`.

ELF normalization covers compiler-emitted static AArch64 relocations for absolute and PC-relative
data, move-wide groups, literal loads, ADR/ADRP, low12 add/load/store fields, test/conditional/direct
branches, GOT addressing, TLS general-dynamic/initial-exec/local-exec sequences, and TLSDESC
sequences. A linker may synthesize a veneer for an external or cross-section branch; the object
transaction itself never invents a hidden veneer.

Unknown relocation records continue to round-trip byte-for-byte. The rewrite transaction permits
them only when the entire mapped section, offset, size, and bytes are unchanged. A moved or modified
unknown field is rejected. Paired/group relocation members move as one owned association and are
validated after remapping.

COFF COMDAT/associative sections, ELF groups, common symbols, TLS sections, debug sections, section
symbols, addends, and function symbol sizes retain their existing normalized identities. All
address arithmetic is checked before narrowing or signed conversion.

## ABI adapters

`ir::NativeAbi` gains `WindowsARM64` and `AAPCS64`, and `IrCallingConvention` distinguishes their
public signatures. Both require 16-byte stack alignment and use `x0` through `x7` for integer and
pointer arguments, `v0` through `v7` for supported scalar FP/vector arguments, `x8` for an indirect
result, `x0`/`x1` or `v0` for supported direct results, and stack slots with ABI-correct size and
alignment after register exhaustion.

The supported adapter type surface is the set represented by current `IrType`: 8/16/32/64-bit
integers, 64-bit pointers, `f32`, `f64`, and 64/128-bit vectors. Aggregate layouts not expressible
by `IrType`, SVE/SME state, and variadic cross-ABI adaptation fail closed. Same-ABI variadic calls
may be preserved when their explicit bindings are already valid.

Adapters validate every caller and destination binding, reject overlaps, preserve all live
nonvolatile integer/vector registers they use, reserve an aligned outgoing area, handle cycles with
owned scratch registers, make a direct typed call, restore the frame, and return with `ret`. Source
register values are saved before any move can overwrite them. The generated plan exposes exact
argument moves, stack size, clobbers, return binding, fixup, and unwind actions.

## Unwind ownership

The normalized model gains `WindowsARM64` and `DwarfCfi64` unwind formats. A leaf function with no
stack or nonvolatile-register effects requires no record.

For COFF, the backend emits the documented 8-byte `.pdata` record with a function-start
`ADDR32NB` relocation and packed unwind data for canonical adapter frames. The packed word encodes
function length, integer/vector saves, frame-chain use, and frame size. If a requested prologue is
not exactly representable by the packed format, emission fails instead of manufacturing incomplete
`.xdata`. Compiler-generated packed or unpacked `.pdata`/`.xdata` records are normalized to their
owning function when relocations and bounds prove ownership; otherwise they remain opaque and block
layout movement.

For ELF64, the backend emits a version-1 `zR` CIE and FDE in `.eh_frame`, using code alignment 1,
data alignment -8, return-address register 30, an explicit pointer encoding, ordered PC advances,
and a function-symbol relocation. The parser handles 32-bit DWARF record lengths in ELF64 objects,
associates FDEs with exact function ranges through function or section-symbol relocations, and keeps
unrecognized augmentation/actions opaque. Unknown frame records block every machine pass;
recognized opaque records permit exact byte-local passes but block function/block layout movement.

## Transformation flow

All seven machine passes use the same sequence:

1. parse and normalize the object;
2. conservatively analyze ARM64 functions on four-byte boundaries;
3. require complete CFG and metadata ownership for the selected operation;
4. ask the fixed ARM64 backend for templates and fixup semantics;
5. build an immutable `ObjectRewritePlan` from a complete source snapshot;
6. remap bytes, symbols, relocations, groups, unwind records, and lineage;
7. write, reparse, reanalyze changed functions, and verify the new object;
8. commit only after every check passes.

Instruction substitution, constant rewriting, branch inversion, and dead-code insertion may operate
inside recognized opaque unwind ranges only when address, size, and instruction boundaries do not
change. Block splitting, block reordering, and function reordering require modeled unwind and total
reference ownership. An unsupported function is skipped or refused without weakening another
function's result.

## Compiler and execution evidence

The corpus compiles checked-in C/C++ fixtures for `aarch64-pc-windows-msvc` COFF and
`aarch64-unknown-linux-gnu` ELF at all six optimization levels, with function sections, data
sections, debug information, unwind tables, PIC, calls, globals, switches, loops, FP/vector code,
COMDAT/groups, TLS, and section-symbol relocations. Each input and transformed output is inspected
with `llvm-readobj`/`llvm-objdump` and accepted individually by `lld-link` or `ld.lld`.

Runtime-safe ELF fixtures link with a freestanding entry and linker script for QEMU's `virt`
machine. The entry provides an aligned stack, calls the test function, emits a fixed result record,
and exits through A64 semihosting `HLT #0xF000` with `SYS_EXIT_EXTENDED`. Tests launch
`qemu-system-aarch64 -M virt -cpu cortex-a57 -nographic -semihosting-config
enable=on,target=native -kernel <image>` under a timeout and compare original/transformed output and
exit status. No guest image, network access, or persistent VM state is required.

ABI evidence executes both same-ABI and cross-ABI adapters as ordinary A64 code in the same
freestanding harness, including register exhaustion, stack arguments, FP/vector registers, indirect
results, register cycles, and two valid incoming stack positions. Windows object/unwind evidence is
additionally linked and inspected with the Windows ARM64 toolchain even though the host cannot run a
Windows ARM64 process natively.

## Robustness, packaging, and promotion

The code-generation and object-rewrite fuzz surfaces include ARM64 seeds for both formats and typed
field mutations. Mutation tests kill missing range, scale, PC-bias, pair ownership, alignment,
unwind ownership, mapping, and source-snapshot checks. Debug, Release, UBSan, supported ASan,
standalone headers, installed consumer, whole-production Clang analysis, and all existing x86/x86-64
gates must remain green.

Acceptance evidence is split into `arm64_object_backend`, `arm64_codegen`, `arm64_abi_adapter`, and
`arm64_unwind`. Only after those registered CTest groups are enabled may the capability registry and
backend services advertise ARM64 object analysis and code generation as supported. README and CLI
output are updated from the same records. The project version remains unchanged during this track;
a public tag and release are created only when the final matrix release advances it.

## Safety boundary

The global program boundary remains unchanged: no debugger/VM/sandbox/security-product detection,
injection, reflective loading, persistence, payload download, dynamic API discovery, malformed or
overlapping instruction streams, exception abuse, signing bypass, or hidden execution. QEMU is only
an acceptance-test execution oracle for checked-in freestanding fixtures. `.sys` linked-image code
transformation remains disabled until its later opt-in PE track.

## Authoritative contracts

- Arm AAPCS64 and ELF64 ABI: <https://github.com/ARM-software/abi-aa>
- Arm A64 semihosting: <https://github.com/ARM-software/abi-aa/blob/main/semihosting/semihosting.rst>
- Microsoft ARM64 ABI and unwind format: <https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling>
- Microsoft PE/COFF ARM64 relocations: <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>
- DWARF call-frame information: <https://dwarfstd.org/doc/DWARF5.pdf>
- QEMU semihosting configuration: <https://qemu.readthedocs.io/en/latest/system/invocation.html>

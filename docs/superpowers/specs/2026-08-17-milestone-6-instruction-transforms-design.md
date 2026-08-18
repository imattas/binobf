# binobf Milestone 6 Instruction Transformations Design

## Goal

Deliver five real, deterministic, semantics-preserving x86-64 relocatable-object transformations: safe instruction substitution, branch inversion, constant rewriting, basic-block splitting, and function layout variation. Every mutation must be instruction-boundary aware, relocation aware, transactional, structurally verified, reanalyzed, and covered by differential execution.

## Eligibility boundary

The first production backend supports COFF and ELF x86-64 relocatable objects. A machine-code pass operates only on symbol-bounded functions for which analysis is complete. It declines opaque instructions, unresolved control flow, overlapping relocations, linked images, ARM64, x86-32, debug-sensitive layout, and any pattern whose exact semantics or repair requirements are not proven.

Instruction and CFG rewrites are exact-size. They never move unrelated bytes or invalidate unwind/debug addresses. Function reordering moves whole function chunks and repairs every affected symbol address, source relocation offset, and supported section-symbol addend. It declines a section when an address-sensitive reference cannot be mapped exactly.

## Passes

### `instruction-substitution`

Vary documented x86 multi-byte NOP encodings. A candidate begins as a decoded `nop`, has no relocation, and is accepted only if the replacement decodes as one same-size `nop` with no register reads or writes. Seeded selection changes only encoding details that the processor documents as semantically inert.

### `branch-inversion`

Recognize an adjacent direct `Jcc target_true; JMP target_false` pair. Invert the condition and exchange the two targets, recomputing signed displacements and rejecting out-of-range or relocated operands. This preserves the two-way transfer exactly without changing code size or flags.

### `constant-rewriting`

Rewrite eligible register-immediate `MOV` encodings to the equivalent `C7 /0` form. The destination register and value are unchanged and flags remain untouched. A 64-bit immediate is eligible only when the original value is exactly the sign extension of 32 bits; reclaimed bytes become validated NOP padding. A 32-bit form may consume one untargeted, unrelocated following NOP while preserving the original byte window.

### `block-splitting`

Replace an eligible in-block NOP window of at least two bytes with `JMP +0` and exact-size NOP fill. The jump targets the next decoded instruction boundary, introduces a real CFG boundary, and has no register, flag, stack, memory, or environment-dependent effect.

### `function-reordering`

Deterministically permute whole function chunks within an executable section. Internal relative control flow remains unchanged because each function moves as a unit. Symbol values and relocation sites move with their chunks. Relocations through the moved section symbol are repaired only when their target addend maps unambiguously; otherwise the section is skipped. Function sizes and section size do not change.

## Verification and failure model

Each pass runs in the existing pass-manager transaction. Before commit, the candidate is serialized, reparsed, and structurally verified. Machine-code passes also reanalyze affected functions and require complete decoding, valid branch destinations, expected CFG changes, and no new unresolved edges. Pass statistics distinguish examined, changed, and skipped candidates, with structured skip diagnostics.

Unit tests cover encodings, displacement limits, relocation conflicts, symbol/addend repair, deterministic seeds, lineage, unsupported architectures, and rollback. Integration tests compile COFF and ELF fixtures, run each applicable pass, inspect outputs with LLVM, link them, and compare behavior with the original across the differential input set.

## Risk and capability reporting

All five passes are medium risk and object-only. CLI capability output states the exact formats, x86-64 support, analysis/relocation requirements, size-change behavior, and post-link restriction. The balanced profile adds the five passes after low-risk cleanup; explicitly selecting medium-risk passes emits a clear warning without blocking use.

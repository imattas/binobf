# Milestone 14: Native Transform Completion Design

## Goal

Complete the v1 metadata and native-layout surface that can be implemented safely in relocatable objects: unnecessary-local-symbol stripping, independent basic-block reordering, and harmless dead-code insertion. Each transform remains deterministic, transactional, lineage-producing, and verifier-gated.

## Safe local-symbol stripping

Add `strip-local-symbols` as a low-risk COFF/ELF object pass. A symbol is removable only when it is local, defined, not a section symbol, not preserved by the transform context, not the target of any relocation, and not required by an external ABI. File symbols and unreferenced local function/object symbols are eligible. The existing writers rebuild symbol indices and relocation references after removal. The pass refuses ambiguous references rather than inferring safety.

The minimal profile becomes `strip-debug`, `cleanup-metadata`, `strip-local-symbols`, and `rename-private-symbols`. The balanced profile includes the same metadata passes before machine-code transforms.

## Harmless dead-code insertion

Add `dead-code-insertion` as a medium-risk x86-64 relocatable-object pass. It operates only on a completely recovered function and an untargeted, relocation-free multi-byte NOP span of at least three bytes. Without changing code size, the pass replaces that span with a valid short jump over one or more valid NOP instructions. The skipped NOP region is a real unreachable block with no side effects. The transform never uses environment state, invalid encodings, overlapping instructions, or opaque predicates.

The pass reanalyzes every changed function, requires complete recovery, records section lineage, clears stale COFF section checksums, and declines any candidate whose target or displacement cannot be proven.

## Independent basic-block reordering

Add `block-reordering` as a medium-risk x86-64 relocatable-object pass. It is intentionally conservative:

- the function must be completely recovered and symbol-backed;
- the entry block remains at the function start;
- every other block must end in an unconditional direct branch, return, trap, or indirect branch, so no implicit fallthrough can change meaning;
- all direct branch targets must remain inside the function and use supported rel8/rel32 encodings;
- the function must contain no relocations, unwind records, interior symbols, or unowned byte ranges;
- every moved instruction and branch target must map uniquely through the block permutation.

Non-entry blocks are deterministically shuffled from the build seed. Bytes are moved in whole block chunks, branch displacements are re-encoded with range checks, symbol addresses are repaired, lineage is recorded, and the function is reanalyzed before the pass can commit. Unsupported functions are skipped without weakening verification.

## Verification

Unit tests cover eligibility, refusals, deterministic layouts, displacement repair, and lineage. Real COFF/ELF assembly fixtures ensure every balanced machine pass changes code accepted by LLVM and standard linkers. Differential execution calls the reordered function and compares observable behavior. Debug, Release, UBSan, seven-surface fuzz smoke, public-header, analyzer, install, deterministic, and policy gates remain mandatory.

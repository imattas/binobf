# Milestone 3 Baseline Transformations Design

## Status

Approved by the project brief: implement strip-debug, private-symbol renaming, and safe metadata cleanup on the verified object round-trip foundation.

## Pass contract and transaction boundary

`TransformPass` exposes a stable name, capability requirements, support probing, and a mutating `run` method. `PassManager` owns an ordered pass list and rejects duplicate names or unmet dependencies. Each pass receives a copy of the last committed `BinaryImage`; successful mutation is accepted only after `write_object` and `parse_object` both succeed. Failure discards the candidate and leaves the caller's image untouched. Dry-run executes and verifies the same candidate but never commits it.

`TransformContext` carries the explicit seed, dry-run mode, preservation allowlists, diagnostics, and monotonically allocated transform IDs. Reports contain examined/changed/skipped counts and pass diagnostics. Changed entities append `TransformationRecord` entries so lineage survives ordinary model copies.

## Deterministic private-symbol renaming

The rename pass targets only format-proven local/private symbols. It excludes undefined symbols, external/weak bindings, section and file symbols, empty names, and allowlisted names. Names are generated from the controlled project PRNG plus a stable symbol-order traversal; collisions are resolved deterministically. Externally visible ABI symbols are never renamed.

## Safe section removal

Strip-debug and metadata cleanup share a format-aware section-removal transaction. The editor first computes the complete removal set, including relocation entities owned by removed sections and symbols defined only in those sections. It refuses unresolved surviving references. It then compacts section and raw symbol indices, repairs ELF `sh_link`/relocation `sh_info`/symbol `st_shndx`, repairs COFF section numbers and relocation-table owners, and preserves auxiliary records only when their understood references remain valid.

ELF symbol-index metadata such as `.llvm_addrsig` is removed whenever symbol indices change. Unknown index-bearing metadata blocks the pass rather than being guessed. COFF linker directives and externally visible symbols are always preserved.

## Baseline passes

- `rename-private-symbols`: deterministic local-name replacement.
- `strip-debug`: removes `.debug*`, `.zdebug*`, and COFF `.debug$*` sections plus their owned references when safe.
- `cleanup-metadata`: removes known nonsemantic compiler-identification sections such as ELF `.comment` and LLVM address-significance metadata; it never removes `.drectve`, unwind data, resources, imports, exports, or ABI symbols.

## Verification

Unit tests prove selection, allowlists, determinism, dry-run, dependency ordering, rollback, diagnostics, statistics, and lineage. Integration tests transform real COFF/ELF fixtures, reparse with binobf and LLVM, link with the standard linker, and run original/transformed Windows fixtures with identical assertions. Capability output remains conservative per pass and format.

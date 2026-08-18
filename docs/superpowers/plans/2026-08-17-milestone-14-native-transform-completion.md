# Milestone 14: Native Transform Completion Plan

### Task 1: Safe local-symbol stripping

- [x] Add failing unit tests for removable, referenced, external, section, and preserved symbols.
- [x] Implement and register `strip-local-symbols` with repaired writer output.
- [x] Add the pass to profiles, CLI capability output, and configuration validation.

### Task 2: Harmless dead-code insertion

- [x] Add failing tests for jump-over-NOP insertion and unsafe candidate refusal.
- [x] Implement deterministic fixed-size dead-code insertion with semantic reanalysis.
- [x] Add real COFF/ELF fixture coverage and lineage assertions.

### Task 3: Independent basic-block reordering

- [x] Add failing tests for deterministic block permutation and rel8/rel32 repair.
- [x] Implement entry-pinned block movement with strict fallthrough, relocation, range, and ownership guards.
- [x] Add executed COFF/ELF differential coverage and standard-tool acceptance.

### Task 4: Integration and documentation

- [x] Register the passes in CLI, archives, profiles, manifests, and capability reporting.
- [x] Update README, transformation, architecture, lineage, and verification documentation.
- [x] Preserve explicit unsupported behavior for post-link images and non-x86-64 targets.

### Task 5: Release gates

- [x] Pass Debug/Release, UBSan, fuzz smoke, standalone headers, analyzer, install, deterministic, and policy gates.

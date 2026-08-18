# binobf Milestone 6 Instruction Transformations Plan

**Goal:** Deliver verified x86-64 instruction, CFG, constant, block, and layout transformations for COFF/ELF relocatable objects.

### Task 1: Transformation API and semantic guards

- [x] Add medium-risk instruction-pass factories and capability declarations.
- [x] Add shared complete-function, relocation-overlap, target, and reanalysis guards.
- [x] Add failing tests for unsupported and ambiguous inputs.

### Task 2: Exact-size instruction rewrites

- [x] Implement validated multi-byte NOP substitution.
- [x] Implement register-immediate constant encoding rewrites.
- [x] Prove exact-size, deterministic, relocation-safe behavior in unit tests.

### Task 3: Exact-size CFG rewrites

- [x] Implement conditional-branch inversion over direct two-way pairs.
- [x] Implement NOP-window basic-block splitting with `JMP +0`.
- [x] Reanalyze candidates and assert expected complete CFGs.

### Task 4: Relocation-aware layout variation

- [x] Implement deterministic whole-function chunk permutation.
- [x] Repair moved symbols, relocation sites, and supported section-symbol addends.
- [x] Verify COFF/ELF linkability and runtime equivalence.

### Task 5: CLI, profiles, documentation, and milestone gates

- [x] Register individual passes and the balanced profile with risk warnings/statistics.
- [x] Extend differential integration coverage to every applicable pass.
- [x] Run clean Debug/Release, standalone headers, analyzer, LLVM inspection, policy scans, and update docs.

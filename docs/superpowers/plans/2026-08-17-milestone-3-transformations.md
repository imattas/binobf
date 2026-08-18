# binobf Milestone 3 Baseline Transformations Plan

**Goal:** Deliver transactional, deterministic strip-debug, private-symbol renaming, and safe metadata cleanup passes for verified ELF/COFF objects.

**Architecture:** A format-neutral pass manager runs candidate-model transactions; format-aware edit utilities repair indices and relationships; every commit must serialize and reparse successfully.

**Tech Stack:** C++20, existing normalized model/writers, CMake/CTest, LLVM inspection/link tools.

## Constraints

- Never rename external or undefined ABI symbols.
- Never remove a section or symbol with an unresolved surviving reference.
- Every randomized decision uses the explicit seed and `DeterministicRng`.
- A failed pass or verification gate leaves the committed model unchanged.
- No anti-analysis, malformed metadata, loader, injection, or signing-bypass behavior.

### Task 1: Pass API and transactional manager

- [x] Add failing tests for ordering, duplicate names, unmet dependencies, dry-run, rollback, reports, and input immutability.
- [x] Add public pass/context/report/outcome types and `PassManager`.
- [x] Verify every candidate through `write_object` plus `parse_object` before commit.
- [x] Run focused and full tests.

### Task 2: Deterministic private-symbol renaming

- [x] Add failing ELF/COFF selection tests including external, undefined, section/file, and allowlisted symbols.
- [x] Implement deterministic collision-free names from the explicit seed.
- [x] Append lineage and report examined/changed/skipped statistics.
- [x] Prove same seed gives identical bytes and different seeds change eligible names only.

### Task 3: Format-aware removal and index repair

- [x] Add failing model tests for section/symbol removal and repaired stable/raw references.
- [x] Implement preflight dependency closure and safe refusal diagnostics.
- [x] Compact ELF/COFF section and symbol indices and repair supported metadata.
- [x] Reparse every edited candidate and run malformed-model regressions.

### Task 4: Strip-debug pass

- [x] Add synthetic ELF/COFF debug-section tests and unsafe-reference rollback tests.
- [x] Remove debug sections, owned relocations, and private symbols only when preflight proves safety.
- [x] Verify standard-tool acceptance and linkability.

### Task 5: Metadata cleanup pass

- [x] Add tests for removable `.comment`/`.llvm_addrsig` and preserved directives/unwind/resources.
- [x] Implement explicit allowlisted cleanup rules with diagnostics for every skip.
- [x] Verify deterministic output and runtime equivalence.

### Task 6: CLI and milestone verification

- [x] Add `passes` capability output and transformation pass/seed/dry-run options.
- [x] Transform real compiler COFF/ELF fixtures, inspect, link, and execute equivalence cases.
- [x] Run clean warning-as-error Debug/Release builds, all tests, standalone headers, static analysis, and source scans.
- [x] Update capability docs without claiming machine-code transformations.

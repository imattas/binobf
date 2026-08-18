# binobf Milestone 12 Hardening Plan

**Goal:** Make parser, verifier, transform, and VM robustness measurable under generated, mutated, sanitized, and benchmarked workloads.

### Task 1: Sanitizer and fuzz infrastructure

- [x] Add opt-in UBSan/ASan CMake support with explicit platform diagnostics.
- [x] Add libFuzzer targets for detector, objects, linked images, archives, and VM bytecode.
- [x] Add bounded fuzz-smoke execution without native payload execution.

### Task 2: Generated property tests

- [x] Generate width-aware arithmetic, boolean, constant, register, slot, memory, and branch programs.
- [x] Compare assembled/decoded VM execution with an independent oracle.
- [x] Cover invalid division, shifts, limits, and deterministic replay.

### Task 3: Crash-proof and mutation suites

- [x] Mutate harmless parser/decoder seeds deterministically and require structured outcomes.
- [x] Add verifier, pass-precondition, VM-semantics, and address-range artifact mutants.
- [x] Report and require a complete kill rate for the required mutation matrix.

### Task 4: Diagnostics and benchmarks

- [x] Extend structured diagnostics with explanation, remediation, and lineage context.
- [x] Add deterministic text/JSON tests for all new fields.
- [x] Add an opt-in benchmark executable and run it on real object/archive/linked fixtures.

### Task 5: Release gates

- [x] Update hardening, verification, developer, and build documentation.
- [x] Pass clean Debug/Release, UBSan, fuzz smoke, headers, analyzer, install, and policy gates.

# binobf Milestone 4 Verification Plan

**Goal:** Ship public structural verification and a reusable compile-transform-run differential harness for supported ELF/COFF objects.

### Task 1: Public structural verification

- [x] Add failing tests for successful reports and malformed section ranges.
- [x] Add public check/status/report types and `verify_object`.
- [x] Route pass-manager verification through the shared verifier.

### Task 2: Verify CLI

- [x] Add failing command tests for valid, malformed, and invalid invocations.
- [x] Implement `binobf verify <object>` with truthful supported/not-applicable/unsupported statuses.
- [x] Verify text and JSON diagnostic behavior.

### Task 3: Differential harness

- [x] Add a deterministic fixture with explicit outputs and side effects.
- [x] Compile original and transformed objects and link separate executables.
- [x] Compare exit status, stdout, deterministic files, function outputs, and side effects over an input matrix.

### Task 4: Integration and adversarial coverage

- [x] Verify compiler-produced ELF/COFF objects through the public verifier.
- [x] Retain LLVM inspection, ELF relocation-linking, and native runtime gates.
- [x] Cover verifier failures transactionally without emitted success.

### Task 5: Milestone verification

- [x] Run clean warning-as-error Debug and Release builds and all tests.
- [x] Run public-header self-containment, Clang analysis, and implementation hygiene scans.
- [x] Update verification, CLI, architecture, and feature-status documentation.

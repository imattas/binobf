# binobf Milestone 8 VM Lowering Plan

**Goal:** Lower a rigorously bounded subset of real x86-64 object functions through normalized binobf IR into the VM and prove it against native execution.

### Task 1: Native IR and validation

- [x] Add typed variables, operands, blocks, instructions, signatures, and lineage.
- [x] Add bounded validation and explicit fallback representation.
- [x] Add adversarial validation tests first.

### Task 2: x86-64 lifting

- [x] Add an explicit selected-function lift API and private Capstone adapter.
- [x] Lift the documented 32-bit register/immediate arithmetic and control-flow subset.
- [x] Reject incomplete CFGs, memory, calls, relocations, unsupported widths, and unknown conditions.

### Task 3: VM lowering

- [x] Deterministically map variables, arguments, immediates, blocks, and conditions.
- [x] Validate every generated VM program and preserve source lineage in the lowering report.
- [x] Prove stable lowering and bytecode round trips.

### Task 4: Differential proof

- [x] Build controlled COFF and ELF native assembly fixtures.
- [x] Link and execute the host fixture in the test process.
- [x] Compare native, lowered VM, and assembled/decoded VM results over boundary inputs.

### Task 5: Documentation and gates

- [x] Document the exact supported subset and explicit-signature requirement.
- [x] Keep bytecode embedding and interpreter stubs marked planned.
- [x] Pass clean Debug/Release, headers, analyzer, install, deterministic, and policy gates.

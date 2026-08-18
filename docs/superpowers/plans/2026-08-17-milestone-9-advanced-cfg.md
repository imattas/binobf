# binobf Milestone 9 Advanced CFG Plan

**Goal:** Implement deterministic, validated advanced CFG transformations and real internal helper calls, with native differential proof.

### Task 1: Flattening and dispatcher

- [x] Add failing deterministic flattening/dispatcher structure tests.
- [x] Implement seeded case allocation, state transitions, and dispatcher chains.
- [x] Validate and differentially execute loops and two-way branches.

### Task 2: Controlled bogus blocks

- [x] Add a mathematically fixed program-local opaque edge.
- [x] Keep the bogus block valid, side-effect-free, and environment-independent.
- [x] Prove the bogus block is represented but never executed on valid inputs.

### Task 3: IR modules and internal VM calls

- [x] Add internal-call/module IR with signature and acyclic-call validation.
- [x] Add a versioned VM internal-call opcode and bounded call frames.
- [x] Extend bytecode, disassembly, malformed-input, and execution tests.

### Task 4: Block outlining and function splitting

- [x] Compute and remap live-ins for safe single-return block outlining.
- [x] Replace outlined blocks with real internal helper calls.
- [x] Split complete functions into ABI-facing wrappers and internal helpers.

### Task 5: CLI, differential proof, and gates

- [x] Expose explicit high-risk CFG options with warnings and deterministic seeds.
- [x] Compare native, baseline VM, flattened, outlined, and split execution.
- [x] Pass clean Debug/Release, headers, analyzer, install, deterministic, and policy gates.

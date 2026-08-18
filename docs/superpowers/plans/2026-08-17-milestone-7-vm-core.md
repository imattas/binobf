# binobf Milestone 7 VM Core Plan

**Goal:** Deliver a fully bounded, versioned, deterministic, architecture-neutral VM core and developer disassembler.

### Task 1: VM values, IR, and validation

- [x] Add typed values, registers, slots, flags, conditions, and variant operations.
- [x] Add program/resource-limit validation with structured diagnostics.
- [x] Add failing width, operand, target, and resource tests.

### Task 2: Runtime state, memory, and native bridge

- [x] Implement bounded register file and VM-local frame stack.
- [x] Implement little-endian bounded linear memory.
- [x] Implement rejecting and caller-supplied native-call bridges.

### Task 3: Interpreter semantics

- [x] Implement every data, arithmetic, bitwise, comparison, branch, memory, call, and return opcode.
- [x] Implement width-correct flags, wrapping, and deterministic failures.
- [x] Add exhaustive opcode/condition/step-budget tests.

### Task 4: Assembler, decoder, and disassembler

- [x] Implement versioned standalone bytecode and length-prefixed records.
- [x] Implement seeded opcode/register permutation and strict decoding.
- [x] Prove malformed-input rejection and assemble/decode round-trip stability.

### Task 5: CLI, docs, and milestone gates

- [x] Add `binobf vm disassemble <program.bvm>`.
- [x] Document bytecode and VM semantics without overclaiming lowering support.
- [x] Run clean Debug/Release, headers, analyzer, deterministic encoding, and policy scans.

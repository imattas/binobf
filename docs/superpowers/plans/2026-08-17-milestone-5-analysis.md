# binobf Milestone 5 Machine-Code Analysis Plan

**Goal:** Deliver conservative multi-architecture decoding, function/CFG recovery, basic register dataflow, relocation-aware references, and lineage.

### Task 1: Dependency and decoder API

- [x] Pin Capstone 5.0.9 behind a private CMake adapter.
- [x] Add failing x86/x86-64/ARM64 and invalid-input decoder tests.
- [x] Implement normalized one-instruction decoding without public Capstone types.

### Task 2: Function discovery and instruction streams

- [x] Add symbol-range, overlap, zero-size, and decode-fallback tests.
- [x] Discover functions conservatively from defined function symbols.
- [x] Assign deterministic stable IDs and source lineage.

### Task 3: CFG recovery

- [x] Add branch, conditional, call, fallthrough, return, and indirect-flow tests.
- [x] Split only at proven instruction boundaries and emit typed edges.
- [x] Mark unresolved or malformed flow incomplete without guessing.

### Task 4: Relocation references and basic dataflow

- [x] Attach instruction-spanning relocations and stable symbol references.
- [x] Normalize register definitions/uses.
- [x] Compute deterministic block live-in/live-out sets to fixed point.

### Task 5: CLI, integration, and milestone gates

- [x] Extend `analyze` with function/instruction/block/edge/completeness summaries.
- [x] Analyze real compiler COFF/ELF fixtures and preserve all Milestone 4 gates.
- [x] Run clean Debug/Release, standalone headers, analyzer, policy scans, and update docs.

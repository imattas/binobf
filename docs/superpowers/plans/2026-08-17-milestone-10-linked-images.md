# binobf Milestone 10 Linked Images Plan

**Goal:** Add conservative, verified PE and ELF linked-image parsing and rewriting for executables and shared libraries.

### Task 1: Linked model and bounded API

- [x] Add failing public model, resource-limit, and unsupported-kind tests.
- [x] Implement `LinkedImage`, typed directories/layout, parse/rewrite reports, and limits.
- [x] Preserve exact source bytes and stable entity relationships.

### Task 2: PE parser and verifier

- [x] Parse PE32/PE32+ headers, sections, RVA mappings, and all data directories.
- [x] Normalize imports, exports, relocations, resources, unwind, TLS, load config, debug, and signing state.
- [x] Reject malformed or unmappable PE metadata with targeted diagnostics.

### Task 3: ELF parser and verifier

- [x] Parse ELF32/ELF64 headers, program/section tables, segments, and linked sections.
- [x] Normalize symbols, imports/exports, relocations, dynamic metadata, notes, unwind, and debug records.
- [x] Distinguish executable, PIE, and shared-library policy and reject malformed relationships.

### Task 4: Transactional linked rewriting

- [x] Implement byte-identical baseline PE/ELF rewriting with reparse verification.
- [x] Implement address-stable debug stripping and repair every affected header/directory/checksum.
- [x] Require explicit PE signature invalidation and keep linked-driver policy conservative.

### Task 5: CLI and real linked fixtures

- [x] Extend analyze, verify, and transform to linked images without weakening object behavior.
- [x] Build and inspect PE executable/DLL and ELF executable/PIE/shared-object fixtures.
- [x] Prove deterministic outputs, metadata preservation, native behavior, and signature diagnostics.

### Task 6: Release gates

- [x] Update capabilities, formats, architecture, developer, and verification documentation.
- [x] Pass clean Debug/Release, standalone headers, analyzer, install, LLVM, runtime, policy, and license gates.

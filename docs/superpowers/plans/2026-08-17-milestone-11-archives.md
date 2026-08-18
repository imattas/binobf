# binobf Milestone 11 Archives Plan

**Goal:** Parse, transform, rebuild, and verify `.a` and `.lib` archives with correct symbol indexes.

### Task 1: Archive model and parser

- [x] Add failing ordinary/GNU/BSD/COFF member-name and range tests.
- [x] Implement bounded archive members, layouts, flavor, and stable IDs.
- [x] Distinguish objects, import objects, indexes, name tables, and opaque members.

### Task 2: Symbol indexes and writer

- [x] Parse GNU and Microsoft linker-member symbol relationships.
- [x] Rebuild long-name tables and final member offsets deterministically.
- [x] Emit valid GNU and dual-linker-member COFF indexes with exact baseline output.

### Task 3: Object-member transformation

- [x] Apply existing object passes independently with member-derived seeds.
- [x] Preserve unsupported/import/opaque members and abort atomically on failure.
- [x] Rebuild indexes from post-transform external symbols.

### Task 4: Verification, CLI, and real fixtures

- [x] Add `verify_archive` and CLI analyze/verify/transform dispatch.
- [x] Build real `.a`, `.lib`, long-name, and import-library fixtures.
- [x] Prove LLVM/linker acceptance, deterministic output, and linked runtime behavior.

### Task 5: Release gates

- [x] Update capability, format, transformation, development, and verification docs.
- [x] Pass clean Debug/Release, headers, analyzer, install, deterministic, policy, and license gates.

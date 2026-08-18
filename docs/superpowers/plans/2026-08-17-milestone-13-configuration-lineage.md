# binobf Milestone 13 Configuration, Manifest, and Lineage Plan

**Goal:** Make transformations reproducibly configurable and emit/query deterministic external evidence without embedding sensitive build metadata.

### Task 1: Pinned adapters and portable hashing

- [x] Add private pinned toml++ and nlohmann/json dependencies with notices and install licenses.
- [x] Add a portable incremental SHA-256 API with known-vector and chunking tests.

### Task 2: Strict configuration

- [x] Add versioned bounded TOML parsing, validation, canonicalization, and stable diagnostics.
- [x] Add `binobf config` and `transform --config` with explicit CLI precedence.
- [x] Test relative paths, profiles/pass lists, preservation, wrong types, unknown keys, and limits.

### Task 3: Deterministic manifests and artifact transactions

- [x] Serialize deterministic manifests containing hashes, effective settings, statistics, and verification state.
- [x] Stage and commit binary, manifest, and optional sidecar as one no-overwrite transaction.
- [x] Test default/custom/disabled manifests, dry-run behavior, deterministic output, and rollback.

### Task 4: Persisted lineage and crash mapping

- [x] Serialize bounded object lineage sidecars from source and verified transformed models.
- [x] Parse/validate sidecars and implement exact protected-address lineage queries.
- [x] Add positive, incomplete, ambiguous, cyclic, malformed, and resource-limit tests.

### Task 5: Hardening and release gates

- [x] Add configuration and lineage fuzz targets plus seeded corpus entries.
- [x] Update README, configuration, lineage, developer, verification, and third-party documentation.
- [x] Pass Debug/Release, UBSan, fuzz smoke, headers, analyzer, install, deterministic, and policy gates.

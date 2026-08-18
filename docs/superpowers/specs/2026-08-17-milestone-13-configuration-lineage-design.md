# Milestone 13 Configuration, Manifest, and Lineage Design

## Scope

Milestone 13 closes three v1 engineering gaps that later code generation depends on: strict project configuration, deterministic external build manifests, and persisted protected-to-source lineage queries. It does not add native code generation or broaden transformation safety claims.

## Configuration

binobf accepts TOML 1.0 through a pinned toml++ adapter hidden behind `binobf::config`. The schema is versioned and intentionally limited to implemented behavior: input/output paths, seed, profile or explicit ordered passes, dry-run, signature-invalidation intent, symbol preservation, manifest policy, and optional object lineage output. Unknown keys, duplicate semantic choices, wrong types, unsupported pass names, invalid paths, and values outside resource limits fail with stable diagnostics.

Relative input, output, manifest, and lineage paths resolve against the configuration file's directory. `transform --config=<path>` may source input/output/pass settings from the file. Explicit CLI input, `-o`, `--passes`, `--seed`, `--dry-run`, signature intent, preservation entries, manifest options, and lineage path override or extend their corresponding configuration values deterministically. No environment variables, implicit search paths, or executable directives are evaluated.

`binobf config <path>` parses and prints canonical effective JSON without touching binary outputs. Canonicalization sorts object keys, preserves pass and allowlist ordering, normalizes paths lexically, and is the exact byte representation hashed into the build manifest.

## Manifest and hashing

Every successful non-dry-run transform writes `<output>.manifest.json` unless `--no-manifest` is explicit. A caller may select another external path. The deterministic manifest contains schema version, binobf version, SHA-256 input/output/config hashes, effective seed, ordered passes, format, architecture, input/output sizes, pass statistics, and verification state. It contains no timestamp, host path outside the user-selected artifact names, machine identifier, pointer, or environment state.

SHA-256 is implemented as a small portable support component with NIST-known vectors, incremental/chunk-boundary tests, and lowercase hexadecimal rendering. It is for reproducibility and artifact identity, not credential handling.

Binary output, manifest, and optional lineage sidecar are staged as sibling temporary files only after all serialization and verification succeeds. Existing destinations are never overwritten. Commit failure removes only newly staged/committed files from this transaction, so the command cannot report success with a partial artifact set.

## Lineage sidecar and query

`--lineage=<path>` is opt-in and initially supported for relocatable objects, where normalized functions/instructions and relocation-rich layout are authoritative. The deterministic JSON sidecar records schema/tool versions, input/output hashes, format/architecture, source entities, protected functions/instructions with address kind/range, and every transformation parent record needed to follow output function or instruction -> current symbol/section -> original entity. Sensitive source paths and source text are excluded.

`binobf lineage <sidecar> --protected-address=<integer>` validates resource limits and schema, finds the narrowest protected instruction/function containing the address, walks only explicit stable-ID lineage edges, and prints the protected entity, original entity/address, and ordered transforms. Ambiguous, missing, cyclic, duplicate, or out-of-range relationships produce structured incomplete/failure diagnostics; the query never guesses. Archive-wide and embedded-VM address namespaces remain unsupported until they have unambiguous member/module identifiers.

## Dependencies and boundaries

toml++ 3.4.0 provides TOML parsing and nlohmann/json 3.12.0 provides deterministic JSON parsing/serialization. Both are pinned, treated as private implementation dependencies, warning-suppressed as third-party code, licensed in installed notices, and absent from public headers.

Configuration and sidecar parsers impose file, table, array, string, entity, edge, and recursion limits. New fuzz targets cover both parsers. No format embeds the manifest or lineage into release binaries.

## Verification

The milestone requires schema unit tests, CLI override tests, config-relative path tests, deterministic canonicalization/hashing, transactional multi-artifact failure tests, manifest hash verification, lineage round trips and positive/negative address queries, malformed/oversized corpus tests, config/lineage fuzz smoke, standalone public headers, analyzer, Debug/Release/UBSan, installation, and installed CLI smoke.

# binobf Milestone 4 Verification Design

## Goal

Make verification a reusable product capability rather than an incidental writer test. Every supported object output must be reparsed, structurally checked, externally linkable, and covered by deterministic semantic comparison before machine-code rewriting begins.

## Structural verifier

Add a public `verify_object` API returning the reparsed `BinaryImage` plus an explicit check report. Supported object checks are header decoding, section ranges, symbol tables, relocations, and entity references. Imports/exports are not applicable to relocatable objects; branch destinations and unwind semantics remain explicitly unsupported until machine-code analysis and linked-image parsing exist. Unsupported checks are reported, never silently claimed.

The verifier composes the hardened parser with the normalized-model validator. Any parse or model failure returns a contextual diagnostic and prevents output commit. The pass manager and CLI use this same verifier so there is one verification contract.

## CLI

`binobf verify <object>` prints the detected format, architecture, entity counts, and status of every structural check. It exits successfully only when all checks required for the supported object scope pass. Malformed or unsupported input returns the existing structured diagnostic path.

## Differential harness

Add a CTest harness under `tests/differential` that compiles a harmless native fixture, transforms its object through the public baseline pass pipeline, links original and transformed executables, and runs the same input matrix against both. For each case it compares exit status, stdout, deterministic output-file bytes, explicit function results exposed in stdout, and expected file side effects. Timing is never captured or compared.

## Acceptance gates

- Adversarial byte mutations fail structural verification with diagnostics.
- Valid compiler and canonical objects report all supported checks passed.
- The CLI verifier is covered for success, malformed input, and usage errors.
- Differential cases cover negative, zero, boundary, and ordinary inputs.
- Debug and Release warning-as-error suites, external inspection/linking, standalone headers, and static analysis pass cleanly.

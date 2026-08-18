# Milestone 15: Function Selection Design

## Goal

Add one deterministic, reusable policy for selecting functions before instruction,
CFG, and VM transformations. Selection is configured in the existing strict TOML
schema and is evaluated against the function's original symbol identity.

## Policy

The optional `[selection]` table supports:

- `include` and `exclude`: exact function names;
- `include_regex` and `exclude_regex`: bounded ECMAScript regular expressions;
- `sections`: exact section names;
- `visibility`: any of `local`, `hidden`, or `external`;
- `percentage`: an integer from 0 through 100;
- `seed`: an optional sampling seed, defaulting to the transform seed.

Exclusion always wins. Exact and regex inclusion clauses form one allowlist; when
neither is present, all names are eligible. Section and visibility constraints are
conjunctive. Percentage sampling uses a documented fixed hash of the seed and a
stable original function identity, so it is independent of traversal order.

## Pipeline integration

`TransformContext` owns the compiled policy, preserves original-name aliases when
private symbols are renamed, and exposes a single `is_function_selected` query.
Function-scoped instruction and CFG passes consult that query. Safe symbol stripping
must retain symbols needed to identify selected functions. Global metadata passes
remain global. Function reordering only permutes selected functions among their
existing selected slots.

## Safety and evidence

Invalid regular expressions and unknown selection keys fail configuration parsing.
Regex and array sizes remain under existing configuration limits. Diagnostics and
pass counters account for policy-skipped functions. Canonical configuration JSON,
and therefore the manifest configuration hash, includes the complete policy.

Source annotations and compilation modules are not present in ordinary stripped
COFF/ELF object metadata, so they are not claimed until trustworthy producer
metadata is available.

## Verification

Unit tests cover precedence, filters, invalid schema, stable sampling, and rename
aliases. Pass tests prove that selected functions change while excluded functions
remain byte-identical. CLI integration exercises TOML selection on a real object,
followed by structural and differential verification.

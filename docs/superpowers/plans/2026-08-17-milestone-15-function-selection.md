# Milestone 15: Function Selection

## Task 1: Selection policy

- [x] Add failing unit tests for exact, regex, exclusion, section, visibility, and sampling behavior.
- [x] Implement a bounded deterministic selector and original-name alias tracking.
- [x] Expose the selector through `TransformContext`.

## Task 2: Configuration

- [x] Extend strict TOML parsing and canonical JSON with `[selection]`.
- [x] Reject invalid regexes, types, values, duplicates, and unknown keys.
- [x] Propagate the effective selection policy through object and archive transforms.

## Task 3: Pass integration

- [x] Apply selection to instruction substitution, constant/branch rewriting, dead code, block splitting, and block reordering.
- [x] Preserve selected local symbols through symbol stripping and aliases through renaming.
- [x] Reorder only selected functions among selected layout slots.

## Task 4: Real behavior and documentation

- [x] Add real-object CLI and differential coverage proving excluded functions remain unchanged.
- [x] Document policy semantics, limitations, diagnostics, and deterministic sampling.

## Task 5: Release gate

- [x] Pass Debug/Release, UBSan, fuzz smoke, standalone headers, analyzer, install, deterministic, and policy gates.

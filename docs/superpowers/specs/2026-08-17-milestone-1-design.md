# binobf Milestone 1 Design

## Status

Approved for implementation by the parent binobf brief. This document refines the already-approved architecture for the first independently verifiable milestone.

## Goal

Deliver a buildable C++20 library and `binobf` CLI that safely identifies supported binary containers, exposes foundational typed models and diagnostics, provides deterministic seeded randomness, and is covered by unit and CLI-level tests.

## Architecture

The initial implementation is split into small public interfaces under `include/binobf` and matching implementation files under `src`. `core` owns stable IDs, normalized enums and model values, diagnostics, and deterministic randomness. `formats` owns a bounds-checked detector that recognizes ELF, PE, COFF object files, and Unix/COFF archives without mutating input. `cli` parses commands and renders library results; `main` is only a process adapter.

LLVM is intentionally not required for Milestone 1. Format detection needs only small fixed headers, while later object parsing and instruction decoding will use LLVM behind binobf-owned interfaces. This preserves a fast bootstrap without coupling the public model to LLVM types.

## Detection Rules

- ELF requires the full identification prefix, supported class and byte order, and enough bytes for the class-specific header fields. Machine and type fields determine architecture and binary type.
- PE requires `MZ`, a bounded DOS `e_lfanew`, a complete `PE\0\0` signature and COFF header, and a supported machine. Characteristics distinguish executable and DLL; a `.sys` source name classifies a valid PE image as a kernel driver.
- COFF objects require a supported machine, a zero optional-header size, a nonzero bounded section count, and a complete section table.
- Archives require the exact `!<arch>\n` signature and are classified as static libraries until member inspection can safely distinguish import libraries.
- Truncated, inconsistent, oversized, or unknown input returns an explicit error diagnostic. File extensions never override invalid bytes.

## Public Behavior

`binobf inspect <path>` prints deterministic key/value facts: path, format, type, architecture, file size, and inspection status. `binobf formats` and `binobf architectures` report accurate initial support levels. `--diagnostics=json` renders machine-readable failures. Inspection opens input read-only and never writes beside it.

## Error Handling and Security

Major subsystem boundaries return a project-owned `Result<T, E>` value. Header reads use checked ranges and explicit little/big-endian helpers. Counts and offsets are validated before addition or multiplication. The detector applies a maximum input size for in-memory inspection and reports contextual diagnostics without requiring verbose logging.

## Verification

Unit tests use synthetic harmless headers and cover every supported format/architecture combination plus truncation, bad offsets, invalid counts, and unknown data. CLI tests call the same command dispatcher used by `main`, create fixtures in a temporary directory, and verify exit codes and text/JSON output. CTest runs all tests in Debug and Release builds; Clang warnings are treated as errors.

## Deferred Work

Detailed section/symbol/relocation parsing, object emission, transformation passes, YAML configuration, lineage sidecars, machine-code analysis, and the VM remain in later milestones. Capability documentation marks them planned, never supported.

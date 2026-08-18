# Milestone 16: Embedded VM Virtualization

## Task 1: Lock the public runtime and protection contracts

- [x] Add failing tests for the C ABI runtime entry point, error reporting, protection report, and input validation.
- [x] Add the public native-runtime and protection headers.

## Task 2: Implement deterministic ABI adapters and object rewriting

- [x] Add failing COFF and ELF model tests for wrapper layout, symbol redirection, bytecode embedding, and relocations.
- [x] Implement Windows x64 and System V AMD64 adapters, deterministic entity/index allocation, relocation synthesis, and section metadata repair.
- [x] Cover repeated protection and reject unsafe direct callers/unwind metadata.

## Task 3: Expose transactional CLI protection

- [x] Add failing CLI tests for parsing, output conflicts, success, determinism, and diagnostics.
- [x] Implement `vm protect` and report its auditable layout.

## Task 4: Prove native and linker behavior

- [x] Add and run a Windows differential executable using protected functions.
- [x] Link protected ELF output relocatably and inspect the resulting symbols/relocations.

## Task 5: Document, package, and gate

- [x] Update README, architecture, virtualization, CLI/configuration, and installation documentation.
- [x] Pass Debug/Release, UBSan, fuzz, standalone headers, analyzer, install, deterministic, native execution, and policy gates.

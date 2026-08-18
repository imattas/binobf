# Developer Guide

## Configure, build, and test

```powershell
cmake -S . -B build/debug -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBINOBF_WARNINGS_AS_ERRORS=ON
cmake --build build/debug
ctest --test-dir build/debug --output-on-failure
```

Production code is C++20. Public interfaces live under `include/binobf`; implementations mirror those paths under `src`; the process entry point lives under `tools/binobf`; tests are split into unit, integration, and differential directories.

For robustness work, use a dedicated UBSan build and the seed-backed libFuzzer smoke target. The fuzzer build creates valid COFF, ELF, PE, archive, VM, TOML-configuration, and lineage-JSON corpus entries before mutation and never executes parsed native code. Use the opt-in benchmark only for regression evidence, never as a correctness assertion. Exact commands and platform limits are in [Hardening](hardening.md).

## Change workflow

1. Name the externally visible break a test will catch.
2. Write the smallest test against the public interface.
3. Run it and confirm it fails for the missing behavior.
4. Implement the behavior without weakening validation or warnings.
5. Run the focused test and then the full suite.
6. Build Debug and Release with warnings as errors.
7. Update capability tables only after verification proves support.

Parsers must use checked offset/range arithmetic before every read. Header counts and sizes need explicit limits. Avoid exceptions across subsystem boundaries; return `Result` with contextual diagnostics. Do not retain owning raw pointers or use raw addresses as entity identity.

Randomized transformations must accept an explicit seed and use `DeterministicRng`. Do not use global or platform randomness for output decisions.

Configuration and evidence parsers must reject unknown schema keys, impose input/nesting/count/string limits, and return stable diagnostics. Third-party TOML/JSON types remain private implementation details. Multi-artifact output must use `commit_artifacts`; never commit a binary before its requested manifest or lineage sidecar has staged successfully.

Machine-code decoding uses the private Capstone adapter. Public headers expose only normalized binobf instruction, register, reference, function, block, and edge types. New decoder behavior needs architecture-specific golden bytes; new CFG behavior needs explicit incomplete-analysis cases. Never turn a decode failure or indirect target into a guessed instruction boundary.

VM changes must preserve explicit width semantics and validate before allocation or execution. Every new opcode needs IR validation, assembler/decoder round-trip, malformed-record coverage, interpreter success/failure cases, and disassembly text. Internal calls must use fresh bounded frames and validated targets/arguments; native calls go only through `VmNativeCallBridge`; memory accesses go only through `VmMemory`. Do not add ambient host access to the interpreter.

Native lifting changes must start from structured decoder operands, never parsed disassembly text. Add golden machine bytes, explicit ABI bindings, fallback diagnostics, and native-vs-lowered differential execution. A new native instruction is not supported merely because its result looks right: width, flags consumed by later branches, control-flow targets, relocations, and ABI observability must all be modeled or rejected.

Advanced IR control-flow changes require deterministic seeds, post-transform validation, structural tests, and native-vs-transformed differential execution. Bogus edges must be valid, side-effect-free, program-local, and independent of timing or environmental state. Outlining requires proven live-ins and safe exits. Internal call graphs must remain acyclic and within both IR call-depth and VM frame-depth limits.

## Adding a format adapter

Keep external library objects inside the adapter. Convert parsed facts into normalized binobf values. Add malformed/truncated fixtures before implementation, then valid round-trip fixtures. A writer is not supported until parse/write/parse, standard linker consumption, runtime behavior, and structural verification all pass.

The current object adapters share checked readers in `src/formats/object_parser_internal.hpp`; this is private implementation detail. Public consumers call `parse_object` and receive only normalized value types and structured diagnostics.

Linked adapters must retain explicit file/RVA/virtual mappings and reject every unmappable mandatory directory before exposing a `LinkedImage`. A linked writer may change only metadata it owns, must repair each affected directory/header/checksum/signature field, reparse through `parse_linked_image`, and pass `verify_linked_image`. Signed PE changes require explicit caller intent. Add real executable and shared-library fixtures, standard-tool inspection, and loader/runtime proof where the host can execute the target.

Archive adapters must keep index/name-table members separate from ordinary members, resolve every linker offset to a stable member ID, and preserve unknown payloads. A changed archive must calculate final member offsets before emitting indexes, rebuild indexes from post-transform object symbols, reparse through `parse_archive`, and pass `verify_archive`. Test both GNU and Microsoft index encodings, long names, import-library preservation, deterministic output, LLVM listing, linking, and runtime behavior.

## Adding a transformation

A pass must declare its requirements and risk, reject unsupported regions, produce diagnostics/statistics/lineage, run transactionally, and have semantic equivalence tests. Machine-code passes must work from complete analyzer output, check relocation overlap before mutation, preserve exact byte windows unless they own full layout repair, and reanalyze every changed function. A transformation count without correctness evidence is not progress.

## Adding verification coverage

Use `verify_object`, `verify_archive`, or `verify_linked_image` for emitted bytes rather than duplicating parse-only checks. New supported checks must have both a valid case and a targeted corrupt-input case. Differential tests must run identical inputs against independently linked original and transformed executables and compare exit status, stdout, deterministic files, explicit results, and expected side effects. Never compare timing.

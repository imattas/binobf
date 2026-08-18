# Milestone 12 Hardening Design

## Outcome

Milestone 12 makes robustness measurable rather than implied. It adds compiler-native fuzz targets for every implemented parser/decoder boundary, deterministic generated semantic properties, verifier-focused artifact mutation tests, opt-in sanitizer builds, and a repeatable benchmark executable. No fuzz target executes parsed native code, produces a deployable payload, or performs environment-sensitive behavior.

## Fuzzing and crash resistance

Five libFuzzer entry points cover format detection, ELF/COFF object parse-write-verify, PE/ELF linked parse-rewrite-verify, archive parse-write-verify, and VM bytecode decode-assemble-execute validation. Every target uses the public bounded APIs and supplies reduced resource limits where available. Successful parsing is followed through reconstruction and verification so transformation boundaries receive coverage as well as header decoders.

Fuzzers are opt-in through `BINOBF_BUILD_FUZZERS`, require Clang, and link compiler-provided libFuzzer plus UndefinedBehaviorSanitizer. AddressSanitizer is enabled on supported non-Windows toolchains; the installed Windows LLVM/MSVC combination lacks the STL ASan integration library and remains an explicitly documented limitation. A `fuzz-smoke` target runs bounded iteration counts for release gating. Configuration and IR serialization fuzzers are not fabricated before those formats exist.

Normal CTest also receives a deterministic robustness suite. It mutates harmless, in-memory object/archive/bytecode seeds using `DeterministicRng`, invokes each applicable public parser, and requires stable success or structured failure without exceptions. Size and iteration ceilings keep this suite fast and reproducible.

## Property and mutation testing

Generated VM properties cover all integer widths, arithmetic/boolean operators, constants, virtual registers, slots, memory, comparisons, and branches. Each generated program is validated, assembled with varied seeds, decoded, executed, and compared with an independent host-side width-aware oracle. Division by zero and invalid shifts are generated deliberately and must fail with the documented diagnostic instead of becoming undefined behavior.

Artifact mutation tests begin from valid serialized objects, archives, linked headers, and VM bytecode. Targeted changes attack verifier predicates, pass preconditions, range arithmetic, counts, indexes, branch targets, opcodes, and resource limits. The suite reports killed/total mutations and fails if any required mutant survives. This is practical mutation testing of the externally trusted bytes; source-level mutation tooling remains optional because no stable Windows C++ mutator is available in the toolchain.

## Diagnostics

Structured diagnostics gain optional detailed explanation, remediation, and lineage entries while preserving the existing severity/code/message contract. Text and JSON renderers include these fields deterministically. Hardening failures use stable codes, bounded contextual values, and no raw host pointers or sensitive environment state.

## Performance benchmarking

An opt-in `binobf-benchmarks` executable measures detection, parsing, reconstruction, verification, and VM decode/execute throughput with warmup and monotonic timing. It accepts explicit fixtures and iteration counts, reports bytes/second and operations/second, and never turns timing into a correctness assertion. Benchmark output is evidence for regressions, not a semantic oracle.

## Acceptance

The milestone requires ordinary Debug/Release CTest, a full UBSan CTest build, bounded libFuzzer smoke runs, generated property success, a 100% required artifact-mutation kill rate, benchmark execution on real fixtures, standalone public-header compilation, analyzer checks, installation, and updated capability documentation.

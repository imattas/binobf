# binobf Milestone 1 Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and verify the first production-quality binobf vertical slice: core types, diagnostics, deterministic randomness, safe binary-format detection, and a usable inspection CLI.

**Architecture:** A C++20 `binobf_core` library owns all behavior and public APIs. The CLI is a thin adapter over the library, format recognition uses bounded structured header reads, and tests exercise the public interfaces without third-party test dependencies.

**Tech Stack:** C++20, CMake 3.25+, Ninja, Clang/clang-cl, CTest.

## Global Constraints

- Treat all binary input as untrusted and validate every offset, count, and range before reading.
- Never perform transformations by blindly modifying byte arrays.
- No owning raw pointers or exceptions across major subsystem boundaries.
- All randomized behavior must use an explicitly seeded project PRNG.
- The CLI and external applications use the same public library API.
- Capability claims use only `supported`, `experimental`, `planned`, or `unsupported` and must match tests.
- This workspace is not a Git repository, so commit steps are omitted rather than initializing or mutating Git state without user direction.

---

## File Map

- `CMakeLists.txt`: project options, library/CLI/test targets, warning policy, and install rules.
- `cmake/BinobfWarnings.cmake`: portable warning-as-error configuration.
- `include/binobf/core/result.hpp`: explicit success/error result type.
- `include/binobf/core/types.hpp`: format/type/architecture enums, stable IDs, addresses, and string conversion.
- `include/binobf/core/model.hpp`: normalized binary image and entity value types.
- `include/binobf/core/diagnostic.hpp`: structured diagnostics and text/JSON rendering.
- `include/binobf/support/deterministic_rng.hpp`: stable seeded PRNG API.
- `include/binobf/formats/detector.hpp`: format-detection request/result and detector interface.
- `include/binobf/cli/command.hpp`: reusable CLI dispatcher.
- `src/core/types.cpp`, `src/core/diagnostic.cpp`, `src/support/deterministic_rng.cpp`: core implementations.
- `src/formats/detector.cpp`: bounded format header recognition.
- `src/cli/command.cpp`, `tools/binobf/main.cpp`: commands and process adapter.
- `tests/test_support.hpp`: focused assertion and test-runner helpers.
- `tests/unit/*.cpp`: unit coverage.
- `tests/integration/cli_tests.cpp`: in-process CLI integration coverage.
- `README.md`, `docs/*.md`: accurate architecture, formats, security boundary, and developer instructions.

### Task 1: Build foundation and typed core model

**Files:**
- Create: `CMakeLists.txt`
- Create: `cmake/BinobfWarnings.cmake`
- Create: `include/binobf/core/result.hpp`
- Create: `include/binobf/core/types.hpp`
- Create: `include/binobf/core/model.hpp`
- Create: `src/core/types.cpp`
- Create: `tests/test_support.hpp`
- Create: `tests/unit/core_types_tests.cpp`

**Interfaces:**
- Produces: `enum class BinaryFormat`, `BinaryType`, `Architecture`; `EntityId`; `BinaryAddress`; `Result<T, E>`; `to_string(...)`; normalized `BinaryImage` entity containers.

- [x] **Step 1: Write the failing core-type tests**

```cpp
TEST_CASE(core_enum_names_are_stable) {
    REQUIRE_EQ(binobf::to_string(binobf::BinaryFormat::PE), "PE");
    REQUIRE_EQ(binobf::to_string(binobf::Architecture::X86_64), "x86-64");
}

TEST_CASE(entity_ids_are_value_identifiers) {
    const binobf::EntityId first{42};
    REQUIRE(first == binobf::EntityId{42});
    REQUIRE(first != binobf::EntityId{43});
}
```

- [x] **Step 2: Configure and prove the tests fail before implementation**

Run: `cmake -S . -B build/debug -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBINOBF_WARNINGS_AS_ERRORS=ON && cmake --build build/debug`

Expected: compilation fails because the core headers/implementations are not yet present.

- [x] **Step 3: Implement the typed values and normalized model**

Use scoped enums and value types. `BinaryImage` owns vectors of sections, segments, symbols, imports, exports, relocations, functions, data objects, unwind/debug records, and resources. Every entity contains an `EntityId` and `TransformationLineage`; no raw pointer is retained.

- [x] **Step 4: Build and run the focused test**

Run: `cmake --build build/debug && ctest --test-dir build/debug -R core_types --output-on-failure`

Expected: `core_types` passes with zero compiler warnings.

### Task 2: Structured diagnostics and deterministic randomness

**Files:**
- Create: `include/binobf/core/diagnostic.hpp`
- Create: `src/core/diagnostic.cpp`
- Create: `include/binobf/support/deterministic_rng.hpp`
- Create: `src/support/deterministic_rng.cpp`
- Create: `tests/unit/diagnostic_tests.cpp`
- Create: `tests/unit/deterministic_rng_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `EntityId`, `BinaryAddress`.
- Produces: `Diagnostic`, `DiagnosticSeverity`, `DiagnosticRenderer::text/json`; `DeterministicRng(seed)`, `next_u64()`, `uniform(bound)`, and deterministic `shuffle(span)`.

- [x] **Step 1: Write diagnostics and PRNG contract tests**

```cpp
TEST_CASE(rng_same_seed_has_same_sequence) {
    binobf::DeterministicRng a{8675309};
    binobf::DeterministicRng b{8675309};
    for (int i = 0; i < 32; ++i) REQUIRE_EQ(a.next_u64(), b.next_u64());
}

TEST_CASE(json_diagnostic_escapes_context) {
    const binobf::Diagnostic d{binobf::DiagnosticSeverity::Error,
        "format.truncated", "bad \"header\""};
    REQUIRE(binobf::render_json(d).find("bad \\\"header\\\"") != std::string::npos);
}
```

- [x] **Step 2: Run and observe missing-interface failures**

Run: `cmake --build build/debug`

Expected: compilation fails on the new diagnostic and RNG includes.

- [x] **Step 3: Implement diagnostics and a specified SplitMix64 generator**

Implement SplitMix64 with unsigned wraparound, rejection sampling for bounded integers, Fisher-Yates shuffle, stable severity strings, and a complete JSON string escaper for control characters.

- [x] **Step 4: Run focused tests**

Run: `ctest --test-dir build/debug -R "diagnostic|deterministic_rng" --output-on-failure`

Expected: both tests pass and the PRNG golden sequence remains stable.

### Task 3: Safe binary-format detector

**Files:**
- Create: `include/binobf/formats/detector.hpp`
- Create: `src/formats/detector.cpp`
- Create: `tests/unit/format_detector_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `std::span<const std::byte>`, optional source path, core enums, `Result`.
- Produces: `DetectionResult { BinaryFormat format; BinaryType type; Architecture architecture; std::uint64_t entryPoint; }` and `detect_binary(...) -> Result<DetectionResult, Diagnostic>`.

- [x] **Step 1: Write a table-driven format test suite**

Construct harmless byte vectors for ELF32/x86, ELF64/x86-64, ELF64/ARM64, PE32/x86, PE32+/x86-64 DLL, PE32+/ARM64 `.sys`, COFF x86/x86-64/ARM64 objects, and archives. Assert the exact normalized result for each.

- [x] **Step 2: Add malformed-input tests**

Cover empty input, every truncated magic/header boundary, a PE offset beyond the buffer, unsupported ELF byte order, zero/oversized COFF section counts, incomplete COFF section tables, and unknown bytes. Assert stable diagnostic codes.

- [x] **Step 3: Run tests and observe detector failures**

Run: `cmake --build build/debug`

Expected: compilation fails because `detector.hpp` does not exist.

- [x] **Step 4: Implement checked header readers and detection**

Use helpers equivalent to:

```cpp
bool contains_range(std::size_t offset, std::size_t length, std::size_t size);
Result<std::uint16_t, Diagnostic> read_u16(std::span<const std::byte>, std::size_t, Endian);
Result<std::uint32_t, Diagnostic> read_u32(std::span<const std::byte>, std::size_t, Endian);
```

Recognize formats in collision-safe order: archive, ELF, valid PE, then COFF. Validate class-specific ELF header sizes, PE signatures and optional-header magic, and checked COFF section-table extent.

- [x] **Step 5: Run detector tests and sanitizer-friendly edge cases**

Run: `ctest --test-dir build/debug -R format_detector --output-on-failure`

Expected: every valid and malformed case passes without access violations.

### Task 4: Inspection CLI vertical slice

**Files:**
- Create: `include/binobf/cli/command.hpp`
- Create: `src/cli/command.cpp`
- Create: `tools/binobf/main.cpp`
- Create: `tests/integration/cli_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: detector and diagnostic rendering APIs.
- Produces: `run_cli(std::span<const std::string_view>, std::ostream&, std::ostream&) -> int`; executable commands `inspect`, `formats`, `architectures`, and `help`.

- [x] **Step 1: Write CLI integration tests first**

```cpp
TEST_CASE(inspect_reports_a_valid_elf_object) {
    const auto fixture = write_temp_fixture(make_elf64_relocatable_x86_64());
    std::ostringstream out, err;
    const std::array args{"inspect"sv, fixture_view};
    REQUIRE_EQ(binobf::cli::run_cli(args, out, err), 0);
    REQUIRE_CONTAINS(out.str(), "format: ELF");
    REQUIRE_CONTAINS(out.str(), "type: relocatable-object");
    REQUIRE(err.str().empty());
}
```

Also cover missing command, missing path, nonexistent file, unknown file, JSON diagnostics, and read-only behavior by hashing the fixture before and after inspection.

- [x] **Step 2: Build and observe missing CLI failures**

Run: `cmake --build build/debug`

Expected: compilation fails because the CLI dispatcher is not implemented.

- [x] **Step 3: Implement the library-backed command dispatcher**

Parse exact commands and `--diagnostics=text|json`; reject unknown options; cap input allocation; read files without write access; print stable key/value lines; return `0` on success, `2` on usage errors, and `3` on inspection failures.

- [x] **Step 4: Build and run CLI tests**

Run: `ctest --test-dir build/debug -R cli --output-on-failure`

Expected: CLI integration tests pass.

- [x] **Step 5: Exercise the real executable**

Run: `build\debug\binobf.exe formats` and `build\debug\binobf.exe architectures`

Expected: both commands exit `0`, list x86/x86-64/ARM64 detection as supported, and do not overclaim parsing or transformation support.

### Task 5: Substantive Milestone 1 documentation

**Files:**
- Create: `README.md`
- Create: `docs/architecture.md`
- Create: `docs/formats.md`
- Create: `docs/ir.md`
- Create: `docs/transformation-passes.md`
- Create: `docs/virtualization.md`
- Create: `docs/lineage.md`
- Create: `docs/verification.md`
- Create: `docs/configuration.md`
- Create: `docs/plugin-development.md`
- Create: `docs/security-boundaries.md`
- Create: `docs/developer-guide.md`

**Interfaces:**
- Consumes: verified executable behavior and actual capability matrix.
- Produces: build/quick-start instructions, architecture diagrams, safety constraints, and honest development status.

- [x] **Step 1: Document only verified support**

Mark header detection and inspection as supported for tested containers. Mark detailed parsing, emission, transformations, configuration, lineage persistence, plugins, and virtualization as planned. Explain why object-time transformations precede linked-binary rewriting.

- [x] **Step 2: Add copy-pasteable build and test commands**

Document Ninja + Clang commands for Debug/Release, CTest use, CLI examples, warning policy, and the no-LLVM Milestone 1 bootstrap with planned adapter integration.

- [x] **Step 3: Validate documented commands**

Run every build, test, and CLI command shown in the README. Correct documentation if output or paths differ.

### Task 6: Completion verification and review

**Files:**
- Modify only files implicated by verification failures.

**Interfaces:**
- Consumes: the entire Milestone 1 repository.
- Produces: fresh Debug/Release evidence and an intentional-change review.

- [x] **Step 1: Run the full Debug gate**

Run: `cmake --build build/debug --clean-first && ctest --test-dir build/debug --output-on-failure`

Expected: clean warning-free build and all tests pass.

- [x] **Step 2: Run the full Release gate**

Run: `cmake -S . -B build/release -G Ninja -DCMAKE_BUILD_TYPE=Release -DBINOBF_WARNINGS_AS_ERRORS=ON && cmake --build build/release && ctest --test-dir build/release --output-on-failure`

Expected: clean build and all tests pass.

- [x] **Step 3: Inspect source for placeholder or forbidden behavior**

Run: `rg -n "TODO|TBD|return true;|anti-debug|process injection|remote process|payload download|reflective load" include src tools tests docs README.md`

Expected: no implementation placeholders and no forbidden capability; documentation may mention prohibited terms only to state the safety boundary.

- [x] **Step 4: Verify the user-visible vertical slice**

Inspect generated ELF, COFF, PE, and archive fixtures with the real executable; confirm malformed samples fail cleanly; hash every sample before and after to prove inspection is non-mutating.

- [x] **Step 5: Review all files and advance the checklist**

Run: `rg --files -g '!build/**'` and manually compare the result to this file map. Update the active milestone checklist, record any intentionally deferred v1 requirements, and begin the Milestone 2 object-parsing design only after all Milestone 1 gates pass.

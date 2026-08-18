# binobf Milestone 2 Object Parsing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse real ELF and COFF relocatable objects into normalized sections, symbols, and relocations and expose the result through the public API and CLI.

**Architecture:** `parse_object` dispatches to small format adapters after Milestone 1 detection. Each adapter uses checked byte readers and deterministic index-to-ID maps; no LLVM types or runtime subprocesses cross the API.

**Tech Stack:** C++20, CMake/Ninja, Clang, CTest, compiler-produced harmless object fixtures, `llvm-readobj` for external verification.

## Global Constraints

- Input is untrusted: validate all ranges, counts, entry sizes, links, and indices before access or allocation.
- Parse only relocatable objects; linked binaries return `object.unsupported_type`.
- Preserve value ownership, stable IDs, raw format indices/types, and deterministic input order.
- A malformed table fails the whole parse; do not return a partially trusted image.
- This workspace is not a Git repository, so no Git operations are part of execution.

---

### Task 1: Refine normalized object metadata

**Files:**
- Modify: `include/binobf/core/model.hpp`
- Modify: `tests/unit/core_types_tests.cpp`

**Produces:** `SectionKind`, `SymbolKind`, `Section::formatIndex/logicalSize/kind`, `Symbol::formatIndex/kind/defined`, and `Relocation::formatIndex/rawType`.

- [x] Write tests proving format indices survive copies, undefined symbols have no section, and raw relocation types are preserved:

```cpp
binobf::Symbol symbol{.id = EntityId{3}, .formatIndex = 7,
    .name = "external", .section = std::nullopt,
    .kind = SymbolKind::Function, .defined = false};
REQUIRE_EQ(symbol.formatIndex, 7U);
REQUIRE(!symbol.section.has_value());
```

- [x] Run `cmake --build build/debug` and `ctest --test-dir build/debug -R core_types --output-on-failure`; expect compilation failure on missing fields/enums.
- [x] Add the normalized fields and enums with owned values, updating existing complete aggregate fixtures.
- [x] Run `ctest --test-dir build/debug -R core_types --output-on-failure` and then `ctest --test-dir build/debug --output-on-failure`; expect all tests to pass.

### Task 2: Public object parser and ELF vertical slice

**Files:**
- Create: `include/binobf/formats/object_parser.hpp`
- Create: `src/formats/object_parser.cpp`
- Create: `src/formats/elf/object_parser.cpp`
- Create: `src/formats/object_parser_internal.hpp`
- Create: `tests/unit/elf_object_parser_tests.cpp`
- Modify: `CMakeLists.txt`

**Produces:** `parse_object(span<byte>, sourceName) -> Result<BinaryImage, Diagnostic>` and internal `parse_elf_object`.

- [x] Write literal ELF32/ELF64 tests for sections, names, symbol visibility/kind, REL/RELA targets/addends, NOBITS behavior, and stable IDs. The core contract is:

```cpp
const auto parsed = binobf::parse_object(make_elf64_relocatable(), "fixture.o");
REQUIRE(parsed.has_value());
REQUIRE_EQ(parsed.value().format, binobf::BinaryFormat::ELF);
REQUIRE_EQ(parsed.value().sections.at(0).name, ".text");
REQUIRE_EQ(parsed.value().symbols.at(0).name, "fixture_add");
REQUIRE_EQ(parsed.value().relocations.at(0).rawType, 2U);
```

- [x] Add malformed cases for table overflow/truncation, invalid string offsets, wrong `sh_link`, bad symbol indices, and linked ELF rejection.
- [x] Run `cmake --build build/debug`; expect failure because `object_parser.hpp` is absent.
- [x] Implement shared checked-read helpers and the ELF adapter, returning diagnostic codes `object.unsupported_type`, `elf.truncated`, `elf.invalid`, and `elf.unsupported` as appropriate.
- [x] Run `ctest --test-dir build/debug -R elf_object_parser --output-on-failure` and the full Debug suite.

### Task 3: COFF object vertical slice

**Files:**
- Create: `src/formats/coff/object_parser.cpp`
- Create: `tests/unit/coff_object_parser_tests.cpp`
- Modify: `src/formats/object_parser.cpp`
- Modify: `CMakeLists.txt`

**Produces:** internal `parse_coff_object`, including standard/long names, auxiliary-symbol skipping, and relocation reference resolution.

- [x] Write literal COFF tests covering inline and string-table names, section flags/alignment, primary/auxiliary symbols, undefined symbols, and relocations:

```cpp
const auto parsed = binobf::parse_object(make_coff_object(), "fixture.obj");
REQUIRE(parsed.has_value());
REQUIRE_EQ(parsed.value().sections.at(0).name, ".text");
REQUIRE(parsed.value().sections.at(0).executable);
REQUIRE_EQ(parsed.value().relocations.at(0).targetSymbol,
           std::optional{parsed.value().symbols.at(1).id});
```

- [x] Add malformed cases for section/raw/relocation/symbol/string ranges and auxiliary-count overflow.
- [x] Run `cmake --build build/debug`; expect the tests to compile but fail with `object.unsupported_format` until COFF dispatch exists.
- [x] Implement the bounded COFF adapter and raw-index maps; preserve unknown relocation numbers as `ArchitectureSpecific` plus `rawType`.
- [x] Run `ctest --test-dir build/debug -R coff_object_parser --output-on-failure` and the full Debug suite.

### Task 4: Real compiler fixture integration

**Files:**
- Create: `tests/integration/object_parser_integration_tests.cpp`
- Modify: `CMakeLists.txt`
- Reuse: `tests/fixtures/arithmetic.c`

**Produces:** CTest coverage against compiler-produced host COFF and cross-target ELF objects.

- [x] Add build rules that compile the harmless fixture to COFF and ELF without checking binaries into source.
- [x] Write an integration executable accepting fixture paths and asserting `.text`, `binobf_fixture_add`, `binobf_fixture_accumulate`, and format-specific relocation/metadata relationships:

```cpp
const auto coff = parse_file(argv[1]);
const auto elf = parse_file(argv[2]);
REQUIRE(find_symbol(coff, "binobf_fixture_add") != nullptr);
REQUIRE(find_symbol(elf, "binobf_fixture_accumulate") != nullptr);
```

- [x] Run `ctest --test-dir build/debug -R object_parser_integration --output-on-failure` and confirm both real variants are accepted.
- [x] Make only compatibility corrections required by documented real-object variants; none were required.
- [x] Cross-check counts and names with `llvm-readobj --sections --symbols --relocations <fixture>` and record the parser/LLVM counts in command output.

### Task 5: Analyze CLI and capability documentation

**Files:**
- Modify: `src/cli/command.cpp`
- Modify: `tests/integration/cli_tests.cpp`
- Modify: `README.md`
- Modify: `docs/formats.md`
- Modify: `docs/architecture.md`
- Modify: `docs/verification.md`

**Produces:** `binobf analyze <object> [--diagnostics=...]` and accurate object-parsing capability claims.

- [x] Write CLI tests for successful object counts, non-object rejection, malformed object diagnostics, and nonmutation:

```cpp
const std::array args{"analyze"sv, fixturePath};
REQUIRE_EQ(binobf::cli::run_cli(args, out, err), 0);
REQUIRE_CONTAINS(out.str(), "sections:");
REQUIRE_CONTAINS(out.str(), "symbols:");
REQUIRE_CONTAINS(out.str(), "relocations:");
```

- [x] Run `ctest --test-dir build/debug -R cli --output-on-failure`; expect the `analyze` cases to return usage error 2.
- [x] Implement `analyze` through `parse_object`; keep file I/O shared and read-only.
- [x] Update only verified capability rows and command examples.
- [x] Run the real CLI against both compiled objects, compare SHA-256 before/after, and require exit code 0 plus unchanged hashes.

### Task 6: Milestone 2 verification

**Files:**
- Modify only files implicated by failures.

- [x] Run `cmake --build build/debug --clean-first` and `ctest --test-dir build/debug --output-on-failure`; require zero warnings and failures.
- [x] Run `cmake --build build/release --clean-first` and `ctest --test-dir build/release --output-on-failure`; require zero warnings and failures.
- [x] Compile every public header standalone with `clang++ -std=c++20 -Wall -Wextra -Wpedantic -Werror -Iinclude -x c++ -fsyntax-only -`.
- [x] Run malformed corpus cases and confirm structured failure without crashes.
- [x] Scan implementation for unfinished markers, unchecked pointer arithmetic, forbidden behavior, and inaccurate support claims.
- [x] Review every remaining v1 gap and advance to the next object-writing/round-trip slice only after all gates pass.

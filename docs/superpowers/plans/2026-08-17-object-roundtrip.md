# binobf Canonical Object Round-Trip Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reconstruct deterministic, linkable ELF/COFF objects from normalized `BinaryImage` values.

**Architecture:** Parsers preserve minimal raw table evidence; a format-neutral writer validates relationships and dispatches to canonical ELF/COFF layout engines. Writers rebuild names, symbols, and relocations and never return original input bytes.

**Tech Stack:** C++20, CMake/CTest, Clang, `llvm-readobj`, `lld-link`/`ld.lld`.

## Global Constraints

- Checked arithmetic precedes every allocation, offset, and table extent.
- Output is deterministic and input images are immutable.
- Unresolved IDs, duplicate indices, or unsupported variants fail explicitly.
- No output is called successful until it reparses and standard tools accept it.
- This non-Git workspace receives no Git operations.

---

### Task 1: Preserve reconstruction metadata

**Files:** `include/binobf/core/model.hpp`, ELF/COFF parsers, parser/core tests.

**Produces:** `ObjectMetadata`; section `formatType/formatFlags/formatLink/formatInfo/formatEntrySize/isSectionNameTable`; symbol `formatTableIndex/formatType/formatStorage/formatOther/formatSectionIndex/auxiliaryData`; relocation `formatTableIndex`.

- [x] Add a failing parser test with literals such as:

```cpp
REQUIRE_EQ(text.formatType, UINT64_C(1));
REQUIRE_EQ(symtab.formatLink, 3U);
REQUIRE_EQ(function.formatStorage, 1U);
REQUIRE_EQ(relocation.formatTableIndex, 5U);
```

- [x] Run parser tests and confirm missing-field compilation failure.
- [x] Add fields and populate them from ELF/COFF entries, including copied COFF auxiliary bytes.
- [x] Run all eight tests and require zero regressions.

### Task 2: Writer validation and public API

**Files:** create `include/binobf/formats/object_writer.hpp`, `src/formats/object_writer.cpp`, `src/verify/object_model_validator.cpp`, tests.

**Produces:** `write_object(const BinaryImage&) -> Result<vector<byte>, Diagnostic>`.

- [x] Write failing tests for duplicate IDs/format indices, dangling section/symbol references, missing table owners, unsupported formats, and input immutability.
- [x] Implement validation with diagnostic codes `object.model_invalid`, `object.unsupported_format`, and `object.size_limit`.
- [x] Add dispatch stubs that return format-specific unsupported diagnostics until each writer lands.
- [x] Run validator tests and the full suite.

### Task 3: Canonical ELF writer

**Files:** create `src/formats/elf/object_writer.cpp`, `tests/unit/elf_object_writer_tests.cpp`.

**Produces:** deterministic ELF32/ELF64 section, string, symbol, REL, and RELA reconstruction.

- [x] Parse the synthetic ELF fixtures, call `write_object`, and assert reparse relationships:

```cpp
const auto output = binobf::write_object(parsed.value());
REQUIRE(output.has_value());
const auto reparsed = binobf::parse_object(output.value(), "roundtrip.o");
REQUIRE_EQ(reparsed.value().symbols.at(0).name, "fixture_add");
REQUIRE_EQ(reparsed.value().relocations.at(0).addend, INT64_C(-4));
```

- [x] Confirm RED on `elf.writer_unavailable`.
- [x] Implement string-table rebuilding, symbol/relocation encoding, checked layout, and section headers.
- [x] Assert two writes of the same image are byte-identical.
- [x] Run focused and full tests.

### Task 4: Canonical COFF writer

**Files:** create `src/formats/coff/object_writer.cpp`, `tests/unit/coff_object_writer_tests.cpp`.

**Produces:** deterministic sections, relocations, primary/auxiliary symbols, and string-table reconstruction.

- [x] Parse the synthetic COFF fixture, write/reparse, and assert long names, aux gaps, and relocation target IDs survive.
- [x] Confirm RED on `coff.writer_unavailable`.
- [x] Implement canonical layout and raw-index-preserving symbol emission.
- [x] Assert deterministic bytes and malformed model rejection.
- [x] Run focused and full tests.

### Task 5: Real link and runtime round trips

**Files:** add `tests/fixtures/driver.c`, `tests/integration/object_writer_integration_tests.cpp`, and CMake fixture/link rules.

- [x] Round-trip compiler-produced COFF and ELF fixtures and reparse output in CTest.
- [x] Run `llvm-readobj --sections --symbols --relocations` on both outputs and require exit 0.
- [x] Link original and rewritten COFF objects with the same harmless driver, run both executables, and require exit code 0.
- [x] Link rewritten ELF relocatable output with `ld.lld -r` on Windows; run the ELF executable path on ELF CI/hosts.
- [x] Compare normalized counts/names/relocation relationships after external linking.

### Task 6: CLI round-trip and milestone verification

**Files:** CLI tests/implementation and capability documentation.

- [x] Add failing `binobf transform input.o -o output.o --passes=none` tests proving no mutation of input and structural equality of output.
- [x] Implement the no-pass round-trip through `parse_object` and `write_object`, then reparse before reporting success.
- [x] Run clean Debug/Release builds, all tests, standalone-header compilation, static analysis, and source scans.
- [x] Mark object emission supported only for variants proven linkable; keep transformations planned until the next slice.

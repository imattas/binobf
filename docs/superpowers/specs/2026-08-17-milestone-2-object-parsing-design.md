# binobf Milestone 2 Object Parsing Design

## Status

Approved for implementation under the parent binobf milestone sequence. This refinement follows the verified Milestone 1 interfaces and the locally available toolchain.

## Goal

Parse little-endian ELF relocatable objects and standard COFF objects into a normalized, value-owned `BinaryImage` containing sections, symbols, and relocations with stable IDs and actionable diagnostics.

## Dependency decision

The installed LLVM distribution provides compiler and inspection executables but no SDK headers, libraries, `llvm-config`, or CMake package. Invoking `llvm-readobj` as a hidden runtime subprocess would make the public library environment-dependent and require parsing human-oriented output. Milestone 2 therefore uses focused internal adapters behind a format-neutral `parse_object` API. The adapters cover documented ELF/COFF structures with checked arithmetic and can later be replaced by LLVM implementations without changing consumers.

## Normalized model refinements

Sections and symbols retain their original format-table indices in addition to stable `EntityId`s. Sections gain a normalized kind; symbols gain kind, visibility, and definition state; relocations retain normalized kind plus the raw format relocation number. Format indices are diagnostics/writer evidence, not identity.

Entity IDs are assigned deterministically in input-table order. Section index maps and raw symbol-index maps resolve references without storing pointers. Auxiliary COFF symbol records receive no normalized entity but remain represented as gaps in the raw-index map so relocation references are resolved correctly.

## ELF adapter

The ELF parser accepts class 32/64, little-endian, version-1 relocatable objects for x86, x86-64, and ARM64. It validates the ELF header, section table arithmetic, each section extent, string-table links, symbol entry sizes/counts, symbol name offsets, relocation links, and every symbol/target-section index.

`SHT_NOBITS` sections have logical size but no file bytes. `SHT_SYMTAB` and `SHT_DYNSYM` symbols are normalized. `SHT_REL` and `SHT_RELA` entries become relocations with explicit addends where present. Unsupported relocation numbers remain `ArchitectureSpecific`; malformed structure is an error rather than a partial parse.

## COFF adapter

The COFF parser accepts standard 20-byte object headers for x86, x86-64, and ARM64. It validates section tables, raw-data ranges, relocation arrays, symbol-table extent, auxiliary-record counts, and the trailing string table. Inline names, symbol long names, and slash-decimal section long names are supported.

Sections, primary symbols, and relocations are normalized in input order. Storage class and type derive visibility/kind. Undefined/absolute/debug symbols have no section entity. COFF addends remain zero in the normalized relocation record because they are encoded in section contents; relocation raw types are preserved.

## Public and CLI behavior

`parse_object(bytes, sourceName)` first calls the verified detector, rejects non-object inputs, and dispatches to the relevant adapter. `binobf analyze <object>` prints format, architecture, section/symbol/relocation counts, and deterministic section summaries. `inspect` continues to be read-only and gains object counts only after a successful parse; malformed objects fail with structured text or JSON diagnostics.

## Verification

Unit tests cover handcrafted boundary conditions and exact normalized mappings. Integration tests parse real COFF and ELF objects compiled from the harmless arithmetic fixture, compare expected named sections/symbols/relocations, and cross-check them manually with `llvm-readobj`. Debug and Release warning-as-error builds and the existing Milestone 1 suite remain mandatory.

## Deferred work

COFF bigobj, ELF extended section numbering, archive members, import libraries, debug-record decoding, linked-image detailed parsing, and object writing are deferred to explicit follow-on slices. Unsupported variants return diagnostics and are not labeled supported.

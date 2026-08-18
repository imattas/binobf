# binobf Canonical Object Round-Trip Design

## Status

Approved as the correctness prerequisite for Milestone 3 transformations.

## Goal

Write valid ELF and COFF relocatable objects from `BinaryImage`, then prove parse-write-parse structural equivalence, standard-tool acceptance, linker acceptance, and unchanged fixture behavior.

## Model evidence required for reconstruction

The normalized model will retain raw format evidence without making it entity identity. Sections record raw type/flags/link/info/entry-size and whether they are the ELF section-name table. Symbols record their owning symbol-table index, raw type/storage/other values, special raw section index, and auxiliary bytes. Relocations record their owning relocation-table index. `BinaryImage` records small object-header attributes such as ELF OSABI/ABI version/flags and COFF characteristics.

These fields are populated by parsers and validated by writers. Stable `EntityId` references remain authoritative for relationships; raw indices are used to preserve table order and externally meaningful numbering.

## ELF writer

The writer emits a canonical little-endian ELF32 or ELF64 relocatable object based on architecture. It preserves section order, rebuilds all string tables from section/symbol names, rebuilds symbol tables in raw-index order, rebuilds REL/RELA entries from entity references, lays out non-NOBITS data with checked alignment, and emits a final section-header table.

The writer refuses missing section-name tables, duplicate raw indices, unsupported section types/classes, unresolved IDs, invalid entry sizes, and relationships inconsistent with raw `sh_link`/`sh_info`. It never copies the original ELF header or symbol/relocation bytes as an opaque shortcut.

## COFF writer

The writer emits a standard 20-byte COFF object header, section headers, aligned section data, relocation arrays, primary/auxiliary symbol records, and a rebuilt string table. Section names longer than eight bytes use slash-decimal offsets; symbol names longer than eight bytes use the COFF long-name union. Raw symbol indices including auxiliary gaps are preserved, and relocation targets resolve through stable symbol IDs.

Timestamps are zero for deterministic output. Raw section characteristics, symbol type/storage class, special section numbers, and auxiliary data are preserved after validation. Bigobj and relocation-overflow encoding remain unsupported.

## API and transactions

`write_object(const BinaryImage&)` returns bytes or a structured diagnostic. It operates on local layout state and never mutates the input image. `validate_object_model` runs first and verifies unique IDs/indices, references, format-specific required fields, size limits, and table ownership.

## Verification

- synthetic ELF32/ELF64/COFF parse-write-parse tests compare normalized entities and relationships;
- real compiler objects round-trip through the writer and reparse;
- `llvm-readobj` accepts and reports expected sections/symbols/relocations;
- Clang/lld link rewritten objects with a harmless driver;
- the linked COFF executable runs and returns the same result as the original fixture build;
- identical image input produces byte-identical output.

Only after these gates pass can metadata transformations use the writer.

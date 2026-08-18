# Formats

## Current support

Milestone 1 safely detects and classifies these headers:

| Container | Recognized kinds | Architectures |
|---|---|---|
| PE | executable, DLL, `.sys` driver | x86, x86-64, ARM64 |
| COFF | relocatable object | x86, x86-64, ARM64 |
| ELF | relocatable, executable, shared object | x86, x86-64, ARM64 |
| `ar` archive | GNU/BSD static archive, COFF `.lib`, PE import library | member-dependent |

Detection validates fixed headers, declared offsets, and COFF/PE section-table extent. `parse_object` supports little-endian ELF32/ELF64 relocatable objects, ELF extended section numbering, `SHN_XINDEX`, standard COFF objects, and COFF bigobj objects. `parse_archive` supports bounded `ar` members, GNU/COFF long names, BSD extended names, GNU and Microsoft linker indexes, ELF/COFF object members, and COFF import records. `parse_linked_image` supports PE32/PE32+ executables, DLLs, and `.sys` files plus ELF32/ELF64 executables, PIEs, and shared objects. Writers reconstruct objects and archives; linked rewriting preserves exact bytes unless an explicit address-stable metadata pass is selected.

## Object parsing

ELF parsing validates section tables and contents, section/string-table links, symbol tables, REL/RELA tables, symbol/section indices, and entry sizes. It normalizes section permissions/kinds, primary symbols, explicit RELA addends, raw relocation types, and stable cross-entity IDs. Extended section counts, extended section-name indexes, and `SHN_XINDEX` symbol references are preserved through the normalized model and deterministic writer.

COFF parsing validates standard and bigobj section, relocation, symbol, auxiliary-record, and string-table structures. It supports inline and string-table symbol names plus slash-decimal long section names. Auxiliary records are validated and skipped while their raw indices remain gaps, preventing relocations from binding to an auxiliary record. Relocation-overflow encoding remains unsupported.

ELF emission rebuilds section-name and symbol string tables, symbol tables, REL/RELA entries, section data, headers, and checked alignment. COFF emission rebuilds standard headers, section data, per-section relocations, primary/auxiliary symbol slots, and long-name storage. Both writers are deterministic and reject dangling IDs, inconsistent raw indices, unsupported encodings, and size overflow.

## Linked-image parsing and rewriting

PE parsing validates the DOS/NT/optional headers, file/section alignment, non-overlapping section mappings, entry point, data-directory ranges, imports and thunks, exports, base-relocation blocks, raw resource tree, x86-64 runtime-function entries, TLS/load-configuration extents, debug records, certificate table, and checksum state. Unknown optional directory payloads remain visible and byte-preserved. ARM64/x86 exception-directory bytes are range-validated but their unwind semantics remain explicitly unsupported.

ELF linked parsing validates program and section mappings, load alignment, entry point, static/dynamic symbol tables, imports/exports, REL/RELA tables, dynamic tags, interpreter, PIE flags, GOT/PLT relocation relationships, notes, and unwind/debug section ranges. Program-header dynamic/interpreter/note metadata remains available even when section headers are absent. General `.eh_frame` semantic decoding remains unsupported.

Linked `--passes=none` is byte-identical. Linked `strip-debug` never moves a loaded range. PE debug directory/data are cleared and the checksum is rebuilt; signed input requires `--allow-signature-invalidation`, which clears and reports the certificate. Non-allocated ELF debug sections and their dependent relocation sections become empty `SHT_NOBITS` entries without index changes. Other post-link code/layout passes are rejected. `inspect` reports shallow header facts; `analyze` reports normalized format facts; `verify` selects the appropriate object, archive, or linked structural verifier.

## Archive parsing and reconstruction

Archive parsing validates every 60-byte header, numeric field, payload range, padding byte, long-name reference, linker-index count, member offset, member index, and terminated symbol name before allocation. Recognized relocatable members are parsed through the existing ELF/COFF adapter; import objects and opaque payloads remain explicit and byte-preserved. Unchanged archives return the exact source bytes.

After an eligible object changes, reconstruction preserves ordinary member order and metadata, emits a deterministic long-name table, calculates final header offsets, and rebuilds symbol relationships from post-transform defined external symbols. GNU/BSD inputs receive a GNU-compatible big-endian index. COFF `.lib` output receives the big-endian first linker member and sorted little-endian second linker member. Import libraries are classified separately and their structural records are not transformed.

## Validation policy

- ELF requires a complete 32-bit or 64-bit little-endian header, version 1, a consistent declared header size, and a recognized object type.
- PE linked parsing additionally requires bounded aligned sections, file-backed mandatory directories, a mapped executable entry point, terminated import/export tables, and valid security/debug ranges.
- `.sys` classification is accepted only after PE validation. An arbitrary file named `.sys` remains unknown.
- COFF objects require a supported machine, no optional header, a bounded nonzero section count, and a complete section table.
- Archives require the exact `!<arch>\n` signature, bounded headers and padding, valid name-table references, and valid GNU/COFF symbol-to-member relationships.

## Remaining adapters

Exact-size x86-64 object instruction/CFG rewrites, whole-function layout variation, archive member transformation/reconstruction, restricted standalone VM lowering and selected-function VM embedding, and conservative linked PE/ELF debug rewriting are supported on verified parse/write-or-rewrite/parse foundations. Post-link code relocation, size-changing general code generation, and full architecture-specific unwind decoding remain planned. Thin archives are unsupported. Linked `.sys` transformations remain metadata-only by default and no signing-bypass behavior is provided.

Mach-O is unsupported in v1, but format-neutral core types and adapter boundaries reserve a clean future integration path.

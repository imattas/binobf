# Milestone 11 Archives Design

## Outcome

Milestone 11 makes Unix `.a` and Windows COFF `.lib` archives first-class containers. binobf parses members without extracting them to temporary files, transforms eligible ELF/COFF relocatable members through the existing verified object pipeline, rebuilds archive name and symbol indexes, and verifies the reconstructed container with both binobf and standard LLVM tools.

## Normalized archive model

`ArchiveImage` owns exact source bytes, detected flavor, stable member IDs, member metadata, resolved names, payloads, layout records, and symbol-to-member relationships. `ArchiveMemberKind` distinguishes relocatable objects, COFF import objects, symbol indexes, long-name tables, and opaque members. Linker and name-table members are never dispatched to the object parser.

The parser accepts the common 60-byte ar header, strict decimal fields, the `` `\n `` trailer, even-byte padding, GNU/COFF `/offset` names, BSD `#1/length` names, ordinary slash-terminated names, GNU `/` and `/SYM64/` indexes, COFF first/second linker members, BSD symbol-table names, and `//` long-name tables. Every count, offset, string, member range, and symbol reference is bounded before allocation. Unknown ordinary members remain byte-preserved and explicitly opaque.

## Reconstruction and indexes

If no member payload or order changed, baseline writing returns the original bytes exactly. Otherwise the writer preserves ordinary member order and metadata, emits a canonical long-name table when needed, recalculates every final member header offset, and then builds symbol indexes from defined external symbols in successfully parsed object members plus supported COFF import-object names.

GNU/BSD-input archives are emitted with a GNU-compatible big-endian symbol index. COFF libraries receive both Microsoft linker members: the big-endian first index and little-endian member/symbol tables with 1-based member indices. Index and long-name headers use deterministic metadata. A second layout pass ensures index offsets refer to final member headers after index sizes are known.

## Transformation policy

The archive transform path applies the requested object passes independently and transactionally to each eligible member. Unsupported/opaque/import members are preserved with explicit skipped statistics. One member failure aborts the entire archive transaction. A seed is derived deterministically from the build seed and stable member identity so member ordering does not introduce ambient randomness.

Archive writing does not run linked-image transforms, unpack executable payloads, or execute members. Import-library objects are structural linker records and remain preserved rather than rewritten as machine code.

## Verification

`verify_archive` reparses the rebuilt bytes, validates member/layout/name/index relationships, verifies every recognized relocatable member through `verify_object`, and checks that every emitted archive symbol resolves to the intended member. Real fixtures include compiler-produced ELF and COFF objects, a GNU `.a`, a COFF `.lib`, long member names, and a Windows import library. LLVM listing/symbol inspection and standard linker/runtime consumers gate support.

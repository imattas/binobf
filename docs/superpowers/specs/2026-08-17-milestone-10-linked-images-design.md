# Milestone 10 Linked Images Design

## Outcome

Milestone 10 adds bounded, structured parsing and conservative rewriting for linked PE32/PE32+ executables, DLLs, and drivers plus ELF32/ELF64 executables, PIEs, and shared objects. The first writable transformations deliberately keep every loaded address and file range stable: byte-preserving round trip and removal of non-executable debug metadata. This makes metadata repair small enough to verify exhaustively while establishing the public linked-image model needed by later code-layout work.

## Public model and parser boundary

`LinkedImage` owns the normalized `BinaryImage`, original bytes, image base, entry point, section/segment layout records, format directories, signing state, and format-specific offsets required for verified reconstruction. Long-lived relationships use entity IDs; file offsets and RVAs are explicit value fields, never host pointers. `parse_linked_image` first uses the existing detector, accepts only PE or linked ELF kinds, applies caller-visible resource ceilings before allocation, and rejects every truncated, overlapping, overflowing, or unmappable mandatory range.

PE parsing covers DOS/NT/optional headers, section mappings, all declared data directories, imports, exports, base relocations, resources, exception/runtime-function entries, TLS, load configuration, debug directory entries, and the Authenticode certificate table. ELF parsing covers ELF/program/section headers, load segments, static and dynamic symbols, imports/exports, REL/RELA relocations, dynamic metadata, interpreter/GOT/PLT relationships, notes, and unwind/debug sections. Unknown optional directory payloads remain preserved byte-for-byte and visible as typed directory records rather than being guessed through.

## Conservative rewrite contract

`rewrite_linked_image` operates from parsed layout records and returns a report containing output bytes, diagnostics, statistics, and explicit signature state. With no passes it returns an exact byte-for-byte image after reparsing and structural verification.

The initial linked `strip-debug` pass changes no loaded code/data address. For PE it clears the debug data-directory entry, debug-directory records, and each validated referenced raw-data range, then recomputes the PE checksum. For ELF it accepts only non-allocated debug sections, clears their payloads, and rewrites their section headers to empty `SHT_NOBITS` records without renumbering sections. Dependent non-allocated debug relocation sections are cleared in the same transaction. Any allocated debug section causes a safe rejection.

Authenticode uses a file-offset directory outside PE RVA mapping. A signed PE is never modified by default. Explicit signature invalidation clears the security-directory entry and certificate bytes, reports that the signature was removed, and recomputes the checksum; it never claims a prior signature remains valid. Linked drivers remain restricted to byte-preserving output and explicitly authorized debug stripping. No linked code transformation is enabled until function, relocation, unwind, and load-configuration repair are independently proven.

## Verification

Every output reparses through the public parser and passes a linked structural verifier. PE checks include headers, section/raw/RVA mappings, directories, imports/exports, relocations, exception ranges, TLS/load-config/debug/security ranges, entry point, checksum, and signature state. ELF checks include headers, program/section ranges, load mappings, symbols, dynamic metadata, relocations, entry point, and section-to-segment containment.

Compiler/linker-produced x86-64 fixtures cover a Windows executable and DLL plus Linux executable, PIE, and shared object. Baseline output must be byte-identical and remain accepted by LLVM. Debug-stripped outputs must contain no parsed debug records, preserve imports/exports and loaded ranges, and retain native behavior. Malformed synthetic fixtures target every bounded table and mapping rule.

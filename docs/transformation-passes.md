# Transformation Passes

The baseline and first x86-64 object machine-code pipelines are implemented. Machine passes are deliberately pattern-bounded and decline any function that cannot be decoded, reconstructed, and verified completely.

| Pass family | Risk | Intended first mode | Status |
|---|---:|---|---|
| Debug stripping | low | ELF/COFF object | supported on x86-64; experimental on x86/ARM64 |
| Linked debug stripping | low | PE/ELF linked image | supported, address-stable |
| Private-symbol renaming | low | ELF/COFF object | supported on x86-64; experimental on x86/ARM64 |
| Metadata cleanup | low | ELF/COFF object | supported on x86-64; experimental on x86/ARM64 |
| Function layout | medium | x86-64 ELF/COFF object | supported for whole proven function chunks |
| Constant rewriting | medium | x86-64 ELF/COFF object | supported for proven equivalent `MOV` encodings |
| Instruction substitution | medium | x86-64 ELF/COFF object | supported for validated multi-byte NOPs |
| Branch inversion | medium | x86-64 ELF/COFF object | supported for adjacent direct `Jcc; JMP` pairs |
| Block splitting | medium | x86-64 ELF/COFF object | supported through exact-size NOP-window splits |
| CFG transformation | high | standalone VM lowering of selected object functions | supported: flatten, safe outline, split |
| Selected-function virtualization | high | embedded bytecode and ABI adapter in x86-64 COFF/ELF objects | restricted but supported |
| Archive member pipeline | member pass risk | ELF/COFF objects in `.a`/`.lib` | supported; indexes rebuilt |

Every pass declares architecture/format support and requirements such as CFG, relocations, lifted IR, code-size changes, and post-link eligibility. Ordering is dependency-aware and deterministic, randomized choices come from an explicit seed, and serialization or reparsing failure rolls the candidate model back. Dry-run uses the same verification path without committing output. Strict TOML function selection can constrain every function-scoped machine pass by original name or regex, section, visibility, denylist, and deterministic percentage sampling.

Externally visible ABI symbols are never silently renamed. Aggressive linked-driver transformations are disabled by default. Missing relocation, unwind, or control-flow information causes a safe skip rather than speculative rewriting.

The built-in `minimal` profile runs debug stripping, metadata cleanup, unreferenced-local-symbol stripping, then private-symbol renaming. Local symbols are removed only when they are defined, non-ABI, unreferenced by relocations, absent from the preserve list, and not guarded by raw-index metadata or opaque auxiliary records. `balanced` adds instruction substitution, constant rewriting, branch inversion, harmless dead-code insertion, block splitting, independent block reordering, and function reordering. Machine-code passes are medium risk, x86-64 object-only, exact-size, and emit a CLI warning. `strong` remains planned until its native embedding prerequisites exist.

`dead-code-insertion` converts a relocation-free, untargeted multi-byte NOP into a valid short jump over valid NOP bytes. The skipped region is unreachable and side-effect-free; no opaque environmental condition or malformed encoding is involved. `block-reordering` pins the entry block and moves only complete relocation-free functions whose blocks have no implicit fallthrough. Direct rel8/rel32 transfers are range-checked and re-encoded after movement, and the changed function must reanalyze completely before commit. Function reordering only permutes contiguous runs of selected functions; excluded function slots and bytes remain fixed.

On linked images, only `strip-debug` is applied; the other low-risk object passes report unsupported and all medium-risk code passes are rejected. PE stripping clears the debug directory and validated raw records, removes an Authenticode certificate only with explicit invalidation intent, and recomputes the checksum. ELF stripping empties non-allocated debug sections and dependent relocation sections without moving or renumbering loaded content. Linked `.sys` files use the same metadata-only boundary.

On static archives, the selected object passes run independently on each recognized ELF/COFF relocatable member. Each member seed is derived from the user seed, resolved name, format, architecture, and original payload, so repeated builds are deterministic without ambient randomness. Any member failure aborts the archive transaction. Opaque members are preserved with skipped statistics; PE import libraries preserve all structural object/import records and remain byte-identical.

Instruction substitution changes only documented multi-byte NOP encodings and re-decodes the result. Constant rewriting replaces eligible register-immediate `MOV` forms with an equivalent `C7 /0` encoding without changing flags, register value, or total byte-window size. Branch inversion exchanges the destinations of a direct conditional/unconditional pair while inverting the condition. Block splitting changes a NOP window to `JMP +0` plus NOP fill. Function reordering moves whole chunks and repairs symbol values, relocation sites, and unambiguous ELF section-symbol addends, including `.eh_frame` references.

Advanced CFG transformations are exposed only by `vm lower` and produce standalone VM bytecode. Flattening creates a deterministic dispatcher and a valid fixed-false bogus edge. Outlining accepts only a proven safe non-entry single-return block and remaps live-ins into a helper. Splitting leaves a wrapper and moves the complete body into a helper. Helper calls are real BVM1 v1.1 internal calls with bounded fresh frames.

`vm protect` handles the restricted native embedding path. It appends a Windows x64 or System V AMD64 adapter and deterministic bytecode, redirects the selected function symbol, and adds a standard relocation to the installed interpreter runtime. It rejects fixed same-object callers, unwind-described functions, incompatible formats/ABIs, and incomplete or unsupported lifting rather than guessing. It remains object-time protection; post-link native virtualization is unsupported.

# Architecture

binobf follows a compiler pipeline rather than patching arbitrary byte ranges.

```mermaid
flowchart TD
    A[Input bytes] --> B[Format detection]
    B --> C[Format adapter and parser]
    C --> D[Normalized BinaryImage]
    D --> E[Instruction decoding]
    E --> F[Function and CFG recovery]
    F --> G[binobf IR]
    G --> H[Analysis passes]
    H --> I[Transactional transformations]
    I --> J[Optional VM lowering]
    J --> K[Layout and code generation]
    K --> L[Format reconstruction]
    L --> M[Structural verification]
    M --> N[Differential verification]
    N --> O[Output and sidecars]
```

Format detection, the foundational normalized model, ELF/COFF relocatable-object parsing, canonical reconstruction, GNU/COFF archive reconstruction, object/archive structural verification, low-risk metadata passes, conservative machine-code analysis, exact-size x86-64 object transformations, restricted native-IR-to-VM lowering, standalone IR/VM control-flow transformations, and restricted selected-function VM embedding are supported. General native lifting and post-link size-changing code generation remain later milestones.

## Component boundaries

`core` contains format-independent value types: stable entity IDs, addresses, the normalized `BinaryImage`, structured diagnostics, explicit results, and transformation lineage records. Long-lived identity is numeric and stable; containers own values rather than linking entities with owning raw pointers.

`capabilities` exposes the public typed capability and acceptance-evidence registries. CLI output and the README feature matrix render from those records, and release tests require every supported record to name registered CTest evidence. Architecture backends are fixed to one architecture and expose their decode, analysis, code-generation, fixup, ABI-adapter, and unwind service levels through binobf types. Capstone remains a private implementation dependency owned by the current x86, x86-64, and ARM64 decode backends; no Capstone type crosses a public header.

`formats` recognizes containers and hosts bounded ELF/COFF relocatable-object adapters that normalize and reconstruct sections, primary symbols, auxiliary data, relocations, and string tables. Archive adapters retain stable member IDs, metadata and exact source layouts, resolve GNU/BSD/COFF member names and linker indexes, and rebuild GNU or dual-member Microsoft indexes after eligible object members change. Separate linked-image adapters normalize PE headers/directories and ELF program/dynamic metadata while retaining exact source/layout records for address-stable reconstruction. The local LLVM installation has command-line tools but no SDK, so these focused adapters sit behind binobf interfaces and can be replaced by LLVM-backed implementations without changing consumers.

`analysis` consumes architecture-owned decoding behind binobf types and provides symbol-led function discovery, relocation-aware instruction references, typed CFG edges, and backward register liveness. Unknown bytes become opaque instructions and indirect control flow stays explicit; either condition marks a function incomplete. Analysis failure reduces later transformation coverage and never licenses guessing.

`ir` represents the first semantics binobf can preserve: typed mutable variables, explicit arguments, register/immediate moves, arithmetic and bitwise operations, comparisons/tests, direct control flow, internal helper calls, returns, and source-instruction fallbacks. Validated modules require unique functions, compatible call signatures, acyclic calls, and bounded call depth. The x86-64 lifter accepts an explicit ABI/signature and preserves unsupported native operations as fallback nodes. Fallbacks block VM lowering rather than being guessed through. Deterministic flattening, safe single-return block outlining, and wrapper/helper splitting operate on fallback-free IR and validate their results.

`transforms` provides capability-declared, deterministic, transactional passes. The manager resolves dependencies, runs on a candidate model, serializes and reparses it, detects incorrect change reports, and commits only on success. A reusable function selector evaluates exact original names, bounded regexes, section/visibility constraints, deny precedence, and seed-stable sampling; name aliases preserve the policy across private-symbol renaming. Current passes strip debug sections, clean explicitly allowlisted compiler metadata, remove proven-unreferenced local symbols, rename proven-private symbols, vary validated NOPs, rewrite selected constants, invert two-way branches, insert valid unreachable NOP regions, split blocks through no-op control transfers, reorder explicit-transfer basic blocks with displacement repair, and reorder selected whole-function runs with relocation repair.

`vm` is an auditable, bounds-checked architecture-neutral execution core with typed IR, virtual registers/slots, bounded memory, explicit flags/control flow, bounded internal-call frames, a controlled native-call bridge, deterministic bytecode assembly, strict decoding, and disassembly. `ir::lower_to_vm` and `ir::lower_module_to_vm` deterministically map complete supported native IR into this core and validate the result. `vm::protect_function` appends a format-specific native ABI adapter and bytecode to a relocatable object's selected code section, redirects the function symbol, and creates a standard relocation to the installed C ABI interpreter entry point. It is not a loader, packer, or environment-detection system.

`verify` exposes shared object, archive, and linked-image structural-verification APIs used by transform commit gates and `binobf verify`. It reparses bytes, validates normalized ranges and relationships, and reports every supported, not-applicable, or unsupported check explicitly. Archive checks cover member layouts, recognized object members, linker-index references, and defined external symbol bindings. Linked checks cover sections, segments, entry points, imports/exports, relocations, directories, parsed unwind/resource/debug records, PE signature state, and nonzero PE checksums. Integration fixtures additionally exercise LLVM inspection, archive listing/linking, native PE loading/execution, relocation linking, and compile-transform-run differential matrices.

`cli` is a consumer of the same public library interfaces available to other applications. `main` adapts process arguments and streams only.

## Dependency direction

```text
CLI -> public binobf APIs
formats/analysis/transforms/vm/verify -> core
LLVM adapters -> binobf interfaces + LLVM
core -> C++ standard library only
```

This direction keeps the normalized model independently testable and allows a future Mach-O adapter without redesigning transformations.

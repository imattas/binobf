# Intermediate Representation

The first native lifted IR is implemented under `include/binobf/ir` as a typed, control-flow-aware representation organized as function, basic block, and instruction. The separate VM-independent execution IR remains under `include/binobf/vm`.

The supported native subset includes explicit argument bindings, typed mutable variables, register/immediate moves, arithmetic, bitwise operations, compare/test, direct and conditional branches, internal helper calls, returns, and architecture-specific fallbacks. Native calls, stack and general memory operations, casts/extensions, and broad native flag semantics remain planned.

The IR is not intended to be a perfect decompiler. A native instruction that cannot be lifted safely remains a fallback operation with lineage to its original address and bytes. Any pass requiring unavailable semantics returns `Unsupported` or `Skipped` for that region.

IR blocks retain stable source block IDs and every operation retains its source instruction ID and bytes where a fallback is necessary. VM lowering emits an instruction-index-to-source lineage table. Function validation checks resource ceilings, unique block/argument identities, explicit widths, variable and flag definition, control-flow targets, and terminators. Module validation additionally checks unique function IDs, entry presence, call targets/signatures, acyclic calls, and maximum call depth.

`flatten_control_flow` converts a fallback-free function to seeded dispatcher form with unique 32-bit states. A mathematically fixed false edge leads to one valid, side-effect-free bogus block and then returns to the dispatcher; no external or environmental predicate is used. `outline_block` extracts only a safe non-entry block ending in a return, computes its live-ins, remaps them to helper arguments, and replaces the block with a real internal call. `split_function` moves the original body into a helper and leaves an ABI-facing call/return wrapper. All transformations validate their results and fail closed when their preconditions are not proven.

Status: selected x86-64 `u32` register/immediate arithmetic and control-flow lifting is **restricted but supported** for complete COFF/ELF object functions. VM lowering, module lowering, advanced standalone control-flow transformations, validation, assembly, decoding, disassembly, interpretation, and selected-function embedding are **supported**. General lifting remains **planned**.

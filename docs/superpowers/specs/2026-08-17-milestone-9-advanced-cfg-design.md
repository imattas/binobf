# Milestone 9 Advanced CFG Design

## Outcome

Milestone 9 implements advanced control-flow transformations on validated binobf IR before bytecode emission. The output remains ordinary, documented VM control flow. No branch depends on debugger, timing, environment, or security-product state, and no malformed or overlapping instruction technique is used.

## Flattening and dispatcher representation

`flatten_control_flow` accepts one explicitly selected, fallback-free `IrFunction` and a seed. It allocates a typed dispatcher-state variable, deterministic unique case values, an initialization block, and a comparison-chain dispatcher. Original direct edges become state assignments followed by a return to the dispatcher. Conditional edges first choose one of two transition blocks, preserving the source condition before dispatcher comparisons replace flags.

All non-argument variables are initialized in the synthetic entry block. This does not alter valid executions, because the source validator already proves their real uses are defined, but it keeps conservative must-definition analysis sound across the dispatcher CFG's deliberately over-approximated edges. Case order, values, and layout are deterministic for a seed.

## Controlled bogus block

Transition blocks set a valid dispatcher state, compare that state with itself, and use the provably true equality edge to reach the dispatcher. The false edge reaches one valid, side-effect-free bogus block. The condition is derived only from deterministic program-local state and is mathematically fixed; the bogus block contains no memory, call, host, timing, or environment operation. Both edges and every target are structurally valid.

## Internal calls, outlining, and splitting

The native IR grows an `IrInternalCall` operation and an `IrModule` that owns uniquely identified functions. Module validation checks call targets, signatures, widths, argument definitions, and rejects recursion for the v1 implementation.

The VM grows a versioned internal `CALL` instruction. Calls create bounded register/slot frames, copy explicit arguments into the callee frame, and restore the caller before writing the return destination. Call depth uses the existing frame limit. Bytecode decoding validates call targets and argument limits before execution.

`outline_block` extracts a safe non-entry return block. It computes live-in variables, remaps them to helper arguments, replaces the block with an internal call and return, and retains source lineage. `split_function` moves the complete original body into an internal helper and leaves an ABI-facing wrapper that calls and returns the helper. General multi-exit outlining, recursion, native ABI stub emission, and unwind generation remain later work.

## Verification

Every transform starts with validation and ends with module/function and VM validation. Unit tests cover deterministic graph shape, case uniqueness, bogus-edge invariants, call-frame failures, recursion rejection, live-in remapping, and lineage. Differential tests lift the real COFF/ELF fixtures, execute original native code, and compare original VM, flattened VM, outlined VM, split VM, and assembled/decoded forms over boundary inputs.

# Virtualization

The binobf VM core is implemented as a conventional, auditable, architecture-neutral interpreter. Selected functions from real x86-64 COFF/ELF object code can be lowered into standalone VM bytecode or embedded behind a native ABI adapter, including validated IR-module transformations that use internal helper calls.

```text
lifted binobf IR
    -> VM-independent instructions
    -> deterministic assembler
    -> versioned bytecode
    -> bounds-checked interpreter
```

The public API provides typed 8/16/32/64-bit and 64-bit pointer values, a bounded virtual register file, frame-local slots, little-endian linear memory, arithmetic and bitwise operations, comparisons, flags, branches, loads/stores, bounded internal calls, returns, and an explicit caller-supplied native-call bridge. Internal calls receive fresh register/slot frames and restore caller flags on return. Uninitialized values, invalid shifts, division by zero, out-of-range memory, rejected calls, excessive frame depth, invalid control flow, and exhausted step budgets return structured diagnostics.

Standalone `BVM1` v1.1 bytecode carries an exact major/minor version, fixed little-endian fields, declared resource counts, the encoding seed, a complete 23-opcode mapping, and length-prefixed instructions with explicit operand widths. The decoder applies byte, instruction, register, slot, memory, native/internal-argument, and version limits before allocation or execution. Version 1.0 is rejected rather than silently accepted with different opcode semantics. Assemble/decode/assemble is stable for the same seed.

Build seeds deterministically permute opcode and virtual-register numbering. The VM does not decrypt executable payloads, download code, detect debuggers/VMs/security products, access remote process memory, or act as a reflective loader. Pointer values are offsets into a supplied validated `VmMemory` capability, never raw process handles or remote addresses.

`lift_function` requires an explicit recovered function, Windows x64 or System V AMD64 ABI, zero-to-four `u32` arguments, and a `u32` return. It currently accepts complete functions using 32-bit register/immediate forms of moves, arithmetic/bitwise operations, immediate shifts, compare/test, supported direct branches, and returns. Conditional branches require flags from a preserved compare/test. Memory operands, stack access, native calls, relocations, indirect control flow, unsupported widths, and incomplete CFGs produce fallbacks or diagnostics and cannot be lowered.

`binobf vm lower object --function=name --abi=windows-x64|sysv-amd64 --args=N -o program.bvm [--seed=N] [--cfg=flatten|--outline-block=N|--split-function]` emits standalone bytecode transactionally. The advanced options are mutually exclusive, explicitly warn that they are high risk, and remain bounded by IR and VM resource limits. Flattening uses deterministic dispatcher states and a fixed program-local bogus edge. Outlining extracts a proven safe single-return block; splitting leaves a wrapper that invokes an internal helper. `binobf vm disassemble program.bvm` decodes and prints the canonical typed program without executing it.

`binobf vm protect object --function=name --abi=windows-x64|sysv-amd64 --args=N -o protected-object [--seed=N]` performs restricted object-time virtualization. It appends a 16-byte-aligned native adapter and `BVM1` bytecode to the selected executable section, redirects the function symbol to the adapter, and adds a normal relocation to `binobf_vm_execute_embedded_u32`. COFF uses `IMAGE_REL_AMD64_REL32` and Windows x64; ELF uses `R_X86_64_PLT32` and System V AMD64. Link the protected object with the installed `binobf_core` static library.

The adapter copies zero through four native `u32` arguments into a bounded array and invokes the C ABI runtime. The runtime strictly decodes the embedded program, allocates only its declared local memory, rejects native VM calls, executes with the standard limits, and returns a `u32`. No exception crosses the C boundary; `binobf_vm_embedded_last_error()` exposes a thread-local structured failure string for diagnostics.

Protection fails before emission when the function is incomplete, outside the supported lifting subset, described by unwind metadata, or reached by a relocation-free direct call/jump elsewhere in the object. Relocation-backed callers remain valid. Repeated protection of different functions reuses the same undefined runtime symbol and relocation table. The original native bytes remain in the object for audit, but ordinary references through the selected symbol bind to the adapter.

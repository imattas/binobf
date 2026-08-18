# Milestone 8 VM Lowering Design

## Outcome

Milestone 8 adds a truthful, fail-closed path from an explicitly selected x86-64 object function to normalized binobf IR and then to the existing VM. The same function is linked and executed natively in the differential suite; VM results must match before the supported subset expands. Bytecode embedding and native stubs remain later work and are not claimed here.

## Selection contract

Native object files do not reliably encode source signatures. Callers therefore select a recovered `Function` and provide a `NativeFunctionSignature`: ABI (`WindowsX64` or `SystemVAMD64`), zero to four unsigned integer arguments, and an unsigned integer return width. Milestone 8 accepts 32-bit integer signatures only. Selection rejects incomplete functions, unknown architectures, missing CFGs, relocation-backed instructions, calls, memory access, stack access, indirect control flow, and every encoding outside the documented subset.

## Normalized IR

The new `binobf::ir` model is architecture-neutral after lifting:

- typed mutable virtual variables and explicit argument bindings;
- register/immediate operands;
- move, arithmetic/bitwise operations, compare, test, direct branch, conditional branch, and return;
- basic blocks with stable IDs and source-instruction lineage;
- an explicit fallback operation for preserved unsupported native instructions.

Validation checks resource limits, unique IDs, operand widths, variable definition, block targets, terminators, argument bindings, and fallback policy. VM lowering refuses fallback operations. Mutable variables deliberately model the small machine-register subset without inventing SSA phi semantics.

## Initial x86-64 lifting subset

Capstone stays behind the binobf adapter. The lifter accepts 32-bit register forms of `mov`, `add`, `sub`, `imul`, `and`, `or`, `xor`, `shl`, `shr`, `not`, `cmp`, `test`, `inc`, `dec`, `jmp`, supported `jcc`, `ret`, and `nop`. Operands are registers or immediate values; memory operands and partial/64-bit register forms are rejected. Supported conditions map exactly to the VM condition set. ABI argument registers are initialized explicitly and `eax` is the return variable.

## Lowering

Each IR variable receives a deterministic VM register. Arguments load from VM frame slots. Immediate operands receive deterministic temporary registers. Basic-block starts are calculated before branch targets are patched. The resulting `VmProgram` is validated by the existing validator and can be assembled, decoded, disassembled, and executed without a separate execution path.

## Verification

Unit tests start red for validation and lift rejection. A controlled assembly fixture supplies straight-line arithmetic and two-way control flow for both COFF and ELF analysis. On the host, the COFF fixture is also linked into the differential test executable. For a boundary-heavy input matrix, the test compares the linked native function with the lowered VM result, then assembles/decodes and repeats VM execution. Unsupported instructions and signatures must return stable diagnostics rather than partial programs.

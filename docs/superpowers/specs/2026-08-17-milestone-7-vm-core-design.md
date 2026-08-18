# binobf Milestone 7 VM Core Design

## Goal

Build a normal, auditable, architecture-neutral bytecode VM core with typed IR, deterministic assembly, bounds-checkable decoding, virtual registers, frame-local stack slots, bounded linear memory, explicit flags and branches, a caller-controlled native-call bridge, disassembly, and exhaustive tests. This milestone does not lower native functions; Milestone 8 consumes this API.

## Semantic model

`VmValue` carries an explicit 8/16/32/64-bit or pointer width and a normalized unsigned bit pattern. Arithmetic wraps to the selected width. Division is unsigned and rejects zero. Shifts reject counts greater than or equal to the operand width. Pointer values are offsets into a supplied `VmMemory` capability, never host process addresses.

The register file and stack-slot frame are independently bounded arrays. Reads of unset entries return a structured error rather than an implicit value. `LOAD_SLOT` and `STORE_SLOT` move typed values between registers and the current VM-local frame. The core reserves a frame stack interface for nested VM calls, but Milestone 7 executes one frame because there is no VM-call opcode yet.

Arithmetic and bitwise operations update zero/sign/carry/overflow flags with width-specific semantics. `CMP` computes subtraction flags without a destination. `TEST` computes AND zero/sign flags and clears carry/overflow. Conditions cover equality, inequality, unsigned below/above-or-equal, signed less/greater-or-equal, zero, and nonzero.

## IR and instruction set

Public IR uses a variant of typed operation records rather than ambiguous unused fields. It includes:

- `MOV`, `LOAD_CONST`, `LOAD_SLOT`, `STORE_SLOT`;
- `LOAD_MEM`, `STORE_MEM` through bounded memory offsets held in registers;
- `ADD`, `SUB`, `MUL`, `DIV`, `AND`, `OR`, `XOR`, `NOT`, `SHL`, `SHR`;
- `CMP`, `TEST`, `JMP`, `JCC`;
- `CALL_NATIVE` with an allowlisted numeric ID and explicit argument registers;
- `RET` with an explicit result register.

Programs declare register, slot, and local-memory counts. Branch targets are instruction indices. Validation rejects out-of-range operands, impossible widths, invalid targets, missing return paths, excessive native arguments, and all configured resource-limit violations before execution.

## Memory and native calls

`LinearVmMemory` owns a bounded byte vector and performs checked little-endian loads/stores. The interpreter accepts the `VmMemory` interface, allowing a protected program to provide another validated capability later. The interface cannot name processes or read arbitrary host addresses.

`VmNativeCallBridge` receives a function ID and immutable typed arguments and returns a typed value or diagnostic. The VM has no dynamic symbol lookup, payload loading, syscall dispatch, or hidden host access. A rejecting bridge is the safe default.

## Bytecode format

Standalone bytecode is little-endian and begins with:

- magic `BVM1`;
- `VmVersion {major, minor}`;
- instruction count, register count, slot count, and local-memory size;
- a complete canonical-opcode to encoded-byte table;
- length-prefixed instruction records.

Every operand has an explicit width. The assembler validates IR first, deterministically permutes unique opcode bytes and virtual-register numbers from a supplied seed, emits canonical instruction-index targets, and never uses ambient randomness. The decoder validates the header, version, mapping bijection, record lengths, operands, counts, and trailing data before returning IR. Assemble/decode/assemble is byte-stable for the same seed.

## Interpreter and limits

Execution validates the program before allocation. `VmLimits` bounds bytecode bytes, instructions, registers, slots, memory, native arguments, frame depth, and executed steps. Each loop iteration checks the program counter and step budget. All failures return stable diagnostic codes with the failing program counter where applicable. No malformed bytecode reaches execution.

## Verification

Unit tests cover every opcode, every condition, all integer widths, wrapping, flags, division and shift failures, uninitialized registers/slots, memory bounds, native bridge success/rejection, branches, loops and step exhaustion, version/magic/truncation/mapping/operand corruption, resource limits, deterministic seed diversity, round trips, register permutation, and disassembly. Standalone headers and static analysis remain release gates.

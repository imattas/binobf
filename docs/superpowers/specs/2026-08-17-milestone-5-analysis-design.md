# binobf Milestone 5 Machine-Code Analysis Design

## Goal

Provide conservative x86, x86-64, and ARM64 instruction analysis for supported relocatable objects: mature decoding, symbol-led function discovery, relocation-aware references, CFG recovery, basic register dataflow, and source lineage. The result must be useful to later transformations without guessing through missing evidence.

## Decoder boundary

Use Capstone 5.0.9 behind a private adapter. Capstone is fetched at a pinned stable tag when no packaged target is supplied. No Capstone handle, enum, register ID, or structure appears in a public header.

The public `InstructionDecoder` consumes an architecture, bounded bytes, an address, and a stable source identity. It returns one normalized instruction with exact source bytes, textual mnemonic/operands, normalized control-flow kind, direct target when encoded, register definitions/uses, fallthrough behavior, and lineage. Unsupported architectures, empty input, invalid encodings, and allocation/library failures return structured diagnostics.

## Analysis model

Add focused value types under `include/binobf/analysis`:

- `Instruction` with stable ID, section/offset/address, exact bytes, kind, target/reference facts, register uses/definitions, and lineage;
- `Function` discovered from defined function symbols, with confidence/source facts and an explicit completeness flag;
- `BasicBlock` and typed CFG edges for fallthrough, direct branch, conditional branch, calls, returns, and unresolved indirect flow;
- relocation-backed instruction references carrying stable relocation and symbol IDs rather than raw pointers;
- per-block `liveIn`/`liveOut` register sets plus instruction definitions/uses.

Register identity is a normalized name plus a stable architecture-local numeric value. It is opaque to callers and does not expose Capstone types.

## Conservative recovery

Executable sections are analyzed only inside symbol-proven function ranges. ELF symbol sizes are honored. A zero-sized function ends at the next defined function in the same section; the final zero-sized function is bounded by the section. Overlap, out-of-range symbols, or impossible ranges produce diagnostics and incomplete functions.

Direct branch targets create intra-function block boundaries only when they land on an instruction boundary in the same proven function. Calls retain fallthrough and record call references but do not create intra-procedural edges to other functions. Indirect branches/calls are explicit unresolved edges. Decode failure creates an opaque fallback instruction of the architecture's minimum safe width and marks the function incomplete; passes requiring complete decoding must decline it.

Relocations whose offsets fall inside an instruction attach stable relocation/symbol references. These override placeholder encoded immediates for external calls/data references without inventing an address.

## Basic dataflow

Capstone's implicit and explicit register-access facts are normalized onto each instruction. A backward fixed-point calculation derives block liveness over CFG successors. Unresolved indirect successors mark the function incomplete; they do not receive fabricated edges.

## Acceptance gates

- Golden decode tests for x86, x86-64, and ARM64 control flow and register access.
- Invalid/truncated input diagnostics and opaque fallback behavior.
- Function and CFG tests for direct/conditional branches, calls, fallthrough, return blocks, and unresolved indirect control flow.
- Relocation-aware reference tests on synthetic and compiler-produced objects.
- Deterministic analysis output and lineage IDs.
- Debug/Release warning-as-error, full prior suite, differential harness, header self-containment, and static analysis remain green.

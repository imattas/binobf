# Machine-Code Analysis

## Current scope

`analyze_object` supports relocatable COFF and ELF objects for x86, x86-64, and ARM64. The x86-64 end-to-end object path is supported against compiler-produced fixtures; x86 and ARM64 object analysis remain experimental while their decoder contracts are covered with golden instruction tests.

Capstone 5.0.9 is pinned by archive hash and isolated in `src/analysis/capstone_instruction_decoder.cpp`. Public APIs do not expose Capstone handles or enums.

## Recovery policy

Functions are discovered from defined function symbols in executable code sections. Declared ELF and COFF auxiliary sizes are honored. A zero-sized symbol is bounded by the next function symbol or section end; recognized trailing NOP alignment after a terminating instruction is excluded. Overlaps, invalid ranges, undecodable bytes, mid-instruction branch targets, falling out of a proven range, and indirect control flow produce diagnostics and mark the function incomplete.

Instructions retain stable IDs, exact source bytes, section offsets, addresses, mnemonic/operand text, control-flow kind, register reads/writes, direct targets where trustworthy, and lineage to their source section. A relocation inside an instruction replaces placeholder encoded branch/call immediates with stable relocation and symbol references.

CFG recovery creates blocks only on decoded instruction boundaries. It records fallthrough, conditional-taken, direct-branch, direct-call, and unresolved-indirect edges. Calls retain fallthrough. Register live-in/live-out sets are computed to a fixed point over intra-procedural successors.

Incomplete functions remain inspectable but are ineligible for any future pass that requires complete decoding or CFG knowledge.

# Milestone 16: Embedded VM Virtualization Design

## Goal

Turn the existing x86-64-to-VM lowering pipeline into real selected-function virtualization for relocatable COFF and ELF objects. The protected object must remain consumable by ordinary platform linkers and must execute the selected function through binobf's bounded interpreter.

## Command and library contract

Add `binobf vm protect <object> --function=<name> --abi=windows-x64|sysv-amd64 --args=N -o <object> [--seed=N]` and a public `protect_function` library API. The v1 signature remains the already documented lowering contract: zero through four `u32` arguments and a `u32` return.

The API returns the rewritten image plus an auditable report containing the selected function, original and protected addresses, wrapper and bytecode ranges, runtime symbol, ABI, argument count, encoding seed, and VM instruction lineage.

## Object layout

The protector lowers and assembles the selected function exactly as `vm lower` does. It appends a 16-byte-aligned x86-64 ABI adapter and the versioned bytecode to the selected executable section, then redirects the selected function symbol to the adapter. Keeping the bytecode in the same section lets the adapter address it with a fixed RIP-relative displacement without a data relocation.

The adapter snapshots the original native argument registers into a bounded stack array and calls the external C ABI entry point `binobf_vm_execute_embedded_u32(bytecode, size, arguments, count)`. A normal linker relocation represents that call:

- COFF x86-64: `IMAGE_REL_AMD64_REL32`.
- ELF x86-64: `R_X86_64_PLT32` in an existing or synthesized `.rela<code-section>` table.

The installed `binobf_core` library defines the runtime entry point. It decodes the embedded `BVM1` program, creates only the declared bounded local memory, rejects native calls, executes under the existing limits, and returns the `u32` result. A thread-local diagnostic accessor exposes runtime failures without throwing through the C ABI.

## Safety and compatibility gates

Protection is rejected unless the input is a relocatable x86-64 COFF or ELF object, the selected function is complete and lowerable, its defining symbol is present, the ABI matches the object format, and all representational limits are satisfied. Windows x64 is accepted for COFF and System V AMD64 for ELF.

The selected function must not have unwind metadata or relocation-free direct callers elsewhere in the same object, because redirecting its symbol would not update those fixed references. Relocation-backed callers remain valid. Existing contents are preserved; the old native body becomes unreachable through the selected symbol but remains available for audit.

Repeated protection of different functions is supported by reusing the runtime symbol and relocation table. Entity IDs, raw symbol indices, relocation indices, section metadata, and COFF section-definition auxiliary records are updated deterministically. Any unsupported or ambiguous case fails before emission.

## Verification

Tests cover wrapper encoding for both ABIs, COFF and ELF relocation synthesis, deterministic bytecode/layout, malformed and unsupported models, repeated protection, parser/writer round trips, CLI transaction behavior, and runtime error reporting. A Windows differential fixture links a protected COFF object with the installed-style core library and executes representative arithmetic and branch functions. ELF output is linked structurally with `ld.lld -r` and inspected because the Windows gate cannot execute Linux binaries.

Fresh Debug, Release, and UBSan suites, VM fuzzing, standalone-header compilation, whole-production static analysis, install verification, deterministic installed CLI output, native execution, and policy checks close the milestone.

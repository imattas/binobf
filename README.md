# binobf

`binobf` is a native-code software-protection framework designed like a compiler. It will transform supported object files and linked binaries only when it can understand, reconstruct, and verify the affected structures. ARM64 COFF and ELF object analysis, code generation, relocations, unwind ownership, fixed-width transformations, corpus/linker validation, and bounded native evidence are supported.

The project is in active development. The current implementation provides a typed core library, structured diagnostics with remediation and lineage, deterministic seeded randomness, safe container/header detection, normalized ELF/COFF relocatable-object parsing, canonical object reconstruction, conservative PE/ELF linked-image parsing and address-stable rewriting, GNU/COFF archive parsing and reconstruction, transactional object-member transformation, public structural verification, compile-transform-run differential testing, a supported i386 object-analysis/code-generation backend, conservative x86-64 machine-code analysis, a bounded architecture-neutral VM core, fail-closed lowering of a deliberately small x86-64 arithmetic/control-flow subset into versioned VM bytecode, deterministic standalone VM control-flow flattening, outlining, and function splitting, restricted selected-function bytecode embedding for x86-64 COFF/ELF objects, and opt-in generated-property, mutation, fuzz, sanitizer, and benchmark tooling. General native lifting and post-link code-layout rewriting remain under development.

## Safety boundary

binobf is for legitimate software protection, compiler research, and IP protection. It does not provide antivirus bypass, sandbox or debugger evasion, process injection, persistence, remote-process manipulation, reflective loading, payload downloaders, malformed executable tricks, or code-signing bypasses. See [Security boundaries](docs/security-boundaries.md).

## Current feature matrix

<!-- binobf:feature-matrix:start -->
| Capability | PE | COFF object | ELF | Archive |
|---|---:|---:|---:|---:|
| Header/container detection | supported | supported | supported | supported |
| Relocatable-object parsing | n/a | supported | supported | supported members |
| Linked-image detailed parsing | supported | n/a | supported | n/a |
| Structural verification | supported | supported | supported | supported |
| Exact linked/object emission | supported | supported | supported | supported |
| Baseline metadata transformations | supported strip-debug | supported | supported including linked | supported per object member |
| x86/x86-64/ARM64 instruction/CFG/layout transformations | planned | supported | supported | supported per object member |
| Selected x86-64 function VM lowering | n/a | restricted | restricted | unsupported |
| Embedded selected-function VM protection | n/a | restricted | restricted | unsupported |

| Architecture | Detection | Decoder | Object analysis | Code generation |
|---|---:|---:|---:|---:|
| x86 | supported | supported | supported | supported |
| x86-64 | supported | supported | supported | restricted object backend |
| ARM64 | supported | supported | supported | supported |
<!-- binobf:feature-matrix:end -->

PE classification includes executables, DLLs, and `.sys` files after a valid PE header is established. ELF classification includes relocatable objects, executables, and shared objects. GNU/BSD-style `ar` containers and Microsoft COFF `.lib` files expose resolved member names, ELF/COFF objects, import records, metadata, architecture, and symbol-to-member relationships.

## Build

Requirements:

- CMake 3.25 or newer
- A C++20 compiler
- Ninja (commands below) or another CMake generator
- Network access on the first configure so CMake can fetch the pinned Capstone 5.0.9 source archive

On Windows with Clang:

```powershell
cmake -S . -B build/debug -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBINOBF_WARNINGS_AS_ERRORS=ON
cmake --build build/debug
ctest --test-dir build/debug --output-on-failure
```

Release build:

```powershell
cmake -S . -B build/release -G Ninja -DCMAKE_BUILD_TYPE=Release -DBINOBF_WARNINGS_AS_ERRORS=ON
cmake --build build/release
ctest --test-dir build/release --output-on-failure
cmake --install build/release --prefix build/install
```

Every push to `main` and pull request is built and tested on Windows and Linux x86-64 by GitHub Actions. Version tags (`vMAJOR.MINOR.PATCH`) produce public release archives for both platforms; the latest packages are listed on the [Releases page](https://github.com/imattas/binobf/releases).

Dedicated UBSan, libFuzzer, and benchmark commands are documented in [Hardening](docs/hardening.md). The current Windows LLVM/MSVC standard library cannot link AddressSanitizer because its required STL integration library is absent; CMake rejects that unsupported combination explicitly.

## Quick start

```powershell
build\debug\binobf.exe inspect path\to\input.exe
build\debug\binobf.exe analyze path\to\input.obj
build\debug\binobf.exe analyze path\to\input.o --diagnostics=json
build\debug\binobf.exe analyze path\to\application.exe
build\debug\binobf.exe verify path\to\input.o
build\debug\binobf.exe verify path\to\library.so
build\debug\binobf.exe analyze path\to\library.a
build\debug\binobf.exe verify path\to\library.lib
build\debug\binobf.exe transform path\to\input.obj -o path\to\roundtrip.obj --passes=none
build\debug\binobf.exe transform path\to\input.obj -o path\to\protected.obj --passes=minimal --seed=123456 --lineage=path\to\protected.lineage.json
build\debug\binobf.exe config path\to\binobf.toml
build\debug\binobf.exe transform --config=path\to\binobf.toml
build\debug\binobf.exe lineage path\to\protected.lineage.json --protected-address=0x20
build\debug\binobf.exe transform path\to\input.o -o path\to\protected.o --passes=balanced --seed=123456
build\debug\binobf.exe transform path\to\input.o --passes=balanced --seed=123456 --dry-run
build\debug\binobf.exe transform path\to\application.exe -o path\to\stripped.exe --passes=strip-debug
build\debug\binobf.exe transform path\to\library.a -o path\to\protected.a --passes=minimal --seed=123456
build\debug\binobf.exe passes
build\debug\binobf.exe inspect path\to\input.o --diagnostics=json
build\debug\binobf.exe formats
build\debug\binobf.exe architectures
build\debug\binobf.exe vm lower path\to\input.obj --function=my_function --abi=windows-x64 --args=2 -o path\to\my_function.bvm --seed=123456
build\debug\binobf.exe vm protect path\to\input.obj --function=my_function --abi=windows-x64 --args=2 -o path\to\protected.obj --seed=123456
build\debug\binobf.exe vm protect path\to\input.o --function=my_function --abi=sysv-amd64 --args=2 -o path\to\protected.o --seed=123456
build\debug\binobf.exe vm lower path\to\input.obj --function=my_function --abi=windows-x64 --args=2 -o path\to\flattened.bvm --seed=123456 --cfg=flatten
build\debug\binobf.exe vm lower path\to\input.obj --function=my_function --abi=windows-x64 --args=2 -o path\to\split.bvm --seed=123456 --split-function
build\debug\binobf.exe vm disassemble path\to\program.bvm
```

Example successful output:

```text
path: example.o
format: ELF
type: relocatable-object
architecture: x86-64
entry-point: 0x0
file-size: 640
inspection: supported
```

Inspection and analysis open inputs read-only, impose a 512 MiB in-memory limit, and return a nonzero status for unknown, malformed, truncated, unsupported, or unreadable input. `analyze` reports normalized sections, symbols, relocations, functions, instructions, basic blocks, CFG edges, and completeness. COFF auxiliary records are validated, function-size metadata is normalized when present, and non-primary records are not misreported as symbols.

`verify` reparses a relocatable object and reports header, section-range, symbol, relocation, entity-reference, and branch-destination checks. Branch validation passes for completely analyzed functions, is not applicable to data-only objects, and remains explicitly unsupported when conservative recovery is incomplete. Object-level imports/exports are not applicable; owned i386 Windows SafeSEH and bounded ELF DWARF CFI are supported, while unknown or opaque unwind ownership remains an explicit refusal.

`transform` supports `strip-debug`, `cleanup-metadata`, safe unreferenced-local-symbol stripping, and `rename-private-symbols` through the `minimal` profile. The `balanced` profile additionally enables exact-size instruction substitution, constant rewriting, branch inversion, valid jump-over-NOP dead-code insertion, block splitting, conservative independent-block reordering, and relocation-aware function reordering for complete x86 and x86-64 COFF/ELF object functions. Strict TOML selection can constrain all function-scoped passes by original name/regex, section, visibility, denylist, and deterministic percentage sampling; selected identities survive symbol stripping and private renaming. Block reordering pins the entry and accepts only relocation-free functions with explicit non-fallthrough transfers whose branch displacements can be rebuilt exactly. These medium-risk passes warn when enabled and skip unsupported regions instead of guessing. Every pass runs transactionally with an explicit seed, reserializes, reparses, reanalyzes affected code, and rolls back on validation failure. `--dry-run` executes the same verified pipeline without writing output. The CLI never overwrites the input or an existing output. Successful transforms emit a deterministic external SHA-256 manifest by default; binary, manifest, and optional object-lineage sidecar commit as one no-overwrite transaction.

The i386 backend targets the SSE2 baseline and supports Windows cdecl/stdcall/fastcall/thiscall plus System V i386 adapters. It owns the ordinary i386 COFF and ELF relocation families, implicit addends and PC bias, common/TLS symbols, COMDAT/group associations, and a frozen old-to-new `ObjectRewritePlan` that repairs sites, targets, addends, symbols, functions, unwind records, and lineage before copy-only commit. Opaque instructions, unresolved indirect flow, unowned associations, opaque moved unwind data, out-of-range branches, and incomplete functions are refused; objects containing unmodeled frame records are skipped rather than rewritten. The implementation uses ordinary auditable object code only and adds no evasion, injection, persistence, dynamic payload, malformed-instruction, or exception-abuse behavior.

For linked PE executables/DLLs/drivers and ELF executables/PIEs/shared objects, `analyze` normalizes sections, segments, imports, exports, relocations, dynamic directories, resources, debug metadata, and supported unwind/signature state. `transform --passes=none` is byte-identical. Linked `strip-debug` changes no loaded address: PE debug records and their validated raw payloads are cleared and the PE checksum is rebuilt; non-allocated ELF debug sections and dependent debug relocations become empty section records without renumbering. A signed PE is rejected unless `--allow-signature-invalidation` is explicit, after which the certificate table is removed and reported. Linked post-link code transformation remains disabled, and `.sys` handling remains limited to exact output or this metadata-only operation.

For `.a` and `.lib`, `analyze` reports members and rebuilt index relationships, while `verify` checks container layout, recognized object members, and object-symbol bindings. `transform` applies the selected object pipeline independently to each eligible ELF/COFF member with a deterministic member-derived seed, then rebuilds long-name and linker indexes transactionally. Opaque members are preserved. PE import-library records and their structural COFF members are never machine-code transformed; an unchanged import library is emitted byte-for-byte.

The public native IR and VM APIs provide explicit widths, virtual variables/registers and frame-local slots, bounded little-endian memory, flags and branches, bounded internal-call frames, a caller-supplied native-call bridge, resource-limited interpretation, seeded opcode/register encoding diversity, strict `BVM1` v1.1 assembly/decoding, and source-instruction lineage. `vm lower` and `vm protect` require an explicit recovered function name, ABI, and zero-to-four `u32` argument count because object files do not reliably contain source signatures. They accept only complete x86-64 functions composed of the documented register/immediate subset; memory operands, native calls, relocations, unsupported flag dependencies, and other native semantics fail closed.

Advanced standalone lowering is opt-in through one of `--cfg=flatten`, `--outline-block=N`, or `--split-function`. Flattening uses seeded, unique dispatcher states and a valid program-local fixed bogus edge; it never consults timing, debuggers, the environment, or external state. Outlining accepts only a safe non-entry single-return block and remaps its live-ins into a helper. Splitting keeps an entry wrapper and moves the body to an internal helper. Internal calls are acyclic in native IR, bounded at validation time, and executed with fresh VM register/slot frames. The CLI labels these transformations high-risk and rejects ambiguous option combinations. `vm disassemble` is inspection-only.

`vm protect` appends a conventional ABI adapter and `BVM1` bytecode to the selected code section, redirects its symbol, and emits an ordinary linker relocation to `binobf_vm_execute_embedded_u32`. Link the resulting object with the installed `binobf_core` static library. COFF uses Windows x64 and ELF uses System V AMD64. Fixed relocation-free internal callers, unwind-described functions, and other unsafe cases are rejected before output.

## Configuration and evidence

Strict TOML configuration, CLI precedence, canonical hashing, default manifests, and opt-in object lineage are documented in [Configuration](docs/configuration.md) and [Persisted lineage](docs/lineage.md).

## Architecture and development

- [Architecture](docs/architecture.md)
- [Supported format direction](docs/formats.md)
- [Developer guide](docs/developer-guide.md)
- [Verification strategy](docs/verification.md)
- [Hardening and fuzzing](docs/hardening.md)
- [Configuration](docs/configuration.md)
- [Persisted lineage](docs/lineage.md)
- [Machine-code analysis](docs/analysis.md)
- [Transformation passes](docs/transformation-passes.md)
- [Virtualization](docs/virtualization.md)

The guiding rule is simple: **never perform a transformation that binobf cannot adequately understand, reconstruct, and verify.**

## License

binobf is available under the [MIT License](LICENSE). Third-party notices and
licenses are documented in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

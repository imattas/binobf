# Verification

Verification is a release gate, not an optional report.

## Current gates

The release-gating capability contract includes `capability_registry`, `capability_evidence`, `capability_render`, `architecture_backend`, and `capability_consistency`. Together they validate the 48-cell registry, bind supported claims to live CTest names, lock generated CLI/README output, verify fixed-architecture backend identity and service levels, and reject cross-registry drift.

The current suite runs warning-as-error Debug and Release builds plus CTest. Tests cover:

- stable normalized enum and entity behavior;
- diagnostic text/JSON rendering and escaping;
- deterministic PRNG golden values, bounds, and shuffle behavior;
- valid ELF, PE, COFF, and archive headers;
- truncation, bad offsets, inconsistent sizes, unsupported byte order, and unknown input;
- ELF32/ELF64 sections, symbols, REL/RELA entries, NOBITS sections, and malformed links/indices;
- COFF long names, section flags/alignment, auxiliary-symbol gaps, relocations, and malformed ranges;
- compiler-produced COFF and ELF object integration, including named functions and resolved relocation references;
- deterministic synthetic ELF32/ELF64/COFF parse-write-parse reconstruction;
- compiler-produced object reconstruction accepted by `llvm-readobj`;
- rewritten ELF acceptance by `ld.lld -r` with reparsed relocation relationships;
- original and rewritten COFF objects linked against the same driver and executed with exit code 0;
- baseline pass ordering, dry-run, rollback, statistics, allowlists, seeded naming, and lineage;
- transformed compiler-produced COFF/ELF acceptance by LLVM and standard linkers;
- transformed COFF runtime equivalence through the harmless arithmetic driver;
- public verifier reports for compiler-produced COFF/ELF objects and adversarial range corruption;
- compile-transform-run differential comparison across negative, zero, ordinary, and boundary-style inputs;
- x86/x86-64/ARM64 decoder golden cases, malformed encodings, symbol-range recovery, CFG edges, relocation overrides, and block liveness;
- compiler-produced COFF/ELF function, instruction, block, completeness, lineage, and relocation-reference recovery;
- exact-size substitution, constant, branch-inversion, dead-code insertion, block-splitting, independent-block reordering, and function-reordering unit properties;
- relocation-aware function reordering, including moved COFF relocation sites and ELF `.eh_frame` section-symbol addends;
- compiler-produced COFF/ELF machine-code fixtures transformed by every balanced pass and accepted by LLVM/linkers;
- native differential execution of code changed by every balanced machine-code pass;
- VM value/IR validation, all arithmetic/bitwise opcodes, all branch conditions, flags, frame slots, bounded memory, native-call policy, and step exhaustion;
- every VM opcode through seeded assemble/decode/assemble round trips, all-prefix truncation rejection, targeted record corruption, resource ceilings, stable disassembly, and decoded-vs-source semantic execution;
- native IR uniqueness, width, variable-definition, target, terminator, fallback, and resource validation;
- native IR flag-definition dataflow plus module function, signature, target, cycle, and call-depth validation;
- real x86-64 COFF/ELF register/immediate arithmetic and control-flow lifting, explicit ABI argument mapping, and unsupported-memory fallback behavior;
- linked native COFF execution compared with lowered and assembled/decoded VM execution across zero, signed boundaries, unsigned boundaries, and wrapping arithmetic;
- transactional `vm lower` CLI emission followed by strict bytecode decoding and execution;
- deterministic dispatcher flattening, unique state values, valid controlled bogus edges, safe outlining live-ins, wrapper/helper splitting, and bounded VM internal-call frames;
- linked native COFF execution compared with baseline, flattened, outlined, split, assembled, decoded, and interpreted VM programs across boundary inputs;
- advanced `vm lower` option exclusivity, warnings, deterministic emission, decoding, and execution;
- embedded-runtime C ABI success/failure containment and thread-local diagnostics;
- deterministic COFF/ELF VM protection layout, symbol redirection, bytecode ranges, standard relocations, repeated protection, and unsafe-caller/unwind rejection;
- protected COFF native linking and execution through the bounded interpreter with exit code 0;
- protected ELF acceptance by `llvm-readobj` and `ld.lld -r` with preserved runtime relocation ownership;
- synthetic malformed PE/ELF linked headers, section/segment mappings, directories, dynamic tables, entry points, limits, and checksum corruption;
- linker-produced PE executable/DLL and ELF executable/PIE/shared-object parsing, exact byte round trips, linked structural verification, and LLVM inspection;
- real PE imports/exports plus ELF dynamic imports, PLT/GOT relationships, dynamic relocations, notes, and sectionless program-header metadata;
- address-stable PE/ELF debug stripping with preserved import/export contracts, explicit PE signature invalidation, and deterministic output;
- rewritten PE executable execution, DLL loading/export invocation, and an independent Windows `MapFileAndCheckSumW` checksum match;
- synthetic GNU/BSD/COFF archive names, padding, limits, indexes, exact round trips, and malformed-header rejection;
- compiler-produced GNU `.a`, Microsoft COFF `.lib`, long-name members, and PE import-library parsing and structural verification;
- deterministic archive member transformation, rebuilt GNU/dual-COFF indexes, `llvm-ar`/`llvm-nm` acceptance, PE/ELF relinking, and matching PE exit code 42;
- CLI exit codes, read-only inspection, transactional pass output, JSON failures, and accurate capability output.
- strict TOML schema/version/type/conflict/limit handling, config-relative paths, canonical JSON, and CLI override precedence;
- SHA-256 manifest identities, default/custom/disabled policy, deterministic repetition, and binary-plus-evidence rollback;
- lineage serialization/parsing, exact protected-address function queries, and missing, ambiguous, incomplete, cyclic, malformed, duplicate, and bounded-input failures;
- 6,144 generated VM semantic cases across all integer widths, binary operations, conditions, registers, slots, memory, branches, invalid arithmetic, limits, and deterministic replay;
- 8,960 deterministic parser/decoder mutation invocations with stable repeated outcomes and reconstruction/verification of accepted inputs;
- a required 19/19 artifact-mutation kill rate across object, linked-image, archive, VM, pass-precondition, and dangling-entity checks;
- seven seed-backed libFuzzer surfaces covering detection, objects, linked images, archives, VM bytecode, TOML configuration, and lineage JSON without executing parsed native code.

## Structural verification

`verify_object` is the shared object gate used by the public API, pass manager, and CLI. Object outputs reparse and validate headers, section ranges, symbols, relocations, entity references, rebuilt table ownership, and branch destinations for completely recovered functions before commit. `verify_archive` reparses member layouts and indexes, verifies every recognized object through `verify_object`, and requires each recognized indexed symbol to bind to a defined external symbol in its target member. `verify_linked_image` validates linked section/segment mappings, entry points, imports/exports, relocations, format directories, parsed unwind/resource/debug records, PE signature state, and nonzero PE checksums. Unsupported unwind semantics remain explicit instead of being treated as passed. Machine-code object passes additionally reanalyze each affected function and require complete recovery before commit. Any required-check failure means the transformation fails and no success is reported.

## Differential verification

Harmless C and assembly object fixtures are compiled, transformed, and linked into independent original and transformed native executables. The transformation fixture guarantees that every balanced machine-code pass changes executed code. A separate VM-lowering fixture is compiled as both COFF and ELF; its COFF bytes are parsed and lifted while the exact same object is linked into the differential process and executed as the native oracle. Baseline, flattened, outlined, and split programs are lowered, assembled, decoded, and interpreted before comparison. The transformation harness runs an identical six-case input matrix and byte-compares exit status, stdout, stderr, deterministic output files, explicit function results, and global-data side effects. Timing is never captured or used for semantic equivalence.

Generated property tests compare assembled/decoded VM execution against an independent host oracle. Deterministic robustness tests mutate real compiler/linker-produced fixtures and require stable success or structured failure on repeated input. The artifact mutation suite fails unless every required corrupt object, linked image, archive, VM program, pass precondition, and entity-reference case is killed. Seed-backed compiler-native fuzz targets exercise every implemented parser/decoder boundary using bounded in-memory input, including strict configuration and lineage sidecars.

The local Windows LLVM installation does not include `stl_asan.lib`, so AddressSanitizer executables cannot currently link and CMake reports this combination as unsupported. Windows sanitizer builds use `RelWithDebInfo` because LLVM's sanitizer C++ runtime is incompatible with the Debug MSVC STL iterator ABI. UndefinedBehaviorSanitizer is the required local sanitizer gate; AddressSanitizer remains enabled for supported non-Windows Clang/GNU toolchains.

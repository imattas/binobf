# Hardening

Hardening is opt-in so ordinary library consumers do not inherit sanitizer, fuzzing, or benchmark flags. All targets operate on local bounded data. Fuzzers parse and reconstruct native formats but never execute parsed native code.

## UndefinedBehaviorSanitizer

```powershell
cmake -S . -B build/ubsan -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo `
  -DBINOBF_WARNINGS_AS_ERRORS=ON `
  -DBINOBF_ENABLE_UNDEFINED_SANITIZER=ON
cmake --build build/ubsan
ctest --test-dir build/ubsan --output-on-failure
```

`BINOBF_ENABLE_ADDRESS_SANITIZER=ON` is available with supported Clang/GNU toolchains. The current Windows LLVM/MSVC standard library does not include `stl_asan.lib`; CMake rejects Windows ASan rather than silently claiming coverage. Windows sanitizer builds use the static MSVC runtime required by LLVM's sanitizer packages and also require `RelWithDebInfo` or `Release` because LLVM's sanitizer C++ runtime and the Debug MSVC STL use incompatible iterator ABIs.

## Seed-backed libFuzzer smoke

```powershell
cmake -S . -B build/fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo `
  -DBINOBF_BUILD_TESTS=OFF -DBINOBF_BUILD_FUZZERS=ON `
  -DBINOBF_ENABLE_UNDEFINED_SANITIZER=ON
cmake --build build/fuzz --target fuzz-smoke
```

The target generates valid COFF and ELF objects, PE and ELF linked images, a GNU archive, and a versioned VM program, and includes valid strict-configuration, lineage, and all six x86/x86-64/ARM64 by COFF/ELF code-generation seeds. It then runs 2,000 deterministic mutations on each of detector, object, linked-image, archive, VM bytecode, TOML configuration, lineage JSON, and bounded machine-emission surfaces. The code-generation fuzzer emits twice for determinism and never executes output. For longer runs, invoke an individual `binobf_fuzz_*` executable with its matching corpus and a larger `-runs` or `-max_total_time` value.

## Generated and mutation tests

The ordinary CTest suite includes `vm_properties`, `parser_robustness`, and `artifact_mutation`. VM properties compare generated programs against an independent host oracle. Parser robustness requires repeatable diagnostics or successful reconstruction and verification. Artifact mutation reports a killed/total score and fails unless the required matrix is 100% killed; the current matrix contains 19 targeted mutations.

## Benchmarks

```powershell
cmake -S . -B build/benchmark -G Ninja -DCMAKE_BUILD_TYPE=Release `
  -DBINOBF_BUILD_TESTS=OFF -DBINOBF_BUILD_BENCHMARKS=ON
cmake --build build/benchmark --target binobf_benchmarks
build\benchmark\binobf-benchmarks.exe --iterations=25 `
  build\debug\fixtures\arithmetic.o `
  build\debug\fixtures\libarchive-arithmetic.a `
  build\debug\fixtures\linked-pe.exe
```

The benchmark warms each operation and uses a monotonic clock. It reports detection plus parse/reconstruct/verify throughput for supplied fixtures and decode/execute throughput for a built-in VM program. Results are host-dependent regression evidence, not pass/fail assertions.

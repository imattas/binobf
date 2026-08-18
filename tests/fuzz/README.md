# Fuzz targets

Configure a dedicated Clang build and run the bounded smoke target:

```powershell
cmake -S . -B build/fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo `
  -DBINOBF_BUILD_TESTS=OFF -DBINOBF_BUILD_FUZZERS=ON `
  -DBINOBF_ENABLE_UNDEFINED_SANITIZER=ON
cmake --build build/fuzz --target fuzz-smoke
```

The smoke target first generates valid COFF/ELF objects, PE/ELF linked images, a GNU archive, and a versioned VM program and uses checked-in TOML, lineage JSON, six architecture/format code-generation seeds, and two bounded x86 object-rewrite seeds. It then runs 2,000 deterministic mutations on each of nine surfaces. The detector, object, linked-image, archive, VM bytecode, configuration, lineage, bounded code-generation, and transactional object-rewrite targets consume only in-memory data through public APIs. Object rewriting caps ranges and replacement growth, requires stable diagnostics for refused plans, and writes/reparses successful plans without executing output. Code generation maps bytes to allowlisted tokens, emits twice for determinism, and never executes output. None of the fuzzers access the network, create persistence, or emit deployable samples. On supported non-Windows toolchains, add `-DBINOBF_ENABLE_ADDRESS_SANITIZER=ON`. The current Windows MSVC STL installation does not provide its required ASan integration library.

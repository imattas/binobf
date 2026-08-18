# Fuzz targets

Configure a dedicated Clang build and run the bounded smoke target:

```powershell
cmake -S . -B build/fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo `
  -DBINOBF_BUILD_TESTS=OFF -DBINOBF_BUILD_FUZZERS=ON `
  -DBINOBF_ENABLE_UNDEFINED_SANITIZER=ON
cmake --build build/fuzz --target fuzz-smoke
```

The smoke target first generates valid COFF/ELF objects, PE/ELF linked images, a GNU archive, and a versioned VM program and uses checked-in TOML and lineage JSON seeds. It then runs 2,000 deterministic mutations on each of seven surfaces. The detector, object, linked-image, archive, VM bytecode, configuration, and lineage targets consume only in-memory bytes through public bounded APIs. They do not execute native input, access the network, create persistence, or emit deployable samples. On supported non-Windows toolchains, add `-DBINOBF_ENABLE_ADDRESS_SANITIZER=ON`. The current Windows MSVC STL installation does not provide its required ASan integration library.

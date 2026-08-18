# C API

`include/binobf/c_api.h` provides the stable, dependency-free C ABI for embedding
binobf in C, Rust, Python, and other native hosts. The ABI is intentionally
small while the C++ API continues to expose the full typed model.

The current ABI revision is `BINOBF_C_API_VERSION == 1` and exports:

- `binobf_version()` for the compiled project version;
- `binobf_detect()` for non-owning binary-format, type, architecture, and entry-point detection.

Callers must zero-initialize output structures and set `struct_size` to the
structure's `sizeof` value. Error strings are copied into caller-owned buffers,
are NUL-terminated when capacity is nonzero, and are truncated rather than
allocated by the library. Input bytes and output buffers remain owned by the
caller for the entire call.

The return value is one of `BINOBF_STATUS_OK`,
`BINOBF_STATUS_INVALID_ARGUMENT`, or `BINOBF_STATUS_FAILURE`. Numeric enum
values are part of the ABI; callers should reject unknown values rather than
assuming a future enum member has the current meaning.

The installed C++ static library and headers can be consumed with the normal
CMake install prefix:

```sh
cmake --install build/release --prefix build/install
```

The C API does not yet expose object mutation. That surface will be added only
after its ownership, transaction, diagnostic, and verification contracts are
independently stable.

# Rust binding

`binobf-sys` is a small, bindgen-free Rust wrapper over `binobf_c`. Build the
native library first, then point Cargo at its directory:

```powershell
$env:BINOBF_C_LIBRARY_DIR = "build/install/lib"
cargo test --manifest-path bindings/rust/Cargo.toml
```

On Windows the installed DLL must also be on `PATH` when running a consumer;
on Linux it must be on `LD_LIBRARY_PATH`.

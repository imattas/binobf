use std::env;

fn main() {
    if let Ok(path) = env::var("BINOBF_C_LIBRARY_DIR") {
        println!("cargo:rustc-link-search=native={path}");
    }
    println!("cargo:rerun-if-env-changed=BINOBF_C_LIBRARY_DIR");
}

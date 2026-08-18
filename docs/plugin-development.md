# Plugin Development

The plugin system is **planned**. It will extend compiler-style passes through a registry without granting plugins a path around validation.

A plugin will declare a unique name and version, supported formats/architectures, risk level, pass requirements, dependencies, and configuration schema. Registration produces ordinary `TransformPass` instances governed by the same deterministic order, transaction boundary, diagnostics, lineage, and structural verification as built-in passes.

Core output writers and the final verifier remain host-controlled. A plugin cannot emit an unchecked output or mark a failed verification as successful. ABI/version compatibility and a safe loading model will be designed before dynamic plugin loading is enabled.

The public library will also allow statically linked applications to register passes directly, which provides a simpler initial extension path and avoids premature binary plugin ABI commitments.

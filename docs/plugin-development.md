# Plugin Development

Statically linked pass extensions are supported through the public registry. Dynamic loading remains planned. Extensions use the same compiler-style pass registry without a path around validation.

A plugin will declare a unique name and version, supported formats/architectures, risk level, pass requirements, dependencies, and configuration schema. Registration produces ordinary `TransformPass` instances governed by the same deterministic order, transaction boundary, diagnostics, lineage, and structural verification as built-in passes.

Core output writers and the final verifier remain host-controlled. A plugin cannot emit an unchecked output or mark a failed verification as successful. ABI/version compatibility and a safe loading model will be designed before dynamic plugin loading is enabled.

Applications register a pass during startup with `register_pass(PassRegistration{...})`. Registration rejects empty names, missing factories, factory/name mismatches, and duplicate names. The registry remains sorted and deterministic, and registered names are accepted by CLI pass parsing and TOML configuration. Dynamic loading is intentionally not enabled until a stable binary ABI and safe loading model exist.

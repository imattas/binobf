# Configuration

binobf accepts a strict, versioned schema-specific subset of TOML 1.0: named tables, booleans, decimal integers, quoted strings, and quoted-string arrays. This bounded grammar is checked before the TOML dependency receives untrusted input. UTF-8 is accepted inside quoted values; keys and structural syntax are ASCII. Multiline strings, dotted keys, dates, floats, environment expansion, includes, executable values, and implicit configuration search paths are not supported. Relative paths resolve from the configuration file directory, and explicit CLI values take precedence.

```toml
version = 1
input = "objects/app.obj"
output = "out/app.protected.obj"
seed = 123456
profile = "balanced"
dry_run = false
allow_signature_invalidation = false
preserve_symbols = ["public_api", "stable_data"]

[selection]
include = ["critical_algorithm"]
include_regex = ["^crypto_internal_.*$"]
exclude = ["public_api"]
exclude_regex = [".*_test$"]
sections = [".text"]
visibility = ["local", "external"]
percentage = 50
seed = 928381

[manifest]
enabled = true
path = "out/app.manifest.json"

[lineage]
path = "out/app.lineage.json"
```

Use either `profile` or an ordered `passes` array, never both. Profiles are `none`, `minimal`, and `balanced`. The supported explicit names are `strip-debug`, `cleanup-metadata`, `strip-local-symbols`, `rename-private-symbols`, `instruction-substitution`, `constant-rewriting`, `branch-inversion`, `dead-code-insertion`, `block-splitting`, `block-reordering`, and `function-reordering`.

`[selection]` is optional and applies to function-scoped instruction, CFG, and layout passes. `include` and `exclude` contain exact original function names; `include_regex` and `exclude_regex` contain bounded ECMAScript full-match expressions. Exclusion wins. Exact and regex includes form one allowlist, while `sections` and `visibility` are additional required filters. Visibility accepts `local`, `hidden`, and `external`. `percentage` is an integer from 0 through 100 and is sampled with a fixed, traversal-order-independent hash. Its seed defaults to the effective transform seed unless `selection.seed` is set. Selected local function symbols are retained long enough to preserve identity, and selection continues to use the original name after private-symbol renaming.

Source annotations and compilation-module selectors are not accepted because ordinary stripped COFF/ELF objects do not carry trustworthy normalized values for them. Unknown selectors fail rather than being ignored.

```powershell
binobf config path\to\binobf.toml
binobf transform --config=path\to\binobf.toml
binobf transform --config=path\to\binobf.toml --seed=99 --passes=minimal
```

`binobf config` prints the canonical effective JSON used for configuration hashing and never writes binary artifacts. Unknown keys, wrong types, duplicate entries, invalid regular expressions, unsupported passes, conflicting manifest settings, incompatible versions, and resource-limit violations fail with stable `config.*` or `selection.*` diagnostics.

The transform schema does not infer native function signatures. `vm lower` and `vm protect` therefore remain explicit CLI/library operations requiring `--function`, `--abi`, and `--args`; `[selection]` controls the ordinary transform pass pipeline and is not silently reused for virtualization.

Every successful non-dry-run transform writes `<output>.manifest.json` by default. Use `--manifest=<path>` to select another external location or `--no-manifest` to opt out. The compact deterministic manifest records artifact and configuration SHA-256 hashes, the tool version, seed, ordered passes, pass statistics, sizes, format, architecture, and reparse verification state. It excludes timestamps, machine identity, environment values, source text, and absolute input paths.

# Persisted lineage

Relocatable-object transforms can emit an external lineage sidecar:

```powershell
binobf transform input.obj -o protected.obj --passes=balanced --seed=123456 `
  --lineage=protected.obj.lineage.json
binobf lineage protected.obj.lineage.json --protected-address=0x40
```

The emitted ranges come from the verified reparsed object. Their original mapping is recovered through the pre-write transform provenance using stable symbol identity, so symbol-table compaction and fresh parser entity IDs do not break crash-to-original-function queries. Ambiguous correlations remain unmapped and queries fail explicitly.

The sidecar contains deterministic original and protected function ranges, section-relative address kinds, explicit origin relationships, transformation records, tool/schema versions, and input/output SHA-256 identities. It contains no source text or host path. The query selects the narrowest supported protected range containing the address, follows only explicit origin links, and reports the verified original function and ordered transforms.

Queries fail rather than guess when the address is absent, equally narrow ranges are ambiguous, an origin is missing, a reference is invalid, or a cycle exists. Archive and linked-image sidecars are currently rejected because a single numeric address does not identify an archive member or linked address namespace unambiguously.

The JSON parser is schema-strict and bounded by input, nesting, string, entity, and transform limits. Sidecars are evidence for crash triage and reproducibility; they are not embedded into protected artifacts.

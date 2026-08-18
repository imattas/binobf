# Capability Contract and Backend Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace duplicated capability claims with a typed, evidence-bound registry and route all existing instruction decoding through an architecture-owned backend without changing current support levels.

**Architecture:** A public `CapabilityRegistry` owns the current format and architecture matrix, while a public pass registry derives pass output from real `TransformPass::requirements()` values. A public `ArchitectureBackend` fixes one architecture per instance and owns decoding; the current Capstone implementation becomes three backend instances without changing decoded semantics. CLI and README renderers consume these registries, and CTest verifies that every supported record names an acceptance test that is actually registered.

**Tech Stack:** C++20, CMake 3.25+, Capstone 5.0.9, existing `Result<T, Diagnostic>` and local test harness.

**Spec:** `docs/superpowers/specs/2026-08-17-full-feature-matrix-program-design.md`

## Global Constraints

- Preserve the safety boundary in `docs/security-boundaries.md`; this track adds no execution, evasion, injection, persistence, payload-loading, malformed-code, or signing-bypass behavior.
- Keep the current matrix values unchanged. This track makes status evidence enforceable; it does not call an incomplete capability supported.
- Preserve byte-for-byte behavior of the existing x86, x86-64, and ARM64 Capstone decoder.
- Keep Capstone and all registry storage private to `binobf_core`; installed headers expose no third-party types.
- Every new parser, lookup, and renderer is deterministic and allocation-bounded by the built-in record count.
- Every task follows red-green-refactor TDD, warning-as-error builds, and focused commits.

---

### Task 1: Typed capability model and validated built-in matrix

**Files:**
- Create: `include/binobf/capabilities/registry.hpp`
- Create: `src/capabilities/registry.cpp`
- Create: `tests/unit/capability_registry_tests.cpp`
- Modify: `CMakeLists.txt:109-170`
- Modify: `CMakeLists.txt:354-524`

**Interfaces:**
- Consumes: `BinaryFormat`, `BinaryType`, `Architecture`, `Result<T, Diagnostic>`.
- Produces: `Capability`, `SupportLevel`, `CapabilityKey`, `CapabilityRecord`, `CapabilityRegistry`, `builtin_capability_registry()`, and stable `to_string` functions.

- [x] **Step 1: Write the failing registry shape and lookup tests**

Create `tests/unit/capability_registry_tests.cpp` with these first cases:

```cpp
#include <binobf/capabilities/registry.hpp>

#include "../test_support.hpp"

#include <algorithm>
#include <string_view>

using namespace std::string_view_literals;

TEST_CASE(builtin_capability_registry_contains_each_public_matrix_axis) {
    const auto& registry = binobf::builtin_capability_registry();
    REQUIRE_EQ(registry.records().size(), 48U);

    const auto peDetection = registry.find(binobf::CapabilityKey{
        .capability = binobf::Capability::Detection,
        .format = binobf::BinaryFormat::PE,
    });
    REQUIRE(peDetection != nullptr);
    REQUIRE_EQ(peDetection->support, binobf::SupportLevel::Supported);

    const auto x86Analysis = registry.find(binobf::CapabilityKey{
        .capability = binobf::Capability::ObjectAnalysis,
        .architecture = binobf::Architecture::X86,
    });
    REQUIRE(x86Analysis != nullptr);
    REQUIRE_EQ(x86Analysis->support, binobf::SupportLevel::Experimental);

    const auto peObjectParsing = registry.find(binobf::CapabilityKey{
        .capability = binobf::Capability::RelocatableObjectParsing,
        .format = binobf::BinaryFormat::PE,
    });
    REQUIRE(peObjectParsing != nullptr);
    REQUIRE_EQ(peObjectParsing->support, binobf::SupportLevel::NotApplicable);
}

TEST_CASE(capability_registry_rejects_duplicate_keys_and_unknown_lookups) {
    const binobf::CapabilityRecord duplicate{
        .key = {.capability = binobf::Capability::Detection,
                .format = binobf::BinaryFormat::PE},
        .support = binobf::SupportLevel::Supported,
        .evidence = {"format-detection"},
    };
    const std::array records{duplicate, duplicate};
    const auto registry = binobf::CapabilityRegistry::create(records);
    REQUIRE(!registry.has_value());
    REQUIRE_EQ(registry.error().code, "capability.duplicate_key");
}

int main() {
    return binobf::test::run_all();
}
```

- [x] **Step 2: Register the test and verify it fails at compile time**

Add `src/capabilities/registry.cpp` to `BINOBF_CORE_SOURCES`, then add:

```cmake
add_executable(
    binobf_capability_registry_tests
    tests/unit/capability_registry_tests.cpp
)
target_link_libraries(binobf_capability_registry_tests PRIVATE binobf::core)
binobf_enable_warnings(binobf_capability_registry_tests)
add_test(NAME capability_registry COMMAND binobf_capability_registry_tests)
```

Run:

```powershell
cmake --build build\m12-verify-debug --target binobf_capability_registry_tests
```

Expected: compilation fails because `binobf/capabilities/registry.hpp` does not exist.

- [x] **Step 3: Implement the public types and duplicate-safe registry constructor**

Create `include/binobf/capabilities/registry.hpp` with this contract:

```cpp
#pragma once

#include <binobf/core/diagnostic.hpp>
#include <binobf/core/result.hpp>
#include <binobf/core/types.hpp>

#include <compare>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace binobf {

enum class Capability : std::uint8_t {
    Detection,
    RelocatableObjectParsing,
    LinkedImageParsing,
    StructuralVerification,
    Emission,
    BaselineMetadataTransformation,
    MachineCodeTransformation,
    VmLowering,
    VmProtection,
    InstructionDecoding,
    ObjectAnalysis,
    CodeGeneration,
};

enum class SupportLevel : std::uint8_t {
    Supported,
    Experimental,
    Restricted,
    Planned,
    Unsupported,
    NotApplicable,
};

struct CapabilityKey {
    Capability capability{Capability::Detection};
    BinaryFormat format{BinaryFormat::Unknown};
    BinaryType binaryType{BinaryType::Unknown};
    Architecture architecture{Architecture::Unknown};

    auto operator<=>(const CapabilityKey&) const = default;
};

struct CapabilityRecord {
    CapabilityKey key;
    SupportLevel support{SupportLevel::Unsupported};
    std::string_view qualifier;
    std::vector<std::string_view> evidence;
};

class CapabilityRegistry {
public:
    [[nodiscard]] static auto create(std::span<const CapabilityRecord> records)
        -> Result<CapabilityRegistry, Diagnostic>;
    [[nodiscard]] auto records() const noexcept -> std::span<const CapabilityRecord>;
    [[nodiscard]] auto find(const CapabilityKey& key) const noexcept
        -> const CapabilityRecord*;

private:
    explicit CapabilityRegistry(std::vector<CapabilityRecord> records)
        : records_(std::move(records)) {}
    std::vector<CapabilityRecord> records_;
};

[[nodiscard]] auto builtin_capability_registry() -> const CapabilityRegistry&;
[[nodiscard]] auto to_string(Capability capability) noexcept -> std::string_view;
[[nodiscard]] auto to_string(SupportLevel support) noexcept -> std::string_view;

} // namespace binobf
```

Implement `CapabilityRegistry::create` by sorting a copied vector on the four key fields, rejecting
adjacent duplicate keys with `capability.duplicate_key`, and returning immutable spans/pointers.
Implement all enum string conversions with exhaustive switches.

- [x] **Step 4: Populate the exact current built-in matrix**

In `src/capabilities/registry.cpp`, create the 48 records represented by the two README tables:

- 9 format capabilities x 4 formats = 36 logical cells, excluding the standalone-VM presentation
  row because it is not a format capability;
- omit no logical cell, including every `NotApplicable` relationship;
- 4 architecture capabilities x 3 architectures = 12 cells;
- use one record per cell, for an exact built-in total of 48.

Use current truth exactly: PE machine-code transformation is `Planned`; COFF/ELF VM lowering and
protection are `Restricted`; archive VM paths are `Unsupported`; x86 and ARM64 analysis are
`Experimental`; x86 and ARM64 code generation is `Planned`; x86-64 code generation is
`Restricted`. Attach at least one existing evidence ID to every `Supported` record and leave
non-supported records evidence-free in this task.

- [x] **Step 5: Run the focused test to green**

Run:

```powershell
cmake --build build\m12-verify-debug --target binobf_capability_registry_tests
ctest --test-dir build\m12-verify-debug -R '^capability_registry$' --output-on-failure
```

Expected: `capability_registry` passes and reports every current matrix cell exactly once.

- [x] **Step 6: Commit the typed registry**

```powershell
git add CMakeLists.txt include/binobf/capabilities/registry.hpp `
  src/capabilities/registry.cpp tests/unit/capability_registry_tests.cpp
git commit -m "feat: add typed capability registry"
```

---

### Task 2: Acceptance-evidence catalog and live CTest enforcement

**Files:**
- Create: `include/binobf/capabilities/evidence.hpp`
- Create: `src/capabilities/evidence.cpp`
- Create: `tests/integration/capability_evidence_tests.cpp`
- Modify: `tests/unit/capability_registry_tests.cpp`
- Modify: `CMakeLists.txt:109-170`
- Modify: `CMakeLists.txt:354-1000`

**Interfaces:**
- Consumes: `CapabilityRegistry::records()` and the generated root `CTestTestfile.cmake`.
- Produces: `AcceptanceEvidence`, `builtin_acceptance_evidence()`, and `validate_capability_evidence()`.

- [x] **Step 1: Add failing evidence validation tests**

Append to `tests/unit/capability_registry_tests.cpp`:

```cpp
#include <binobf/capabilities/evidence.hpp>

TEST_CASE(supported_capabilities_require_known_release_evidence) {
    const auto validated = binobf::validate_capability_evidence(
        binobf::builtin_capability_registry(),
        binobf::builtin_acceptance_evidence());
    REQUIRE(validated.has_value());
    REQUIRE(validated.value() > 0U);
}

TEST_CASE(unknown_and_duplicate_evidence_ids_are_rejected) {
    const std::array duplicateEvidence{
        binobf::AcceptanceEvidence{"format-detection", "format_detector", true},
        binobf::AcceptanceEvidence{"format-detection", "core_types", true},
    };
    const auto duplicate = binobf::validate_capability_evidence(
        binobf::builtin_capability_registry(), duplicateEvidence);
    REQUIRE(!duplicate.has_value());
    REQUIRE_EQ(duplicate.error().code, "capability.duplicate_evidence");
}
```

- [x] **Step 2: Run the focused build and confirm the missing-header failure**

```powershell
cmake --build build\m12-verify-debug --target binobf_capability_registry_tests
```

Expected: compilation fails because `binobf/capabilities/evidence.hpp` is absent.

- [x] **Step 3: Implement the evidence catalog contract**

Create `include/binobf/capabilities/evidence.hpp`:

```cpp
#pragma once

#include <binobf/capabilities/registry.hpp>

#include <span>
#include <string_view>

namespace binobf {

struct AcceptanceEvidence {
    std::string_view id;
    std::string_view ctestName;
    bool releaseGate{true};
};

[[nodiscard]] auto builtin_acceptance_evidence()
    -> std::span<const AcceptanceEvidence>;
[[nodiscard]] auto validate_capability_evidence(
    const CapabilityRegistry& registry,
    std::span<const AcceptanceEvidence> evidence)
    -> Result<std::size_t, Diagnostic>;

} // namespace binobf
```

Implement deterministic duplicate-ID detection, require each `Supported` record to have at least
one evidence ID, require every referenced ID to exist, and require referenced evidence to have a
non-empty CTest name. Return the number of validated supported records.

The built-in evidence catalog must bind current records to these existing test names where
applicable: `format_detector`, `object_parser_integration`, `object_writer_integration`,
`linked_image_integration`, `archive_integration`, `structural_verifier`,
`instruction_transform_integration`, `vm_lowering_differential`, and
`vm_protection_integration`.

- [x] **Step 4: Add an integration test that checks actual registered CTest names**

Create `tests/integration/capability_evidence_tests.cpp` that accepts exactly one path argument,
reads the generated root `CTestTestfile.cmake`, calls `validate_capability_evidence`, and verifies
each `releaseGate` entry's `ctestName` appears in an `add_test` record. Use bounded file reading and
return a nonzero exit with the missing test name on failure.

Register it after all other tests in `CMakeLists.txt`:

```cmake
add_executable(
    binobf_capability_evidence_tests
    tests/integration/capability_evidence_tests.cpp
)
target_link_libraries(binobf_capability_evidence_tests PRIVATE binobf::core)
binobf_enable_warnings(binobf_capability_evidence_tests)
add_test(
    NAME capability_evidence
    COMMAND binobf_capability_evidence_tests
        "${CMAKE_CURRENT_BINARY_DIR}/CTestTestfile.cmake"
)
```

- [x] **Step 5: Run both evidence tests to green**

```powershell
cmake --build build\m12-verify-debug --target `
  binobf_capability_registry_tests binobf_capability_evidence_tests
ctest --test-dir build\m12-verify-debug `
  -R '^capability_(registry|evidence)$' --output-on-failure
```

Expected: both tests pass; temporarily changing an evidence CTest name makes
`capability_evidence` fail with that name.

- [ ] **Step 6: Commit evidence enforcement**

```powershell
git add CMakeLists.txt include/binobf/capabilities/evidence.hpp `
  src/capabilities/evidence.cpp tests/unit/capability_registry_tests.cpp `
  tests/integration/capability_evidence_tests.cpp
git commit -m "test: bind capabilities to acceptance evidence"
```

---

### Task 3: Public pass registration derived from real pass objects

**Files:**
- Create: `include/binobf/transforms/registry.hpp`
- Create: `src/transforms/registry.cpp`
- Create: `tests/unit/pass_registry_tests.cpp`
- Modify: `src/cli/command.cpp:439-477`
- Modify: `src/cli/command.cpp:688-702`
- Modify: `CMakeLists.txt:109-170`
- Modify: `CMakeLists.txt:420-456`

**Interfaces:**
- Consumes: all eleven `make_*_pass()` factories and `TransformPass::requirements()`.
- Produces: `PassRegistration`, `registered_passes()`, `find_registered_pass()`, and `make_registered_pass()`.

- [ ] **Step 1: Write failing pass-registry completeness tests**

Create `tests/unit/pass_registry_tests.cpp`:

```cpp
#include <binobf/transforms/registry.hpp>

#include "../test_support.hpp"

#include <algorithm>
#include <array>
#include <string_view>

using namespace std::string_view_literals;

TEST_CASE(pass_registry_has_unique_names_and_factories_for_every_builtin) {
    constexpr std::array expected{
        "strip-debug"sv, "cleanup-metadata"sv, "strip-local-symbols"sv,
        "rename-private-symbols"sv, "instruction-substitution"sv,
        "constant-rewriting"sv, "branch-inversion"sv, "dead-code-insertion"sv,
        "block-splitting"sv, "block-reordering"sv, "function-reordering"sv,
    };
    const auto registrations = binobf::registered_passes();
    REQUIRE_EQ(registrations.size(), expected.size());
    for (const auto name : expected) {
        const auto* registration = binobf::find_registered_pass(name);
        REQUIRE(registration != nullptr);
        const auto pass = binobf::make_registered_pass(name);
        REQUIRE(pass != nullptr);
        REQUIRE_EQ(pass->name(), name);
    }
    REQUIRE(binobf::find_registered_pass("not-a-pass") == nullptr);
    REQUIRE(binobf::make_registered_pass("not-a-pass") == nullptr);
}

int main() {
    return binobf::test::run_all();
}
```

- [ ] **Step 2: Register and run the test to verify missing interfaces**

Add the source and test target using the existing unit-test pattern, then run:

```powershell
cmake --build build\m12-verify-debug --target binobf_pass_registry_tests
```

Expected: compilation fails because `binobf/transforms/registry.hpp` does not exist.

- [ ] **Step 3: Implement registrations with factory function pointers**

Create `include/binobf/transforms/registry.hpp`:

```cpp
#pragma once

#include <binobf/transforms/pass.hpp>

#include <memory>
#include <span>
#include <string_view>

namespace binobf {

using PassFactory = std::unique_ptr<TransformPass> (*)();

struct PassRegistration {
    std::string_view name;
    PassFactory factory{nullptr};
};

[[nodiscard]] auto registered_passes() -> std::span<const PassRegistration>;
[[nodiscard]] auto find_registered_pass(std::string_view name) noexcept
    -> const PassRegistration*;
[[nodiscard]] auto make_registered_pass(std::string_view name)
    -> std::unique_ptr<TransformPass>;

} // namespace binobf
```

Define one sorted static registration per existing factory. At static initialization, do not
construct pass objects. `make_registered_pass` calls the selected non-null factory.

- [ ] **Step 4: Remove CLI pass-name and factory duplication**

Replace the name chain at `src/cli/command.cpp:688-702` with `make_registered_pass(name)`. Replace
the explicit-name validation at `src/cli/command.cpp:459-469` with
`find_registered_pass(name) == nullptr`. Keep profile expansion order unchanged.

- [ ] **Step 5: Run pass, config, CLI, and transformation tests**

```powershell
cmake --build build\m12-verify-debug --target `
  binobf_pass_registry_tests binobf_pass_manager_tests `
  binobf_config_tests binobf_cli_tests
ctest --test-dir build\m12-verify-debug `
  -R '^(pass_registry|pass_manager|config|cli)$' --output-on-failure
```

Expected: all four tests pass, profiles retain their order, and an unknown pass still exits with
the existing diagnostic.

- [ ] **Step 6: Commit the pass registry**

```powershell
git add CMakeLists.txt include/binobf/transforms/registry.hpp `
  src/transforms/registry.cpp src/cli/command.cpp tests/unit/pass_registry_tests.cpp
git commit -m "refactor: centralize transform pass registration"
```

---

### Task 4: Capability renderers for CLI and README matrices

**Files:**
- Create: `include/binobf/capabilities/render.hpp`
- Create: `src/capabilities/render.cpp`
- Create: `tests/unit/capability_render_tests.cpp`
- Modify: `src/cli/command.cpp:1358-1416`
- Modify: `tests/integration/cli_tests.cpp:348-376`
- Modify: `README.md:11-30`
- Modify: `CMakeLists.txt:109-170`
- Modify: `CMakeLists.txt:354-524`

**Interfaces:**
- Consumes: `CapabilityRegistry`, `registered_passes()`, and each pass's `PassRequirements`.
- Produces: `render_format_capabilities_text()`, `render_architecture_capabilities_text()`,
  `render_pass_capabilities_text()`, and `render_feature_matrix_markdown()`.

- [ ] **Step 1: Write failing exact-render tests**

Create `tests/unit/capability_render_tests.cpp` with assertions that:

```cpp
const auto& registry = binobf::builtin_capability_registry();
REQUIRE_CONTAINS(
    binobf::render_format_capabilities_text(registry),
    "COFF detection=supported parsing=supported emission=supported");
REQUIRE_CONTAINS(
    binobf::render_architecture_capabilities_text(registry),
    "x86 detection=supported decoder=supported object-analysis=experimental codegen=planned");
REQUIRE_CONTAINS(
    binobf::render_pass_capabilities_text(),
    "instruction-substitution risk=medium");
REQUIRE_CONTAINS(
    binobf::render_feature_matrix_markdown(registry),
    "| x86-64 | supported | supported | supported | restricted object backend |");
```

Add a second case that checks the markdown renderer emits the exact 9-row format table and 3-row
architecture table in deterministic order.

- [ ] **Step 2: Register the test and confirm the missing-renderer failure**

```powershell
cmake --build build\m12-verify-debug --target binobf_capability_render_tests
```

Expected: compile failure because `binobf/capabilities/render.hpp` is absent.

- [ ] **Step 3: Implement deterministic rendering from registry records**

Declare the four functions in `include/binobf/capabilities/render.hpp`, each returning
`std::string`. Implement fixed presentation order arrays and look up every cell by `CapabilityKey`.
Return `capability.missing_record` only from an internal checked lookup during construction of the
built-in registry; public renderers operate on a previously validated registry and render an
explicit `missing` token if passed an incomplete custom registry.

For pass output, instantiate each `registered_passes()` factory once, read `name()` and
`requirements()`, sort architecture/format names, and render risk, CFG, relocation, size-change, and
post-link fields from those values. Do not duplicate pass names or requirement claims in the
renderer.

- [ ] **Step 4: Replace the CLI's hard-coded capability strings**

Change `print_formats`, `print_architectures`, and `print_passes` to write the corresponding
renderer result. Update CLI tests to compare the entire expected output, not isolated substrings.
This test must prove output is byte-stable and still reflects the current non-supported statuses.

- [ ] **Step 5: Bind the README tables to generated markdown**

Wrap the two README tables with these markers:

```markdown
<!-- binobf:feature-matrix:start -->
...rendered tables...
<!-- binobf:feature-matrix:end -->
```

Add a test in `capability_render_tests.cpp` that receives `README.md` as `argv[1]`, extracts bytes
between the markers, and compares them with `render_feature_matrix_markdown`. Register the test
command with `${CMAKE_CURRENT_SOURCE_DIR}/README.md`. A table edit without a registry change must
fail this test.

- [ ] **Step 6: Run renderer and CLI tests**

```powershell
cmake --build build\m12-verify-debug --target `
  binobf_capability_render_tests binobf_cli_tests
ctest --test-dir build\m12-verify-debug `
  -R '^(capability_render|cli)$' --output-on-failure
```

Expected: both tests pass and all generated text remains current and deterministic.

- [ ] **Step 7: Commit registry-backed presentation**

```powershell
git add CMakeLists.txt README.md include/binobf/capabilities/render.hpp `
  src/capabilities/render.cpp src/cli/command.cpp `
  tests/unit/capability_render_tests.cpp tests/integration/cli_tests.cpp
git commit -m "refactor: render capability claims from registry"
```

---

### Task 5: Architecture backend contract and fixed-architecture Capstone adapters

**Files:**
- Create: `include/binobf/architecture/backend.hpp`
- Create: `src/architecture/capstone_backend.cpp`
- Create: `tests/unit/architecture_backend_tests.cpp`
- Modify: `include/binobf/analysis/instruction_decoder.hpp:14-33`
- Modify: `src/analysis/capstone_instruction_decoder.cpp:16-269`
- Modify: `src/analysis/object_analyzer.cpp:437-447`
- Modify: `src/transforms/instruction.cpp:200-220`
- Modify: `tests/unit/instruction_decoder_tests.cpp:1-120`
- Modify: `CMakeLists.txt:109-170`
- Modify: `CMakeLists.txt:440-456`

**Interfaces:**
- Consumes: `DecodeRequest`, `InstructionDecoder`, `CapabilityRegistry`, and Capstone.
- Produces: `BackendService`, `BackendServiceRecord`, `ArchitectureBackend`,
  `make_architecture_backend(Architecture)`, and a compatibility `make_instruction_decoder()`
  dispatcher.

- [ ] **Step 1: Write failing backend identity, service, and mismatch tests**

Create `tests/unit/architecture_backend_tests.cpp`:

```cpp
#include <binobf/architecture/backend.hpp>

#include "../test_support.hpp"

#include <array>

TEST_CASE(backends_have_fixed_supported_architecture_and_decode_service) {
    for (const auto architecture : std::array{
             binobf::Architecture::X86,
             binobf::Architecture::X86_64,
             binobf::Architecture::ARM64}) {
        const auto backend = binobf::make_architecture_backend(architecture);
        REQUIRE(backend.has_value());
        REQUIRE_EQ(backend.value()->architecture(), architecture);
        const auto* decode = backend.value()->find_service(binobf::BackendService::Decode);
        REQUIRE(decode != nullptr);
        REQUIRE_EQ(decode->support, binobf::SupportLevel::Supported);
    }
}

TEST_CASE(backend_rejects_unknown_architecture_and_mismatched_decode_request) {
    const auto unknown = binobf::make_architecture_backend(binobf::Architecture::Unknown);
    REQUIRE(!unknown.has_value());
    REQUIRE_EQ(unknown.error().code, "architecture.unsupported");

    auto backend = binobf::make_architecture_backend(binobf::Architecture::X86_64);
    REQUIRE(backend.has_value());
    const std::array bytes{std::byte{0xC3}};
    const auto decoded = backend.value()->decode(binobf::DecodeRequest{
        .architecture = binobf::Architecture::X86,
        .bytes = bytes,
        .address = {0x1000, binobf::AddressKind::Virtual},
        .instructionId = binobf::EntityId{1},
        .sectionId = binobf::EntityId{2},
    });
    REQUIRE(!decoded.has_value());
    REQUIRE_EQ(decoded.error().code, "architecture.request_mismatch");
}

int main() {
    return binobf::test::run_all();
}
```

- [ ] **Step 2: Register the test and verify the missing backend contract**

```powershell
cmake --build build\m12-verify-debug --target binobf_architecture_backend_tests
```

Expected: compilation fails because `binobf/architecture/backend.hpp` is absent.

- [ ] **Step 3: Define the backend service and decoder interface**

Create `include/binobf/architecture/backend.hpp`:

```cpp
#pragma once

#include <binobf/analysis/instruction_decoder.hpp>
#include <binobf/capabilities/registry.hpp>

#include <memory>
#include <span>
#include <string_view>

namespace binobf {

enum class BackendService : std::uint8_t {
    Decode,
    AnalyzeObject,
    EmitCode,
    EncodeFixups,
    BuildAbiAdapter,
    BuildUnwind,
};

struct BackendServiceRecord {
    BackendService service{BackendService::Decode};
    SupportLevel support{SupportLevel::Unsupported};
    std::span<const std::string_view> evidence;
};

class ArchitectureBackend : public InstructionDecoder {
public:
    [[nodiscard]] virtual auto architecture() const noexcept -> Architecture = 0;
    [[nodiscard]] virtual auto name() const noexcept -> std::string_view = 0;
    [[nodiscard]] virtual auto services() const noexcept
        -> std::span<const BackendServiceRecord> = 0;
    [[nodiscard]] auto find_service(BackendService service) const noexcept
        -> const BackendServiceRecord*;
};

[[nodiscard]] auto make_architecture_backend(Architecture architecture)
    -> Result<std::unique_ptr<ArchitectureBackend>, Diagnostic>;

} // namespace binobf
```

Keep `DecodeRequest::architecture` during this migration so mismatches are diagnosable. The service
table truthfully marks only currently implemented services supported; it mirrors matrix states for
analysis/code generation and contains evidence IDs for supported decode.

- [ ] **Step 4: Move Capstone ownership into fixed-architecture backend instances**

Move the Capstone implementation to `src/architecture/capstone_backend.cpp`. Construct each backend
with one `Architecture`, call `Handle::open(architecture_)`, and reject a decode request whose
architecture differs. Preserve the existing instruction kinds, targets, register sets, references,
lineage, diagnostic codes, and byte encodings.

Keep `make_instruction_decoder()` in `src/analysis/capstone_instruction_decoder.cpp` as a dispatching
compatibility object. Its `decode` creates the matching architecture backend and delegates once.
This avoids breaking installed consumers while internal paths migrate.

- [ ] **Step 5: Route object analysis and instruction reanalysis through one backend instance**

In `analyze_object`, create one backend for `input.architecture` before function decoding and reuse
it for every instruction. In instruction transforms, create one backend for the image architecture
and reuse it for post-transform re-decoding. Propagate backend creation diagnostics unchanged.

- [ ] **Step 6: Run golden decoder, analyzer, transform, and backend tests**

```powershell
cmake --build build\m12-verify-debug --target `
  binobf_architecture_backend_tests binobf_instruction_decoder_tests `
  binobf_object_analyzer_tests binobf_instruction_transform_tests
ctest --test-dir build\m12-verify-debug `
  -R '^(architecture_backend|instruction_decoder|object_analyzer|instruction_transforms)$' `
  --output-on-failure
```

Expected: all tests pass; existing golden instruction objects and diagnostics are byte-for-byte
unchanged except for the new mismatch diagnostic exercised only by the new API.

- [ ] **Step 7: Commit architecture-owned decoding**

```powershell
git add CMakeLists.txt include/binobf/architecture/backend.hpp `
  include/binobf/analysis/instruction_decoder.hpp `
  src/architecture/capstone_backend.cpp `
  src/analysis/capstone_instruction_decoder.cpp src/analysis/object_analyzer.cpp `
  src/transforms/instruction.cpp tests/unit/architecture_backend_tests.cpp `
  tests/unit/instruction_decoder_tests.cpp
git commit -m "refactor: route decoding through architecture backends"
```

---

### Task 6: Cross-registry consistency and public-header/package gates

**Files:**
- Create: `tests/integration/capability_consistency_tests.cpp`
- Modify: `tests/unit/capability_registry_tests.cpp`
- Modify: `docs/architecture.md`
- Modify: `docs/developer-guide.md`
- Modify: `docs/verification.md`
- Modify: `CMakeLists.txt:340-352`
- Modify: `CMakeLists.txt:950-1000`

**Interfaces:**
- Consumes: built-in capability, evidence, pass, and backend registries.
- Produces: one release-gating consistency test and installed public capability/backend headers.

- [ ] **Step 1: Write the failing consistency test**

Create `tests/integration/capability_consistency_tests.cpp` with these invariants:

```cpp
const auto& capabilities = binobf::builtin_capability_registry();
for (const auto architecture : std::array{
         binobf::Architecture::X86,
         binobf::Architecture::X86_64,
         binobf::Architecture::ARM64}) {
    auto backend = binobf::make_architecture_backend(architecture);
    REQUIRE(backend.has_value());
    const auto* decodeService = backend.value()->find_service(binobf::BackendService::Decode);
    const auto* decodeCapability = capabilities.find({
        .capability = binobf::Capability::InstructionDecoding,
        .architecture = architecture,
    });
    REQUIRE(decodeService != nullptr);
    REQUIRE(decodeCapability != nullptr);
    REQUIRE_EQ(decodeService->support, decodeCapability->support);
}

for (const auto& registration : binobf::registered_passes()) {
    const auto pass = registration.factory();
    REQUIRE(pass != nullptr);
    REQUIRE_EQ(pass->name(), registration.name);
    REQUIRE(!pass->requirements().formats.empty());
    REQUIRE(!pass->requirements().architectures.empty());
}
```

Also compare `render_feature_matrix_markdown()` to the README marker block and call
`validate_capability_evidence()`.

- [ ] **Step 2: Register the test and make the intended pass-metadata failures visible**

Run:

```powershell
cmake --build build\m12-verify-debug --target binobf_capability_consistency_tests
ctest --test-dir build\m12-verify-debug -R '^capability_consistency$' --output-on-failure
```

Expected: the test initially exposes any baseline pass that omits a truthful architecture or
format requirement. Update only that pass's `requirements()` record to match its existing tested
behavior; do not broaden `supports()` or change a matrix status.

- [ ] **Step 3: Document the contract and promotion rule**

Update documentation with exact statements:

- `docs/architecture.md`: registries are public, backends own fixed-architecture services, and
  Capstone remains private.
- `docs/developer-guide.md`: adding or promoting a capability requires a record, evidence catalog
  entry, registered CTest, standard-tool/runtime evidence, renderer update through the registry,
  and consistency gate.
- `docs/verification.md`: list `capability_registry`, `capability_evidence`,
  `capability_render`, `architecture_backend`, and `capability_consistency` as release gates.

- [ ] **Step 4: Run standalone-header and install-consumer checks**

Run the repository's standalone public-header loop against every header under `include/binobf`,
including the five new headers. Then install the Debug or Release build to a new prefix under
`build/track17-install` and compile a consumer that includes:

```cpp
#include <binobf/architecture/backend.hpp>
#include <binobf/capabilities/evidence.hpp>
#include <binobf/capabilities/registry.hpp>
#include <binobf/capabilities/render.hpp>
#include <binobf/transforms/registry.hpp>
```

The consumer must create all three backends, validate built-in evidence, render both matrices, and
exit zero.

- [ ] **Step 5: Run the complete track gate**

Run:

```powershell
cmake --build build\m12-verify-debug
ctest --test-dir build\m12-verify-debug --output-on-failure
cmake --build build\m12-verify-release
ctest --test-dir build\m12-verify-release --output-on-failure
cmake --build build\m12-ubsan-relwithdebinfo
ctest --test-dir build\m12-ubsan-relwithdebinfo --output-on-failure
cmake --build build\m13-fuzz-final --target fuzz-smoke
```

Then run whole-production static analysis, `git diff --check`, the source-corpus hygiene check, and
the installed consumer. Expected: every gate passes, capability text still reports the current
truth, and no build artifact is tracked.

- [ ] **Step 6: Commit documentation and release gates**

```powershell
git add CMakeLists.txt docs/architecture.md docs/developer-guide.md `
  docs/verification.md tests/unit/capability_registry_tests.cpp `
  tests/integration/capability_consistency_tests.cpp
git commit -m "test: enforce capability and backend consistency"
```

- [ ] **Step 7: Record track completion without claiming program completion**

Update this plan's checkboxes and the umbrella program checklist. Confirm `git status -sb` is clean.
The next design track is LLVM MC plus expanded native IR from the approved program spec; do not
promote feature-matrix cells during this foundation track.

#include <binobf/capabilities/render.hpp>
#include <binobf/capabilities/registry.hpp>

#include "../test_support.hpp"

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

namespace {

std::filesystem::path readmePath;

constexpr std::string_view expectedMarkdown =
    "| Capability | PE | COFF object | ELF | Archive |\n"
    "|---|---:|---:|---:|---:|\n"
    "| Header/container detection | supported | supported | supported | supported |\n"
    "| Relocatable-object parsing | n/a | supported | supported | supported members |\n"
    "| Linked-image detailed parsing | supported | n/a | supported | n/a |\n"
    "| Structural verification | supported | supported | supported | supported |\n"
    "| Exact linked/object emission | supported | supported | supported | supported |\n"
    "| Baseline metadata transformations | supported strip-debug | supported | supported including linked | supported per object member |\n"
    "| x86/x86-64/ARM64 instruction/CFG/layout transformations | planned | supported | supported | supported per object member |\n"
    "| Selected x86-64 function VM lowering | n/a | restricted | restricted | unsupported |\n"
    "| Embedded selected-function VM protection | n/a | restricted | restricted | unsupported |\n"
    "\n"
    "| Architecture | Detection | Decoder | Object analysis | Code generation |\n"
    "|---|---:|---:|---:|---:|\n"
    "| x86 | supported | supported | supported | supported |\n"
    "| x86-64 | supported | supported | supported | restricted object backend |\n"
    "| ARM64 | supported | supported | supported | supported |\n";

constexpr std::string_view expectedPassText =
    "block-reordering risk=medium cfg=yes relocations=required lifted-ir=no size-change=no post-link=unsupported formats=COFF,ELF architectures=arm64,x86,x86-64\n"
    "block-splitting risk=medium cfg=yes relocations=not-required lifted-ir=no size-change=no post-link=unsupported formats=COFF,ELF architectures=arm64,x86,x86-64\n"
    "branch-inversion risk=medium cfg=yes relocations=not-required lifted-ir=no size-change=no post-link=unsupported formats=COFF,ELF architectures=arm64,x86,x86-64\n"
    "cleanup-metadata risk=low cfg=no relocations=required lifted-ir=no size-change=no post-link=unsupported formats=COFF,ELF architectures=arm64,x86,x86-64\n"
    "constant-rewriting risk=medium cfg=no relocations=not-required lifted-ir=no size-change=no post-link=unsupported formats=COFF,ELF architectures=arm64,x86,x86-64\n"
    "dead-code-insertion risk=medium cfg=yes relocations=not-required lifted-ir=no size-change=no post-link=unsupported formats=COFF,ELF architectures=arm64,x86,x86-64\n"
    "function-reordering risk=medium cfg=yes relocations=required lifted-ir=no size-change=no post-link=unsupported formats=COFF,ELF architectures=arm64,x86,x86-64\n"
    "instruction-substitution risk=medium cfg=no relocations=not-required lifted-ir=no size-change=no post-link=unsupported formats=COFF,ELF architectures=arm64,x86,x86-64\n"
    "rename-private-symbols risk=low cfg=no relocations=not-required lifted-ir=no size-change=no post-link=unsupported formats=COFF,ELF architectures=arm64,x86,x86-64\n"
    "strip-debug risk=low cfg=no relocations=required lifted-ir=no size-change=no post-link=unsupported formats=COFF,ELF architectures=arm64,x86,x86-64\n"
    "strip-local-symbols risk=low cfg=no relocations=required lifted-ir=no size-change=no post-link=unsupported formats=COFF,ELF architectures=arm64,x86,x86-64\n";

} // namespace

TEST_CASE(capability_renderers_report_registry_and_pass_truth) {
    const auto& registry = binobf::builtin_capability_registry();
    REQUIRE_CONTAINS(
        binobf::render_format_capabilities_text(registry),
        "COFF detection=supported parsing=supported emission=supported");
    REQUIRE_CONTAINS(
        binobf::render_architecture_capabilities_text(registry),
        "x86 detection=supported decoder=supported object-analysis=supported codegen=supported");
    REQUIRE_CONTAINS(
        binobf::render_pass_capabilities_text(),
        "instruction-substitution risk=medium");
    REQUIRE_EQ(binobf::render_pass_capabilities_text(), expectedPassText);
    REQUIRE_CONTAINS(
        binobf::render_feature_matrix_markdown(registry),
        "| x86-64 | supported | supported | supported | restricted object backend |");
}

TEST_CASE(markdown_renderer_is_complete_and_deterministic) {
    const auto& registry = binobf::builtin_capability_registry();
    REQUIRE_EQ(binobf::render_feature_matrix_markdown(registry), expectedMarkdown);
    REQUIRE_EQ(binobf::render_feature_matrix_markdown(registry),
               binobf::render_feature_matrix_markdown(registry));
}

TEST_CASE(readme_feature_matrix_matches_generated_markdown) {
    std::ifstream input(readmePath, std::ios::binary);
    REQUIRE(input.good());
    const std::string contents(std::istreambuf_iterator<char>{input},
                               std::istreambuf_iterator<char>{});
    REQUIRE(!input.bad());

    constexpr std::string_view startMarker = "<!-- binobf:feature-matrix:start -->\n";
    constexpr std::string_view endMarker = "<!-- binobf:feature-matrix:end -->";
    const auto start = contents.find(startMarker);
    REQUIRE(start != std::string::npos);
    const auto bodyStart = start + startMarker.size();
    const auto end = contents.find(endMarker, bodyStart);
    REQUIRE(end != std::string::npos);
    REQUIRE_EQ(contents.substr(bodyStart, end - bodyStart),
               binobf::render_feature_matrix_markdown(
                   binobf::builtin_capability_registry()));
}

auto main(int argc, char** argv) -> int {
    if (argc != 2) {
        return 2;
    }
    readmePath = argv[1];
    return binobf::test::run_all();
}

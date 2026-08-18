#include <binobf/formats/object_parser.hpp>
#include <binobf/formats/object_writer.hpp>
#include <binobf/transforms/instruction.hpp>
#include <binobf/transforms/pass_manager.hpp>

#include "../test_support.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::filesystem::path coffFixture;
std::filesystem::path elfFixture;

auto read_file(const std::filesystem::path& path) -> std::vector<std::byte> {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("could not open i386 transform fixture");
    const auto end = stream.tellg();
    if (end < 0) throw std::runtime_error("could not size i386 transform fixture");
    std::vector<std::byte> result(static_cast<std::size_t>(end));
    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(result.data()), static_cast<std::streamsize>(result.size()));
    if (!stream) throw std::runtime_error("could not read i386 transform fixture");
    return result;
}

auto passes() -> std::array<std::unique_ptr<binobf::TransformPass>, 7> {
    return {
        binobf::make_instruction_substitution_pass(),
        binobf::make_constant_rewriting_pass(),
        binobf::make_branch_inversion_pass(),
        binobf::make_block_splitting_pass(),
        binobf::make_dead_code_insertion_pass(),
        binobf::make_block_reordering_pass(),
        binobf::make_function_reordering_pass(),
    };
}

auto run_every_pass(const std::filesystem::path& fixture) -> void {
    const auto originalBytes = read_file(fixture);
    const auto parsed = binobf::parse_object(originalBytes, fixture.filename().string());
    REQUIRE(parsed.has_value());
    REQUIRE_EQ(parsed.value().architecture, binobf::Architecture::X86);
    const auto common = std::ranges::find(
        parsed.value().symbols, std::string{"binobf_x86_common"}, &binobf::Symbol::name);
    const auto tls = std::ranges::find(
        parsed.value().symbols, std::string{"binobf_x86_tls"}, &binobf::Symbol::name);
    REQUIRE(common != parsed.value().symbols.end());
    REQUIRE(tls != parsed.value().symbols.end());
    REQUIRE_EQ(common->definition, std::optional{binobf::SymbolDefinitionKind::Common});
    const auto tlsSection = tls->section.has_value()
        ? std::ranges::find(parsed.value().sections, *tls->section, &binobf::Section::id)
        : parsed.value().sections.end();
    REQUIRE(tls->kind == binobf::SymbolKind::Tls
            || (tlsSection != parsed.value().sections.end()
                && tlsSection->name.starts_with(".tls")));
    REQUIRE(!parsed.value().sectionAssociations.empty());
    for (auto& pass : passes()) {
        const auto passName = std::string{pass->name()};
        auto candidate = parsed.value();
        binobf::PassManager manager;
        REQUIRE(manager.add(std::move(pass)).has_value());
        binobf::TransformContext context{UINT64_C(0x386386), false};
        const auto transformed = manager.run(context, candidate);
        if (!transformed.has_value()) {
            throw std::runtime_error(
                passName + ": " + transformed.error().code + ": " + transformed.error().message);
        }
        REQUIRE_EQ(transformed.value().reports.size(), std::size_t{1});
        REQUIRE_EQ(transformed.value().reports.front().status, binobf::PassStatus::Applied);
        REQUIRE(transformed.value().reports.front().statistics.changed > 0U);
        const auto written = binobf::write_object(transformed.value().image);
        REQUIRE(written.has_value());
        REQUIRE(written.value() != originalBytes);
        const auto reparsed = binobf::parse_object(written.value(), "i386-transformed.o");
        REQUIRE(reparsed.has_value());
        REQUIRE_EQ(reparsed.value().architecture, binobf::Architecture::X86);
        const auto reparsedCommon = std::ranges::find(
            reparsed.value().symbols, std::string{"binobf_x86_common"}, &binobf::Symbol::name);
        const auto reparsedTls = std::ranges::find(
            reparsed.value().symbols, std::string{"binobf_x86_tls"}, &binobf::Symbol::name);
        REQUIRE(reparsedCommon != reparsed.value().symbols.end());
        REQUIRE(reparsedTls != reparsed.value().symbols.end());
        REQUIRE_EQ(reparsedCommon->definition,
                   std::optional{binobf::SymbolDefinitionKind::Common});
        REQUIRE_EQ(reparsedTls->kind, tls->kind);
        REQUIRE_EQ(reparsedTls->tlsModel, tls->tlsModel);
        REQUIRE_EQ(reparsed.value().sectionAssociations.size(),
                   parsed.value().sectionAssociations.size());
    }
}

} // namespace

TEST_CASE(all_seven_machine_passes_transform_real_i386_coff_and_elf_objects) {
    run_every_pass(coffFixture);
    run_every_pass(elfFixture);
}

int main(int argc, char** argv) {
    if (argc != 3) return 2;
    coffFixture = argv[1];
    elfFixture = argv[2];
    return binobf::test::run_all();
}

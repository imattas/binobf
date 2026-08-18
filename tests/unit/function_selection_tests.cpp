#include "../test_support.hpp"

#include <binobf/transforms/pass.hpp>
#include <binobf/transforms/selection.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace {

auto make_image() -> binobf::BinaryImage {
    binobf::BinaryImage image;
    for (const auto& [id, name] : std::vector<std::pair<std::uint64_t, std::string>>{
             {1, ".text"}, {2, ".cold"}}) {
        binobf::Section section;
        section.id = binobf::EntityId{id};
        section.name = name;
        image.sections.push_back(std::move(section));
    }
    const auto addSymbol = [&image](std::uint64_t id,
                                    std::string name,
                                    std::uint64_t sectionId,
                                    binobf::SymbolVisibility visibility) {
        binobf::Symbol symbol;
        symbol.id = binobf::EntityId{id};
        symbol.name = std::move(name);
        symbol.section = binobf::EntityId{sectionId};
        symbol.kind = binobf::SymbolKind::Function;
        symbol.visibility = visibility;
        symbol.defined = true;
        image.symbols.push_back(std::move(symbol));
    };
    addSymbol(10, "keep_api", 1, binobf::SymbolVisibility::External);
    addSymbol(11, "keep_bad", 1, binobf::SymbolVisibility::External);
    addSymbol(12, "keep_local", 1, binobf::SymbolVisibility::Local);
    addSymbol(13, "keep_cold", 2, binobf::SymbolVisibility::External);
    for (const auto& symbol : image.symbols) {
        binobf::Function function;
        function.id = binobf::EntityId{symbol.id.value() + 100};
        function.name = symbol.name;
        function.section = *symbol.section;
        function.symbol = symbol.id;
        function.externallyVisible = symbol.visibility == binobf::SymbolVisibility::External;
        function.complete = true;
        image.functions.push_back(std::move(function));
    }
    return image;
}

} // namespace

TEST_CASE(function_selection_combines_allowlists_filters_and_deny_precedence) {
    binobf::FunctionSelectionPolicy policy;
    policy.includeRegex = {"^keep_.*$"};
    policy.excludeNames = {"keep_bad"};
    policy.sections = {".text"};
    policy.visibilities = {binobf::SymbolVisibility::External};
    const auto selector = binobf::FunctionSelector::compile(policy);
    REQUIRE(selector.has_value());
    const auto image = make_image();
    REQUIRE(selector.value().matches(image, image.functions.at(0), "keep_api"));
    REQUIRE(!selector.value().matches(image, image.functions.at(1), "keep_bad"));
    REQUIRE(!selector.value().matches(image, image.functions.at(2), "keep_local"));
    REQUIRE(!selector.value().matches(image, image.functions.at(3), "keep_cold"));
}

TEST_CASE(function_selection_rejects_invalid_regex_and_has_stable_sampling) {
    binobf::FunctionSelectionPolicy invalid;
    invalid.includeRegex = {"[unterminated"};
    const auto rejected = binobf::FunctionSelector::compile(invalid);
    REQUIRE(!rejected.has_value());
    REQUIRE_EQ(rejected.error().code, "selection.regex");

    auto image = make_image();
    binobf::FunctionSelectionPolicy sampled;
    sampled.percentage = 37;
    sampled.seed = UINT64_C(0x12345678);
    const auto first = binobf::FunctionSelector::compile(sampled);
    const auto second = binobf::FunctionSelector::compile(sampled);
    REQUIRE(first.has_value());
    REQUIRE(second.has_value());
    for (const auto& function : image.functions) {
        REQUIRE_EQ(
            first.value().matches(image, function, function.name),
            second.value().matches(image, function, function.name));
    }
    sampled.percentage = 0;
    const auto none = binobf::FunctionSelector::compile(sampled);
    REQUIRE(none.has_value());
    for (const auto& function : image.functions) {
        REQUIRE(!none.value().matches(image, function, function.name));
    }
}

TEST_CASE(transform_context_tracks_original_names_across_private_symbol_renaming) {
    binobf::TransformContext context{99, false};
    binobf::FunctionSelectionPolicy policy;
    policy.includeNames = {"keep_local"};
    REQUIRE(context.set_function_selection(policy).has_value());
    context.record_symbol_rename("keep_local", "__bo_renamed");

    auto image = make_image();
    image.symbols.at(2).name = "__bo_renamed";
    image.functions.at(2).name = "__bo_renamed";
    REQUIRE(context.is_function_selected(image, image.functions.at(2)));
    REQUIRE(!context.is_function_selected(image, image.functions.at(0)));
}

int main() {
    return binobf::test::run_all();
}

#include "../test_support.hpp"

#include <binobf/transforms/pass_manager.hpp>

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

auto make_image() -> binobf::BinaryImage {
    binobf::BinaryImage image;
    image.format = binobf::BinaryFormat::COFF;
    image.type = binobf::BinaryType::RelocatableObject;
    image.architecture = binobf::Architecture::X86_64;
    image.sections.push_back(binobf::Section{
        .id = binobf::EntityId{1}, .formatIndex = 1,
        .formatFlags = 0x60300020, .name = ".text",
        .kind = binobf::SectionKind::Code, .address = {},
        .logicalSize = 1, .alignment = 4, .readable = true,
        .executable = true, .contents = {std::byte{0x90}}, .lineage = {}});
    return image;
}

class TestPass final : public binobf::TransformPass {
public:
    TestPass(
        std::string passName,
        std::vector<std::string> dependencies,
        std::string replacement,
        std::vector<std::string>* order = nullptr,
        bool reportChanged = true,
        bool supported = true,
        bool corrupt = false)
        : name_(std::move(passName)), dependencies_(std::move(dependencies)),
          replacement_(std::move(replacement)), order_(order),
          reportChanged_(reportChanged), supported_(supported), corrupt_(corrupt) {}

    auto name() const noexcept -> std::string_view override { return name_; }
    auto dependencies() const -> std::vector<std::string> override { return dependencies_; }
    auto requirements() const -> binobf::PassRequirements override { return {}; }
    auto supports(const binobf::TransformContext&, const binobf::BinaryImage&) const
        -> bool override { return supported_; }

    auto run(binobf::TransformContext&, binobf::BinaryImage& image) const
        -> binobf::Result<binobf::TransformResult, binobf::Diagnostic> override {
        if (order_ != nullptr) order_->push_back(name_);
        if (corrupt_) {
            image.sections.front().alignment = 0;
        } else if (!replacement_.empty()) {
            image.sections.front().name = replacement_;
        }
        return binobf::Result<binobf::TransformResult, binobf::Diagnostic>::success(
            binobf::TransformResult{
                .changed = reportChanged_,
                .statistics = {.examined = 1, .changed = reportChanged_ ? 1U : 0U},
                .diagnostics = {},
            });
    }

private:
    std::string name_;
    std::vector<std::string> dependencies_;
    std::string replacement_;
    std::vector<std::string>* order_;
    bool reportChanged_;
    bool supported_;
    bool corrupt_;
};

} // namespace

TEST_CASE(pass_manager_orders_dependencies_deterministically) {
    std::vector<std::string> order;
    binobf::PassManager manager;
    REQUIRE(manager.add(std::make_unique<TestPass>(
        "second", std::vector<std::string>{"first"}, ".second", &order)).has_value());
    REQUIRE(manager.add(std::make_unique<TestPass>(
        "first", std::vector<std::string>{}, ".first", &order)).has_value());
    binobf::TransformContext context{17, false};
    const auto outcome = manager.run(context, make_image());
    REQUIRE(outcome.has_value());
    REQUIRE_EQ(order, (std::vector<std::string>{"first", "second"}));
    REQUIRE_EQ(outcome.value().reports.size(), std::size_t{2});
    REQUIRE_EQ(outcome.value().reports.at(0).name, "first");
    REQUIRE_EQ(outcome.value().reports.at(1).name, "second");
    REQUIRE_EQ(outcome.value().image.sections.front().name, ".second");
}

TEST_CASE(pass_manager_rejects_duplicate_and_missing_dependencies) {
    binobf::PassManager duplicate;
    REQUIRE(duplicate.add(std::make_unique<TestPass>(
        "same", std::vector<std::string>{}, "")).has_value());
    const auto duplicateResult = duplicate.add(std::make_unique<TestPass>(
        "same", std::vector<std::string>{}, ""));
    REQUIRE(!duplicateResult.has_value());
    REQUIRE_EQ(duplicateResult.error().code, "pass.duplicate");

    binobf::PassManager missing;
    REQUIRE(missing.add(std::make_unique<TestPass>(
        "dependent", std::vector<std::string>{"absent"}, "")).has_value());
    binobf::TransformContext context{0, false};
    const auto outcome = missing.run(context, make_image());
    REQUIRE(!outcome.has_value());
    REQUIRE_EQ(outcome.error().code, "pass.missing_dependency");
}

TEST_CASE(pass_manager_dry_run_reports_but_does_not_commit) {
    binobf::PassManager manager;
    REQUIRE(manager.add(std::make_unique<TestPass>(
        "rename", std::vector<std::string>{}, ".renamed")).has_value());
    binobf::TransformContext context{123, true};
    const auto input = make_image();
    const auto outcome = manager.run(context, input);
    REQUIRE(outcome.has_value());
    REQUIRE_EQ(outcome.value().image.sections.front().name, ".text");
    REQUIRE(outcome.value().changed);
    REQUIRE_EQ(outcome.value().reports.front().status, binobf::PassStatus::Applied);
    REQUIRE_EQ(outcome.value().reports.front().statistics.changed, std::size_t{1});
    REQUIRE_EQ(input.sections.front().name, ".text");
}

TEST_CASE(pass_manager_rolls_back_failed_verification) {
    binobf::PassManager manager;
    REQUIRE(manager.add(std::make_unique<TestPass>(
        "corrupt", std::vector<std::string>{}, "", nullptr, true, true, true)).has_value());
    const auto input = make_image();
    binobf::TransformContext context{0, false};
    const auto outcome = manager.run(context, input);
    REQUIRE(!outcome.has_value());
    REQUIRE_EQ(outcome.error().code, "pass.verification_failed");
    REQUIRE_EQ(outcome.error().pass, std::optional<std::string>{"corrupt"});
    REQUIRE(outcome.error().explanation.has_value());
    REQUIRE(outcome.error().remediation.has_value());
    REQUIRE_EQ(input.sections.front().alignment, UINT64_C(4));
}

TEST_CASE(pass_manager_detects_change_contract_violations_and_skips_unsupported_passes) {
    binobf::PassManager violating;
    REQUIRE(violating.add(std::make_unique<TestPass>(
        "liar", std::vector<std::string>{}, ".changed", nullptr, false)).has_value());
    binobf::TransformContext context{0, false};
    const auto violation = violating.run(context, make_image());
    REQUIRE(!violation.has_value());
    REQUIRE_EQ(violation.error().code, "pass.contract_violation");

    binobf::PassManager unsupported;
    REQUIRE(unsupported.add(std::make_unique<TestPass>(
        "unsupported", std::vector<std::string>{}, ".changed", nullptr, true, false)).has_value());
    const auto skipped = unsupported.run(context, make_image());
    REQUIRE(skipped.has_value());
    REQUIRE(!skipped.value().changed);
    REQUIRE_EQ(skipped.value().reports.front().status, binobf::PassStatus::Unsupported);
    REQUIRE_EQ(skipped.value().reports.front().diagnostics.size(), std::size_t{1});
    REQUIRE_EQ(
        skipped.value().reports.front().diagnostics.front().code,
        "pass.unsupported");
    REQUIRE_EQ(skipped.value().image.sections.front().name, ".text");
}

int main() {
    return binobf::test::run_all();
}

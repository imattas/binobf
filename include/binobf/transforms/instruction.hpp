#pragma once

#include <binobf/transforms/pass.hpp>

#include <memory>

namespace binobf {

[[nodiscard]] auto make_instruction_substitution_pass()
    -> std::unique_ptr<TransformPass>;
[[nodiscard]] auto make_branch_inversion_pass()
    -> std::unique_ptr<TransformPass>;
[[nodiscard]] auto make_constant_rewriting_pass()
    -> std::unique_ptr<TransformPass>;
[[nodiscard]] auto make_block_splitting_pass()
    -> std::unique_ptr<TransformPass>;
[[nodiscard]] auto make_dead_code_insertion_pass()
    -> std::unique_ptr<TransformPass>;
[[nodiscard]] auto make_block_reordering_pass()
    -> std::unique_ptr<TransformPass>;
[[nodiscard]] auto make_function_reordering_pass()
    -> std::unique_ptr<TransformPass>;

} // namespace binobf

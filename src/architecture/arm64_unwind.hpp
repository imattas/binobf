#pragma once

#include <binobf/architecture/object_backend.hpp>

namespace binobf::detail {

[[nodiscard]] auto build_arm64_unwind_plan(const UnwindRequest &request)
    -> Result<UnwindPlan, Diagnostic>;

} // namespace binobf::detail

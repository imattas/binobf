#pragma once

#include <binobf/architecture/codegen.hpp>
#include <binobf/architecture/object_backend.hpp>

namespace binobf::detail {

[[nodiscard]] auto build_arm64_abi_adapter(const AbiAdapterRequest &request,
                                           const CodegenProvider &codegen)
    -> Result<AbiAdapterPlan, Diagnostic>;

[[nodiscard]] auto build_arm64_unwind_plan(const UnwindRequest &request)
    -> Result<UnwindPlan, Diagnostic>;

} // namespace binobf::detail

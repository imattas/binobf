#pragma once

#include <binobf/architecture/codegen.hpp>
#include <binobf/architecture/object_backend.hpp>

namespace binobf::detail {

[[nodiscard]] auto build_x86_64_abi_adapter(
    const AbiAdapterRequest& request,
    const CodegenProvider& codegen) -> Result<AbiAdapterPlan, Diagnostic>;

} // namespace binobf::detail

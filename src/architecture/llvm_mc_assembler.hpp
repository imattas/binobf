#pragma once

#include <binobf/architecture/codegen.hpp>

namespace binobf::detail {

[[nodiscard]] auto assemble_with_llvm_mc(const MachineAssemblyRequest& request)
    -> Result<MachineEmission, Diagnostic>;

} // namespace binobf::detail

#pragma once

#include <binobf/architecture/codegen.hpp>

#include <llvm/Object/ObjectFile.h>

#include <span>
#include <vector>

namespace binobf::detail {

[[nodiscard]] auto normalize_llvm_fixups(
    const llvm::object::SectionRef& section,
    std::span<const std::byte> sectionBytes,
    const MachineAssemblyRequest& request)
    -> Result<std::vector<MachineFixup>, Diagnostic>;

} // namespace binobf::detail

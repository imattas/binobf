#pragma once

#include <binobf/architecture/codegen.hpp>
#include <binobf/architecture/object_backend.hpp>

namespace binobf::detail {

[[nodiscard]] auto emit_arm64_transform(const MachineTransformRequest &request,
                                        const CodegenProvider &codegen)
    -> Result<MachineTransformEmission, Diagnostic>;

} // namespace binobf::detail

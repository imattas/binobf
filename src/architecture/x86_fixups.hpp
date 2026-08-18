#pragma once

#include <binobf/architecture/object_backend.hpp>

#include <span>

namespace binobf::detail {

[[nodiscard]] auto x86_fixup_semantics(BinaryFormat format, std::uint64_t rawType)
    -> Result<ObjectFixupSemantics, Diagnostic>;

[[nodiscard]] auto encode_x86_fixup(
    const ObjectFixupSemantics& semantics,
    std::int64_t value) -> Result<ObjectFixupEncoding, Diagnostic>;

[[nodiscard]] auto decode_x86_fixup(
    const ObjectFixupSemantics& semantics,
    std::span<const std::byte> fieldBytes) -> Result<std::int64_t, Diagnostic>;

} // namespace binobf::detail

#include "llvm_fixups.hpp"

#include <binobf/core/types.hpp>

#include <llvm/BinaryFormat/COFF.h>
#include <llvm/BinaryFormat/ELF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Support/Error.h>

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace binobf::detail {
namespace {

struct FixupShape {
    MachineFixupKind kind{MachineFixupKind::Absolute32};
    std::uint8_t bitWidth{0};
    bool isSigned{false};
    bool pcRelative{false};
    std::uint8_t encodedBytes{0};
    std::int8_t coffPcBias{0};
};

[[nodiscard]] auto failure(std::string code, std::string message)
    -> Result<std::vector<MachineFixup>, Diagnostic> {
    return Result<std::vector<MachineFixup>, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error,
        std::move(code),
        std::move(message),
    });
}

[[nodiscard]] constexpr auto absolute(
    MachineFixupKind kind,
    std::uint8_t width,
    bool isSigned = false) noexcept -> FixupShape {
    return FixupShape{kind, width, isSigned, false,
                      static_cast<std::uint8_t>(width / 8U), 0};
}

[[nodiscard]] constexpr auto relative(
    MachineFixupKind kind,
    std::uint8_t width,
    std::uint8_t encodedBytes,
    std::int8_t coffPcBias = 0) noexcept -> FixupShape {
    return FixupShape{kind, width, true, true, encodedBytes, coffPcBias};
}

[[nodiscard]] auto map_coff_fixup(
    Architecture architecture,
    std::uint64_t type,
    std::span<const std::byte> bytes,
    std::uint64_t offset) -> Result<FixupShape, Diagnostic> {
    switch (architecture) {
    case Architecture::X86:
        switch (type) {
        case llvm::COFF::IMAGE_REL_I386_DIR16:
            return Result<FixupShape, Diagnostic>::success(
                absolute(MachineFixupKind::Absolute16, 16U));
        case llvm::COFF::IMAGE_REL_I386_REL16:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::PcRelative16, 16U, 2U, 2));
        case llvm::COFF::IMAGE_REL_I386_DIR32:
            return Result<FixupShape, Diagnostic>::success(
                absolute(MachineFixupKind::Absolute32, 32U));
        case llvm::COFF::IMAGE_REL_I386_REL32:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::PcRelative32, 32U, 4U, 4));
        case llvm::COFF::IMAGE_REL_I386_SECREL:
            return Result<FixupShape, Diagnostic>::success(
                absolute(MachineFixupKind::SectionRelative32, 32U));
        default:
            break;
        }
        break;
    case Architecture::X86_64:
        switch (type) {
        case llvm::COFF::IMAGE_REL_AMD64_ADDR64:
            return Result<FixupShape, Diagnostic>::success(
                absolute(MachineFixupKind::Absolute64, 64U));
        case llvm::COFF::IMAGE_REL_AMD64_ADDR32:
            return Result<FixupShape, Diagnostic>::success(
                absolute(MachineFixupKind::Absolute32, 32U));
        case llvm::COFF::IMAGE_REL_AMD64_REL32:
        case llvm::COFF::IMAGE_REL_AMD64_REL32_1:
        case llvm::COFF::IMAGE_REL_AMD64_REL32_2:
        case llvm::COFF::IMAGE_REL_AMD64_REL32_3:
        case llvm::COFF::IMAGE_REL_AMD64_REL32_4:
        case llvm::COFF::IMAGE_REL_AMD64_REL32_5: {
            const auto suffix = static_cast<std::int8_t>(
                type - llvm::COFF::IMAGE_REL_AMD64_REL32);
            return Result<FixupShape, Diagnostic>::success(
                relative(
                    MachineFixupKind::PcRelative32,
                    32U,
                    4U,
                    static_cast<std::int8_t>(4 + suffix)));
        }
        case llvm::COFF::IMAGE_REL_AMD64_SECREL:
            return Result<FixupShape, Diagnostic>::success(
                absolute(MachineFixupKind::SectionRelative32, 32U));
        default:
            break;
        }
        break;
    case Architecture::ARM64:
        switch (type) {
        case llvm::COFF::IMAGE_REL_ARM64_ADDR64:
            return Result<FixupShape, Diagnostic>::success(
                absolute(MachineFixupKind::Absolute64, 64U));
        case llvm::COFF::IMAGE_REL_ARM64_ADDR32:
            return Result<FixupShape, Diagnostic>::success(
                absolute(MachineFixupKind::Absolute32, 32U));
        case llvm::COFF::IMAGE_REL_ARM64_BRANCH26: {
            if (offset > bytes.size() || bytes.size() - offset < 4U) {
                break;
            }
            const auto index = static_cast<std::size_t>(offset);
            const auto word = std::to_integer<std::uint32_t>(bytes[index]) |
                (std::to_integer<std::uint32_t>(bytes[index + 1U]) << 8U) |
                (std::to_integer<std::uint32_t>(bytes[index + 2U]) << 16U) |
                (std::to_integer<std::uint32_t>(bytes[index + 3U]) << 24U);
            const auto kind = (word & 0xfc000000U) == 0x94000000U
                ? MachineFixupKind::AArch64Call26
                : MachineFixupKind::AArch64Branch26;
            return Result<FixupShape, Diagnostic>::success(
                relative(kind, 26U, 4U));
        }
        case llvm::COFF::IMAGE_REL_ARM64_PAGEBASE_REL21:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::AArch64Page21, 21U, 4U));
        case llvm::COFF::IMAGE_REL_ARM64_PAGEOFFSET_12A:
        case llvm::COFF::IMAGE_REL_ARM64_PAGEOFFSET_12L:
            return Result<FixupShape, Diagnostic>::success(FixupShape{
                MachineFixupKind::AArch64PageOffset12, 12U, false, false, 4U, 0});
        case llvm::COFF::IMAGE_REL_ARM64_SECREL:
            return Result<FixupShape, Diagnostic>::success(
                absolute(MachineFixupKind::SectionRelative32, 32U));
        case llvm::COFF::IMAGE_REL_ARM64_REL32:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::PcRelative32, 32U, 4U));
        default:
            break;
        }
        break;
    case Architecture::Unknown:
        break;
    }
    return Result<FixupShape, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error,
        "codegen.unsupported_fixup",
        "unsupported COFF relocation type " + std::to_string(type) +
            " for architecture " + std::string{to_string(architecture)},
    });
}

[[nodiscard]] auto map_elf_fixup(
    Architecture architecture,
    std::uint64_t type) -> Result<FixupShape, Diagnostic> {
    switch (architecture) {
    case Architecture::X86:
        switch (type) {
        case llvm::ELF::R_386_8:
            return Result<FixupShape, Diagnostic>::success(
                absolute(MachineFixupKind::Absolute8, 8U));
        case llvm::ELF::R_386_16:
            return Result<FixupShape, Diagnostic>::success(
                absolute(MachineFixupKind::Absolute16, 16U));
        case llvm::ELF::R_386_32:
            return Result<FixupShape, Diagnostic>::success(
                absolute(MachineFixupKind::Absolute32, 32U));
        case llvm::ELF::R_386_PC8:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::PcRelative8, 8U, 1U));
        case llvm::ELF::R_386_PC16:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::PcRelative16, 16U, 2U));
        case llvm::ELF::R_386_PC32:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::PcRelative32, 32U, 4U));
        case llvm::ELF::R_386_PLT32:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::PltRelative32, 32U, 4U));
        case llvm::ELF::R_386_GOT32:
        case llvm::ELF::R_386_GOTPC:
        case llvm::ELF::R_386_GOT32X:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::GotRelative32, 32U, 4U));
        default:
            break;
        }
        break;
    case Architecture::X86_64:
        switch (type) {
        case llvm::ELF::R_X86_64_8:
            return Result<FixupShape, Diagnostic>::success(
                absolute(MachineFixupKind::Absolute8, 8U));
        case llvm::ELF::R_X86_64_16:
            return Result<FixupShape, Diagnostic>::success(
                absolute(MachineFixupKind::Absolute16, 16U));
        case llvm::ELF::R_X86_64_32:
            return Result<FixupShape, Diagnostic>::success(
                absolute(MachineFixupKind::Absolute32, 32U));
        case llvm::ELF::R_X86_64_32S:
            return Result<FixupShape, Diagnostic>::success(
                absolute(MachineFixupKind::Absolute32, 32U, true));
        case llvm::ELF::R_X86_64_64:
            return Result<FixupShape, Diagnostic>::success(
                absolute(MachineFixupKind::Absolute64, 64U));
        case llvm::ELF::R_X86_64_PC8:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::PcRelative8, 8U, 1U));
        case llvm::ELF::R_X86_64_PC16:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::PcRelative16, 16U, 2U));
        case llvm::ELF::R_X86_64_PC32:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::PcRelative32, 32U, 4U));
        case llvm::ELF::R_X86_64_PC64:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::PcRelative64, 64U, 8U));
        case llvm::ELF::R_X86_64_PLT32:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::PltRelative32, 32U, 4U));
        case llvm::ELF::R_X86_64_GOTPCREL:
        case llvm::ELF::R_X86_64_GOTPCRELX:
        case llvm::ELF::R_X86_64_REX_GOTPCRELX:
        case llvm::ELF::R_X86_64_CODE_4_GOTPCRELX:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::GotRelative32, 32U, 4U));
        default:
            break;
        }
        break;
    case Architecture::ARM64:
        switch (type) {
        case llvm::ELF::R_AARCH64_ABS16:
            return Result<FixupShape, Diagnostic>::success(
                absolute(MachineFixupKind::Absolute16, 16U));
        case llvm::ELF::R_AARCH64_ABS32:
            return Result<FixupShape, Diagnostic>::success(
                absolute(MachineFixupKind::Absolute32, 32U));
        case llvm::ELF::R_AARCH64_ABS64:
            return Result<FixupShape, Diagnostic>::success(
                absolute(MachineFixupKind::Absolute64, 64U));
        case llvm::ELF::R_AARCH64_PREL16:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::PcRelative16, 16U, 2U));
        case llvm::ELF::R_AARCH64_PREL32:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::PcRelative32, 32U, 4U));
        case llvm::ELF::R_AARCH64_PREL64:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::PcRelative64, 64U, 8U));
        case llvm::ELF::R_AARCH64_JUMP26:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::AArch64Branch26, 26U, 4U));
        case llvm::ELF::R_AARCH64_CALL26:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::AArch64Call26, 26U, 4U));
        case llvm::ELF::R_AARCH64_ADR_PREL_PG_HI21:
        case llvm::ELF::R_AARCH64_ADR_PREL_PG_HI21_NC:
            return Result<FixupShape, Diagnostic>::success(
                relative(MachineFixupKind::AArch64Page21, 21U, 4U));
        case llvm::ELF::R_AARCH64_ADD_ABS_LO12_NC:
        case llvm::ELF::R_AARCH64_LDST8_ABS_LO12_NC:
        case llvm::ELF::R_AARCH64_LDST16_ABS_LO12_NC:
        case llvm::ELF::R_AARCH64_LDST32_ABS_LO12_NC:
        case llvm::ELF::R_AARCH64_LDST64_ABS_LO12_NC:
        case llvm::ELF::R_AARCH64_LDST128_ABS_LO12_NC:
            return Result<FixupShape, Diagnostic>::success(FixupShape{
                MachineFixupKind::AArch64PageOffset12, 12U, false, false, 4U, 0});
        default:
            break;
        }
        break;
    case Architecture::Unknown:
        break;
    }
    return Result<FixupShape, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error,
        "codegen.unsupported_fixup",
        "unsupported ELF relocation type " + std::to_string(type) +
            " for architecture " + std::string{to_string(architecture)},
    });
}

[[nodiscard]] auto read_unsigned(
    std::span<const std::byte> bytes,
    std::uint64_t offset,
    std::uint8_t byteCount) -> Result<std::uint64_t, Diagnostic> {
    if (offset > bytes.size() || bytes.size() - offset < byteCount) {
        return Result<std::uint64_t, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "codegen.invalid_fixup",
            "relocation storage extends outside the emitted section",
        });
    }
    const auto start = static_cast<std::size_t>(offset);
    std::uint64_t value = 0U;
    for (std::uint8_t index = 0U; index < byteCount; ++index) {
        value |= static_cast<std::uint64_t>(
                     std::to_integer<std::uint8_t>(bytes[start + index]))
                 << (8U * index);
    }
    return Result<std::uint64_t, Diagnostic>::success(value);
}

[[nodiscard]] auto sign_extend(
    std::uint64_t value,
    std::uint8_t bitWidth) noexcept -> std::int64_t {
    if (bitWidth < 64U) {
        const auto signBit = std::uint64_t{1U} << (bitWidth - 1U);
        const auto mask = (std::uint64_t{1U} << bitWidth) - 1U;
        value &= mask;
        if ((value & signBit) != 0U) {
            value |= ~mask;
        }
    }
    return std::bit_cast<std::int64_t>(value);
}

[[nodiscard]] auto implicit_addend(
    const FixupShape& shape,
    std::span<const std::byte> bytes,
    std::uint64_t offset,
    Architecture architecture) -> Result<std::int64_t, Diagnostic> {
    auto encoded = read_unsigned(bytes, offset, shape.encodedBytes);
    if (!encoded.has_value()) {
        return Result<std::int64_t, Diagnostic>::failure(
            std::move(encoded).error());
    }
    if (architecture == Architecture::ARM64 && shape.bitWidth == 26U) {
        return Result<std::int64_t, Diagnostic>::success(
            sign_extend(encoded.value() & 0x03ffffffU, 26U) * 4);
    }
    if (architecture == Architecture::ARM64 &&
        shape.kind == MachineFixupKind::AArch64Page21) {
        const auto word = static_cast<std::uint32_t>(encoded.value());
        const auto immediate = ((word >> 29U) & 0x3U) |
            (((word >> 5U) & 0x7ffffU) << 2U);
        return Result<std::int64_t, Diagnostic>::success(
            sign_extend(immediate, 21U) * 4096);
    }
    if (architecture == Architecture::ARM64 &&
        shape.kind == MachineFixupKind::AArch64PageOffset12) {
        const auto word = static_cast<std::uint32_t>(encoded.value());
        return Result<std::int64_t, Diagnostic>::success(
            static_cast<std::int64_t>((word >> 10U) & 0xfffU));
    }
    if (!shape.isSigned &&
        encoded.value() > static_cast<std::uint64_t>(
                              std::numeric_limits<std::int64_t>::max())) {
        return Result<std::int64_t, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "codegen.invalid_fixup",
            "an unsigned relocation addend cannot be represented without truncation",
        });
    }
    return Result<std::int64_t, Diagnostic>::success(
        shape.isSigned
            ? sign_extend(encoded.value(), shape.bitWidth)
            : static_cast<std::int64_t>(encoded.value()));
}

[[nodiscard]] auto symbol_name(const llvm::object::RelocationRef& relocation)
    -> Result<std::string, Diagnostic> {
    const auto symbol = relocation.getSymbol();
    if (symbol == relocation.getObject()->symbol_end()) {
        return Result<std::string, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "codegen.invalid_fixup",
            "relocation does not reference a symbol",
        });
    }
    auto nameOrError = symbol->getName();
    if (!nameOrError) {
        return Result<std::string, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "codegen.invalid_fixup",
            "could not read relocation symbol: " +
                llvm::toString(nameOrError.takeError()),
        });
    }
    if (nameOrError->empty()) {
        return Result<std::string, Diagnostic>::failure(Diagnostic{
            DiagnosticSeverity::Error,
            "codegen.invalid_fixup",
            "relocation symbol name must not be empty",
        });
    }
    return Result<std::string, Diagnostic>::success(nameOrError->str());
}

} // namespace

auto normalize_llvm_fixups(
    const llvm::object::SectionRef& section,
    std::span<const std::byte> sectionBytes,
    const MachineAssemblyRequest& request)
    -> Result<std::vector<MachineFixup>, Diagnostic> {
    std::vector<llvm::object::RelocationRef> relocations;
    const auto* object = section.getObject();
    for (const auto& relocationSection : object->sections()) {
        if (relocationSection.relocations().empty()) {
            continue;
        }
        auto relocatedSection = relocationSection.getRelocatedSection();
        if (!relocatedSection) {
            return failure(
                "codegen.object_failed",
                "could not resolve an emitted relocation section: " +
                    llvm::toString(relocatedSection.takeError()));
        }
        if (*relocatedSection == object->section_end() ||
            **relocatedSection != section) {
            continue;
        }
        for (const auto& relocation : relocationSection.relocations()) {
            if (relocations.size() >= request.limits.maxFixups) {
                return failure(
                    "codegen.resource_limit",
                    "the emitted section exceeds the configured fixup limit");
            }
            relocations.push_back(relocation);
        }
    }

    std::vector<MachineFixup> fixups;
    for (const auto& relocation : relocations) {
        const auto type = relocation.getType();
        auto shape = request.format == BinaryFormat::COFF
            ? map_coff_fixup(
                  request.architecture, type, sectionBytes, relocation.getOffset())
            : map_elf_fixup(request.architecture, type);
        if (!shape.has_value()) {
            return Result<std::vector<MachineFixup>, Diagnostic>::failure(
                std::move(shape).error());
        }
        if (relocation.getOffset() >= sectionBytes.size() ||
            sectionBytes.size() - relocation.getOffset() < shape.value().encodedBytes) {
            return failure(
                "codegen.invalid_fixup",
                "relocation storage extends outside the emitted section");
        }
        auto symbol = symbol_name(relocation);
        if (!symbol.has_value()) {
            return Result<std::vector<MachineFixup>, Diagnostic>::failure(
                std::move(symbol).error());
        }

        std::int64_t addend = 0;
        bool hasExplicitAddend = false;
        if (request.format == BinaryFormat::ELF) {
            auto addendOrError = llvm::object::ELFRelocationRef{relocation}.getAddend();
            if (addendOrError) {
                addend = *addendOrError;
                hasExplicitAddend = true;
            } else {
                llvm::consumeError(addendOrError.takeError());
            }
        }
        if (!hasExplicitAddend) {
            auto implicit = implicit_addend(
                shape.value(), sectionBytes, relocation.getOffset(), request.architecture);
            if (!implicit.has_value()) {
                return Result<std::vector<MachineFixup>, Diagnostic>::failure(
                    std::move(implicit).error());
            }
            addend = implicit.value();
        }
        if (request.format == BinaryFormat::COFF && shape.value().pcRelative) {
            addend -= shape.value().coffPcBias;
        }

        fixups.push_back(MachineFixup{
            .offset = relocation.getOffset(),
            .bitWidth = shape.value().bitWidth,
            .isSigned = shape.value().isSigned,
            .pcRelative = shape.value().pcRelative,
            .addend = addend,
            .symbol = std::move(symbol).value(),
            .kind = shape.value().kind,
        });
    }

    std::sort(fixups.begin(), fixups.end(), [](const auto& left, const auto& right) {
        if (left.offset != right.offset) {
            return left.offset < right.offset;
        }
        if (left.kind != right.kind) {
            return left.kind < right.kind;
        }
        return left.symbol < right.symbol;
    });
    for (std::size_t index = 1U; index < fixups.size(); ++index) {
        if (fixups[index - 1U].offset == fixups[index].offset &&
            fixups[index - 1U] != fixups[index]) {
            return failure(
                "codegen.invalid_fixup",
                "incompatible relocations overlap at the same section offset");
        }
    }
    fixups.erase(std::unique(fixups.begin(), fixups.end()), fixups.end());
    return Result<std::vector<MachineFixup>, Diagnostic>::success(std::move(fixups));
}

} // namespace binobf::detail

#include <binobf/core/types.hpp>

namespace binobf {

auto to_string(BinaryFormat format) noexcept -> std::string_view {
    switch (format) {
    case BinaryFormat::PE: return "PE";
    case BinaryFormat::COFF: return "COFF";
    case BinaryFormat::ELF: return "ELF";
    case BinaryFormat::Archive: return "archive";
    case BinaryFormat::Unknown: return "unknown";
    }
    return "unknown";
}

auto to_string(BinaryType type) noexcept -> std::string_view {
    switch (type) {
    case BinaryType::Executable: return "executable";
    case BinaryType::SharedLibrary: return "shared-library";
    case BinaryType::KernelDriver: return "kernel-driver";
    case BinaryType::RelocatableObject: return "relocatable-object";
    case BinaryType::StaticLibrary: return "static-library";
    case BinaryType::ImportLibrary: return "import-library";
    case BinaryType::Unknown: return "unknown";
    }
    return "unknown";
}

auto to_string(Architecture architecture) noexcept -> std::string_view {
    switch (architecture) {
    case Architecture::X86: return "x86";
    case Architecture::X86_64: return "x86-64";
    case Architecture::ARM64: return "arm64";
    case Architecture::Unknown: return "unknown";
    }
    return "unknown";
}

} // namespace binobf

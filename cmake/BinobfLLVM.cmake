include(FetchContent)

cmake_policy(PUSH)
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()
if(POLICY CMP0219)
    cmake_policy(SET CMP0219 OLD)
endif()

set(LLVM_TARGETS_TO_BUILD "X86;AArch64" CACHE STRING "LLVM targets required by binobf" FORCE)
set(LLVM_ENABLE_PROJECTS "" CACHE STRING "Do not build LLVM subprojects" FORCE)
set(LLVM_ENABLE_RUNTIMES "" CACHE STRING "Do not build LLVM runtimes" FORCE)
set(LLVM_INCLUDE_TESTS OFF CACHE BOOL "Do not build LLVM tests" FORCE)
set(LLVM_INCLUDE_EXAMPLES OFF CACHE BOOL "Do not build LLVM examples" FORCE)
set(LLVM_INCLUDE_BENCHMARKS OFF CACHE BOOL "Do not build LLVM benchmarks" FORCE)
set(LLVM_INCLUDE_DOCS OFF CACHE BOOL "Do not build LLVM documentation" FORCE)
set(LLVM_BUILD_TOOLS OFF CACHE BOOL "Do not build LLVM tools" FORCE)
set(LLVM_BUILD_UTILS OFF CACHE BOOL "Do not build LLVM utilities" FORCE)
set(LLVM_ENABLE_BINDINGS OFF CACHE BOOL "Do not build LLVM language bindings" FORCE)
set(LLVM_ENABLE_TERMINFO OFF CACHE BOOL "Do not use terminfo in private LLVM" FORCE)
set(LLVM_ENABLE_ZLIB OFF CACHE BOOL "Do not use zlib in private LLVM" FORCE)
set(LLVM_ENABLE_ZSTD OFF CACHE BOOL "Do not use zstd in private LLVM" FORCE)
set(LLVM_ENABLE_LIBXML2 OFF CACHE BOOL "Do not use libxml2 in private LLVM" FORCE)
set(LLVM_ENABLE_CURL OFF CACHE BOOL "Do not use curl in private LLVM" FORCE)
set(LLVM_ENABLE_LIBEDIT OFF CACHE BOOL "Do not use libedit in private LLVM" FORCE)
set(LLVM_ENABLE_LIBPFM OFF CACHE BOOL "Do not use libpfm in private LLVM" FORCE)
set(LLVM_ENABLE_HTTPLIB OFF CACHE BOOL "Do not use httplib in private LLVM" FORCE)
set(LLVM_ENABLE_RTTI OFF CACHE BOOL "Match LLVM's default no-RTTI configuration" FORCE)
set(LLVM_ENABLE_EH OFF CACHE BOOL "Match LLVM's default no-exceptions configuration" FORCE)

FetchContent_Declare(
    llvm_dependency
    URL https://github.com/llvm/llvm-project/releases/download/llvmorg-22.1.8/llvm-project-22.1.8.src.tar.xz
    URL_HASH SHA256=922f1817a0df7b1489272d18134ee0087a8b068828f87ac63b9861b1a9965888
    DOWNLOAD_EXTRACT_TIMESTAMP FALSE
)
FetchContent_GetProperties(llvm_dependency)
if(NOT llvm_dependency_POPULATED)
    FetchContent_Populate(llvm_dependency)
    set(_binobf_parent_cxx_standard "${CMAKE_CXX_STANDARD}")
    set(_binobf_parent_cxx_standard_required "${CMAKE_CXX_STANDARD_REQUIRED}")
    set(_binobf_parent_cxx_extensions "${CMAKE_CXX_EXTENSIONS}")
    set(CMAKE_CXX_STANDARD 17)
    add_subdirectory(
        "${llvm_dependency_SOURCE_DIR}/llvm"
        "${llvm_dependency_BINARY_DIR}"
        EXCLUDE_FROM_ALL
    )
    set(CMAKE_CXX_STANDARD "${_binobf_parent_cxx_standard}")
    set(CMAKE_CXX_STANDARD_REQUIRED "${_binobf_parent_cxx_standard_required}")
    set(CMAKE_CXX_EXTENSIONS "${_binobf_parent_cxx_extensions}")
    unset(_binobf_parent_cxx_standard)
    unset(_binobf_parent_cxx_standard_required)
    unset(_binobf_parent_cxx_extensions)
endif()

cmake_policy(POP)

llvm_map_components_to_libnames(BINOBF_LLVM_LIBRARIES
    Support
    Target
    MC
    MCParser
    Object
    BinaryFormat
    X86Info
    X86Desc
    X86AsmParser
    AArch64Info
    AArch64Desc
    AArch64AsmParser
)

# Static consumers need the private LLVM closure because binobf_core is an
# archive. Keep this list pinned with the LLVM version and the actual link
# closure exercised by the installed-consumer gate.
set(BINOBF_LLVM_INSTALL_LIBRARIES
    LLVMTarget
    LLVMAnalysis
    LLVMFrontendHLSL
    LLVMProfileData
    LLVMSymbolize
    LLVMDebugInfoGSYM
    LLVMDebugInfoPDB
    LLVMDebugInfoCodeView
    LLVMDebugInfoMSF
    LLVMDebugInfoBTF
    LLVMDebugInfoDWARF
    LLVMObject
    LLVMIRReader
    LLVMBitReader
    LLVMAsmParser
    LLVMCore
    LLVMRemarks
    LLVMBitstreamReader
    LLVMTextAPI
    LLVMX86AsmParser
    LLVMX86Desc
    LLVMX86Info
    LLVMMCDisassembler
    LLVMAArch64AsmParser
    LLVMMCParser
    LLVMAArch64Desc
    LLVMAArch64Info
    LLVMMC
    LLVMDebugInfoDWARFLowLevel
    LLVMBinaryFormat
    LLVMTargetParser
    LLVMCodeGenTypes
    LLVMAArch64Utils
    LLVMSupport
    LLVMDemangle
)

function(binobf_link_llvm_mc target)
    target_include_directories(${target} SYSTEM PRIVATE
        "${llvm_dependency_SOURCE_DIR}/llvm/include"
        "${llvm_dependency_BINARY_DIR}/include"
    )
    # The bundled LLVM is built without C++ RTTI.  Keep consumers aligned;
    # otherwise Clang can emit references to LLVM's unavailable typeinfo when
    # a static consumer pulls a different subset of the MC implementation.
    target_compile_options(${target} PRIVATE
        "$<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang,AppleClang>:-fno-rtti>"
        # UBSan's vptr check requires C++ RTTI and reports false positives for
        # valid polymorphic objects compiled consistently without RTTI.
        "$<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang,AppleClang>:-fno-sanitize=vptr>"
        "$<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/GR->"
    )
    target_link_libraries(${target} PRIVATE ${BINOBF_LLVM_LIBRARIES})
endfunction()

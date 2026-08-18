cmake_minimum_required(VERSION 3.25)

project(binobf VERSION 0.1.0 LANGUAGES C CXX)

option(BINOBF_BUILD_TESTS "Build the binobf test suite" ON)
option(BINOBF_BUILD_FUZZERS "Build compiler-native libFuzzer targets" OFF)
option(BINOBF_BUILD_BENCHMARKS "Build the developer performance benchmark" OFF)
option(BINOBF_ENABLE_UNDEFINED_SANITIZER "Enable UndefinedBehaviorSanitizer" OFF)
option(BINOBF_ENABLE_ADDRESS_SANITIZER "Enable AddressSanitizer" OFF)
option(BINOBF_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)

if(WIN32 AND (
    BINOBF_BUILD_FUZZERS OR
    BINOBF_ENABLE_UNDEFINED_SANITIZER OR
    BINOBF_ENABLE_ADDRESS_SANITIZER
))
    set(CMAKE_MSVC_RUNTIME_LIBRARY
        "MultiThreaded$<$<CONFIG:Debug>:Debug>"
        CACHE STRING "Runtime required by the Windows LLVM sanitizer packages" FORCE
    )
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(BinobfWarnings)
include(FetchContent)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared third-party libraries" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "Build static third-party libraries" FORCE)
set(BUILD_STATIC_RUNTIME OFF CACHE BOOL "Use the active compiler runtime" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "Build Capstone tests" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "Build Capstone command-line tool" FORCE)
set(CAPSTONE_BUILD_CSTEST OFF CACHE BOOL "Build Capstone test command" FORCE)
set(CAPSTONE_INSTALL OFF CACHE BOOL "Install private Capstone dependency" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "Enable all Capstone architectures" FORCE)
set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "Enable Capstone x86 support" FORCE)
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "Enable Capstone ARM64 support" FORCE)
FetchContent_Declare(
    capstone_dependency
    URL https://github.com/capstone-engine/capstone/archive/refs/tags/5.0.9.tar.gz
    URL_HASH SHA256=0619da31af08152600af95c481527ef6d756c0a8404fca7544a4fdf6dfc2c0f9
    DOWNLOAD_EXTRACT_TIMESTAMP FALSE
)
set(_binobf_project_version "${PROJECT_VERSION}")
unset(PROJECT_VERSION)
FetchContent_MakeAvailable(capstone_dependency)
set(PROJECT_VERSION "${_binobf_project_version}")
unset(_binobf_project_version)

set(TOMLPLUSPLUS_BUILD_TESTS OFF CACHE BOOL "Build toml++ tests" FORCE)
set(TOMLPLUSPLUS_BUILD_EXAMPLES OFF CACHE BOOL "Build toml++ examples" FORCE)
FetchContent_Declare(
    tomlplusplus_dependency
    URL https://github.com/marzer/tomlplusplus/archive/refs/tags/v3.4.0.tar.gz
    URL_HASH SHA256=8517f65938a4faae9ccf8ebb36631a38c1cadfb5efa85d9a72e15b9e97d25155
    DOWNLOAD_EXTRACT_TIMESTAMP FALSE
)
set(JSON_BuildTests OFF CACHE BOOL "Build nlohmann/json tests" FORCE)
set(JSON_Install OFF CACHE BOOL "Install nlohmann/json" FORCE)
FetchContent_Declare(
    nlohmann_json_dependency
    URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
    URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa
    DOWNLOAD_EXTRACT_TIMESTAMP FALSE
)
FetchContent_MakeAvailable(tomlplusplus_dependency nlohmann_json_dependency)
if(MSVC)
    target_compile_options(capstone PRIVATE /w)
else()
    target_compile_options(capstone PRIVATE -w)
endif()

if(BINOBF_ENABLE_UNDEFINED_SANITIZER OR BINOBF_ENABLE_ADDRESS_SANITIZER)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        message(FATAL_ERROR "binobf sanitizers require Clang or GCC")
    endif()
    if(BINOBF_ENABLE_ADDRESS_SANITIZER AND WIN32)
        message(FATAL_ERROR
            "AddressSanitizer is unavailable with this Windows MSVC STL toolchain; use UBSan or a supported non-Windows toolchain"
        )
    endif()
    if(WIN32 AND CMAKE_BUILD_TYPE STREQUAL "Debug")
        message(FATAL_ERROR
            "Windows LLVM sanitizer runtimes are incompatible with the Debug MSVC STL iterator ABI; use RelWithDebInfo for sanitizer builds"
        )
    endif()
    set(_binobf_sanitizers "")
    if(BINOBF_ENABLE_ADDRESS_SANITIZER)
        list(APPEND _binobf_sanitizers address)
    endif()
    if(BINOBF_ENABLE_UNDEFINED_SANITIZER)
        list(APPEND _binobf_sanitizers undefined)
    endif()
    list(JOIN _binobf_sanitizers "," _binobf_sanitizer_list)
    add_compile_options("-fsanitize=${_binobf_sanitizer_list}")
    add_link_options("-fsanitize=${_binobf_sanitizer_list}")
    if(BINOBF_ENABLE_UNDEFINED_SANITIZER)
        add_compile_options(-fno-sanitize-recover=undefined)
        add_link_options(-fno-sanitize-recover=undefined)
    endif()
endif()

set(BINOBF_CORE_SOURCES
    src/capabilities/evidence.cpp
    src/capabilities/registry.cpp
    src/formats/archive.cpp
    src/formats/archive_writer.cpp
    src/analysis/capstone_instruction_decoder.cpp
    src/analysis/object_analyzer.cpp
    src/cli/command.cpp
    src/config/config.cpp
    src/core/diagnostic.cpp
    src/core/types.cpp
    src/evidence/lineage.cpp
    src/evidence/manifest.cpp
    src/formats/coff/object_parser.cpp
    src/formats/coff/object_writer.cpp
    src/formats/detector.cpp
    src/formats/elf/object_parser.cpp
    src/formats/elf/object_writer.cpp
    src/formats/elf/linked_parser.cpp
    src/formats/linked_image.cpp
    src/formats/linked_writer.cpp
    src/formats/object_parser.cpp
    src/formats/object_writer.cpp
    src/formats/pe/linked_parser.cpp
    src/ir/control_flow.cpp
    src/ir/native.cpp
    src/ir/native_lifter.cpp
    src/ir/outlining.cpp
    src/ir/vm_lowering.cpp
    src/support/deterministic_rng.cpp
    src/support/artifact_transaction.cpp
    src/support/sha256.cpp
    src/transforms/pass_manager.cpp
    src/transforms/registry.cpp
    src/transforms/selection.cpp
    src/transforms/instruction.cpp
    src/transforms/rename_private_symbols.cpp
    src/transforms/section_removal.cpp
    src/verify/object_model_validator.cpp
    src/verify/structural_verifier.cpp
    src/vm/ir.cpp
    src/vm/runtime.cpp
    src/vm/native_runtime.cpp
    src/vm/protection.cpp
    src/vm/bytecode.cpp
)
add_library(binobf_core STATIC ${BINOBF_CORE_SOURCES})
add_library(binobf::core ALIAS binobf_core)
target_compile_definitions(binobf_core PRIVATE
    BINOBF_VERSION="${PROJECT_VERSION}"
    TOML_EXCEPTIONS=0
)
target_include_directories(binobf_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_include_directories(binobf_core SYSTEM PRIVATE
    "${capstone_dependency_SOURCE_DIR}/include"
)
target_link_libraries(binobf_core PRIVATE "$<LINK_ONLY:capstone_static>")
target_link_libraries(binobf_core PRIVATE
    tomlplusplus::tomlplusplus
    nlohmann_json::nlohmann_json
)
binobf_enable_warnings(binobf_core)

if(BINOBF_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "BINOBF_BUILD_FUZZERS requires Clang libFuzzer support")
    endif()
    add_library(binobf_fuzz_core STATIC ${BINOBF_CORE_SOURCES})
    target_include_directories(binobf_fuzz_core PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    )
    target_include_directories(binobf_fuzz_core SYSTEM PRIVATE
        "${capstone_dependency_SOURCE_DIR}/include"
    )
    target_link_libraries(binobf_fuzz_core PRIVATE "$<LINK_ONLY:capstone_static>")
    target_link_libraries(binobf_fuzz_core PRIVATE
        tomlplusplus::tomlplusplus
        nlohmann_json::nlohmann_json
    )
    target_compile_definitions(binobf_fuzz_core PRIVATE
        BINOBF_VERSION="${PROJECT_VERSION}"
        TOML_EXCEPTIONS=0
    )
    target_compile_options(binobf_fuzz_core PRIVATE -fsanitize=fuzzer-no-link)
    binobf_enable_warnings(binobf_fuzz_core)

    function(binobf_add_fuzzer target source)
        add_executable(${target} ${source})
        target_link_libraries(${target} PRIVATE binobf_fuzz_core)
        target_compile_options(${target} PRIVATE -fsanitize=fuzzer-no-link)
        target_link_options(${target} PRIVATE -fsanitize=fuzzer)
        binobf_enable_warnings(${target})
    endfunction()

    binobf_add_fuzzer(binobf_fuzz_detector tests/fuzz/detector_fuzzer.cpp)
    binobf_add_fuzzer(binobf_fuzz_object tests/fuzz/object_fuzzer.cpp)
    binobf_add_fuzzer(binobf_fuzz_linked tests/fuzz/linked_fuzzer.cpp)
    binobf_add_fuzzer(binobf_fuzz_archive tests/fuzz/archive_fuzzer.cpp)
    binobf_add_fuzzer(binobf_fuzz_vm_bytecode tests/fuzz/vm_bytecode_fuzzer.cpp)
    binobf_add_fuzzer(binobf_fuzz_config tests/fuzz/config_fuzzer.cpp)
    binobf_add_fuzzer(binobf_fuzz_lineage tests/fuzz/lineage_fuzzer.cpp)

    add_executable(binobf_fuzz_seed_generator tests/fuzz/vm_seed_generator.cpp)
    target_link_libraries(binobf_fuzz_seed_generator PRIVATE binobf::core)
    binobf_enable_warnings(binobf_fuzz_seed_generator)

    find_program(BINOBF_FUZZ_LLVM_AR llvm-ar REQUIRED)
    find_program(BINOBF_FUZZ_LD_LLD ld.lld REQUIRED)
    set(BINOBF_FUZZ_CORPUS_ROOT "${CMAKE_CURRENT_BINARY_DIR}/fuzz-corpus")
    set(BINOBF_FUZZ_OBJECT_DIR "${BINOBF_FUZZ_CORPUS_ROOT}/object")
    set(BINOBF_FUZZ_LINKED_DIR "${BINOBF_FUZZ_CORPUS_ROOT}/linked")
    set(BINOBF_FUZZ_ARCHIVE_DIR "${BINOBF_FUZZ_CORPUS_ROOT}/archive")
    set(BINOBF_FUZZ_VM_DIR "${BINOBF_FUZZ_CORPUS_ROOT}/vm")
    set(BINOBF_FUZZ_CONFIG_DIR "${BINOBF_FUZZ_CORPUS_ROOT}/config")
    set(BINOBF_FUZZ_LINEAGE_DIR "${BINOBF_FUZZ_CORPUS_ROOT}/lineage")
    set(BINOBF_FUZZ_COFF_SEED "${BINOBF_FUZZ_OBJECT_DIR}/arithmetic.obj")
    set(BINOBF_FUZZ_ELF_SEED "${BINOBF_FUZZ_OBJECT_DIR}/arithmetic.o")
    set(BINOBF_FUZZ_PE_OBJECT "${BINOBF_FUZZ_LINKED_DIR}/linked-pe.obj")
    set(BINOBF_FUZZ_PE_SEED "${BINOBF_FUZZ_LINKED_DIR}/linked-pe.exe")
    set(BINOBF_FUZZ_ELF_OBJECT "${BINOBF_FUZZ_LINKED_DIR}/linked-elf.o")
    set(BINOBF_FUZZ_ELF_LINKED_SEED "${BINOBF_FUZZ_LINKED_DIR}/linked-elf")
    set(BINOBF_FUZZ_ARCHIVE_SEED "${BINOBF_FUZZ_ARCHIVE_DIR}/libarithmetic.a")
    set(BINOBF_FUZZ_VM_SEED "${BINOBF_FUZZ_VM_DIR}/program.bvm")
    set(BINOBF_FUZZ_CONFIG_SEED "${BINOBF_FUZZ_CONFIG_DIR}/minimal.toml")
    set(BINOBF_FUZZ_LINEAGE_SEED "${BINOBF_FUZZ_LINEAGE_DIR}/minimal.json")
    add_custom_command(
        OUTPUT
            "${BINOBF_FUZZ_COFF_SEED}"
            "${BINOBF_FUZZ_ELF_SEED}"
            "${BINOBF_FUZZ_PE_SEED}"
            "${BINOBF_FUZZ_ELF_LINKED_SEED}"
            "${BINOBF_FUZZ_ARCHIVE_SEED}"
            "${BINOBF_FUZZ_VM_SEED}"
            "${BINOBF_FUZZ_CONFIG_SEED}"
            "${BINOBF_FUZZ_LINEAGE_SEED}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory
            "${BINOBF_FUZZ_OBJECT_DIR}"
            "${BINOBF_FUZZ_LINKED_DIR}"
            "${BINOBF_FUZZ_ARCHIVE_DIR}"
            "${BINOBF_FUZZ_VM_DIR}"
            "${BINOBF_FUZZ_CONFIG_DIR}"
            "${BINOBF_FUZZ_LINEAGE_DIR}"
        COMMAND "${CMAKE_C_COMPILER}" --target=x86_64-pc-windows-msvc -gcodeview
            -c "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/arithmetic.c"
            -o "${BINOBF_FUZZ_COFF_SEED}"
        COMMAND "${CMAKE_C_COMPILER}" --target=x86_64-unknown-linux-gnu -g
            -c "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/arithmetic.c"
            -o "${BINOBF_FUZZ_ELF_SEED}"
        COMMAND "${CMAKE_C_COMPILER}" --target=x86_64-pc-windows-msvc -gcodeview
            -c "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/linked_pe.S"
            -o "${BINOBF_FUZZ_PE_OBJECT}"
        COMMAND "${CMAKE_C_COMPILER}" --target=x86_64-pc-windows-msvc
            -nostdlib -fuse-ld=lld "${BINOBF_FUZZ_PE_OBJECT}"
            "-Wl,/entry:binobf_linked_entry" "-Wl,/subsystem:console"
            "-Wl,/export:binobf_linked_export" -lkernel32 -o "${BINOBF_FUZZ_PE_SEED}"
        COMMAND "${CMAKE_C_COMPILER}" --target=x86_64-unknown-linux-gnu -g
            -c "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/linked_elf.S"
            -o "${BINOBF_FUZZ_ELF_OBJECT}"
        COMMAND "${BINOBF_FUZZ_LD_LLD}" --entry=_start --emit-relocs
            -o "${BINOBF_FUZZ_ELF_LINKED_SEED}" "${BINOBF_FUZZ_ELF_OBJECT}"
        COMMAND "${BINOBF_FUZZ_LLVM_AR}" rcs "${BINOBF_FUZZ_ARCHIVE_SEED}"
            "${BINOBF_FUZZ_ELF_SEED}"
        COMMAND "$<TARGET_FILE:binobf_fuzz_seed_generator>" "${BINOBF_FUZZ_VM_SEED}"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz/corpus/config/minimal.toml"
            "${BINOBF_FUZZ_CONFIG_SEED}"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz/corpus/lineage/minimal.json"
            "${BINOBF_FUZZ_LINEAGE_SEED}"
        DEPENDS
            binobf_fuzz_seed_generator
            tests/fixtures/arithmetic.c
            tests/fixtures/linked_pe.S
            tests/fixtures/linked_elf.S
            tests/fuzz/corpus/config/minimal.toml
            tests/fuzz/corpus/lineage/minimal.json
        VERBATIM
    )
    add_custom_target(
        binobf_fuzz_corpus
        DEPENDS
            "${BINOBF_FUZZ_COFF_SEED}"
            "${BINOBF_FUZZ_ELF_SEED}"
            "${BINOBF_FUZZ_PE_SEED}"
            "${BINOBF_FUZZ_ELF_LINKED_SEED}"
            "${BINOBF_FUZZ_ARCHIVE_SEED}"
            "${BINOBF_FUZZ_VM_SEED}"
            "${BINOBF_FUZZ_CONFIG_SEED}"
            "${BINOBF_FUZZ_LINEAGE_SEED}"
    )

    add_custom_target(fuzz-smoke
        COMMAND binobf_fuzz_detector -runs=2000 -seed=12012 -max_len=65536 -timeout=5
            "${BINOBF_FUZZ_OBJECT_DIR}" "${BINOBF_FUZZ_LINKED_DIR}"
            "${BINOBF_FUZZ_ARCHIVE_DIR}" "${BINOBF_FUZZ_VM_DIR}"
        COMMAND binobf_fuzz_object -runs=2000 -seed=12012 -max_len=65536 -timeout=5
            "${BINOBF_FUZZ_OBJECT_DIR}"
        COMMAND binobf_fuzz_linked -runs=2000 -seed=12012 -max_len=65536 -timeout=5
            "${BINOBF_FUZZ_LINKED_DIR}"
        COMMAND binobf_fuzz_archive -runs=2000 -seed=12012 -max_len=65536 -timeout=5
            "${BINOBF_FUZZ_ARCHIVE_DIR}"
        COMMAND binobf_fuzz_vm_bytecode -runs=2000 -seed=12012 -max_len=65536 -timeout=5
            "${BINOBF_FUZZ_VM_DIR}"
        COMMAND binobf_fuzz_config -runs=2000 -seed=12012 -max_len=65536 -timeout=5
            "${BINOBF_FUZZ_CONFIG_DIR}"
        COMMAND binobf_fuzz_lineage -runs=2000 -seed=12012 -max_len=65536 -timeout=5
            "${BINOBF_FUZZ_LINEAGE_DIR}"
        DEPENDS
            binobf_fuzz_detector
            binobf_fuzz_object
            binobf_fuzz_linked
            binobf_fuzz_archive
            binobf_fuzz_vm_bytecode
            binobf_fuzz_config
            binobf_fuzz_lineage
            binobf_fuzz_corpus
        USES_TERMINAL
    )
endif()

add_executable(binobf tools/binobf/main.cpp)
target_link_libraries(binobf PRIVATE binobf::core)
binobf_enable_warnings(binobf)

if(BINOBF_BUILD_BENCHMARKS)
    add_executable(binobf_benchmarks tools/benchmark/main.cpp)
    set_target_properties(binobf_benchmarks PROPERTIES OUTPUT_NAME "binobf-benchmarks")
    target_link_libraries(binobf_benchmarks PRIVATE binobf::core)
    binobf_enable_warnings(binobf_benchmarks)
endif()

install(TARGETS binobf binobf_core capstone_static
    RUNTIME DESTINATION bin
    ARCHIVE DESTINATION lib
)
install(DIRECTORY include/binobf DESTINATION include)
install(FILES README.md THIRD_PARTY_NOTICES.md DESTINATION share/doc/binobf)
install(FILES LICENSE DESTINATION share/licenses/binobf)
install(FILES
    licenses/CAPSTONE_LICENSE.txt
    licenses/TOMLPLUSPLUS_LICENSE.txt
    licenses/NLOHMANN_JSON_LICENSE.txt
    DESTINATION share/licenses/binobf
)

if(BINOBF_BUILD_TESTS)
    enable_testing()

    add_executable(binobf_core_types_tests tests/unit/core_types_tests.cpp)
    target_link_libraries(binobf_core_types_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_core_types_tests)
    add_test(NAME core_types COMMAND binobf_core_types_tests)

    add_executable(
        binobf_capability_registry_tests
        tests/unit/capability_registry_tests.cpp
    )
    target_link_libraries(binobf_capability_registry_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_capability_registry_tests)
    add_test(NAME capability_registry COMMAND binobf_capability_registry_tests)

    add_executable(binobf_diagnostic_tests tests/unit/diagnostic_tests.cpp)
    target_link_libraries(binobf_diagnostic_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_diagnostic_tests)
    add_test(NAME diagnostic COMMAND binobf_diagnostic_tests)

    add_executable(binobf_deterministic_rng_tests tests/unit/deterministic_rng_tests.cpp)
    target_link_libraries(binobf_deterministic_rng_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_deterministic_rng_tests)
    add_test(NAME deterministic_rng COMMAND binobf_deterministic_rng_tests)

    add_executable(binobf_sha256_tests tests/unit/sha256_tests.cpp)
    target_link_libraries(binobf_sha256_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_sha256_tests)
    add_test(NAME sha256 COMMAND binobf_sha256_tests)

    add_executable(binobf_config_tests tests/unit/config_tests.cpp)
    target_link_libraries(binobf_config_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_config_tests)
    add_test(NAME config COMMAND binobf_config_tests)

    add_executable(binobf_manifest_tests tests/unit/manifest_tests.cpp)
    target_link_libraries(binobf_manifest_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_manifest_tests)
    add_test(NAME manifest COMMAND binobf_manifest_tests)

    add_executable(binobf_lineage_tests tests/unit/lineage_tests.cpp)
    target_link_libraries(binobf_lineage_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_lineage_tests)
    add_test(NAME lineage COMMAND binobf_lineage_tests)

    add_executable(
        binobf_artifact_transaction_tests
        tests/unit/artifact_transaction_tests.cpp
    )
    target_link_libraries(binobf_artifact_transaction_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_artifact_transaction_tests)
    add_test(NAME artifact_transaction COMMAND binobf_artifact_transaction_tests)

    add_executable(binobf_format_detector_tests tests/unit/format_detector_tests.cpp)
    target_link_libraries(binobf_format_detector_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_format_detector_tests)
    add_test(NAME format_detector COMMAND binobf_format_detector_tests)

    add_executable(binobf_elf_object_parser_tests tests/unit/elf_object_parser_tests.cpp)
    target_link_libraries(binobf_elf_object_parser_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_elf_object_parser_tests)
    add_test(NAME elf_object_parser COMMAND binobf_elf_object_parser_tests)

    add_executable(binobf_coff_object_parser_tests tests/unit/coff_object_parser_tests.cpp)
    target_link_libraries(binobf_coff_object_parser_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_coff_object_parser_tests)
    add_test(NAME coff_object_parser COMMAND binobf_coff_object_parser_tests)

    add_executable(binobf_object_writer_tests tests/unit/object_writer_tests.cpp)
    target_link_libraries(binobf_object_writer_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_object_writer_tests)
    add_test(NAME object_writer COMMAND binobf_object_writer_tests)

    add_executable(binobf_pass_manager_tests tests/unit/pass_manager_tests.cpp)
    target_link_libraries(binobf_pass_manager_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_pass_manager_tests)
    add_test(NAME pass_manager COMMAND binobf_pass_manager_tests)

    add_executable(binobf_pass_registry_tests tests/unit/pass_registry_tests.cpp)
    target_link_libraries(binobf_pass_registry_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_pass_registry_tests)
    add_test(NAME pass_registry COMMAND binobf_pass_registry_tests)

    add_executable(binobf_function_selection_tests tests/unit/function_selection_tests.cpp)
    target_link_libraries(binobf_function_selection_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_function_selection_tests)
    add_test(NAME function_selection COMMAND binobf_function_selection_tests)

    add_executable(binobf_baseline_transform_tests tests/unit/baseline_transform_tests.cpp)
    target_link_libraries(binobf_baseline_transform_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_baseline_transform_tests)
    add_test(NAME baseline_transforms COMMAND binobf_baseline_transform_tests)

    add_executable(binobf_structural_verifier_tests tests/unit/structural_verifier_tests.cpp)
    target_link_libraries(binobf_structural_verifier_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_structural_verifier_tests)
    add_test(NAME structural_verifier COMMAND binobf_structural_verifier_tests)

    add_executable(binobf_instruction_decoder_tests tests/unit/instruction_decoder_tests.cpp)
    target_link_libraries(binobf_instruction_decoder_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_instruction_decoder_tests)
    add_test(NAME instruction_decoder COMMAND binobf_instruction_decoder_tests)

    add_executable(binobf_object_analyzer_tests tests/unit/object_analyzer_tests.cpp)
    target_link_libraries(binobf_object_analyzer_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_object_analyzer_tests)
    add_test(NAME object_analyzer COMMAND binobf_object_analyzer_tests)

    add_executable(
        binobf_instruction_transform_tests
        tests/unit/instruction_transform_tests.cpp
    )
    target_link_libraries(binobf_instruction_transform_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_instruction_transform_tests)
    add_test(NAME instruction_transforms COMMAND binobf_instruction_transform_tests)

    add_executable(binobf_vm_ir_tests tests/unit/vm_ir_tests.cpp)
    target_link_libraries(binobf_vm_ir_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_vm_ir_tests)
    add_test(NAME vm_ir COMMAND binobf_vm_ir_tests)

    add_executable(binobf_vm_runtime_tests tests/unit/vm_runtime_tests.cpp)
    target_link_libraries(binobf_vm_runtime_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_vm_runtime_tests)
    add_test(NAME vm_runtime COMMAND binobf_vm_runtime_tests)

    add_executable(binobf_vm_bytecode_tests tests/unit/vm_bytecode_tests.cpp)
    target_link_libraries(binobf_vm_bytecode_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_vm_bytecode_tests)
    add_test(NAME vm_bytecode COMMAND binobf_vm_bytecode_tests)

    add_executable(binobf_native_ir_tests tests/unit/native_ir_tests.cpp)
    target_link_libraries(binobf_native_ir_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_native_ir_tests)
    add_test(NAME native_ir COMMAND binobf_native_ir_tests)

    add_executable(binobf_native_lifter_tests tests/unit/native_lifter_tests.cpp)
    target_link_libraries(binobf_native_lifter_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_native_lifter_tests)
    add_test(NAME native_lifter COMMAND binobf_native_lifter_tests)

    add_executable(binobf_vm_lowering_tests tests/unit/vm_lowering_tests.cpp)
    target_link_libraries(binobf_vm_lowering_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_vm_lowering_tests)
    add_test(NAME vm_lowering COMMAND binobf_vm_lowering_tests)

    add_executable(binobf_vm_protection_tests tests/unit/vm_protection_tests.cpp)
    target_link_libraries(binobf_vm_protection_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_vm_protection_tests)
    add_test(NAME vm_protection COMMAND binobf_vm_protection_tests)

    add_executable(
        binobf_control_flow_transform_tests
        tests/unit/control_flow_transform_tests.cpp
    )
    target_link_libraries(binobf_control_flow_transform_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_control_flow_transform_tests)
    add_test(NAME control_flow_transforms COMMAND binobf_control_flow_transform_tests)

    add_executable(binobf_ir_module_tests tests/unit/ir_module_tests.cpp)
    target_link_libraries(binobf_ir_module_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_ir_module_tests)
    add_test(NAME ir_module COMMAND binobf_ir_module_tests)

    add_executable(binobf_outlining_tests tests/unit/outlining_tests.cpp)
    target_link_libraries(binobf_outlining_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_outlining_tests)
    add_test(NAME outlining COMMAND binobf_outlining_tests)

    add_executable(binobf_linked_image_tests tests/unit/linked_image_tests.cpp)
    target_link_libraries(binobf_linked_image_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_linked_image_tests)
    add_test(NAME linked_image COMMAND binobf_linked_image_tests)

    add_executable(binobf_archive_tests tests/unit/archive_tests.cpp)
    target_link_libraries(binobf_archive_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_archive_tests)
    add_test(NAME archive COMMAND binobf_archive_tests)

    add_executable(binobf_vm_property_tests tests/property/vm_property_tests.cpp)
    target_link_libraries(binobf_vm_property_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_vm_property_tests)
    add_test(NAME vm_properties COMMAND binobf_vm_property_tests)

    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        add_library(binobf_fixture_host OBJECT EXCLUDE_FROM_ALL tests/fixtures/arithmetic.c)
        if(BINOBF_ENABLE_UNDEFINED_SANITIZER OR BINOBF_ENABLE_ADDRESS_SANITIZER)
            target_compile_options(binobf_fixture_host PRIVATE -fno-sanitize=all)
        endif()
        binobf_enable_warnings(binobf_fixture_host)

        set(BINOBF_ELF_FIXTURE "${CMAKE_CURRENT_BINARY_DIR}/fixtures/arithmetic-elf.o")
        add_custom_command(
            OUTPUT "${BINOBF_ELF_FIXTURE}"
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/fixtures"
            COMMAND "${CMAKE_C_COMPILER}" --target=x86_64-unknown-linux-gnu
                -std=c11 -Wall -Wextra -Wpedantic -Werror
                -c "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/arithmetic.c"
                -o "${BINOBF_ELF_FIXTURE}"
            DEPENDS tests/fixtures/arithmetic.c
            VERBATIM
        )
        add_custom_target(binobf_fixture_elf DEPENDS "${BINOBF_ELF_FIXTURE}")

        set(BINOBF_TRANSFORM_PATTERN_FIXTURE
            "${CMAKE_CURRENT_BINARY_DIR}/fixtures/transform-patterns.obj")
        add_custom_command(
            OUTPUT "${BINOBF_TRANSFORM_PATTERN_FIXTURE}"
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/fixtures"
            COMMAND "${CMAKE_C_COMPILER}"
                -c "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/transform_patterns.S"
                -o "${BINOBF_TRANSFORM_PATTERN_FIXTURE}"
            DEPENDS tests/fixtures/transform_patterns.S
            VERBATIM
        )
        add_custom_target(
            binobf_fixture_transform_patterns
            DEPENDS "${BINOBF_TRANSFORM_PATTERN_FIXTURE}"
        )

        set(BINOBF_TRANSFORM_PATTERN_ELF_FIXTURE
            "${CMAKE_CURRENT_BINARY_DIR}/fixtures/transform-patterns.o")
        add_custom_command(
            OUTPUT "${BINOBF_TRANSFORM_PATTERN_ELF_FIXTURE}"
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/fixtures"
            COMMAND "${CMAKE_C_COMPILER}" --target=x86_64-unknown-linux-gnu
                -c "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/transform_patterns.S"
                -o "${BINOBF_TRANSFORM_PATTERN_ELF_FIXTURE}"
            DEPENDS tests/fixtures/transform_patterns.S
            VERBATIM
        )
        add_custom_target(
            binobf_fixture_transform_patterns_elf
            DEPENDS "${BINOBF_TRANSFORM_PATTERN_ELF_FIXTURE}"
        )

        set(BINOBF_VM_LOWERING_FIXTURE
            "${CMAKE_CURRENT_BINARY_DIR}/fixtures/vm-lowering.obj")
        add_custom_command(
            OUTPUT "${BINOBF_VM_LOWERING_FIXTURE}"
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/fixtures"
            COMMAND "${CMAKE_C_COMPILER}"
                -c "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/vm_lowering.S"
                -o "${BINOBF_VM_LOWERING_FIXTURE}"
            DEPENDS tests/fixtures/vm_lowering.S
            VERBATIM
        )
        add_custom_target(binobf_fixture_vm_lowering DEPENDS "${BINOBF_VM_LOWERING_FIXTURE}")

        set(BINOBF_VM_LOWERING_ELF_FIXTURE
            "${CMAKE_CURRENT_BINARY_DIR}/fixtures/vm-lowering.o")
        add_custom_command(
            OUTPUT "${BINOBF_VM_LOWERING_ELF_FIXTURE}"
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/fixtures"
            COMMAND "${CMAKE_C_COMPILER}" --target=x86_64-unknown-linux-gnu
                -c "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/vm_lowering.S"
                -o "${BINOBF_VM_LOWERING_ELF_FIXTURE}"
            DEPENDS tests/fixtures/vm_lowering.S
            VERBATIM
        )
        add_custom_target(
            binobf_fixture_vm_lowering_elf
            DEPENDS "${BINOBF_VM_LOWERING_ELF_FIXTURE}"
        )

        add_executable(
            binobf_object_parser_integration_tests
            tests/integration/object_parser_integration_tests.cpp
        )
        target_link_libraries(binobf_object_parser_integration_tests PRIVATE binobf::core)
        binobf_enable_warnings(binobf_object_parser_integration_tests)
        add_dependencies(
            binobf_object_parser_integration_tests
            binobf_fixture_host
            binobf_fixture_elf
        )
        add_test(
            NAME object_parser_integration
            COMMAND binobf_object_parser_integration_tests
                "$<TARGET_OBJECTS:binobf_fixture_host>"
                "${BINOBF_ELF_FIXTURE}"
        )

        find_program(BINOBF_LLVM_READOBJ llvm-readobj REQUIRED)
        find_program(BINOBF_LLVM_AR llvm-ar REQUIRED)
        find_program(BINOBF_LLVM_LIB llvm-lib REQUIRED)
        find_program(BINOBF_LLVM_NM llvm-nm REQUIRED)
        find_program(BINOBF_LD_LLD ld.lld REQUIRED)

        set(BINOBF_LINKED_FIXTURE_DIR "${CMAKE_CURRENT_BINARY_DIR}/linked-fixtures")
        set(BINOBF_LINKED_PE_OBJECT "${BINOBF_LINKED_FIXTURE_DIR}/linked-pe.obj")
        set(BINOBF_LINKED_PE_EXE "${BINOBF_LINKED_FIXTURE_DIR}/linked-pe.exe")
        set(BINOBF_LINKED_PE_DLL "${BINOBF_LINKED_FIXTURE_DIR}/linked-pe.dll")
        set(BINOBF_LINKED_PE_IMPLIB "${BINOBF_LINKED_FIXTURE_DIR}/linked-pe-import.lib")
        set(BINOBF_LINKED_ELF_OBJECT "${BINOBF_LINKED_FIXTURE_DIR}/linked-elf.o")
        set(BINOBF_LINKED_ELF_SHARED_OBJECT
            "${BINOBF_LINKED_FIXTURE_DIR}/linked-elf-shared.o")
        set(BINOBF_LINKED_ELF_EXE "${BINOBF_LINKED_FIXTURE_DIR}/linked-elf")
        set(BINOBF_LINKED_ELF_PIE "${BINOBF_LINKED_FIXTURE_DIR}/linked-elf-pie")
        set(BINOBF_LINKED_ELF_SO "${BINOBF_LINKED_FIXTURE_DIR}/linked-elf.so")
        add_custom_command(
            OUTPUT
                "${BINOBF_LINKED_PE_EXE}"
                "${BINOBF_LINKED_PE_DLL}"
                "${BINOBF_LINKED_PE_IMPLIB}"
                "${BINOBF_LINKED_ELF_EXE}"
                "${BINOBF_LINKED_ELF_PIE}"
                "${BINOBF_LINKED_ELF_SO}"
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${BINOBF_LINKED_FIXTURE_DIR}"
            COMMAND "${CMAKE_C_COMPILER}" --target=x86_64-pc-windows-msvc -gcodeview
                -c "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/linked_pe.S"
                -o "${BINOBF_LINKED_PE_OBJECT}"
            COMMAND "${CMAKE_C_COMPILER}" --target=x86_64-pc-windows-msvc
                -nostdlib -fuse-ld=lld "${BINOBF_LINKED_PE_OBJECT}"
                "-Wl,/entry:binobf_linked_entry" "-Wl,/subsystem:console" "-Wl,/debug"
                "-Wl,/pdb:${BINOBF_LINKED_FIXTURE_DIR}/linked-pe.pdb"
                "-Wl,/export:binobf_linked_export" -lkernel32
                -o "${BINOBF_LINKED_PE_EXE}"
            COMMAND "${CMAKE_C_COMPILER}" --target=x86_64-pc-windows-msvc
                -nostdlib -fuse-ld=lld "${BINOBF_LINKED_PE_OBJECT}"
                "-Wl,/dll" "-Wl,/noentry" "-Wl,/debug"
                "-Wl,/pdb:${BINOBF_LINKED_FIXTURE_DIR}/linked-pe-dll.pdb"
                "-Wl,/implib:${BINOBF_LINKED_PE_IMPLIB}"
                "-Wl,/export:binobf_linked_export" -lkernel32
                -o "${BINOBF_LINKED_PE_DLL}"
            COMMAND "${CMAKE_C_COMPILER}" --target=x86_64-unknown-linux-gnu -g
                -c "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/linked_elf.S"
                -o "${BINOBF_LINKED_ELF_OBJECT}"
            COMMAND "${CMAKE_C_COMPILER}" --target=x86_64-unknown-linux-gnu -g
                -c "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/linked_elf_shared.S"
                -o "${BINOBF_LINKED_ELF_SHARED_OBJECT}"
            COMMAND "${BINOBF_LD_LLD}" --entry=_start --build-id --emit-relocs
                -o "${BINOBF_LINKED_ELF_EXE}" "${BINOBF_LINKED_ELF_OBJECT}"
            COMMAND "${BINOBF_LD_LLD}" -pie --entry=_start --build-id --emit-relocs
                -o "${BINOBF_LINKED_ELF_PIE}" "${BINOBF_LINKED_ELF_OBJECT}"
            COMMAND "${BINOBF_LD_LLD}" -shared --build-id --emit-relocs
                -o "${BINOBF_LINKED_ELF_SO}" "${BINOBF_LINKED_ELF_SHARED_OBJECT}"
            DEPENDS
                tests/fixtures/linked_pe.S
                tests/fixtures/linked_elf.S
                tests/fixtures/linked_elf_shared.S
            VERBATIM
        )
        add_custom_target(
            binobf_fixture_linked_images
            DEPENDS
                "${BINOBF_LINKED_PE_EXE}"
                "${BINOBF_LINKED_PE_DLL}"
                "${BINOBF_LINKED_PE_IMPLIB}"
                "${BINOBF_LINKED_ELF_EXE}"
                "${BINOBF_LINKED_ELF_PIE}"
                "${BINOBF_LINKED_ELF_SO}"
        )
        add_executable(
            binobf_linked_image_integration_tests
            tests/integration/linked_image_integration_tests.cpp
        )
        target_link_libraries(binobf_linked_image_integration_tests PRIVATE binobf::core)
        binobf_enable_warnings(binobf_linked_image_integration_tests)
        add_dependencies(binobf_linked_image_integration_tests binobf_fixture_linked_images)
        add_test(
            NAME linked_image_integration
            COMMAND binobf_linked_image_integration_tests
                "${BINOBF_LINKED_PE_EXE}"
                "${BINOBF_LINKED_PE_DLL}"
                "${BINOBF_LINKED_ELF_EXE}"
                "${BINOBF_LINKED_ELF_PIE}"
                "${BINOBF_LINKED_ELF_SO}"
                "${BINOBF_LLVM_READOBJ}"
                "${CMAKE_CURRENT_BINARY_DIR}/linked-image-integration"
        )

        set(BINOBF_ARCHIVE_FIXTURE_DIR "${CMAKE_CURRENT_BINARY_DIR}/archive-fixtures")
        set(BINOBF_ARCHIVE_COFF_ADD "${BINOBF_ARCHIVE_FIXTURE_DIR}/archive-add.obj")
        set(BINOBF_ARCHIVE_COFF_LONG
            "${BINOBF_ARCHIVE_FIXTURE_DIR}/archive-double-with-a-deliberately-long-member-name.obj")
        set(BINOBF_ARCHIVE_ELF_ADD "${BINOBF_ARCHIVE_FIXTURE_DIR}/archive-add.o")
        set(BINOBF_ARCHIVE_ELF_LONG
            "${BINOBF_ARCHIVE_FIXTURE_DIR}/archive-double-with-a-deliberately-long-member-name.o")
        set(BINOBF_ARCHIVE_COFF_DRIVER "${BINOBF_ARCHIVE_FIXTURE_DIR}/archive-driver.obj")
        set(BINOBF_ARCHIVE_ELF_DRIVER "${BINOBF_ARCHIVE_FIXTURE_DIR}/archive-driver.o")
        set(BINOBF_ARCHIVE_LIB "${BINOBF_ARCHIVE_FIXTURE_DIR}/archive.lib")
        set(BINOBF_ARCHIVE_A "${BINOBF_ARCHIVE_FIXTURE_DIR}/libarchive.a")
        set(BINOBF_ARCHIVE_PE_EXE "${BINOBF_ARCHIVE_FIXTURE_DIR}/archive-original.exe")
        set(BINOBF_ARCHIVE_ELF_EXE "${BINOBF_ARCHIVE_FIXTURE_DIR}/archive-original-elf")
        add_custom_command(
            OUTPUT
                "${BINOBF_ARCHIVE_LIB}"
                "${BINOBF_ARCHIVE_A}"
                "${BINOBF_ARCHIVE_PE_EXE}"
                "${BINOBF_ARCHIVE_ELF_EXE}"
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${BINOBF_ARCHIVE_FIXTURE_DIR}"
            COMMAND "${CMAKE_C_COMPILER}" --target=x86_64-pc-windows-msvc -gcodeview
                -c "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/archive_add.c"
                -o "${BINOBF_ARCHIVE_COFF_ADD}"
            COMMAND "${CMAKE_C_COMPILER}" --target=x86_64-pc-windows-msvc -gcodeview
                -c "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/archive_double_with_a_deliberately_long_member_name.c"
                -o "${BINOBF_ARCHIVE_COFF_LONG}"
            COMMAND "${CMAKE_C_COMPILER}" --target=x86_64-unknown-linux-gnu -g
                -c "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/archive_add.c"
                -o "${BINOBF_ARCHIVE_ELF_ADD}"
            COMMAND "${CMAKE_C_COMPILER}" --target=x86_64-unknown-linux-gnu -g
                -c "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/archive_double_with_a_deliberately_long_member_name.c"
                -o "${BINOBF_ARCHIVE_ELF_LONG}"
            COMMAND "${CMAKE_C_COMPILER}" --target=x86_64-pc-windows-msvc
                -c "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/archive_driver_pe.S"
                -o "${BINOBF_ARCHIVE_COFF_DRIVER}"
            COMMAND "${CMAKE_C_COMPILER}" --target=x86_64-unknown-linux-gnu
                -c "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/archive_driver_elf.S"
                -o "${BINOBF_ARCHIVE_ELF_DRIVER}"
            COMMAND "${BINOBF_LLVM_LIB}" "/out:${BINOBF_ARCHIVE_LIB}"
                "${BINOBF_ARCHIVE_COFF_ADD}" "${BINOBF_ARCHIVE_COFF_LONG}"
            COMMAND "${BINOBF_LLVM_AR}" rcs "${BINOBF_ARCHIVE_A}"
                "${BINOBF_ARCHIVE_ELF_ADD}" "${BINOBF_ARCHIVE_ELF_LONG}"
            COMMAND "${CMAKE_C_COMPILER}" --target=x86_64-pc-windows-msvc
                -nostdlib -fuse-ld=lld "${BINOBF_ARCHIVE_COFF_DRIVER}"
                "${BINOBF_ARCHIVE_LIB}" "-Wl,/entry:archive_entry"
                "-Wl,/subsystem:console" -lkernel32 -o "${BINOBF_ARCHIVE_PE_EXE}"
            COMMAND "${BINOBF_LD_LLD}" --entry=_start -o "${BINOBF_ARCHIVE_ELF_EXE}"
                "${BINOBF_ARCHIVE_ELF_DRIVER}" "${BINOBF_ARCHIVE_A}"
            DEPENDS
                tests/fixtures/archive_add.c
                tests/fixtures/archive_double_with_a_deliberately_long_member_name.c
                tests/fixtures/archive_driver_pe.S
                tests/fixtures/archive_driver_elf.S
            VERBATIM
        )
        add_custom_target(
            binobf_fixture_archives
            DEPENDS
                "${BINOBF_ARCHIVE_LIB}"
                "${BINOBF_ARCHIVE_A}"
                "${BINOBF_ARCHIVE_PE_EXE}"
                "${BINOBF_ARCHIVE_ELF_EXE}"
                "${BINOBF_LINKED_PE_IMPLIB}"
        )
        add_executable(
            binobf_archive_integration_tests
            tests/integration/archive_integration_tests.cpp
        )
        target_link_libraries(binobf_archive_integration_tests PRIVATE binobf::core)
        binobf_enable_warnings(binobf_archive_integration_tests)
        add_dependencies(binobf_archive_integration_tests binobf_fixture_archives)
        add_test(
            NAME archive_integration
            COMMAND binobf_archive_integration_tests
                "${BINOBF_ARCHIVE_A}"
                "${BINOBF_ARCHIVE_LIB}"
                "${BINOBF_LINKED_PE_IMPLIB}"
                "${BINOBF_ARCHIVE_PE_EXE}"
                "${BINOBF_ARCHIVE_ELF_EXE}"
                "${CMAKE_C_COMPILER}"
                "${BINOBF_LLVM_AR}"
                "${BINOBF_LLVM_NM}"
                "${BINOBF_LD_LLD}"
                "${CMAKE_CURRENT_BINARY_DIR}/archive-integration"
        )

        add_executable(
            binobf_parser_robustness_tests
            tests/property/parser_robustness_tests.cpp
        )
        target_link_libraries(binobf_parser_robustness_tests PRIVATE binobf::core)
        binobf_enable_warnings(binobf_parser_robustness_tests)
        add_dependencies(
            binobf_parser_robustness_tests
            binobf_fixture_host
            binobf_fixture_elf
            binobf_fixture_linked_images
            binobf_fixture_archives
        )
        add_test(
            NAME parser_robustness
            COMMAND binobf_parser_robustness_tests
                "$<TARGET_OBJECTS:binobf_fixture_host>"
                "${BINOBF_ELF_FIXTURE}"
                "${BINOBF_LINKED_PE_EXE}"
                "${BINOBF_LINKED_ELF_EXE}"
                "${BINOBF_LINKED_ELF_SO}"
                "${BINOBF_ARCHIVE_A}"
        )

        add_executable(
            binobf_artifact_mutation_tests
            tests/mutation/artifact_mutation_tests.cpp
        )
        target_link_libraries(binobf_artifact_mutation_tests PRIVATE binobf::core)
        binobf_enable_warnings(binobf_artifact_mutation_tests)
        add_dependencies(
            binobf_artifact_mutation_tests
            binobf_fixture_host
            binobf_fixture_elf
            binobf_fixture_linked_images
            binobf_fixture_archives
        )
        add_test(
            NAME artifact_mutation
            COMMAND binobf_artifact_mutation_tests
                "$<TARGET_OBJECTS:binobf_fixture_host>"
                "${BINOBF_ELF_FIXTURE}"
                "${BINOBF_LINKED_PE_EXE}"
                "${BINOBF_LINKED_ELF_EXE}"
                "${BINOBF_ARCHIVE_A}"
        )
        add_executable(
            binobf_object_writer_integration_tests
            tests/integration/object_writer_integration_tests.cpp
        )
        target_link_libraries(binobf_object_writer_integration_tests PRIVATE binobf::core)
        binobf_enable_warnings(binobf_object_writer_integration_tests)
        add_dependencies(
            binobf_object_writer_integration_tests
            binobf_fixture_host
            binobf_fixture_elf
        )
        add_test(
            NAME object_writer_integration
            COMMAND binobf_object_writer_integration_tests
                "$<TARGET_OBJECTS:binobf_fixture_host>"
                "${BINOBF_ELF_FIXTURE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/driver.c"
                "${CMAKE_C_COMPILER}"
                "${BINOBF_LLVM_READOBJ}"
                "${BINOBF_LD_LLD}"
                "${CMAKE_CURRENT_BINARY_DIR}/writer-integration"
        )

        add_executable(
            binobf_differential_tests
            tests/differential/differential_tests.cpp
            tests/differential/harness.cpp
        )
        target_link_libraries(binobf_differential_tests PRIVATE binobf::core)
        binobf_enable_warnings(binobf_differential_tests)
        add_dependencies(
            binobf_differential_tests
            binobf_fixture_host
            binobf_fixture_transform_patterns
        )
        add_test(
            NAME differential_object_semantics
            COMMAND binobf_differential_tests
                "${BINOBF_TRANSFORM_PATTERN_FIXTURE}"
                "$<TARGET_OBJECTS:binobf_fixture_host>"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/differential_driver.c"
                "${CMAKE_C_COMPILER}"
                "${CMAKE_CURRENT_BINARY_DIR}/differential"
        )

        add_executable(
            binobf_instruction_transform_integration_tests
            tests/integration/instruction_transform_integration_tests.cpp
        )
        target_link_libraries(
            binobf_instruction_transform_integration_tests
            PRIVATE binobf::core
        )
        binobf_enable_warnings(binobf_instruction_transform_integration_tests)
        add_dependencies(
            binobf_instruction_transform_integration_tests
            binobf_fixture_transform_patterns
            binobf_fixture_transform_patterns_elf
        )
        add_test(
            NAME instruction_transform_integration
            COMMAND binobf_instruction_transform_integration_tests
                "${BINOBF_TRANSFORM_PATTERN_FIXTURE}"
                "${BINOBF_TRANSFORM_PATTERN_ELF_FIXTURE}"
                "${BINOBF_LLVM_READOBJ}"
                "${BINOBF_LD_LLD}"
                "${CMAKE_CURRENT_BINARY_DIR}/instruction-transform-integration"
        )

        set_source_files_properties(
            "${BINOBF_VM_LOWERING_FIXTURE}"
            PROPERTIES GENERATED TRUE EXTERNAL_OBJECT TRUE
        )
        add_executable(
            binobf_vm_lowering_differential_tests
            tests/differential/vm_lowering_differential_tests.cpp
            "${BINOBF_VM_LOWERING_FIXTURE}"
        )
        target_link_libraries(binobf_vm_lowering_differential_tests PRIVATE binobf::core)
        binobf_enable_warnings(binobf_vm_lowering_differential_tests)
        add_dependencies(
            binobf_vm_lowering_differential_tests
            binobf_fixture_vm_lowering
            binobf_fixture_vm_lowering_elf
        )
        add_test(
            NAME vm_lowering_differential
            COMMAND binobf_vm_lowering_differential_tests
                "${BINOBF_VM_LOWERING_FIXTURE}"
                "${BINOBF_VM_LOWERING_ELF_FIXTURE}"
        )

        set(BINOBF_VM_PROTECTED_COFF_FIXTURE
            "${CMAKE_CURRENT_BINARY_DIR}/fixtures/vm-protected.obj")
        add_custom_command(
            OUTPUT "${BINOBF_VM_PROTECTED_COFF_FIXTURE}"
            COMMAND "${CMAKE_COMMAND}" -E rm -f "${BINOBF_VM_PROTECTED_COFF_FIXTURE}"
            COMMAND "$<TARGET_FILE:binobf>" vm protect
                "${BINOBF_VM_LOWERING_FIXTURE}"
                --function=binobf_vm_add --abi=windows-x64 --args=2
                -o "${BINOBF_VM_PROTECTED_COFF_FIXTURE}" --seed=16016
            DEPENDS binobf "${BINOBF_VM_LOWERING_FIXTURE}"
            VERBATIM
        )
        add_custom_target(
            binobf_fixture_vm_protected
            DEPENDS "${BINOBF_VM_PROTECTED_COFF_FIXTURE}"
        )
        set_source_files_properties(
            "${BINOBF_VM_PROTECTED_COFF_FIXTURE}"
            PROPERTIES GENERATED TRUE EXTERNAL_OBJECT TRUE
        )
        add_executable(
            binobf_vm_protected_execution_tests
            tests/fixtures/vm_protected_driver.cpp
            "${BINOBF_VM_PROTECTED_COFF_FIXTURE}"
        )
        target_link_libraries(binobf_vm_protected_execution_tests PRIVATE binobf::core)
        binobf_enable_warnings(binobf_vm_protected_execution_tests)
        add_dependencies(
            binobf_vm_protected_execution_tests
            binobf_fixture_vm_protected
        )
        add_test(
            NAME vm_protected_execution
            COMMAND binobf_vm_protected_execution_tests
        )

        add_executable(
            binobf_vm_protection_integration_tests
            tests/integration/vm_protection_integration_tests.cpp
        )
        target_link_libraries(binobf_vm_protection_integration_tests PRIVATE binobf::core)
        binobf_enable_warnings(binobf_vm_protection_integration_tests)
        add_dependencies(
            binobf_vm_protection_integration_tests
            binobf_fixture_vm_lowering
            binobf_fixture_vm_lowering_elf
        )
        add_test(
            NAME vm_protection_integration
            COMMAND binobf_vm_protection_integration_tests
                "${BINOBF_VM_LOWERING_FIXTURE}"
                "${BINOBF_VM_LOWERING_ELF_FIXTURE}"
                "${BINOBF_LLVM_READOBJ}"
                "${BINOBF_LD_LLD}"
                "${CMAKE_CURRENT_BINARY_DIR}/vm-protection-integration"
        )
    endif()

    add_executable(binobf_cli_tests tests/integration/cli_tests.cpp)
    target_link_libraries(binobf_cli_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_cli_tests)
    add_test(NAME cli COMMAND binobf_cli_tests)

    add_executable(
        binobf_capability_evidence_tests
        tests/integration/capability_evidence_tests.cpp
    )
    target_link_libraries(binobf_capability_evidence_tests PRIVATE binobf::core)
    binobf_enable_warnings(binobf_capability_evidence_tests)
    add_test(
        NAME capability_evidence
        COMMAND binobf_capability_evidence_tests
            "${CMAKE_CURRENT_BINARY_DIR}/CTestTestfile.cmake"
    )
endif()

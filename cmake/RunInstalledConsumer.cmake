if(NOT DEFINED BINOBF_SOURCE_DIR OR
   NOT DEFINED BINOBF_BUILD_DIR OR
   NOT DEFINED BINOBF_INSTALL_PREFIX OR
   NOT DEFINED BINOBF_CXX_COMPILER OR
   NOT DEFINED BINOBF_CONSUMER_SOURCE OR
   NOT DEFINED BINOBF_CONSUMER_NAME OR
   NOT DEFINED BINOBF_INSTALLED_LIBRARIES)
    message(FATAL_ERROR "installed-consumer gate is missing required configuration")
endif()

file(REAL_PATH "${BINOBF_BUILD_DIR}" _build_root)
file(REAL_PATH "${BINOBF_INSTALL_PREFIX}" _install_root BASE_DIRECTORY "${_build_root}")
cmake_path(IS_PREFIX _build_root "${_install_root}" NORMALIZE _inside_build)
if(NOT _inside_build OR _install_root STREQUAL _build_root)
    message(FATAL_ERROR "installed-consumer prefix must be a child of the build tree")
endif()

file(REMOVE_RECURSE "${_install_root}")
execute_process(
    COMMAND "${CMAKE_COMMAND}" --install "${_build_root}" --prefix "${_install_root}"
    RESULT_VARIABLE _install_result
    OUTPUT_VARIABLE _install_output
    ERROR_VARIABLE _install_error
)
if(NOT _install_result EQUAL 0)
    message(FATAL_ERROR
        "install failed (${_install_result})\n${_install_output}\n${_install_error}")
endif()

set(_llvm_license "${_install_root}/share/licenses/binobf/LLVM_LICENSE.txt")
if(NOT EXISTS "${_llvm_license}")
    message(FATAL_ERROR "installed LLVM license is missing: ${_llvm_license}")
endif()

string(REPLACE "|" ";" _library_names "${BINOBF_INSTALLED_LIBRARIES}")
set(_library_paths)
foreach(_library IN LISTS _library_names)
    set(_path "${_install_root}/lib/${_library}")
    if(NOT EXISTS "${_path}")
        message(FATAL_ERROR "installed library is missing: ${_library}")
    endif()
    list(APPEND _library_paths "${_path}")
endforeach()

set(_compile_flags -std=c++20)
set(_system_libraries)
if(WIN32)
    if(BINOBF_UNDEFINED_SANITIZER)
        list(APPEND _compile_flags
            -D_MT -Xclang --dependent-lib=libcmt
            -Xclang -flto-visibility-public-std)
    elseif(BINOBF_CONFIGURATION STREQUAL "Debug")
        list(APPEND _compile_flags
            -D_DEBUG -D_DLL -D_MT -Xclang --dependent-lib=msvcrtd)
    else()
        list(APPEND _compile_flags -D_DLL -D_MT -Xclang --dependent-lib=msvcrt)
    endif()
    list(APPEND _system_libraries
        -lpsapi -lshell32 -lole32 -luuid -ladvapi32 -lws2_32 -lntdll)
endif()
if(BINOBF_UNDEFINED_SANITIZER)
    list(APPEND _compile_flags -fsanitize=undefined -fno-sanitize-recover=undefined)
endif()

set(_consumer "${_install_root}/bin/${BINOBF_CONSUMER_NAME}${CMAKE_EXECUTABLE_SUFFIX}")
execute_process(
    COMMAND "${BINOBF_CXX_COMPILER}"
        ${_compile_flags}
        -I "${_install_root}/include"
        "${BINOBF_CONSUMER_SOURCE}"
        ${_library_paths}
        ${_system_libraries}
        -o "${_consumer}"
    RESULT_VARIABLE _compile_result
    OUTPUT_VARIABLE _compile_output
    ERROR_VARIABLE _compile_error
)
if(NOT _compile_result EQUAL 0)
    message(FATAL_ERROR
        "installed consumer compile failed (${_compile_result})\n${_compile_output}\n${_compile_error}")
endif()

set(_consumer_arguments)
if(BINOBF_TRACK3)
    if(NOT DEFINED BINOBF_C_COMPILER OR NOT DEFINED BINOBF_X86_FIXTURE_SOURCE)
        message(FATAL_ERROR "Track 3 installed consumer requires its C compiler and fixture source")
    endif()
    set(_fixture_dir "${_install_root}/share/binobf-track3-fixtures")
    file(MAKE_DIRECTORY "${_fixture_dir}")
    set(_coff_fixture "${_fixture_dir}/transform-patterns.obj")
    set(_elf_fixture "${_fixture_dir}/transform-patterns.o")
    execute_process(
        COMMAND "${BINOBF_C_COMPILER}" --target=i686-pc-windows-msvc -m32
            -c "${BINOBF_X86_FIXTURE_SOURCE}" -o "${_coff_fixture}"
        RESULT_VARIABLE _coff_result
        OUTPUT_VARIABLE _coff_output
        ERROR_VARIABLE _coff_error
    )
    if(NOT _coff_result EQUAL 0)
        message(FATAL_ERROR "Track 3 COFF fixture failed (${_coff_result})\n${_coff_output}${_coff_error}")
    endif()
    execute_process(
        COMMAND "${BINOBF_C_COMPILER}" --target=i386-unknown-linux-gnu -m32
            -c "${BINOBF_X86_FIXTURE_SOURCE}" -o "${_elf_fixture}"
        RESULT_VARIABLE _elf_result
        OUTPUT_VARIABLE _elf_output
        ERROR_VARIABLE _elf_error
    )
    if(NOT _elf_result EQUAL 0)
        message(FATAL_ERROR "Track 3 ELF fixture failed (${_elf_result})\n${_elf_output}${_elf_error}")
    endif()
    list(APPEND _consumer_arguments "${_coff_fixture}" "${_elf_fixture}")
endif()

execute_process(
    COMMAND "${_consumer}" ${_consumer_arguments}
    RESULT_VARIABLE _run_result
    OUTPUT_VARIABLE _run_output
    ERROR_VARIABLE _run_error
)
if(NOT _run_result EQUAL 0)
    message(FATAL_ERROR
        "installed consumer failed (${_run_result})\n${_run_output}\n${_run_error}")
endif()

message(STATUS "installed consumer passed: ${BINOBF_CONSUMER_NAME}")

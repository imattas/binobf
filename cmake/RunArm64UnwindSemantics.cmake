foreach(required IN ITEMS CLANG LD_LLD LLVM_READOBJ GENERATOR TARGET_SOURCE WORK_DIR)
    if(NOT DEFINED ${required})
        message(FATAL_ERROR "RunArm64UnwindSemantics requires ${required}")
    endif()
endforeach()

file(MAKE_DIRECTORY "${WORK_DIR}")
set(adapter_object "${WORK_DIR}/adapter.o")
set(unwind_object "${WORK_DIR}/unwind.o")
set(windows_object "${WORK_DIR}/windows-unwind.obj")
set(target_object "${WORK_DIR}/target.o")
set(linked_image "${WORK_DIR}/unwind.elf")

execute_process(COMMAND "${GENERATOR}" "${adapter_object}" "${unwind_object}"
    "${windows_object}" RESULT_VARIABLE generate_result TIMEOUT 30)
if(NOT generate_result EQUAL 0)
    message(FATAL_ERROR "ARM64 unwind evidence generation failed: ${generate_result}")
endif()

execute_process(COMMAND "${LLVM_READOBJ}" --unwind --relocations --symbols
    "${windows_object}" RESULT_VARIABLE windows_result
    OUTPUT_VARIABLE windows_output ERROR_VARIABLE windows_error TIMEOUT 30)
if(NOT windows_result EQUAL 0)
    message(FATAL_ERROR "LLVM rejected Windows ARM64 packed unwind\n${windows_output}${windows_error}")
endif()
if(NOT windows_output MATCHES "\.pdata"
    OR NOT windows_output MATCHES "IMAGE_REL_ARM64_ADDR32NB"
    OR NOT windows_output MATCHES "FunctionLength"
    OR NOT windows_output MATCHES "FrameSize")
    message(FATAL_ERROR "Windows ARM64 packed unwind evidence is incomplete\n${windows_output}")
endif()

execute_process(COMMAND "${CLANG}" --target=aarch64-unknown-linux-gnu -march=armv8-a
    -c "${TARGET_SOURCE}" -o "${target_object}" RESULT_VARIABLE compile_result
    OUTPUT_VARIABLE compile_output ERROR_VARIABLE compile_error TIMEOUT 30)
if(NOT compile_result EQUAL 0)
    message(FATAL_ERROR "ARM64 unwind target compile failed\n${compile_output}${compile_error}")
endif()
execute_process(COMMAND "${LD_LLD}" -m aarch64elf
    -e binobf_arm64_unwind_target -o "${linked_image}"
    "${target_object}" "${unwind_object}" RESULT_VARIABLE link_result
    OUTPUT_VARIABLE link_output ERROR_VARIABLE link_error TIMEOUT 30)
if(NOT link_result EQUAL 0)
    message(FATAL_ERROR "generated ARM64 unwind object did not link\n${link_output}${link_error}")
endif()
execute_process(COMMAND "${LLVM_READOBJ}" --unwind --symbols "${linked_image}"
    RESULT_VARIABLE linked_result OUTPUT_VARIABLE linked_output
    ERROR_VARIABLE linked_error TIMEOUT 30)
if(NOT linked_result EQUAL 0)
    message(FATAL_ERROR "LLVM rejected linked ARM64 unwind metadata\n${linked_output}${linked_error}")
endif()
string(TOLOWER "${linked_output}" linked_lower)
string(REGEX MATCH "initial_location: (0x[0-9a-f]+)" initial_match "${linked_lower}")
set(initial_location "${CMAKE_MATCH_1}")
string(REGEX MATCH
    "name: binobf_arm64_unwind_target[^\n]*\n[ \t]*value: (0x[0-9a-f]+)"
    symbol_match "${linked_lower}")
set(symbol_location "${CMAKE_MATCH_1}")
if(initial_location STREQUAL "" OR symbol_location STREQUAL ""
    OR NOT initial_location STREQUAL symbol_location)
    message(FATAL_ERROR
        "linked ARM64 FDE does not start at its function: ${initial_location} vs ${symbol_location}\n${linked_output}")
endif()

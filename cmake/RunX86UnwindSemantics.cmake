foreach(required IN ITEMS LLVM_READOBJ LD_LLD GENERATOR WORK_DIR)
    if(NOT DEFINED ${required})
        message(FATAL_ERROR "RunX86UnwindSemantics requires ${required}")
    endif()
endforeach()

file(MAKE_DIRECTORY "${WORK_DIR}")
set(adapter_object "${WORK_DIR}/adapter.obj")
set(unwind_object "${WORK_DIR}/unwind.o")
execute_process(COMMAND "${GENERATOR}" "${adapter_object}" "${unwind_object}"
    RESULT_VARIABLE generate_result TIMEOUT 30)
if(NOT generate_result EQUAL 0)
    message(FATAL_ERROR "unwind evidence artifact generation failed: ${generate_result}")
endif()

set(linked_image "${WORK_DIR}/unwind.elf")
execute_process(COMMAND "${LD_LLD}" -m elf_i386 -e owned_function
    -o "${linked_image}" "${unwind_object}"
    RESULT_VARIABLE link_result OUTPUT_VARIABLE link_output ERROR_VARIABLE link_error TIMEOUT 30)
if(NOT link_result EQUAL 0)
    message(FATAL_ERROR "generated unwind object did not link\n${link_output}${link_error}")
endif()
execute_process(COMMAND "${LLVM_READOBJ}" --unwind --symbols "${linked_image}"
    RESULT_VARIABLE linked_result OUTPUT_VARIABLE linked_output
    ERROR_VARIABLE linked_error TIMEOUT 30)
if(NOT linked_result EQUAL 0)
    message(FATAL_ERROR "LLVM rejected linked unwind metadata\n${linked_output}${linked_error}")
endif()
string(TOLOWER "${linked_output}" linked_lower)
string(REGEX MATCH "initial_location: (0x[0-9a-f]+)" initial_match "${linked_lower}")
set(initial_location "${CMAKE_MATCH_1}")
string(REGEX MATCH "name: owned_function[^\n]*\n[ \t]*value: (0x[0-9a-f]+)"
    symbol_match "${linked_lower}")
set(symbol_location "${CMAKE_MATCH_1}")
if(initial_location STREQUAL "" OR symbol_location STREQUAL ""
    OR NOT initial_location STREQUAL symbol_location)
    message(FATAL_ERROR
        "linked FDE does not start at owned_function: ${initial_location} vs ${symbol_location}\n${linked_output}")
endif()
execute_process(COMMAND "${LLVM_READOBJ}" --unwind --relocations --symbols "${unwind_object}"
    RESULT_VARIABLE inspect_result OUTPUT_VARIABLE inspect_output
    ERROR_VARIABLE inspect_error TIMEOUT 30)
if(NOT inspect_result EQUAL 0)
    message(FATAL_ERROR "LLVM rejected generated unwind metadata\n${inspect_output}${inspect_error}")
endif()
if(NOT inspect_output MATCHES "\.eh_frame" OR NOT inspect_output MATCHES "R_386_PC32"
    OR NOT inspect_output MATCHES "owned_function")
    message(FATAL_ERROR "LLVM unwind inspection lacked owned FDE evidence\n${inspect_output}")
endif()

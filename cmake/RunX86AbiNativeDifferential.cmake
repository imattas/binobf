foreach(required IN ITEMS CLANG LLD_LINK KERNEL32_LIB ENTRY_SOURCE GENERATOR WORK_DIR)
    if(NOT DEFINED ${required})
        message(FATAL_ERROR "RunX86AbiNativeDifferential requires ${required}")
    endif()
endforeach()

file(MAKE_DIRECTORY "${WORK_DIR}")
set(entry_object "${WORK_DIR}/entry.obj")
set(adapter_object "${WORK_DIR}/adapter.obj")
set(unwind_object "${WORK_DIR}/unwind.o")
set(executable "${WORK_DIR}/abi-native.exe")

execute_process(COMMAND "${GENERATOR}" "${adapter_object}" "${unwind_object}"
    RESULT_VARIABLE generate_result TIMEOUT 30)
if(NOT generate_result EQUAL 0)
    message(FATAL_ERROR "ABI evidence artifact generation failed: ${generate_result}")
endif()
execute_process(COMMAND "${CLANG}" --target=i686-pc-windows-msvc -m32 -c
    "${ENTRY_SOURCE}" -o "${entry_object}" RESULT_VARIABLE compile_result
    OUTPUT_VARIABLE compile_output ERROR_VARIABLE compile_error TIMEOUT 30)
if(NOT compile_result EQUAL 0)
    message(FATAL_ERROR "ABI native fixture compile failed\n${compile_output}${compile_error}")
endif()
execute_process(COMMAND "${LLD_LINK}" /machine:x86 /entry:binobf_x86_abi_entry
    /subsystem:console /nodefaultlib /safeseh:no "/out:${executable}"
    "${entry_object}" "${adapter_object}" "${KERNEL32_LIB}"
    RESULT_VARIABLE link_result OUTPUT_VARIABLE link_output ERROR_VARIABLE link_error TIMEOUT 30)
if(NOT link_result EQUAL 0)
    message(FATAL_ERROR "ABI native fixture link failed\n${link_output}${link_error}")
endif()
execute_process(COMMAND "${executable}" RESULT_VARIABLE run_result
    OUTPUT_VARIABLE run_output ERROR_VARIABLE run_error TIMEOUT 10)
if(NOT run_result STREQUAL "0")
    message(FATAL_ERROR "ABI native fixture returned ${run_result}\n${run_output}${run_error}")
endif()

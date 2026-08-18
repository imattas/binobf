foreach(required IN ITEMS CLANG LD_LLD LLVM_READOBJ QEMU ENTRY_SOURCE
        SEMIHOSTING_SOURCE WINDOWS_UNWIND_SOURCE LINKER_SCRIPT GENERATOR WORK_DIR)
    if(NOT DEFINED ${required})
        message(FATAL_ERROR "RunArm64AbiNativeDifferential requires ${required}")
    endif()
endforeach()

file(MAKE_DIRECTORY "${WORK_DIR}")
set(adapter_object "${WORK_DIR}/adapter.o")
set(mixed_adapter_object "${WORK_DIR}/mixed-adapter.o")
set(indirect_adapter_object "${WORK_DIR}/indirect-adapter.o")
set(unwind_object "${WORK_DIR}/unwind.o")
set(entry_object "${WORK_DIR}/entry.o")
set(semihosting_object "${WORK_DIR}/semihosting.o")
set(windows_unwind_object "${WORK_DIR}/windows-unwind-reference.obj")
set(executable "${WORK_DIR}/abi-native.elf")

execute_process(COMMAND "${GENERATOR}" "${adapter_object}" "${unwind_object}"
    RESULT_VARIABLE generate_result TIMEOUT 30)
if(NOT generate_result EQUAL 0)
    message(FATAL_ERROR "ARM64 ABI evidence generation failed: ${generate_result}")
endif()

foreach(object IN ITEMS "${adapter_object}" "${mixed_adapter_object}"
        "${indirect_adapter_object}" "${unwind_object}")
    execute_process(COMMAND "${LLVM_READOBJ}" --file-headers --sections --symbols
        --relocations --unwind "${object}" RESULT_VARIABLE inspect_result
        OUTPUT_VARIABLE inspect_output ERROR_VARIABLE inspect_error TIMEOUT 30)
    if(NOT inspect_result EQUAL 0)
        message(FATAL_ERROR "LLVM rejected ARM64 service artifact ${object}\n${inspect_output}${inspect_error}")
    endif()
endforeach()

execute_process(COMMAND "${CLANG}" --target=aarch64-pc-windows-msvc -march=armv8-a
    -c "${WINDOWS_UNWIND_SOURCE}" -o "${windows_unwind_object}"
    RESULT_VARIABLE windows_unwind_result OUTPUT_VARIABLE windows_unwind_output
    ERROR_VARIABLE windows_unwind_error TIMEOUT 30)
if(NOT windows_unwind_result EQUAL 0)
    message(FATAL_ERROR "Windows ARM64 unwind reference compile failed\n${windows_unwind_output}${windows_unwind_error}")
endif()
execute_process(COMMAND "${LLVM_READOBJ}" --file-headers --sections --unwind
    "${windows_unwind_object}" RESULT_VARIABLE windows_inspect_result
    OUTPUT_VARIABLE windows_inspect_output ERROR_VARIABLE windows_inspect_error TIMEOUT 30)
if(NOT windows_inspect_result EQUAL 0)
    message(FATAL_ERROR "LLVM rejected Windows ARM64 unwind reference\n${windows_inspect_output}${windows_inspect_error}")
endif()

execute_process(COMMAND "${CLANG}" --target=aarch64-unknown-linux-gnu -march=armv8-a
    -ffreestanding -fno-asynchronous-unwind-tables -c "${ENTRY_SOURCE}" -o "${entry_object}"
    RESULT_VARIABLE entry_result OUTPUT_VARIABLE entry_output ERROR_VARIABLE entry_error TIMEOUT 30)
if(NOT entry_result EQUAL 0)
    message(FATAL_ERROR "ARM64 ABI entry compile failed\n${entry_output}${entry_error}")
endif()
execute_process(COMMAND "${CLANG}" --target=aarch64-unknown-linux-gnu -march=armv8-a
    -ffreestanding -fno-asynchronous-unwind-tables -c "${SEMIHOSTING_SOURCE}"
    -o "${semihosting_object}" RESULT_VARIABLE semihosting_result
    OUTPUT_VARIABLE semihosting_output ERROR_VARIABLE semihosting_error TIMEOUT 30)
if(NOT semihosting_result EQUAL 0)
    message(FATAL_ERROR "ARM64 semihosting compile failed\n${semihosting_output}${semihosting_error}")
endif()
execute_process(COMMAND "${LD_LLD}" -m aarch64elf -T "${LINKER_SCRIPT}" -o "${executable}"
    "${entry_object}" "${adapter_object}" "${mixed_adapter_object}"
    "${indirect_adapter_object}" "${semihosting_object}"
    RESULT_VARIABLE link_result OUTPUT_VARIABLE link_output ERROR_VARIABLE link_error TIMEOUT 30)
if(NOT link_result EQUAL 0)
    message(FATAL_ERROR "ARM64 ABI image link failed\n${link_output}${link_error}")
endif()
execute_process(COMMAND "${LLVM_READOBJ}" --file-headers --sections --symbols "${executable}"
    RESULT_VARIABLE image_result OUTPUT_VARIABLE image_output ERROR_VARIABLE image_error TIMEOUT 30)
if(NOT image_result EQUAL 0)
    message(FATAL_ERROR "LLVM rejected ARM64 ABI image\n${image_output}${image_error}")
endif()

execute_process(COMMAND "${QEMU}" -machine virt -cpu cortex-a72 -nographic
    -semihosting-config enable=on,target=native -kernel "${executable}"
    RESULT_VARIABLE run_result OUTPUT_VARIABLE run_output ERROR_VARIABLE run_error TIMEOUT 15)
if(NOT run_result STREQUAL "0")
    message(FATAL_ERROR "ARM64 ABI QEMU fixture returned ${run_result}\n${run_output}${run_error}")
endif()
set(run_transcript "${run_output}${run_error}")
if(NOT run_transcript MATCHES "ARM64_ABI_PASS")
    message(FATAL_ERROR "ARM64 ABI QEMU fixture did not report success\n${run_transcript}")
endif()

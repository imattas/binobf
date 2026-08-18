foreach(required IN ITEMS CLANG LLD_LINK LLVM_READOBJ KERNEL32_LIB ENTRY_SOURCE FIXTURE_SOURCE TRANSFORMER WORK_DIR)
    if(NOT DEFINED ${required})
        message(FATAL_ERROR "RunX86NativeDifferential requires ${required}")
    endif()
endforeach()

file(MAKE_DIRECTORY "${WORK_DIR}")
set(entry_object "${WORK_DIR}/native-entry.obj")
set(fixture_object "${WORK_DIR}/native-fixture.obj")

function(run_checked label)
    execute_process(
        COMMAND ${ARGN}
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error
        TIMEOUT 30
    )
    if(NOT result EQUAL 0)
        string(JOIN " " rendered ${ARGN})
        message(FATAL_ERROR "${label} failed (${result}): ${rendered}\n${output}${error}")
    endif()
endfunction()

run_checked("compile native entry"
    "${CLANG}" --target=i686-pc-windows-msvc -m32 -c "${ENTRY_SOURCE}" -o "${entry_object}")
run_checked("compile native fixture"
    "${CLANG}" --target=i686-pc-windows-msvc -m32 -c "${FIXTURE_SOURCE}" -o "${fixture_object}")

function(link_native object output)
    run_checked("link ${output}"
        "${LLD_LINK}" /machine:x86 /entry:binobf_x86_native_entry /subsystem:console
        /nodefaultlib /safeseh:no "/out:${output}" "${entry_object}" "${object}"
        "${KERNEL32_LIB}")
    execute_process(
        COMMAND "${LLVM_READOBJ}" --file-headers "${output}"
        RESULT_VARIABLE inspect_result
        OUTPUT_VARIABLE inspect_output
        ERROR_VARIABLE inspect_error
        TIMEOUT 10
    )
    if(NOT inspect_result EQUAL 0 OR NOT inspect_output MATCHES "IMAGE_FILE_MACHINE_I386")
        message(FATAL_ERROR "${output} is not a valid i386 PE\n${inspect_output}${inspect_error}")
    endif()
endfunction()

function(run_native executable run_directory expected_hex)
    file(MAKE_DIRECTORY "${run_directory}")
    file(REMOVE "${run_directory}/binobf-native-result.bin")
    execute_process(
        COMMAND "${executable}"
        WORKING_DIRECTORY "${run_directory}"
        RESULT_VARIABLE run_result
        OUTPUT_VARIABLE run_output
        ERROR_VARIABLE run_error
        TIMEOUT 10
    )
    if(NOT run_result STREQUAL "37")
        message(FATAL_ERROR
            "${executable} returned ${run_result}, expected 37\n${run_output}${run_error}")
    endif()
    set(result_file "${run_directory}/binobf-native-result.bin")
    if(NOT EXISTS "${result_file}")
        message(FATAL_ERROR "${executable} did not write its native result")
    endif()
    file(READ "${result_file}" result_hex HEX)
    string(TOLOWER "${result_hex}" result_hex)
    if(NOT result_hex STREQUAL expected_hex)
        message(FATAL_ERROR
            "${executable} wrote ${result_hex}, expected ${expected_hex}")
    endif()
endfunction()

set(expected_hex "2a0000002a00000007000000")
set(original_executable "${WORK_DIR}/native-original.exe")
link_native("${fixture_object}" "${original_executable}")
run_native("${original_executable}" "${WORK_DIR}/run-original" "${expected_hex}")

set(transformed_directory "${WORK_DIR}/transformed")
run_checked("produce transformed native objects"
    "${TRANSFORMER}" "${fixture_object}" "${transformed_directory}")
file(STRINGS "${transformed_directory}/manifest.txt" transformed_entries)
list(LENGTH transformed_entries transformed_count)
if(NOT transformed_count EQUAL 7)
    message(FATAL_ERROR "native transformer produced ${transformed_count} entries, expected 7")
endif()
foreach(entry IN LISTS transformed_entries)
    string(REPLACE "|" ";" fields "${entry}")
    list(GET fields 0 pass_name)
    list(GET fields 1 object_path)
    set(executable "${WORK_DIR}/native-${pass_name}.exe")
    link_native("${object_path}" "${executable}")
    run_native("${executable}" "${WORK_DIR}/run-${pass_name}" "${expected_hex}")
endforeach()

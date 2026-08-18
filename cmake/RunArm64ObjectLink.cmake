if(NOT DEFINED INPUT_DIR OR NOT DEFINED READOBJ OR NOT DEFINED OBJDUMP OR
   NOT DEFINED LLD_LINK OR NOT DEFINED LD_LLD OR NOT DEFINED OUTPUT_DIR)
    message(FATAL_ERROR "RunArm64ObjectLink requires INPUT_DIR, tool paths, and OUTPUT_DIR")
endif()

file(MAKE_DIRECTORY "${OUTPUT_DIR}")
file(GLOB_RECURSE artifacts
    "${INPUT_DIR}/*.obj" "${INPUT_DIR}/*.o")
if(NOT artifacts)
    message(FATAL_ERROR "ARM64 object link gate found no artifacts in ${INPUT_DIR}")
endif()

foreach(artifact IN LISTS artifacts)
    execute_process(
        COMMAND "${READOBJ}" --file-headers --sections --symbols --relocations --unwind "${artifact}"
        RESULT_VARIABLE readobj_result OUTPUT_VARIABLE readobj_output ERROR_VARIABLE readobj_error)
    if(NOT readobj_result EQUAL 0)
        message(FATAL_ERROR "llvm-readobj rejected ${artifact}: ${readobj_error}")
    endif()
    execute_process(
        COMMAND "${OBJDUMP}" -d "${artifact}"
        RESULT_VARIABLE objdump_result OUTPUT_VARIABLE objdump_output ERROR_VARIABLE objdump_error)
    if(NOT objdump_result EQUAL 0)
        message(FATAL_ERROR "llvm-objdump rejected ${artifact}: ${objdump_error}")
    endif()
    get_filename_component(stem "${artifact}" NAME)
    if(stem MATCHES ".*\\.obj$")
        execute_process(
            COMMAND "${LLD_LINK}" /lib /out:${OUTPUT_DIR}/${stem}.lib "${artifact}"
            RESULT_VARIABLE link_result OUTPUT_VARIABLE link_output ERROR_VARIABLE link_error)
    else()
        execute_process(
            COMMAND "${LD_LLD}" -r -o "${OUTPUT_DIR}/${stem}.linked.o" "${artifact}"
            RESULT_VARIABLE link_result OUTPUT_VARIABLE link_output ERROR_VARIABLE link_error)
    endif()
    if(NOT link_result EQUAL 0)
        message(FATAL_ERROR "linker rejected ${artifact}: ${link_output}${link_error}")
    endif()
endforeach()
file(WRITE "${OUTPUT_DIR}/complete.stamp" "complete\n")

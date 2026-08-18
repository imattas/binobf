if(NOT DEFINED CLANG OR NOT DEFINED CLANGXX OR NOT DEFINED SOURCE_DIR OR NOT DEFINED OUTPUT_DIR)
    message(FATAL_ERROR "RunX86ObjectCorpus requires CLANG, CLANGXX, SOURCE_DIR, and OUTPUT_DIR")
endif()

file(MAKE_DIRECTORY "${OUTPUT_DIR}/coff" "${OUTPUT_DIR}/elf")
execute_process(
    COMMAND "${CLANG}" --version
    RESULT_VARIABLE version_result
    OUTPUT_VARIABLE compiler_version
    ERROR_VARIABLE compiler_version_error
)
if(NOT version_result EQUAL 0)
    message(FATAL_ERROR "clang --version failed: ${compiler_version_error}")
endif()
string(REPLACE "\r\n" "\n" compiler_version "${compiler_version}")
string(REPLACE "\n" " | " compiler_version "${compiler_version}")
file(WRITE "${OUTPUT_DIR}/manifest.txt" "compiler|${compiler_version}\n")

set(optimizations O0 O1 O2 O3 Os Oz)
set(sources corpus.c corpus.cpp corpus.S)
foreach(format IN ITEMS coff elf)
    if(format STREQUAL "coff")
        set(target i686-pc-windows-msvc)
        set(format_flags -gcodeview)
        set(suffix obj)
    else()
        set(target i386-unknown-linux-gnu)
        set(format_flags -fPIC -g)
        set(suffix o)
    endif()
    foreach(optimization IN LISTS optimizations)
        foreach(source IN LISTS sources)
            get_filename_component(extension "${source}" EXT)
            get_filename_component(stem "${source}" NAME_WE)
            if(extension STREQUAL ".cpp")
                set(compiler "${CLANGXX}")
                set(language_flags -std=c++20 -fexceptions -fcxx-exceptions)
                set(language cpp)
            elseif(extension STREQUAL ".c")
                set(compiler "${CLANG}")
                set(language_flags -std=c11 -fcommon)
                set(language c)
            else()
                set(compiler "${CLANG}")
                set(language_flags)
                set(language asm)
            endif()
            set(output "${OUTPUT_DIR}/${format}/${optimization}-${language}.${suffix}")
            set(command
                "${compiler}" "--target=${target}" -m32 -msse2
                -ffunction-sections -fdata-sections "-${optimization}"
                ${format_flags} ${language_flags} -c
                "${SOURCE_DIR}/${source}" -o "${output}"
            )
            execute_process(
                COMMAND ${command}
                RESULT_VARIABLE compile_result
                OUTPUT_VARIABLE compile_output
                ERROR_VARIABLE compile_error
            )
            if(NOT compile_result EQUAL 0)
                string(JOIN " " rendered_command ${command})
                message(FATAL_ERROR
                    "x86 corpus compilation failed (${compile_result}): ${rendered_command}\n"
                    "${compile_output}${compile_error}")
            endif()
            string(JOIN " " rendered_command ${command})
            file(APPEND "${OUTPUT_DIR}/manifest.txt"
                "object|${format}|${optimization}|${language}|${output}|${rendered_command}\n")
        endforeach()
    endforeach()
endforeach()
file(WRITE "${OUTPUT_DIR}/complete.stamp" "complete\n")

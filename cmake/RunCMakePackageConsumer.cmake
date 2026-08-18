if(NOT DEFINED BINOBF_SOURCE_DIR OR NOT DEFINED BINOBF_BUILD_DIR
   OR NOT DEFINED BINOBF_INSTALL_PREFIX OR NOT DEFINED BINOBF_CXX_COMPILER
   OR NOT DEFINED BINOBF_CONFIGURATION)
    message(FATAL_ERROR "CMake package consumer gate is missing required configuration")
endif()

file(REAL_PATH "${BINOBF_BUILD_DIR}" _build_root)
file(REAL_PATH "${BINOBF_INSTALL_PREFIX}" _install_root BASE_DIRECTORY "${_build_root}")
cmake_path(IS_PREFIX _build_root "${_install_root}" NORMALIZE _inside_build)
if(NOT _inside_build OR _install_root STREQUAL _build_root)
    message(FATAL_ERROR "package consumer prefix must be a child of the build tree")
endif()

file(REMOVE_RECURSE "${_install_root}")
execute_process(
    COMMAND "${CMAKE_COMMAND}" --install "${_build_root}" --prefix "${_install_root}"
    RESULT_VARIABLE _install_result
    OUTPUT_VARIABLE _install_output
    ERROR_VARIABLE _install_error
)
if(NOT _install_result EQUAL 0)
    message(FATAL_ERROR "install failed (${_install_result})\n${_install_output}\n${_install_error}")
endif()

set(_consumer_build "${_install_root}/consumer-build")
execute_process(
    COMMAND "${CMAKE_COMMAND}" -S "${BINOBF_SOURCE_DIR}/tests/installed/c_api_package"
        -B "${_consumer_build}" -G Ninja
        "-DCMAKE_PREFIX_PATH=${_install_root}"
        "-DCMAKE_CXX_COMPILER=${BINOBF_CXX_COMPILER}"
        "-DCMAKE_BUILD_TYPE=${BINOBF_CONFIGURATION}"
    RESULT_VARIABLE _configure_result
    OUTPUT_VARIABLE _configure_output
    ERROR_VARIABLE _configure_error
)
if(NOT _configure_result EQUAL 0)
    message(FATAL_ERROR "package consumer configure failed (${_configure_result})\n${_configure_output}\n${_configure_error}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${_consumer_build}" --parallel 2
    RESULT_VARIABLE _build_result
    OUTPUT_VARIABLE _consumer_build_output
    ERROR_VARIABLE _consumer_build_error
)
if(NOT _build_result EQUAL 0)
    message(FATAL_ERROR "package consumer build failed (${_build_result})\n${_consumer_build_output}\n${_consumer_build_error}")
endif()

set(_consumer "${_consumer_build}/binobf-c-api-package-consumer${CMAKE_EXECUTABLE_SUFFIX}")
execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "PATH=${_install_root}/bin;$ENV{PATH}" "${_consumer}"
    RESULT_VARIABLE _run_result
    OUTPUT_VARIABLE _run_output
    ERROR_VARIABLE _run_error
)
if(NOT _run_result EQUAL 0)
    message(FATAL_ERROR "package consumer failed (${_run_result})\n${_run_output}\n${_run_error}")
endif()

message(STATUS "CMake package consumer passed")

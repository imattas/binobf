cmake_minimum_required(VERSION 3.24)
project(binobf_c_api_package_consumer LANGUAGES CXX)

find_package(binobf CONFIG REQUIRED)

add_executable(binobf-c-api-package-consumer
    ../c_api_package_consumer.cpp
)
target_link_libraries(binobf-c-api-package-consumer PRIVATE binobf::c)

cmake_minimum_required(VERSION 3.16)
project(Tlaloc C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_compile_options(-Wall -Wextra -Wnull-dereference -Wwrite-strings)

# Sanitisers for debug builds
if(NOT CMAKE_CROSSCOMPILING)
    add_compile_options(-fsanitize=undefined,address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=undefined,address)
endif()

add_subdirectory(src/lens)
add_subdirectory(src/soul)
add_subdirectory(src/pulse)
add_subdirectory(src/surosam)

enable_testing()
add_subdirectory(tests)

add_executable(lens
    lens.c
    lens.h
)

target_include_directories(lens PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_options(lens PRIVATE -fsanitize=undefined,address)

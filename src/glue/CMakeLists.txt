add_executable(glue
    glue.c
    glue.h
)

target_include_directories(glue PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

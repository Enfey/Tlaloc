add_executable(surosam
    surosam.c
    surosam.h
)

target_include_directories(surosam PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

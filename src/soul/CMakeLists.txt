add_executable(soul
    soul.c
    soul.h
)

target_include_directories(soul PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
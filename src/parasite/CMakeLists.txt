add_executable(parasite
    parasite.c
    parasite.h
)

target_include_directories(parasite PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(meld
    meld.c
    meld.h
)

target_include_directories(meld PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

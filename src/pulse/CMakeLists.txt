add_executable(pulse
    pulse.c
    pulse.h
)

target_include_directories(pulse PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

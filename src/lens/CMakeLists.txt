# Lens static lib for lens CLI + components using lens
add_library(lens_lib STATIC
    lens.c
    lens.h
)
target_include_directories(lens_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(lens
    main.c
)
target_link_libraries(lens PRIVATE lens_lib)
target_include_directories(lens PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

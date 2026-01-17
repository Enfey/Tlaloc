add_executable(meld
    meld.c
    meld.h
    meld_archive.c
    meld_archive.h
    meld_dynlink.c
    meld_dynlink.h
    meld_input.c
    meld_input.h
    meld_layout.c
    meld_layout.h
    meld_output.c
    meld_output.h
    meld_reloc.c
    meld_reloc.h
    meld_section.c
    meld_section.h
    meld_symbol.c
    meld_symbol.h
    meld_synthetic.c
    meld_synthetic.h
)

target_include_directories(meld PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(meld PRIVATE lens_lib)

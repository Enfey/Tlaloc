# Tlaloc test infrastructure inspired by mold's test setup, thank you (because making this work would've taken significantly more time & effort) !
# Tests are named: <arch><bits>-<test_name>
# https://cmake.org/cmake/help/book/mastering-cmake/chapter/Testing%20With%20CMake%20and%20CTest.html
# Should scale reasonably well.

option(TLALOC_ENABLE_QEMU_TESTS "Enable tests on non-native targets" ON)

set(MACHINE ${CMAKE_HOST_SYSTEM_PROCESSOR})

# CMAKE_HOST_SYSTEM_PROCESSOR returns "aarch64" on ARM32 userland
# with ARM64 kernel. Use `cc -dumpmachine` to get the real target triple.
execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpmachine
  RESULT_VARIABLE EXIT_CODE
  OUTPUT_VARIABLE ARCH
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET)

if(NOT EXIT_CODE AND ARCH MATCHES "([^-]+).*")
  set(MACHINE ${CMAKE_MATCH_1})
endif()

if(${MACHINE} MATCHES "amd64")
  set(MACHINE x86_64)
elseif(${MACHINE} MATCHES "i.86")
  set(MACHINE i686)
elseif(${MACHINE} MATCHES "^arm.*")
  set(MACHINE arm)
elseif(${MACHINE} STREQUAL "aarch64")
  set(MACHINE aarch64)
endif()

message(STATUS "Test target machine: ${MACHINE}")

if(TLALOC_ENABLE_QEMU_TESTS)
  # Architectures we support testing
  list(APPEND QEMU_ARCHS arm aarch64)

  # Corresponding toolchain triples
  list(APPEND TRIPLES
    arm-linux-gnueabihf
    arm-linux-gnueabi
    aarch64-linux-gnu)

  foreach(ARCH IN LISTS QEMU_ARCHS)
    find_program(HAS_qemu-${ARCH} qemu-${ARCH})
    if(HAS_qemu-${ARCH})
      message(STATUS "Found qemu-${ARCH}: ${HAS_qemu-${ARCH}}")
    endif()
  endforeach()

  foreach(TRIPLE IN LISTS TRIPLES)
    find_program(HAS_${TRIPLE}-gcc ${TRIPLE}-gcc)
    if(HAS_${TRIPLE}-gcc)
      message(STATUS "Found ${TRIPLE}-gcc: ${HAS_${TRIPLE}-gcc}")
    endif()
  endforeach()
endif()

function(add_target ARCH BITS TRIPLE)
  set(QEMU_ARCH ${ARGV3}) 

  if(NOT QEMU_ARCH)
    set(QEMU_ARCH ${ARCH})
  endif()

  if(${ARCH} STREQUAL ${MACHINE})
    set(IS_NATIVE 1)
  endif()

  # Determine if lens itself needs QEMU to run
  # (when lens is cross-compiled for a different architecture)
  if(CMAKE_CROSSCOMPILING)
    set(LENS_NEEDS_QEMU 1)
  endif()

  # Find all generic tests (not arch-specific)
  file(GLOB ALL_TESTS RELATIVE ${CMAKE_CURRENT_LIST_DIR} CONFIGURE_DEPENDS
    "lens/*.sh")

  # Exclude arch-specific tests from generic tests
  list(FILTER ALL_TESTS EXCLUDE REGEX "^lens/arch-")

  # Find arch-specific tests
  file(GLOB ARCH_TESTS RELATIVE ${CMAKE_CURRENT_LIST_DIR} CONFIGURE_DEPENDS
    "lens/arch-${ARCH}${BITS}-*.sh")

  list(APPEND TESTS ${ALL_TESTS} ${ARCH_TESTS})

  foreach(TEST IN LISTS TESTS)
    # lens/foo.sh -> foo
    get_filename_component(TEST_BASENAME ${TEST} NAME_WE)
    string(REGEX REPLACE "^arch-${ARCH}${BITS}-" "" TEST_BASENAME "${TEST_BASENAME}")

    set(TESTNAME "${ARCH}${BITS}-${TEST_BASENAME}")

    add_test(NAME ${TESTNAME}
      COMMAND bash -x ${CMAKE_CURRENT_LIST_DIR}/${TEST}
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

    set_property(TEST ${TESTNAME} APPEND PROPERTY ENVIRONMENT
      "MACHINE=${MACHINE}"
      "ARCH=${ARCH}"
      "BITS=${BITS}"
      "LENS=${CMAKE_BINARY_DIR}/bin/lens"
      "TRIPLE=${TRIPLE}")

    # Set QEMU_LENS if lens itself was cross-compiled
    if(LENS_NEEDS_QEMU)
      set(QEMU_SYSROOT "/usr/${TRIPLE}")
      set_property(TEST ${TESTNAME} APPEND PROPERTY ENVIRONMENT
        "QEMU_LENS=qemu-${QEMU_ARCH} -L ${QEMU_SYSROOT}")
    endif()

    if(IS_NATIVE)
      # lens target arch matches test binary arch
      set_property(TEST ${TESTNAME} APPEND PROPERTY ENVIRONMENT
        "CC=${CMAKE_C_COMPILER}")
      set_property(TEST ${TESTNAME} APPEND PROPERTY SKIP_REGULAR_EXPRESSION
        "skipped")
    else()
      # need cross-compiler to create test binaries
      set_property(TEST ${TESTNAME} APPEND PROPERTY ENVIRONMENT
        "CC=${TRIPLE}-gcc"
        "READELF=${TRIPLE}-readelf"
        "OBJDUMP=${TRIPLE}-objdump")
    endif()
  endforeach()
endfunction()

# Add ARM32 tests
if(${MACHINE} STREQUAL "arm")
  add_target(arm 32 ${CMAKE_C_COMPILER})
elseif(HAS_qemu-arm)
  if(HAS_arm-linux-gnueabihf-gcc)
    add_target(arm 32 arm-linux-gnueabihf)
  elseif(HAS_arm-linux-gnueabi-gcc)
    add_target(arm 32 arm-linux-gnueabi)
  endif()
endif()

# Add ARM64 tests (when I add support to lens that is)
# if(${MACHINE} STREQUAL "aarch64")
#   add_target(aarch64 64 ${CMAKE_C_COMPILER})
# elseif(HAS_qemu-aarch64 AND HAS_aarch64-linux-gnu-gcc)
#   add_target(aarch64 64 aarch64-linux-gnu)
# endif()

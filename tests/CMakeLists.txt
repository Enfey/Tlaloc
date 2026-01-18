# Tlaloc test infrastructure inspired by mold's test setup, thank you (because making this work would've taken significantly more time & effort) !
# Tests are named: <component>-<test_name> or <component>-<arch><bits>-<test_name>
# https://cmake.org/cmake/help/book/mastering-cmake/chapter/Testing%20With%20CMake%20and%20CTest.html
# Should scale reasonably well.
#   ctest                        - Run tests
#   ctest -R "^lens-"            - Run lens tests
#   ctest -R "^meld-"            - Run meld tests
#   ctest -R "arm32"             - Run ARM32 tests
#   ctest -L lens                - Run tests with 'lens' label

option(TLALOC_ENABLE_QEMU_TESTS "Enable tests on non-native targets" ON)

set(TLALOC_TEST_COMPONENTS lens meld)

set(MACHINE ${CMAKE_HOST_SYSTEM_PROCESSOR})

# CMAKE_HOST_SYSTEM_PROCESSOR returns "aarch64" on ARM32 userland
# with ARM64 kernel. Use `cc -dumpmachine` to get the real target triple.
execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpmachine
  RESULT_VARIABLE EXIT_CODE
  OUTPUT_VARIABLE COMPILER_TARGET_TRIPLE
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET)

if(NOT EXIT_CODE AND COMPILER_TARGET_TRIPLE MATCHES "([^-]+).*")
  set(MACHINE ${CMAKE_MATCH_1})
endif()

if(${MACHINE} MATCHES "^arm.*")
  set(MACHINE arm)
elseif(${MACHINE} STREQUAL "aarch64")
  set(MACHINE aarch64)
endif()

# We use NATIVE_TRIPLE (from -dumpmachine) instead of CMAKE_C_COMPILER,
# CMAKE_C_COMPILER is a full path e.g., /usr/bin/arm-linux-gnueabi-gcc
# which would break: /usr/${TRIPLE} -> /usr//usr/bin/...
if(COMPILER_TARGET_TRIPLE)
  set(NATIVE_TRIPLE ${COMPILER_TARGET_TRIPLE})
else()
  set(NATIVE_TRIPLE "")
endif()

message(STATUS "Test target machine: ${MACHINE}")
message(STATUS "Compiler target triple: ${NATIVE_TRIPLE}")

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

# Registers a single test for a component
#
# Args(non-obvious):
#   COMPONENT 
#   TEST_PATH 
#   TESTNAME   - Full test name for ctest
#   ARCH       - Target architecture (arm, aarch64)
#   BITS       - Bit width (32, 64)
#   TRIPLE     - Toolchain triple
#   IS_NATIVE  - Whether target matches host
#   NEEDS_QEMU - Whether component binary needs QEMU to run (was cross-compiled )
#
function(register_test COMPONENT TEST_PATH TESTNAME ARCH BITS TRIPLE IS_NATIVE NEEDS_QEMU)
  set(QEMU_ARCH ${ARCH})

  add_test(NAME ${TESTNAME}
    COMMAND bash -x ${CMAKE_CURRENT_LIST_DIR}/${TEST_PATH}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

  # Add component label for filtering (ctest -L lens)
  set_property(TEST ${TESTNAME} PROPERTY LABELS ${COMPONENT})

  # Common env vars
  set_property(TEST ${TESTNAME} APPEND PROPERTY ENVIRONMENT
    "MACHINE=${MACHINE}"
    "ARCH=${ARCH}"
    "BITS=${BITS}"
    "TRIPLE=${TRIPLE}"
    "${COMPONENT}=${CMAKE_BINARY_DIR}/bin/${COMPONENT}")

  string(TOUPPER ${COMPONENT} COMPONENT_UPPER)
  set_property(TEST ${TESTNAME} APPEND PROPERTY ENVIRONMENT
    "${COMPONENT_UPPER}=${CMAKE_BINARY_DIR}/bin/${COMPONENT}")

  if(NEEDS_QEMU)
    set(QEMU_SYSROOT "/usr/${TRIPLE}")
    set_property(TEST ${TESTNAME} APPEND PROPERTY ENVIRONMENT
      "QEMU_${COMPONENT_UPPER}=qemu-${QEMU_ARCH} -L ${QEMU_SYSROOT}")
  endif()

  if(IS_NATIVE)
    set_property(TEST ${TESTNAME} APPEND PROPERTY ENVIRONMENT
      "CC=${CMAKE_C_COMPILER}"
      "READELF=readelf"
      "OBJDUMP=objdump")
    set_property(TEST ${TESTNAME} APPEND PROPERTY SKIP_REGULAR_EXPRESSION
      "skipped")
  else()
    set_property(TEST ${TESTNAME} APPEND PROPERTY ENVIRONMENT
      "CC=${TRIPLE}-gcc"
      "READELF=${TRIPLE}-readelf"
      "OBJDUMP=${TRIPLE}-objdump")
  endif()
endfunction()

function(add_component_arch_tests COMPONENT ARCH BITS TRIPLE)
  if(${ARCH} STREQUAL ${MACHINE})
    set(IS_NATIVE 1)
  else()
    set(IS_NATIVE 0)
  endif()

  if(CMAKE_CROSSCOMPILING)
    set(NEEDS_QEMU 1)
  else()
    set(NEEDS_QEMU 0)
  endif()

  # Pattern: arch-arm32-*.sh or arch-aarch64-*.sh
  if(${ARCH} STREQUAL "arm")
    set(ARCH_PATTERN "arch-arm${BITS}")
  else()
    set(ARCH_PATTERN "arch-${ARCH}")
  endif()

  file(GLOB ARCH_TESTS RELATIVE ${CMAKE_CURRENT_LIST_DIR} CONFIGURE_DEPENDS
    "${COMPONENT}/${ARCH_PATTERN}-*.sh")

  foreach(TEST IN LISTS ARCH_TESTS)
    # lens/arch-arm32-thumb.sh -> thumb
    get_filename_component(TEST_BASENAME ${TEST} NAME_WE)
    string(REGEX REPLACE "^${ARCH_PATTERN}-" "" TEST_BASENAME "${TEST_BASENAME}")

    # Test name: lens-arm32-thumb
    set(TESTNAME "${COMPONENT}-${ARCH_PATTERN}-${TEST_BASENAME}")
    string(REGEX REPLACE "-arch-" "-" TESTNAME "${TESTNAME}")

    register_test(${COMPONENT} ${TEST} ${TESTNAME} ${ARCH} ${BITS} ${TRIPLE} ${IS_NATIVE} ${NEEDS_QEMU})
  endforeach()
endfunction()

function(add_component_generic_tests COMPONENT ARCH BITS TRIPLE)
  if(${ARCH} STREQUAL ${MACHINE})
    set(IS_NATIVE 1)
  else()
    set(IS_NATIVE 0)
  endif()

  if(CMAKE_CROSSCOMPILING)
    set(NEEDS_QEMU 1)
  else()
    set(NEEDS_QEMU 0)
  endif()

  file(GLOB GENERIC_TESTS RELATIVE ${CMAKE_CURRENT_LIST_DIR} CONFIGURE_DEPENDS
    "${COMPONENT}/*.sh")
  list(FILTER GENERIC_TESTS EXCLUDE REGEX "^${COMPONENT}/arch-")

  foreach(TEST IN LISTS GENERIC_TESTS)
    get_filename_component(TEST_BASENAME ${TEST} NAME_WE)

    # Test name e.g., lens-pie etc.
    set(TESTNAME "${COMPONENT}-${TEST_BASENAME}")

    register_test(${COMPONENT} ${TEST} ${TESTNAME} ${ARCH} ${BITS} ${TRIPLE} ${IS_NATIVE} ${NEEDS_QEMU})
  endforeach()
endfunction()

macro(register_all_arch_tests ARCH BITS TRIPLE)
  foreach(COMPONENT IN LISTS TLALOC_TEST_COMPONENTS)
    if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/${COMPONENT}")
      add_component_arch_tests(${COMPONENT} ${ARCH} ${BITS} ${TRIPLE})
    endif()
  endforeach()
endmacro()

macro(register_all_generic_tests ARCH BITS TRIPLE)
  foreach(COMPONENT IN LISTS TLALOC_TEST_COMPONENTS)
    if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/${COMPONENT}")
      add_component_generic_tests(${COMPONENT} ${ARCH} ${BITS} ${TRIPLE})
    endif()
  endforeach()
endmacro()


if(${MACHINE} STREQUAL "arm")
  register_all_arch_tests(arm 32 ${NATIVE_TRIPLE})
elseif(HAS_qemu-arm)
  if(HAS_arm-linux-gnueabihf-gcc)
    register_all_arch_tests(arm 32 arm-linux-gnueabihf)
  elseif(HAS_arm-linux-gnueabi-gcc)
    register_all_arch_tests(arm 32 arm-linux-gnueabi)
  endif()
endif()

if(${MACHINE} STREQUAL "aarch64")
  register_all_arch_tests(aarch64 64 ${NATIVE_TRIPLE})
elseif(HAS_qemu-aarch64 AND HAS_aarch64-linux-gnu-gcc)
  register_all_arch_tests(aarch64 64 aarch64-linux-gnu)
endif()

message(STATUS "Registered arch-specific tests for ARM32 and AArch64")

if(${MACHINE} STREQUAL "aarch64")
  register_all_generic_tests(aarch64 64 ${NATIVE_TRIPLE})
elseif(HAS_qemu-aarch64 AND HAS_aarch64-linux-gnu-gcc)
  register_all_generic_tests(aarch64 64 aarch64-linux-gnu)
elseif(${MACHINE} STREQUAL "arm")
  register_all_generic_tests(arm 32 ${NATIVE_TRIPLE})
elseif(HAS_qemu-arm)
  if(HAS_arm-linux-gnueabihf-gcc)
    register_all_generic_tests(arm 32 arm-linux-gnueabihf)
  elseif(HAS_arm-linux-gnueabi-gcc)
    register_all_generic_tests(arm 32 arm-linux-gnueabi)
  endif()
endif()

message(STATUS "Test components: ${TLALOC_TEST_COMPONENTS}")


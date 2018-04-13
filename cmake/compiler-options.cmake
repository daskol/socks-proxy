#   compiler-options.cmake
#
#   Setup build types and compiler options

# Setup standard and common compiler options.

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CUTT_CXX_FLAGS "-Wall")

    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS "7.0.0")
        message(FATAL_ERROR "Not supported GNU compiler older than v7.0.0.")
    else()
        set(CMAKE_CXX_STANDARD 17)
    endif()
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CUTT_CXX_FLAGS "-Wall -Wextra -Wpedantic")

    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS "5.0.0")
        message(FATAL_ERROR "Not supported Clang compiler older than v5.0.0.")
    else ()
        set(CMAKE_CXX_STANDARD 17)
    endif()
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Intel")
    message(WARNING "Only limitted support provided for Intel compiler.")
    set(CUTT_CXX_FLAGS "-Wall")

    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS "17.0.0")
        message(FATAL_ERROR "Not supported Intel compiler older than v17.0.0.")
    else ()
        set(CMAKE_CXX_STANDARD 14)
    endif()
else ()
    message(FATAL_ERROR "Not supported compiler ${CMAKE_CXX_COMPILER_ID}.")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CUTT_CXX_FLAGS}")
set(SAN_FLAGS "-g -fno-omit-frame-pointer")

# ASAN Build Type
# TODO: append -mllvm and -asan-stack=0 for clang

set(CMAKE_C_FLAGS_ASAN
    "${CMAKE_C_FLAGS} ${SAN_FLAGS} -fsanitize=address,undefined"
    CACHE STRING "C compiler flags in ASAN build."
    FORCE)

set(CMAKE_CXX_FLAGS_ASAN
    "${CMAKE_CXX_FLAGS} ${SAN_FLAGS} -fsanitize=address,undefined"
    CACHE STRING "CXX compiler flags in ASAN build."
    FORCE)

set(CMAKE_EXE_LINKER_FLAGS_ASAN
    "${CMAKE_EXE_LINKER_FLAGS} ${SAN_FLAGS} -fsanitize=address,undefined -pie"
    CACHE STRING "Linker flags in ASAN build."
    FORCE)

# TSAN Build Type

set(CMAKE_C_FLAGS_TSAN "${CMAKE_C_FLAGS} ${SAN_FLAGS} -fsanitize=thread"
    CACHE STRING "C compiler flags in TSAN build."
    FORCE)

set(CMAKE_CXX_FLAGS_TSAN "${CMAKE_CXX_FLAGS} ${SAN_FLAGS} -fsanitize=thread"
    CACHE STRING "CXX compiler flags in TSAN build."
    FORCE)

set(CMAKE_EXE_LINKER_FLAGS_TSAN
    "${CMAKE_EXE_LINKER_FLAGS} ${SAN_FLAGS} -fsanitize=thread -pie"
    CACHE STRING "Linker flags in TSAN build."
    FORCE)

# MSAN Build Type

set(CMAKE_C_FLAGS_MSAN "${CMAKE_C_FLAGS} ${SAN_FLAGS} -fsanitize=memory"
    CACHE STRING "C compiler flags in MSAN build."
    FORCE)

set(CMAKE_CXX_FLAGS_MSAN "${CMAKE_CXX_FLAGS} ${SAN_FLAGS} -fsanitize=memory"
    CACHE STRING "CXX compiler flags in MSAN build."
    FORCE)

set(CMAKE_EXE_LINKER_FLAGS_MSAN
    "${CMAKE_EXE_LINKER_FLAGS} ${SAN_FLAGS}-fsanitize=memory -pie"
    CACHE STRING "Linker flags in MSAN build."
    FORCE)

# DEBUG Build Type

set(CMAKE_C_FLAGS_DEBUG "-O0 ${SAN_FLAGS}"
    CACHE STRING "C compiler flags in Debug build."
    FORCE)

set(CMAKE_CXX_FLAGS_DEBUG "-O0 ${SAN_FLAGS}"
    CACHE STRING "CXX compiler flags in Debug build."
    FORCE)

# RELEASE Build Type

set(CMAKE_C_FLAGS_RELEASE "-O2"
    CACHE STRING "C compiler flags in Release build."
    FORCE)

set(CMAKE_CXX_FLAGS_RELEASE "-O2"
    CACHE STRING "CXX compiler flags in Release build."
    FORCE)

# RELWITHDEBINFO Build Type

set(CMAKE_C_FLAGS_RELWITHDEBINFO "-g -O2"
    CACHE STRING "C compiler flags in RelWithDebInfo build."
    FORCE)

set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-g -O2"
    CACHE STRING "CXX compiler flags in RelWithDebInfo build."
    FORCE)

# CMakeLists.txt - cmake build for secp256k1
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/bcoin-org/bcrypto

cmake_minimum_required(VERSION 3.4)
project(secp256k1 LANGUAGES C)

include(CheckCCompilerFlag)
include(TestBigEndian)

set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 90)

option(SECP256K1_ENABLE_ASM "Use inline x86-64 assembly if available" ON)
option(SECP256K1_ENABLE_DEBUG "Enable debug build" OFF)
option(SECP256K1_ENABLE_INT128 "Use __int128 if available" ON)

if(MSVC)
  # CMake defaults for windows:
  #
  #   CMAKE_C_FLAGS: /DWIN32 /D_WINDOWS /W3
  #   CMAKE_C_FLAGS_RELEASE: /MD /O2 /Ob2 /DNDEBUG
  #   CMAKE_C_FLAGS_DEBUG: /MDd /Zi /Ob0 /Od /RTC1
  #
  # For this reason, we don't mess with optimization
  # levels here.  We assume the person building will
  # pass `--config [build-type]` when building. e.g.
  #
  #   $ cmake --build . --config Release
  set(CMAKE_C_FLAGS_DEBUG "/MDd /Zi /O2 /Ob2")
  check_c_compiler_flag(/wd4244 SECP256K1_HAS_WCONV_DATA_LOSS1)
  check_c_compiler_flag(/wd4267 SECP256K1_HAS_WCONV_DATA_LOSS2)
  check_c_compiler_flag(/wd4334 SECP256K1_HAS_W64BIT_SHIFT)
else()
  # CMake defaults for unix:
  #
  #   CMAKE_C_FLAGS:
  #   CMAKE_C_FLAGS_DEBUG: -g
  #   CMAKE_C_FLAGS_RELEASE: -O3 -NDEBUG
  #
  # For Makefiles, -DCMAKE_BUILD_TYPE=[build-type]
  # must be passed on the command line for any of
  # the defaults to have an effect. We assume that
  # CMAKE_BUILD_TYPE is empty and pick debug and
  # optimization flags ourselves.
  set(CMAKE_C_FLAGS_DEBUG "-g")
  set(CMAKE_C_FLAGS_RELEASE "")
  check_c_compiler_flag(-g SECP256K1_HAS_G)
  check_c_compiler_flag(-pedantic SECP256K1_HAS_PEDANTIC)
  check_c_compiler_flag(-Wall SECP256K1_HAS_WALL)
  check_c_compiler_flag(-Wextra SECP256K1_HAS_WEXTRA)
  check_c_compiler_flag(-Wcast-align SECP256K1_HAS_WCAST_ALIGN)
  check_c_compiler_flag(-Wnested-externs SECP256K1_HAS_WNESTED_EXTERNS)
  check_c_compiler_flag(-Wno-implicit-fallthrough SECP256K1_HAS_WFALLTHROUGH)
  check_c_compiler_flag(-Wno-long-long SECP256K1_HAS_WLONGLONG)
  check_c_compiler_flag(-Wno-nonnull-compare SECP256K1_HAS_WNONNULL_COMPARE)
  check_c_compiler_flag(-Wno-overlength-strings SECP256K1_HAS_WOVERLENGTH)
  check_c_compiler_flag(-Wno-unused-function SECP256K1_HAS_WUNUSED_FUNCTION)
  check_c_compiler_flag(-Wshadow SECP256K1_HAS_WSHADOW)
  check_c_compiler_flag(-Wstrict-prototypes SECP256K1_HAS_WSTRICT_PROTOTYPES)
  check_c_compiler_flag(-O3 SECP256K1_HAS_O3)
endif()

check_c_source_compiles([=[
#include <stdint.h>
#if !defined(__amd64__) && !defined(__x86_64__)
#  error "not an x64 platform"
#endif
int main(void) {
  uint32_t stream[8], state[8];
  __asm__ __volatile__(
    "movups (%%rsi), %%xmm0\\n"
    "movups 16(%%rsi), %%xmm1\\n"
    "pxor %%xmm1, %%xmm0\\n"
    "movups %%xmm0,(%%rdi)\\n"
    "movups %%xmm1,16(%%rdi)\\n"
    :
    : "D" (stream), "S" (state)
    : "xmm0", "xmm1", "cc", "memory"
  );
  return 0;
}
]=] SECP256K1_HAS_ASM_X64)

check_c_source_compiles([=[
typedef char check_64bit_t[sizeof(void *) == 8 ? 1 : -1];
typedef signed __int128 int128_t;
typedef unsigned __int128 uint128_t;
int main(void) {
  uint128_t r;
  r = ((uint128_t)1) << 64;
  r *= 113;
  r >>= 65;
  return r & 1;
}
]=] SECP256K1_HAS_INT128)

TEST_BIG_ENDIAN(SECP256K1_BIGENDIAN)

set(secp256k1_defines
    USE_NUM_NONE=1
    USE_FIELD_INV_BUILTIN=1
    USE_SCALAR_INV_BUILTIN=1
    ECMULT_WINDOW_SIZE=15
    ECMULT_GEN_PREC_BITS=4
    USE_ENDOMORPHISM=1
    ENABLE_MODULE_ECDH=1
    ENABLE_MODULE_ELLIGATOR=1
    ENABLE_MODULE_EXTRA=1
    ENABLE_MODULE_RECOVERY=1
    ENABLE_MODULE_SCHNORRLEG=1)

set(SECP256K1_64BIT OFF)

if(SECP256K1_ENABLE_ASM AND SECP256K1_HAS_ASM_X64)
  list(APPEND secp256k1_defines USE_ASM_X86_64=1)
  set(SECP256K1_64BIT ON)
endif()

if(SECP256K1_ENABLE_DEBUG)
  if(SECP256K1_HAS_G)
    list(APPEND secp256k1_cflags -g)
  endif()
endif()

if(SECP256K1_ENABLE_INT128 AND SECP256K1_HAS_INT128)
  list(APPEND secp256k1_defines HAVE___INT128=1)
  set(SECP256K1_64BIT ON)
endif()

if(SECP256K1_BIGENDIAN)
  list(APPEND secp256k1_defines WORDS_BIGENDIAN=1)
endif()

if(SECP256K1_64BIT)
  list(APPEND secp256k1_defines USE_FIELD_5X52=1)
  list(APPEND secp256k1_defines USE_SCALAR_4X64=1)
else()
  list(APPEND secp256k1_defines USE_FIELD_10X26=1)
  list(APPEND secp256k1_defines USE_SCALAR_8X32=1)
endif()

if(MSVC)
  if(SECP256K1_HAS_WCONV_DATA_LOSS1)
    list(APPEND secp256k1_cflags /wd4244)
  endif()
  if(SECP256K1_HAS_WCONV_DATA_LOSS2)
    list(APPEND secp256k1_cflags /wd4267)
  endif()
  if(SECP256K1_HAS_W64BIT_SHIFT)
    list(APPEND secp256k1_cflags /wd4334)
  endif()
else()
  if(SECP256K1_HAS_PEDANTIC)
    list(APPEND secp256k1_cflags -pedantic)
  endif()
  if(SECP256K1_HAS_WALL)
    list(APPEND secp256k1_cflags -Wall)
  endif()
  if(SECP256K1_HAS_WEXTRA)
    list(APPEND secp256k1_cflags -Wextra)
  endif()
  if(SECP256K1_HAS_WCAST_ALIGN)
    list(APPEND secp256k1_cflags -Wcast-align)
  endif()
  if(SECP256K1_HAS_WNESTED_EXTERNS)
    list(APPEND secp256k1_cflags -Wnested-externs)
  endif()
  if(SECP256K1_HAS_WFALLTHROUGH)
    list(APPEND secp256k1_cflags -Wno-implicit-fallthrough)
  endif()
  if(SECP256K1_HAS_WLONGLONG)
    list(APPEND secp256k1_cflags -Wno-long-long)
  endif()
  if(SECP256K1_HAS_WNONNULL_COMPARE)
    list(APPEND secp256k1_cflags -Wno-nonnull-compare)
  endif()
  if(SECP256K1_HAS_WOVERLENGTH)
    list(APPEND secp256k1_cflags -Wno-overlength-strings)
  endif()
  if(SECP256K1_HAS_WUNUSED_FUNCTION)
    list(APPEND secp256k1_cflags -Wno-unused-function)
  endif()
  if(SECP256K1_HAS_WSHADOW)
    list(APPEND secp256k1_cflags -Wshadow)
  endif()
  if(SECP256K1_HAS_WSTRICT_PROTOTYPES)
    list(APPEND secp256k1_cflags -Wstrict-prototypes)
  endif()
  if(SECP256K1_HAS_O3)
    list(APPEND secp256k1_cflags -O3)
  endif()
endif()

set(secp256k1_sources
    contrib/lax_der_parsing.c
    src/secp256k1.c)

set(secp256k1_includes
    ${PROJECT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src)

add_library(secp256k1_o OBJECT ${secp256k1_sources})
target_compile_definitions(secp256k1_o PRIVATE ${secp256k1_defines}
                                               SECP256K1_BUILD)
target_compile_options(secp256k1_o PRIVATE ${secp256k1_cflags})
target_include_directories(secp256k1_o PRIVATE ${PROJECT_SOURCE_DIR}/include)
set_property(TARGET secp256k1_o PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library(secp256k1 SHARED $<TARGET_OBJECTS:secp256k1_o>)
target_compile_definitions(secp256k1 PRIVATE ${secp256k1_defines})
target_compile_options(secp256k1 PRIVATE ${secp256k1_cflags})
target_include_directories(secp256k1 PRIVATE ${secp256k1_includes})

add_library(secp256k1_static STATIC $<TARGET_OBJECTS:secp256k1_o>)
target_compile_definitions(secp256k1_static PRIVATE ${secp256k1_defines})
target_compile_options(secp256k1_static PRIVATE ${secp256k1_cflags})
target_include_directories(secp256k1_static PRIVATE ${secp256k1_includes})

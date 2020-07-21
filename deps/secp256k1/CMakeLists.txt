# CMakeLists.txt - cmake build for secp256k1
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/bcoin-org/bcrypto

cmake_minimum_required(VERSION 3.4)
project(libsecp256k1 LANGUAGES C)

include(../../cmake/AppendCCompilerFlag.cmake)
include(TestBigEndian)

set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 90)

option(SECP256K1_ENABLE_ASM "Use inline x86-64 assembly if available" ON)
option(SECP256K1_ENABLE_INT128 "Use __int128 if available" ON)

set(secp256k1_cflags)

if(MSVC)
  append_c_compiler_flag(secp256k1_cflags /wd4244)
  append_c_compiler_flag(secp256k1_cflags /wd4267)
  append_c_compiler_flag(secp256k1_cflags /wd4334)
else()
  append_c_compiler_flag(secp256k1_cflags -pedantic)
  append_c_compiler_flag(secp256k1_cflags -Wall)
  append_c_compiler_flag(secp256k1_cflags -Wextra)
  append_c_compiler_flag(secp256k1_cflags -Wcast-align)
  append_c_compiler_flag(secp256k1_cflags -Wnested-externs)
  append_c_compiler_flag(secp256k1_cflags -Wno-implicit-fallthrough)
  append_c_compiler_flag(secp256k1_cflags -Wno-long-long)
  append_c_compiler_flag(secp256k1_cflags -Wno-nonnull-compare)
  append_c_compiler_flag(secp256k1_cflags -Wno-overlength-strings)
  append_c_compiler_flag(secp256k1_cflags -Wno-unused-function)
  append_c_compiler_flag(secp256k1_cflags -Wshadow)
  append_c_compiler_flag(secp256k1_cflags -Wstrict-prototypes)
endif()

check_c_source_compiles([=[
#include <stdint.h>
int main(void) {
  uint64_t a = 11, tmp;
  __asm__ __volatile__("movq $0x100000000,%1; mulq %%rsi"
                       : "+a" (a) : "S" (tmp) : "cc", "%rdx");
  return 0;
}
]=] SECP256K1_HAS_ASM_X64)

check_type_size("__int128" SECP256K1_HAS_INT128)

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

set(SECP256K1_USE_ASM OFF)
set(SECP256K1_USE_INT128 OFF)

if(SECP256K1_ENABLE_ASM AND SECP256K1_HAS_ASM_X64)
  list(APPEND secp256k1_defines USE_ASM_X86_64=1)
  set(SECP256K1_USE_ASM ON)
endif()

if(SECP256K1_ENABLE_INT128 AND SECP256K1_HAS_INT128)
  list(APPEND secp256k1_defines HAVE___INT128=1)
  set(SECP256K1_USE_INT128 ON)
endif()

if(SECP256K1_BIGENDIAN)
  list(APPEND secp256k1_defines WORDS_BIGENDIAN=1)
endif()

if(SECP256K1_USE_ASM OR SECP256K1_USE_INT128)
  list(APPEND secp256k1_defines USE_FIELD_5X52=1)
else()
  list(APPEND secp256k1_defines USE_FIELD_10X26=1)
endif()

if(SECP256K1_USE_INT128)
  list(APPEND secp256k1_defines USE_SCALAR_4X64=1)
else()
  list(APPEND secp256k1_defines USE_SCALAR_8X32=1)
endif()

add_node_library(secp256k1 STATIC contrib/lax_der_parsing.c src/secp256k1.c)
target_compile_definitions(secp256k1 PRIVATE ${secp256k1_defines})
target_compile_options(secp256k1 PRIVATE ${secp256k1_cflags})
target_include_directories(secp256k1 PRIVATE ${PROJECT_SOURCE_DIR}
                                             ${PROJECT_SOURCE_DIR}/include
                                             ${PROJECT_SOURCE_DIR}/src)

# CMakeLists.txt - cmake build for libtorsion
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/bcoin-org/libtorsion

cmake_minimum_required(VERSION 3.4)
project(libtorsion LANGUAGES C)

include(../../cmake/AppendCCompilerFlag.cmake)

set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 90)
set(CMAKE_OSX_DEPLOYMENT_TARGET 10.7)

option(TORSION_ENABLE_ASM "Use inline x86-64 assembly if available" ON)
option(TORSION_ENABLE_CRT "Enable chinese remainder theorem for RSA" OFF)
option(TORSION_ENABLE_DEBUG "Enable debug build" OFF)
option(TORSION_ENABLE_INT128 "Use __int128 if available" ON)
option(TORSION_ENABLE_LIBSECP256K1 "Use libsecp256k1 field element backend" OFF)
option(TORSION_ENABLE_PTHREAD "Use pthread as a fallback for TLS" ON)
option(TORSION_ENABLE_TLS "Enable TLS" ON)
option(TORSION_ENABLE_VERIFY "Enable scalar bounds checks" OFF)

set(torsion_cflags)

if(MSVC)
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /DTORSION_DEBUG")

  append_c_compiler_flag(torsion_cflags /wd4146)
  append_c_compiler_flag(torsion_cflags /wd4244)
  append_c_compiler_flag(torsion_cflags /wd4267)
  append_c_compiler_flag(torsion_cflags /wd4334)
else()
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DTORSION_DEBUG")

  append_c_compiler_flag(torsion_cflags -pedantic)
  append_c_compiler_flag(torsion_cflags -Wall)
  append_c_compiler_flag(torsion_cflags -Wextra)
  append_c_compiler_flag(torsion_cflags -Wcast-align)
  append_c_compiler_flag(torsion_cflags -Wno-implicit-fallthrough)
  append_c_compiler_flag(torsion_cflags -Wno-long-long)
  append_c_compiler_flag(torsion_cflags -Wno-overlength-strings)
  append_c_compiler_flag(torsion_cflags -Wshadow)
endif()

check_c_source_compiles([=[
int main(void) {
  unsigned char ptr[32];
  int x = 0;
  __asm__ ("" : "+r" (x) ::);
  __asm__ __volatile__("" :: "r" (ptr) : "memory");
  return x;
}
]=] TORSION_HAS_ASM)

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
]=] TORSION_HAS_ASM_X64)

check_c_source_compiles([=[
typedef char check_64bit_t[sizeof(void *) == 8 ? 1 : -1];
typedef signed __int128 int128_t;
typedef unsigned __int128 uint128_t;
int main(void) {
  uint128_t r = 1;
  r <<= 64;
  r *= 113;
  r >>= 65;
  return r & 1;
}
]=] TORSION_HAS_INT128)

check_c_source_compiles([=[
#if defined(_WIN32) && !defined(__MINGW32__)
#  define TLS __declspec(thread)
#else
#  define TLS __thread
#endif
static TLS int value;
int main(void) {
  value = 1;
  return 0;
}
]=] TORSION_HAS_TLS)

set(TORSION_HAS_THREADS OFF)

if(WIN32)
  set(TORSION_HAS_THREADS ON)
else()
  set(THREADS_PREFER_PTHREAD_FLAG ON)
  find_package(Threads)
  if(CMAKE_USE_PTHREADS_INIT)
    set(TORSION_HAS_THREADS ON)
  endif()
endif()

set(torsion_defines)

list(APPEND torsion_defines TORSION_HAVE_CONFIG)

if(WIN32)
  list(APPEND torsion_defines _WIN32_WINNT=0x0600)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  list(APPEND torsion_defines _POSIX_C_SOURCE=200112)
endif()

if(TORSION_ENABLE_ASM AND TORSION_HAS_ASM)
  list(APPEND torsion_defines TORSION_HAVE_ASM)
endif()

if(TORSION_ENABLE_ASM AND TORSION_HAS_ASM_X64)
  list(APPEND torsion_defines TORSION_HAVE_ASM_X64)
endif()

if(TORSION_ENABLE_CRT)
  list(APPEND torsion_defines TORSION_USE_CRT)
endif()

if(TORSION_ENABLE_DEBUG)
  list(APPEND torsion_defines TORSION_DEBUG)
endif()

if(TORSION_ENABLE_INT128 AND TORSION_HAS_INT128)
  list(APPEND torsion_defines TORSION_HAVE_INT128)
endif()

if(TORSION_ENABLE_LIBSECP256K1)
  list(APPEND torsion_defines TORSION_USE_LIBSECP256K1)
endif()

if(TORSION_ENABLE_TLS AND TORSION_HAS_TLS)
  list(APPEND torsion_defines TORSION_HAVE_TLS)
endif()

if(TORSION_ENABLE_VERIFY)
  list(APPEND torsion_defines TORSION_VERIFY)
endif()

set(torsion_sources
    src/aead.c
    src/asn1.c
    src/cipher.c
    src/ecc.c
    src/encoding.c
    src/entropy/env.c
    src/entropy/hw.c
    src/entropy/sys.c
    src/drbg.c
    src/dsa.c
    src/hash.c
    src/ies.c
    src/internal.c
    src/kdf.c
    src/mac.c
    src/mpi.c
    src/rand.c
    src/rsa.c
    src/stream.c
    src/util.c)

set(torsion_libs)

if(TORSION_ENABLE_PTHREAD AND TORSION_HAS_THREADS AND NOT WIN32)
  if(NOT TORSION_ENABLE_TLS OR NOT TORSION_HAS_TLS)
    list(APPEND torsion_defines TORSION_HAVE_PTHREAD)
    list(APPEND torsion_libs Threads::Threads)
  endif()
endif()

add_node_library(torsion STATIC ${torsion_sources})
target_compile_definitions(torsion PRIVATE ${torsion_defines})
target_compile_options(torsion PRIVATE ${torsion_cflags})
target_include_directories(torsion PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(torsion INTERFACE ${torsion_libs})

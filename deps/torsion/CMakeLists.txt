# CMakeLists.txt - cmake build for libtorsion
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/bcoin-org/libtorsion

cmake_minimum_required(VERSION 3.4)
project(libtorsion LANGUAGES C)

include(CheckCCompilerFlag)
include(CheckIncludeFile)

set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 90)
set(CMAKE_OSX_DEPLOYMENT_TARGET 10.12)

option(TORSION_ENABLE_ASM "Use inline x86-64 assembly if available" ON)
option(TORSION_ENABLE_CRT "Enable chinese remainder theorem for RSA" OFF)
option(TORSION_ENABLE_DEBUG "Enable debug build" OFF)
option(TORSION_ENABLE_INT128 "Use __int128 if available" ON)
option(TORSION_ENABLE_LIBSECP256K1 "Use libsecp256k1 field element backend" OFF)
option(TORSION_ENABLE_PTHREAD "Use pthread as a fallback for TLS" ON)
option(TORSION_ENABLE_TLS "Enable TLS" ON)
option(TORSION_ENABLE_VERIFY "Enable scalar bounds checks" OFF)

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
  set(CMAKE_C_FLAGS_DEBUG "/MDd /Zi /O2 /Ob2 /DTORSION_DEBUG")
  check_c_compiler_flag(/wd4146 TORSION_HAS_WMINUS_UNSIGNED)
  check_c_compiler_flag(/wd4244 TORSION_HAS_WCONV_DATA_LOSS1)
  check_c_compiler_flag(/wd4267 TORSION_HAS_WCONV_DATA_LOSS2)
  check_c_compiler_flag(/wd4334 TORSION_HAS_W64BIT_SHIFT)
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
  set(CMAKE_C_FLAGS_DEBUG "-g -DTORSION_DEBUG")
  set(CMAKE_C_FLAGS_RELEASE "")
  check_c_compiler_flag(-g TORSION_HAS_G)
  check_c_compiler_flag(-pedantic TORSION_HAS_PEDANTIC)
  check_c_compiler_flag(-Wall TORSION_HAS_WALL)
  check_c_compiler_flag(-Wextra TORSION_HAS_WEXTRA)
  check_c_compiler_flag(-Wcast-align TORSION_HAS_WCAST_ALIGN)
  check_c_compiler_flag(-Wno-implicit-fallthrough TORSION_HAS_WFALLTHROUGH)
  check_c_compiler_flag(-Wno-long-long TORSION_HAS_WLONGLONG)
  check_c_compiler_flag(-Wno-overlength-strings TORSION_HAS_WOVERLENGTH)
  check_c_compiler_flag(-Wshadow TORSION_HAS_WSHADOW)
  check_c_compiler_flag(-O3 TORSION_HAS_O3)
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
  uint128_t r;
  r = ((uint128_t)1) << 64;
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

list(APPEND torsion_defines TORSION_HAVE_CONFIG)

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
  if(TORSION_HAS_G)
    list(APPEND torsion_cflags -g)
  endif()
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

if(MSVC)
  if(TORSION_HAS_WMINUS_UNSIGNED)
    list(APPEND torsion_cflags /wd4146)
  endif()
  if(TORSION_HAS_WCONV_DATA_LOSS1)
    list(APPEND torsion_cflags /wd4244)
  endif()
  if(TORSION_HAS_WCONV_DATA_LOSS2)
    list(APPEND torsion_cflags /wd4267)
  endif()
  if(TORSION_HAS_W64BIT_SHIFT)
    list(APPEND torsion_cflags /wd4334)
  endif()
else()
  if(TORSION_HAS_PEDANTIC)
    list(APPEND torsion_cflags -pedantic)
  endif()
  if(TORSION_HAS_WALL)
    list(APPEND torsion_cflags -Wall)
  endif()
  if(TORSION_HAS_WEXTRA)
    list(APPEND torsion_cflags -Wextra)
  endif()
  if(TORSION_HAS_WCAST_ALIGN)
    list(APPEND torsion_cflags -Wcast-align)
  endif()
  if(TORSION_HAS_WFALLTHROUGH)
    list(APPEND torsion_cflags -Wno-implicit-fallthrough)
  endif()
  if(TORSION_HAS_WLONGLONG)
    list(APPEND torsion_cflags -Wno-long-long)
  endif()
  if(TORSION_HAS_WOVERLENGTH)
    list(APPEND torsion_cflags -Wno-overlength-strings)
  endif()
  if(TORSION_HAS_WSHADOW)
    list(APPEND torsion_cflags -Wshadow)
  endif()
  if(TORSION_HAS_O3)
    list(APPEND torsion_cflags -O3)
  endif()
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

if(TORSION_ENABLE_PTHREAD AND TORSION_HAS_THREADS AND NOT WIN32)
  if(NOT TORSION_ENABLE_TLS OR NOT TORSION_HAS_TLS)
    list(APPEND torsion_defines TORSION_HAVE_PTHREAD)
    list(APPEND torsion_libs Threads::Threads)
  endif()
endif()

add_node_library(torsion STATIC ${torsion_sources})
target_compile_definitions(torsion PRIVATE ${torsion_defines} TORSION_BUILD)
target_compile_options(torsion PRIVATE ${torsion_cflags})
target_include_directories(torsion PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(torsion INTERFACE ${torsion_libs})

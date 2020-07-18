# CMakeLists.txt - cmake build for bcrypto
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/bcoin-org/bcrypto

cmake_minimum_required(VERSION 3.4)
project(bcrypto LANGUAGES C)

include(CheckCCompilerFlag)
include(TestBigEndian)

set(CMAKE_C_VISIBILITY_PRESET default)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
# set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD 99)
set(CMAKE_OSX_DEPLOYMENT_TARGET 10.12)

option(BCRYPTO_ENABLE_ASM "Use inline x86-64 assembly if available" ON)
option(BCRYPTO_ENABLE_DEBUG "Enable debug build" OFF)
option(BCRYPTO_ENABLE_INT128 "Use __int128 if available" ON)
option(BCRYPTO_ENABLE_LIBSECP256K1 "Use libsecp256k1" ON)
option(BCRYPTO_ENABLE_PTHREAD "Use pthread as a fallback for TLS" ON)
option(BCRYPTO_ENABLE_TLS "Enable TLS" ON)

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
  check_c_compiler_flag(/wd4146 BCRYPTO_HAS_WMINUS_UNSIGNED)
  check_c_compiler_flag(/wd4244 BCRYPTO_HAS_WCONV_DATA_LOSS1)
  check_c_compiler_flag(/wd4267 BCRYPTO_HAS_WCONV_DATA_LOSS2)
  check_c_compiler_flag(/wd4334 BCRYPTO_HAS_W64BIT_SHIFT)
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
  check_c_compiler_flag(-g BCRYPTO_HAS_G)
  check_c_compiler_flag(-pedantic BCRYPTO_HAS_PEDANTIC)
  check_c_compiler_flag(-Wall BCRYPTO_HAS_WALL)
  check_c_compiler_flag(-Wextra BCRYPTO_HAS_WEXTRA)
  check_c_compiler_flag(-Wcast-align BCRYPTO_HAS_WCAST_ALIGN)
  check_c_compiler_flag(-Wnested-externs BCRYPTO_HAS_WNESTED_EXTERNS)
  check_c_compiler_flag(-Wno-implicit-fallthrough BCRYPTO_HAS_WFALLTHROUGH)
  check_c_compiler_flag(-Wno-long-long BCRYPTO_HAS_WLONGLONG)
  check_c_compiler_flag(-Wno-nonnull-compare BCRYPTO_HAS_WNONNULL_COMPARE)
  check_c_compiler_flag(-Wno-overlength-strings BCRYPTO_HAS_WOVERLENGTH)
  check_c_compiler_flag(-Wno-unused-function BCRYPTO_HAS_WUNUSED_FUNCTION)
  check_c_compiler_flag(-Wshadow BCRYPTO_HAS_WSHADOW)
  check_c_compiler_flag(-Wstrict-prototypes BCRYPTO_HAS_WSTRICT_PROTOTYPES)
  check_c_compiler_flag(-O3 BCRYPTO_HAS_O3)
endif()

check_c_source_compiles([=[
#if defined(__EMSCRIPTEN__) || defined(__wasm__)
#  error "cannot use inline asm with wasm"
#endif
int main(void) {
  unsigned char ptr[32];
  int x = 0;
  __asm__ ("" : "+r" (x) ::);
  __asm__ __volatile__("" :: "r" (ptr) : "memory");
  return x;
}
]=] BCRYPTO_HAS_ASM)

check_c_source_compiles([=[
#include <stdint.h>
#if defined(__EMSCRIPTEN__) || defined(__wasm__)
#  error "cannot use inline asm with wasm"
#endif
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
]=] BCRYPTO_HAS_ASM_X64)

check_c_source_compiles([=[
#if defined(__EMSCRIPTEN__) || defined(__wasm__)
#  error "cannot use __int128 with wasm"
#endif
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
]=] BCRYPTO_HAS_INT128)

check_c_source_compiles([=[
#if defined(__EMSCRIPTEN__) || defined(__wasm__)
#  define TLS
#elif defined(_WIN32) && !defined(__MINGW32__)
#  define TLS __declspec(thread)
#else
#  define TLS __thread
#endif
static TLS int value;
int main(void) {
  value = 1;
  return 0;
}
]=] BCRYPTO_HAS_TLS)

set(BCRYPTO_HAS_THREADS OFF)

if(NOT EMSCRIPTEN)
  if(WIN32)
    set(BCRYPTO_HAS_THREADS ON)
  else()
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads)
    if(CMAKE_USE_PTHREADS_INIT)
      set(BCRYPTO_HAS_THREADS ON)
    endif()
  endif()
endif()

TEST_BIG_ENDIAN(BCRYPTO_BIGENDIAN)

list(APPEND torsion_defines TORSION_HAVE_CONFIG)

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

list(APPEND bcrypto_defines NODE_GYP_MODULE_NAME=${CMAKE_PROJECT_NAME})
list(APPEND bcrypto_defines BUILDING_NODE_EXTENSION)

if(APPLE)
  list(APPEND bcrypto_ldflags -undefined)
  list(APPEND bcrypto_ldflags dynamic_lookup)
  list(APPEND bcrypto_defines _DARWIN_USE_64_BIT_INODE=1)
endif()

if(NOT WIN32)
  list(APPEND bcrypto_defines _LARGEFILE_SOURCE)
  list(APPEND bcrypto_defines _FILE_OFFSET_BITS=64)
endif()

if(MSVC)
  # For when we add win_delay_load_hook.
  # list(APPEND bcrypto_sources deps/win_delay_load_hook.cc)
  # list(APPEND bcrypto_cflags HOST_BINARY=node.exe)
  # list(APPEND bcrypto_ldflags /DELAYLOAD:NODE.EXE)
  # list(APPEND bcrypto_cflags /ignore:4199)
  # Unsure if this is necessary for C.
  # list(APPEND bcrypto_ldflags /SAFESEH:NO)
endif()

set(BCRYPTO_64BIT OFF)

if(BCRYPTO_ENABLE_ASM AND BCRYPTO_HAS_ASM)
  list(APPEND torsion_defines TORSION_HAVE_ASM)
  list(APPEND secp256k1_defines USE_ASM_X86_64=1)
  set(BCRYPTO_64BIT ON)
endif()

if(BCRYPTO_ENABLE_ASM AND BCRYPTO_HAS_ASM_X64)
  list(APPEND torsion_defines TORSION_HAVE_ASM_X64)
endif()

if(BCRYPTO_ENABLE_DEBUG)
  if(BCRYPTO_HAS_G)
    list(APPEND torsion_cflags -g)
    list(APPEND secp256k1_cflags -g)
    list(APPEND bcrypto_cflags -g)
  endif()
  list(APPEND torsion_defines TORSION_DEBUG)
endif()

if(BCRYPTO_ENABLE_INT128 AND BCRYPTO_HAS_INT128)
  list(APPEND torsion_defines TORSION_HAVE_INT128)
  list(APPEND secp256k1_defines HAVE___INT128=1)
  set(BCRYPTO_64BIT ON)
endif()

if(BCRYPTO_ENABLE_TLS AND BCRYPTO_HAS_TLS)
  list(APPEND torsion_defines TORSION_HAVE_TLS)
endif()

if(BCRYPTO_BIGENDIAN)
  list(APPEND secp256k1_defines WORDS_BIGENDIAN=1)
endif()

if(BCRYPTO_64BIT)
  list(APPEND secp256k1_defines USE_FIELD_5X52=1)
  list(APPEND secp256k1_defines USE_SCALAR_4X64=1)
else()
  list(APPEND secp256k1_defines USE_FIELD_10X26=1)
  list(APPEND secp256k1_defines USE_SCALAR_8X32=1)
endif()

if(MSVC)
  if(BCRYPTO_HAS_WMINUS_UNSIGNED)
    list(APPEND torsion_cflags /wd4146)
  endif()
  if(BCRYPTO_HAS_WCONV_DATA_LOSS1)
    list(APPEND torsion_cflags /wd4244)
    list(APPEND secp256k1_cflags /wd4244)
    list(APPEND bcrypto_cflags /wd4244)
  endif()
  if(BCRYPTO_HAS_WCONV_DATA_LOSS2)
    list(APPEND torsion_cflags /wd4267)
    list(APPEND secp256k1_cflags /wd4267)
    list(APPEND bcrypto_cflags /wd4267)
  endif()
  if(BCRYPTO_HAS_W64BIT_SHIFT)
    list(APPEND torsion_cflags /wd4334)
    list(APPEND secp256k1_cflags /wd4334)
  endif()
else()
  # if(NOT EMSCRIPTEN AND BCRYPTO_HAS_PEDANTIC)
  #   list(APPEND torsion_cflags -pedantic)
  #   list(APPEND secp256k1_cflags -pedantic)
  # endif()
  if(BCRYPTO_HAS_WALL)
    list(APPEND torsion_cflags -Wall)
    list(APPEND secp256k1_cflags -Wall)
    list(APPEND bcrypto_cflags -Wall)
  endif()
  if(BCRYPTO_HAS_WEXTRA)
    list(APPEND torsion_cflags -Wextra)
    list(APPEND secp256k1_cflags -Wextra)
    list(APPEND bcrypto_cflags -Wextra)
  endif()
  if(BCRYPTO_HAS_WCAST_ALIGN)
    list(APPEND torsion_cflags -Wcast-align)
    list(APPEND secp256k1_cflags -Wcast-align)
    list(APPEND bcrypto_cflags -Wcast-align)
  endif()
  if(BCRYPTO_HAS_WNESTED_EXTERNS)
    list(APPEND secp256k1_cflags -Wnested-externs)
  endif()
  if(BCRYPTO_HAS_WFALLTHROUGH)
    list(APPEND torsion_cflags -Wno-implicit-fallthrough)
    list(APPEND secp256k1_cflags -Wno-implicit-fallthrough)
  endif()
  if(BCRYPTO_HAS_WLONGLONG)
    list(APPEND torsion_cflags -Wno-long-long)
    list(APPEND secp256k1_cflags -Wno-long-long)
  endif()
  if(BCRYPTO_HAS_WNONNULL_COMPARE)
    list(APPEND secp256k1_cflags -Wno-nonnull-compare)
  endif()
  if(BCRYPTO_HAS_WOVERLENGTH)
    list(APPEND torsion_cflags -Wno-overlength-strings)
    list(APPEND secp256k1_cflags -Wno-overlength-strings)
  endif()
  if(BCRYPTO_HAS_WUNUSED_FUNCTION)
    list(APPEND secp256k1_cflags -Wno-unused-function)
  endif()
  if(BCRYPTO_HAS_WSHADOW)
    list(APPEND torsion_cflags -Wshadow)
    list(APPEND secp256k1_cflags -Wshadow)
    list(APPEND bcrypto_cflags -Wshadow)
  endif()
  if(BCRYPTO_HAS_O3)
    list(APPEND torsion_cflags -O3)
    list(APPEND secp256k1_cflags -O3)
    list(APPEND bcrypto_cflags -O3)
  endif()
  if(BCRYPTO_HAS_WSTRICT_PROTOTYPES)
    list(APPEND secp256k1_cflags -Wstrict-prototypes)
  endif()
endif()

set(torsion_sources
    deps/torsion/src/aead.c
    deps/torsion/src/asn1.c
    deps/torsion/src/cipher.c
    deps/torsion/src/ecc.c
    deps/torsion/src/encoding.c
    deps/torsion/src/entropy/env.c
    deps/torsion/src/entropy/hw.c
    deps/torsion/src/entropy/sys.c
    deps/torsion/src/drbg.c
    deps/torsion/src/dsa.c
    deps/torsion/src/hash.c
    deps/torsion/src/ies.c
    deps/torsion/src/internal.c
    deps/torsion/src/kdf.c
    deps/torsion/src/mac.c
    deps/torsion/src/mpi.c
    deps/torsion/src/rand.c
    deps/torsion/src/rsa.c
    deps/torsion/src/stream.c
    deps/torsion/src/util.c)

set(secp256k1_sources
    deps/secp256k1/contrib/lax_der_parsing.c
    deps/secp256k1/src/secp256k1.c)

set(bcrypto_sources src/bcrypto.c)
set(bcrypto_libs torsion)

if(BCRYPTO_ENABLE_PTHREAD AND BCRYPTO_HAS_THREADS AND NOT WIN32)
  if(NOT BCRYPTO_ENABLE_TLS OR NOT BCRYPTO_HAS_TLS)
    list(APPEND torsion_defines TORSION_HAVE_PTHREAD)
    list(APPEND torsion_libs Threads::Threads)
  endif()
endif()

add_library(torsion STATIC ${torsion_sources})
target_compile_definitions(torsion PRIVATE ${torsion_defines} TORSION_BUILD)
target_compile_options(torsion PRIVATE ${torsion_cflags})
target_include_directories(torsion PRIVATE
                           ${PROJECT_SOURCE_DIR}/deps/torsion/include)
target_link_libraries(torsion INTERFACE ${torsion_libs})
set_property(TARGET torsion PROPERTY POSITION_INDEPENDENT_CODE 1)

if(BCRYPTO_ENABLE_LIBSECP256K1)
  add_library(secp256k1 STATIC ${secp256k1_sources})
  target_compile_definitions(secp256k1 PRIVATE ${secp256k1_defines}
                                               SECP256K1_BUILD)
  target_compile_options(secp256k1 PRIVATE ${secp256k1_cflags})
  target_include_directories(secp256k1 PRIVATE
                             ${PROJECT_SOURCE_DIR}/deps/secp256k1
                             ${PROJECT_SOURCE_DIR}/deps/secp256k1/include
                             ${PROJECT_SOURCE_DIR}/deps/secp256k1/src)
  set_property(TARGET secp256k1 PROPERTY POSITION_INDEPENDENT_CODE 1)
  list(APPEND bcrypto_defines BCRYPTO_USE_SECP256K1)
  list(APPEND bcrypto_libs secp256k1)
endif()

add_library(bcrypto SHARED ${bcrypto_sources})
target_compile_definitions(bcrypto PRIVATE ${bcrypto_defines})
target_compile_options(bcrypto PRIVATE ${bcrypto_cflags})
target_include_directories(bcrypto PRIVATE
                           ${PROJECT_SOURCE_DIR}/deps/torsion/include
                           ${PROJECT_SOURCE_DIR}/deps/secp256k1/contrib
                           ${PROJECT_SOURCE_DIR}/deps/secp256k1/include
                           /usr/local/include/node
                           /usr/include/node)
target_link_options(bcrypto PRIVATE ${bcrypto_ldflags})
target_link_libraries(bcrypto PRIVATE ${bcrypto_libs})
set_property(TARGET bcrypto PROPERTY PREFIX "")
set_property(TARGET bcrypto PROPERTY SUFFIX ".node")

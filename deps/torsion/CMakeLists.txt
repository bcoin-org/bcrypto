# CMakeLists.txt - cmake build for libtorsion
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/bcoin-org/libtorsion

set(TORSION_PKG_VERSION 0.0.0)
set(TORSION_ABI_VERSION 0:0:0)

#
# Initialization
#

cmake_minimum_required(VERSION 3.4)
project(libtorsion VERSION ${TORSION_PKG_VERSION} LANGUAGES C)

if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release")
endif()

#
# Includes
#

include(cmake/AppendCCompilerFlag.cmake)
include(cmake/CheckCThreadLocalStorage.cmake)
include(cmake/TargetLinkOptions.cmake)
include(cmake/WritePkgConfigFile.cmake)
include(CheckCSourceCompiles)
include(CheckIncludeFile)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CTest)
include(GNUInstallDirs)

#
# Early Checks
#

set(TORSION_WASM 0)

check_symbol_exists(__EMSCRIPTEN__ "" TORSION_EMSCRIPTEN)
check_symbol_exists(__wasi__ "" TORSION_WASI)

if(TORSION_EMSCRIPTEN OR TORSION_WASI)
  set(TORSION_WASM 1)
endif()

#
# Options
#

option(TORSION_ENABLE_ASM "Use inline x86-64 assembly if available" ON)
option(TORSION_ENABLE_COVERAGE "Enable coverage" OFF)
option(TORSION_ENABLE_DEBUG "Enable debug build" OFF)
option(TORSION_ENABLE_INT128 "Use __int128 if available" ON)
option(TORSION_ENABLE_PTHREAD "Use pthread as a fallback for TLS" ON)
option(TORSION_ENABLE_RNG "Enable RNG" ON)
option(TORSION_ENABLE_TLS "Enable thread-local storage" ON)
option(TORSION_ENABLE_VERIFY "Enable scalar bounds checks" OFF)

if(TORSION_WASM)
  set(TORSION_INITIAL_MEMORY "16777216" CACHE STRING "WASM initial memory")
  set(TORSION_MAX_MEMORY "2147483648" CACHE STRING "WASM maximum memory")
  set(TORSION_STACK_SIZE "5242880" CACHE STRING "WASM stack size")
endif()

if(TORSION_EMSCRIPTEN)
  set(TORSION_ENVIRONMENT "node" CACHE STRING "Emscripten environment")
endif()

#
# Flags
#

set(torsion_cflags)
set(torsion_ldflags)

set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 90)

if(NOT TORSION_WASM)
  set(CMAKE_C_VISIBILITY_PRESET hidden)
  set(CMAKE_OSX_DEPLOYMENT_TARGET 10.7)
endif()

if(TORSION_WASI AND CMAKE_C_FLAGS STREQUAL "-v")
  set(CMAKE_C_FLAGS "")
endif()

if(MSVC)
  append_c_compiler_flag(torsion_cflags /wd4146
                                        /wd4244
                                        /wd4267
                                        /wd4334)
else()
  append_c_compiler_flag(torsion_cflags -pedantic
                                        -Wall
                                        -Wextra
                                        -Wcast-align
                                        -Wno-implicit-fallthrough
                                        -Wno-long-long
                                        -Wno-overlength-strings
                                        -Wshadow)
endif()

if(TORSION_ENABLE_COVERAGE)
  list(APPEND torsion_cflags -O0 --coverage)
  list(APPEND torsion_ldflags --coverage)
endif()

if(TORSION_ENABLE_DEBUG)
  if(MSVC)
    append_c_compiler_flag(torsion_cflags /Zi)
  else()
    append_c_compiler_flag(torsion_cflags -g)
  endif()
endif()

#
# Feature Testing
#

if(TORSION_ENABLE_ASM)
  check_c_source_compiles([=[
    #if !defined(__GNUC__) && !defined(__clang__)
    #  error "not a gnu-compatible compiler"
    #endif
    int main(void) {
      unsigned char ptr[32];
      int x = 0;
      __asm__ ("" : "+r" (x));
      __asm__ __volatile__ ("" :: "r" (ptr) : "memory");
      return x;
    }
  ]=] TORSION_HAS_ASM)
else()
  set(TORSION_HAS_ASM)
endif()

if(TORSION_ENABLE_ASM)
  check_c_source_compiles([=[
    #if !defined(__GNUC__) && !defined(__clang__)
    #  error "not a gnu-compatible compiler"
    #endif
    #if defined(__amd64__) || defined(__x86_64__)
    #  error "not an x86 platform"
    #endif
    #ifndef __i386__
    #  error "not an x86 platform"
    #endif
    int main(void) {
      unsigned int z = 953;
      unsigned int c = 709;
      unsigned int x = 109;
      unsigned int y = 577;
      __asm__ __volatile__ (
        "movl %k2, %%eax\\n"
        "mull %k3\\n"
        "addl %k4, %%eax\\n"
        "adcl $0, %%edx\\n"
        "subl %%eax, %k0\\n"
        "adcl $0, %%edx\\n"
        : "+r" (z), "=&d" (c)
        : "%rm" (x), "rm" (y),
          "rm" (c)
        : "cc", "memory",
          "eax"
      );
      return 0;
    }
  ]=] TORSION_HAS_ASM_X86)
else()
  set(TORSION_HAS_ASM_X86)
endif()

if(TORSION_ENABLE_ASM)
  check_c_source_compiles([=[
    #if !defined(__GNUC__) && !defined(__clang__)
    #  error "not a gnu-compatible compiler"
    #endif
    #if !defined(__amd64__) && !defined(__x86_64__)
    #  error "not an x64 platform"
    #endif
    int main(void) {
      unsigned long long z = 953;
      unsigned long long c = 709;
      unsigned long long x = 109;
      unsigned long long y = 577;
      __asm__ __volatile__ (
        "movq %q2, %%rax\\n"
        "mulq %q3\\n"
        "addq %q4, %%rax\\n"
        "adcq $0, %%rdx\\n"
        "subq %%rax, %q0\\n"
        "adcq $0, %%rdx\\n"
        : "+r" (z), "=&d" (c)
        : "%rm" (x), "rm" (y),
          "rm" (c)
        : "cc", "memory",
          "rax"
      );
      return 0;
    }
  ]=] TORSION_HAS_ASM_X64)
else()
  set(TORSION_HAS_ASM_X64)
endif()

if(BUILD_TESTING AND NOT TORSION_WASM)
  check_c_source_compiles([=[
    #include <sys/types.h>
    #include <sys/wait.h>
    #include <unistd.h>
    int main(void) {
      unsigned char data[32];
      int pfds[2];
      int status;
      pid_t pid;
      pipe(pfds);
      pid = fork();
      close(pfds[1]);
      read(pfds[0], data, 32);
      close(pfds[0]);
      waitpid(pid, &status, 0);
      WIFEXITED(status);
      WEXITSTATUS(status);
      return 0;
    }
  ]=] TORSION_HAS_FORK)
else()
  set(TORSION_HAS_FORK)
endif()

if(TORSION_ENABLE_INT128)
  check_c_source_compiles([=[
    typedef char check_64bit_t[sizeof(void *) >= 8 ? 1 : -1];
    typedef signed __int128 xint128_t;
    typedef unsigned __int128 xuint128_t;
    int main(void) {
      xuint128_t r = 1;
      r <<= 64;
      r *= 113;
      r >>= 65;
      return r & 1;
    }
  ]=] TORSION_HAS_INT128)
else()
  set(TORSION_HAS_INT128)
endif()

if(TORSION_ENABLE_PTHREAD AND NOT TORSION_WASM)
  set(THREADS_PREFER_PTHREAD_FLAG ON)

  find_package(Threads)

  set(TORSION_HAS_PTHREAD ${CMAKE_USE_PTHREADS_INIT})
else()
  set(TORSION_HAS_PTHREAD 0)
endif()

if(TORSION_ENABLE_TLS)
  check_c_thread_local_storage(TORSION_TLS)
else()
  set(TORSION_TLS)
endif()

if(NOT TORSION_TLS)
  set(TORSION_HAS_TLS_FALLBACK ${TORSION_HAS_PTHREAD})
else()
  set(TORSION_HAS_TLS_FALLBACK 0)
endif()

set(TORSION_HAS_MEMCHECK 0)
set(TORSION_HAS_ZLIB 0)

if(BUILD_TESTING AND NOT TORSION_WASM AND NOT WIN32)
  check_include_file(valgrind/memcheck.h TORSION_HAS_MEMCHECK_H)

  if(TORSION_HAS_MEMCHECK_H)
    set(TORSION_HAS_MEMCHECK 1)
  endif()

  if (TORSION_ENABLE_RNG)
    check_include_file(zlib.h TORSION_HAS_ZLIB_H)
    check_library_exists(z compress2 "" TORSION_HAS_ZLIB_A)

    if(TORSION_HAS_ZLIB_H AND TORSION_HAS_ZLIB_A)
      set(TORSION_HAS_ZLIB 1)
    endif()
  endif()
endif()

#
# Defines
#

set(torsion_defines)

list(APPEND torsion_defines TORSION_HAVE_CONFIG)

if(TORSION_HAS_ASM)
  list(APPEND torsion_defines TORSION_HAVE_ASM)
endif()

if(TORSION_HAS_ASM_X86)
  list(APPEND torsion_defines TORSION_HAVE_ASM_X86)
endif()

if(TORSION_HAS_ASM_X64)
  list(APPEND torsion_defines TORSION_HAVE_ASM_X64)
endif()

if(TORSION_ENABLE_COVERAGE)
  list(APPEND torsion_defines TORSION_COVERAGE)
endif()

if(TORSION_ENABLE_DEBUG)
  list(APPEND torsion_defines TORSION_DEBUG)
else()
  list(APPEND torsion_defines $<$<CONFIG:Debug>:TORSION_DEBUG>)
endif()

if(TORSION_HAS_FORK)
  list(APPEND torsion_defines TORSION_HAVE_FORK)
endif()

if(TORSION_HAS_INT128)
  list(APPEND torsion_defines TORSION_HAVE_INT128)
endif()

if(TORSION_ENABLE_RNG)
  list(APPEND torsion_defines TORSION_HAVE_RNG)
endif()

if(TORSION_HAS_PTHREAD OR WIN32)
  list(APPEND torsion_defines TORSION_HAVE_THREADS)
endif()

if(TORSION_TLS)
  list(APPEND torsion_defines TORSION_HAVE_TLS)
  list(APPEND torsion_defines TORSION_TLS=${TORSION_TLS})
else()
  list(APPEND torsion_defines TORSION_TLS=)
endif()

if(TORSION_HAS_TLS_FALLBACK)
  list(APPEND torsion_defines TORSION_HAVE_PTHREAD)
endif()

if(TORSION_ENABLE_VERIFY)
  list(APPEND torsion_defines TORSION_VERIFY)
endif()

if(TORSION_HAS_ZLIB)
  list(APPEND torsion_defines TORSION_HAVE_ZLIB)
endif()

#
# Libraries
#

set(torsion_libs)
set(pkgconf_libs)
set(test_libs)

if(TORSION_HAS_TLS_FALLBACK)
  list(APPEND torsion_libs Threads::Threads)
  list(APPEND pkgconf_libs ${CMAKE_THREAD_LIBS_INIT})
endif()

if(TORSION_HAS_PTHREAD)
  list(APPEND test_libs Threads::Threads)
endif()

if(TORSION_HAS_ZLIB)
  list(APPEND test_libs z)
endif()

#
# Includes
#

set(torsion_includes ${PROJECT_SOURCE_DIR}/include)

#
# Sources
#

set(torsion_sources src/aead.c
                    src/asn1.c
                    src/cipher.c
                    src/ecc.c
                    src/encoding.c
                    src/drbg.c
                    src/dsa.c
                    src/hash.c
                    src/ies.c
                    src/internal.c
                    src/kdf.c
                    src/mac.c
                    src/mpi.c
                    src/rsa.c
                    src/stream.c
                    src/util.c)

set(rng_sources src/entropy/env.c
                src/entropy/hrt.c
                src/entropy/hw.c
                src/entropy/sys.c
                src/rand.c)

set(test_sources test/test.c test/utils.c)
set(bench_sources test/bench.c test/hrtime.c test/utils.c)
set(ctgrind_sources test/ctgrind.c test/utils.c)

if(TORSION_ENABLE_RNG)
  list(APPEND torsion_sources ${rng_sources})
endif()

if(TORSION_HAS_PTHREAD OR WIN32)
  list(APPEND test_sources test/thread.c)
endif()

#
# Targets
#

if(NOT PROJECT_NAME STREQUAL CMAKE_PROJECT_NAME)
  # Bulding a subproject. Keep it simple.
  if(TORSION_WASM)
    add_library(torsion OBJECT ${torsion_sources})
    target_compile_definitions(torsion PRIVATE ${torsion_defines})
    target_compile_options(torsion PRIVATE ${torsion_cflags})
    target_include_directories(torsion PUBLIC ${torsion_includes})
  else()
    if(COMMAND add_node_library)
      add_node_library(torsion STATIC ${torsion_sources})
    else()
      add_library(torsion STATIC ${torsion_sources})
      set_property(TARGET torsion PROPERTY POSITION_INDEPENDENT_CODE ON)
    endif()

    target_compile_definitions(torsion PRIVATE ${torsion_defines})
    target_compile_options(torsion PRIVATE ${torsion_cflags})
    target_include_directories(torsion PUBLIC ${torsion_includes})
    target_link_options(torsion INTERFACE ${torsion_ldflags})
    target_link_libraries(torsion INTERFACE ${torsion_libs})
  endif()
elseif(TORSION_WASM)
  if(TORSION_EMSCRIPTEN)
    # CMAKE_CROSSCOMPILING_EMULATOR is mistakenly quoted by emcmake.
    string(REPLACE "\"" "" CMAKE_CROSSCOMPILING_EMULATOR
           "${CMAKE_CROSSCOMPILING_EMULATOR}")

    set(torsion_ldflags "SHELL:-s SINGLE_FILE=1"
                        "SHELL:-s ASSERTIONS=0"
                        "SHELL:-s NODEJS_CATCH_EXIT=0"
                        "SHELL:-s NODEJS_CATCH_REJECTION=0"
                        "SHELL:-s ALLOW_MEMORY_GROWTH=1"
                        "SHELL:-s INITIAL_MEMORY=${TORSION_INITIAL_MEMORY}"
                        "SHELL:-s MAXIMUM_MEMORY=${TORSION_MAX_MEMORY}"
                        "SHELL:-s TOTAL_STACK=${TORSION_STACK_SIZE}"
                        "SHELL:-s ENVIRONMENT=${TORSION_ENVIRONMENT}")

    set(torsion_sources_lib "")
    set(torsion_ldflags_lib "SHELL:-s EXPORTED_FUNCTIONS=@etc/exports.json")
  else()
    set(CMAKE_EXECUTABLE_SUFFIX ".wasm")

    set(torsion_ldflags -Wl,--allow-undefined
                        -Wl,--initial-memory=${TORSION_INITIAL_MEMORY}
                        -Wl,--max-memory=${TORSION_MAX_MEMORY}
                        -Wl,-z -Wl,stack-size=${TORSION_STACK_SIZE}
                        -Wl,--stack-first)

    # Note: We have to manually choose crt1-reactor.o
    # until reactor support is widely available via:
    #
    #   -mexec-model=reactor
    #
    # See: https://github.com/llvm/llvm-project/commit/d496437
    #      https://reviews.llvm.org/D62922
    set(torsion_syslib ${CMAKE_SYSROOT}/lib/${CMAKE_C_COMPILER_TARGET})
    set(torsion_sources_lib ${torsion_syslib}/crt1-reactor.o)
    set(torsion_ldflags_lib -nostartfiles
                            -Wl,--entry=_initialize
                            -Wl,--export-dynamic
                            -Wl,--export=malloc
                            -Wl,--export=free)
  endif()

  add_library(torsion_o OBJECT ${torsion_sources})
  target_compile_definitions(torsion_o PUBLIC ${torsion_defines}
                                       PRIVATE TORSION_BUILD)
  target_compile_options(torsion_o PUBLIC ${torsion_cflags})
  target_include_directories(torsion_o PUBLIC ${torsion_includes})
  target_link_options(torsion_o INTERFACE ${torsion_ldflags})

  add_executable(torsion ${torsion_sources_lib})
  target_link_options(torsion PRIVATE ${torsion_ldflags_lib})
  target_link_libraries(torsion PRIVATE torsion_o)

  if(BUILD_TESTING)
    add_executable(torsion_bench ${bench_sources})
    target_link_libraries(torsion_bench PRIVATE torsion_o)

    add_executable(torsion_test ${test_sources})
    target_link_libraries(torsion_test PRIVATE torsion_o)
    add_test(NAME test_wasm COMMAND torsion_test)

    if(CMAKE_GENERATOR STREQUAL "Unix Makefiles")
      add_custom_target(bench COMMAND torsion_bench)
      add_custom_target(check COMMAND ${CMAKE_MAKE_PROGRAM} test)
    endif()
  endif()
else()
  add_library(torsion_o OBJECT ${torsion_sources})
  target_compile_definitions(torsion_o PRIVATE ${torsion_defines} TORSION_BUILD)
  target_compile_options(torsion_o PRIVATE ${torsion_cflags})
  target_include_directories(torsion_o PRIVATE ${torsion_includes})
  set_property(TARGET torsion_o PROPERTY POSITION_INDEPENDENT_CODE ON)

  add_library(torsion SHARED $<TARGET_OBJECTS:torsion_o>)
  target_compile_definitions(torsion INTERFACE ${torsion_defines})
  target_compile_options(torsion INTERFACE ${torsion_cflags})
  target_include_directories(torsion INTERFACE ${torsion_includes})
  target_link_options(torsion PUBLIC ${torsion_ldflags})
  target_link_libraries(torsion PRIVATE ${torsion_libs})

  add_library(torsion_static STATIC $<TARGET_OBJECTS:torsion_o>)
  target_compile_definitions(torsion_static INTERFACE ${torsion_defines})
  target_compile_options(torsion_static INTERFACE ${torsion_cflags})
  target_include_directories(torsion_static INTERFACE ${torsion_includes})
  target_link_options(torsion_static INTERFACE ${torsion_ldflags})
  target_link_libraries(torsion_static INTERFACE ${torsion_libs})

  if(UNIX)
    string(REPLACE ":" "." torsion_version "${TORSION_ABI_VERSION}")
    string(REGEX MATCH "^[0-9]+" torsion_soversion "${TORSION_ABI_VERSION}")

    set_target_properties(torsion PROPERTIES VERSION ${torsion_version}
                                             SOVERSION ${torsion_soversion})
    set_target_properties(torsion_static PROPERTIES OUTPUT_NAME torsion)

    write_pkgconfig_file(libtorsion.pc.in libtorsion.pc
      PREFIX ${CMAKE_INSTALL_PREFIX}
      EXEC_PREFIX \${prefix}
      LIBDIR \${exec_prefix}/${CMAKE_INSTALL_LIBDIR}
      INCLUDEDIR \${prefix}/${CMAKE_INSTALL_INCLUDEDIR}
      PACKAGE_NAME ${PROJECT_NAME}
      PACKAGE_VERSION ${PROJECT_VERSION}
      LIBS_PRIVATE ${pkgconf_libs}
    )

    install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    install(FILES LICENSE
            DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/${PROJECT_NAME})
    install(FILES README.md DESTINATION ${CMAKE_INSTALL_DOCDIR})
    install(FILES ${PROJECT_BINARY_DIR}/libtorsion.pc
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
    install(TARGETS torsion LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
    install(TARGETS torsion_static ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
  endif()

  if(WIN32)
    install(DIRECTORY include/ DESTINATION include)
    install(FILES LICENSE README.md DESTINATION .)
    install(TARGETS torsion torsion_static
            RUNTIME DESTINATION lib/$<CONFIG>
            ARCHIVE DESTINATION lib/$<CONFIG>)
  endif()

  if(BUILD_TESTING)
    add_executable(torsion_bench ${bench_sources})
    target_link_libraries(torsion_bench PRIVATE torsion)

    add_executable(torsion_test ${test_sources})
    target_link_libraries(torsion_test PRIVATE torsion ${test_libs})
    add_test(NAME test_shared COMMAND torsion_test)

    add_executable(torsion_test_static ${test_sources})
    target_link_libraries(torsion_test_static PRIVATE torsion_static
                                                      ${test_libs})
    add_test(NAME test_static COMMAND torsion_test_static)

    if(TORSION_HAS_MEMCHECK)
      add_executable(torsion_ctgrind ${ctgrind_sources})
      target_link_libraries(torsion_ctgrind PRIVATE torsion)
    endif()

    find_program(TORSION_VALGRIND valgrind)

    if(TORSION_VALGRIND)
      if(TORSION_HAS_MEMCHECK AND NOT TORSION_ENABLE_DEBUG)
        add_test(NAME test_ctgrind COMMAND ${TORSION_VALGRIND}
                                            --leak-check=full
                                            --error-exitcode=1
                                           $<TARGET_FILE:torsion_ctgrind>)
      endif()

      add_test(NAME test_valgrind COMMAND ${TORSION_VALGRIND}
                                          --leak-check=full
                                          --error-exitcode=1
                                          $<TARGET_FILE:torsion_test>)
    endif()

    if(CMAKE_GENERATOR STREQUAL "Unix Makefiles")
      add_custom_target(bench COMMAND torsion_bench)
      add_custom_target(check COMMAND ${CMAKE_MAKE_PROGRAM} test)

      if(TORSION_VALGRIND)
        if(TORSION_HAS_MEMCHECK AND NOT TORSION_ENABLE_DEBUG)
          add_custom_target(ctgrind COMMAND ${TORSION_VALGRIND}
                                            --leak-check=full
                                            --error-exitcode=1
                                            $<TARGET_FILE:torsion_ctgrind>
                                    DEPENDS torsion_ctgrind)
        endif()

        add_custom_target(valgrind COMMAND ${TORSION_VALGRIND}
                                           --leak-check=full
                                           --error-exitcode=1
                                           $<TARGET_FILE:torsion_test>
                                   DEPENDS torsion_test)
      endif()
    endif()
  endif()
endif()

#
# Output
#

string(TOUPPER "${CMAKE_BUILD_TYPE}" torsion_build_type)

message(STATUS "Build Options:

   CMAKE_BUILD_TYPE:     ${CMAKE_BUILD_TYPE}
   CMAKE_INSTALL_PREFIX: ${CMAKE_INSTALL_PREFIX}
   CMAKE_SYSTEM_NAME:    ${CMAKE_SYSTEM_NAME}
   CMAKE_C_COMPILER:     ${CMAKE_C_COMPILER}
   CMAKE_C_FLAGS:        ${CMAKE_C_FLAGS_${torsion_build_type}} ${CMAKE_C_FLAGS}
   torsion_cflags:       ${torsion_cflags}
   torsion_ldflags:      ${torsion_ldflags}
   torsion_defines:      ${torsion_defines}
   torsion_libs:         ${torsion_libs}
")

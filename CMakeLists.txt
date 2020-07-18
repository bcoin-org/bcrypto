# CMakeLists.txt - cmake build for bcrypto
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/bcoin-org/bcrypto

cmake_minimum_required(VERSION 3.4)
project(bcrypto LANGUAGES C)

include(CheckCCompilerFlag)

set(CMAKE_C_VISIBILITY_PRESET default)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)
set(CMAKE_OSX_DEPLOYMENT_TARGET 10.12)

option(BCRYPTO_ENABLE_DEBUG "Enable debug build" OFF)
option(BCRYPTO_ENABLE_LIBSECP256K1 "Use libsecp256k1" ON)

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
  check_c_compiler_flag(/wd4244 BCRYPTO_HAS_WCONV_DATA_LOSS1)
  check_c_compiler_flag(/wd4267 BCRYPTO_HAS_WCONV_DATA_LOSS2)
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
  check_c_compiler_flag(-g BCRYPTO_HAS_G)
  check_c_compiler_flag(-Wall BCRYPTO_HAS_WALL)
  check_c_compiler_flag(-Wextra BCRYPTO_HAS_WEXTRA)
  check_c_compiler_flag(-Wcast-align BCRYPTO_HAS_WCAST_ALIGN)
  check_c_compiler_flag(-Wshadow BCRYPTO_HAS_WSHADOW)
  check_c_compiler_flag(-O3 BCRYPTO_HAS_O3)
endif()

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
  list(APPEND bcrypto_sources deps/win_delay_load_hook.cc)
  list(APPEND bcrypto_ldflags /DELAYLOAD:NODE.EXE)
  list(APPEND bcrypto_defines HOST_BINARY=node.exe)
  list(APPEND bcrypto_cflags /wd4199)
  # Unsure if this is necessary for C.
  # list(APPEND bcrypto_ldflags /SAFESEH:NO)
endif()

if(BCRYPTO_ENABLE_DEBUG)
  if(BCRYPTO_HAS_G)
    list(APPEND bcrypto_cflags -g)
  endif()
endif()

if(MSVC)
  if(BCRYPTO_HAS_WCONV_DATA_LOSS1)
    list(APPEND bcrypto_cflags /wd4244)
  endif()
  if(BCRYPTO_HAS_WCONV_DATA_LOSS2)
    list(APPEND bcrypto_cflags /wd4267)
  endif()
else()
  if(BCRYPTO_HAS_WALL)
    list(APPEND bcrypto_cflags -Wall)
  endif()
  if(BCRYPTO_HAS_WEXTRA)
    list(APPEND bcrypto_cflags -Wextra)
  endif()
  if(BCRYPTO_HAS_WCAST_ALIGN)
    list(APPEND bcrypto_cflags -Wcast-align)
  endif()
  if(BCRYPTO_HAS_WSHADOW)
    list(APPEND bcrypto_cflags -Wshadow)
  endif()
  if(BCRYPTO_HAS_O3)
    list(APPEND bcrypto_cflags -O3)
  endif()
endif()

list(APPEND bcrypto_sources src/bcrypto.c)
list(APPEND bcrypto_libs torsion_static)

add_subdirectory(deps/torsion)

if(BCRYPTO_ENABLE_LIBSECP256K1)
  add_subdirectory(deps/secp256k1)
  list(APPEND bcrypto_defines BCRYPTO_USE_SECP256K1)
  list(APPEND bcrypto_libs secp256k1_static)
endif()

add_library(bcrypto SHARED ${bcrypto_sources})
target_compile_definitions(bcrypto PRIVATE ${bcrypto_defines})
target_compile_options(bcrypto PRIVATE ${bcrypto_cflags})
target_include_directories(bcrypto PRIVATE
                           ${PROJECT_SOURCE_DIR}/deps/torsion/include
                           ${PROJECT_SOURCE_DIR}/deps/secp256k1/contrib
                           ${PROJECT_SOURCE_DIR}/deps/secp256k1/include
                           ${PROJECT_SOURCE_DIR}/deps/node)
target_link_options(bcrypto PRIVATE ${bcrypto_ldflags})
target_link_libraries(bcrypto PRIVATE ${bcrypto_libs})
set_property(TARGET bcrypto PROPERTY PREFIX "")
set_property(TARGET bcrypto PROPERTY SUFFIX ".node")

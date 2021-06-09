# WritePkgConfigFile.cmake - pkgconfig file for cmake
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/chjj

if(COMMAND write_pkgconfig_file)
  return()
endif()

include(CMakeParseArguments)

function(write_pkgconfig_file input output)
  cmake_parse_arguments(
    PARSED
    ""
    "PREFIX;EXEC_PREFIX;LIBDIR;INCLUDEDIR;PACKAGE_NAME;PACKAGE_VERSION"
    "LIBS;LIBS_PRIVATE"
    ${ARGN}
  )

  set(prefix ${PARSED_PREFIX})
  set(exec_prefix ${PARSED_EXEC_PREFIX})
  set(libdir ${PARSED_LIBDIR})
  set(includedir ${PARSED_INCLUDEDIR})
  set(PACKAGE_NAME ${PARSED_PACKAGE_NAME})
  set(PACKAGE_VERSION ${PARSED_PACKAGE_VERSION})
  set(LIBS ${PARSED_LIBS})
  set(LIBS_PRIVATE ${PARSED_LIBS_PRIVATE})

  string(REPLACE ";" " " LIBS "${LIBS}")
  string(REPLACE ";" " " LIBS_PRIVATE "${LIBS_PRIVATE}")

  configure_file(${input} ${output} @ONLY)
endfunction()

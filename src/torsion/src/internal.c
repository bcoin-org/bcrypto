/*!
 * internal.c - internal utils for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#include <stdlib.h>
#include <string.h>
#include "internal.h"

#if defined(__EMSCRIPTEN__) || defined(__wasm__)
/* Save some space for wasm builds. */
#else
#  include <stdio.h>
#  define TORSION_HAVE_STDIO
#endif

void
__torsion_assert_fail(const char *file, int line, const char *expr) {
#ifdef TORSION_HAVE_STDIO
  fprintf(stderr, "%s:%d: Assertion `%s' failed.\n", file, line, expr);
  fflush(stderr);
#else
  (void)file;
  (void)line;
  (void)expr;
#endif
  abort();
}

void
torsion_die(const char *msg) {
#ifdef TORSION_HAVE_STDIO
  fprintf(stderr, "%s\n", msg);
  fflush(stderr);
#else
  (void)msg;
#endif
  abort();
}

void
torsion_abort(void) {
  torsion_die("libtorsion: aborted.");
}

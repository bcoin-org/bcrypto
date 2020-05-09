/*!
 * internal.c - internal utils for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "internal.h"

#ifndef TORSION_NO_ASSERT
void
__torsion_assert_fail(const char *file, int line, const char *expr) {
  fprintf(stderr, "%s:%d: Assertion `%s' failed.\n", file, line, expr);
  fflush(stderr);
  abort();
}
#endif

void
torsion_die(const char *msg) {
  fprintf(stderr, "%s\n", msg);
  fflush(stderr);
  abort();
}

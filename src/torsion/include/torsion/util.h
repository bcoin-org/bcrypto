/*!
 * util.h - utils for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef _TORSION_UTIL_H
#define _TORSION_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * Symbol Aliases
 */

#define cleanse torsion_cleanse

/*
 * Memzero
 */

void
cleanse(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _TORSION_UTIL_H */

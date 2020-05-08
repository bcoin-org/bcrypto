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
 * Callbacks
 */

typedef void torsion_die_f(const char *msg);
typedef void *torsion_malloc_f(size_t size);
typedef void *torsion_realloc_f(void *ptr, size_t size);
typedef void torsion_free_f(void *ptr);

/*
 * Error Handling
 */

void
torsion_set_die_function(torsion_die_f *die_fn);

void
torsion_get_die_function(torsion_die_f **die_fn);

void
torsion_die(const char *msg);

/*
 * Allocation
 */

void
torsion_set_memory_functions(torsion_malloc_f *malloc_fn,
                             torsion_realloc_f *realloc_fn,
                             torsion_free_f *free_fn);

void
torsion_get_memory_functions(torsion_malloc_f **malloc_fn,
                             torsion_realloc_f **realloc_fn,
                             torsion_free_f **free_fn);

#ifdef __GNUC__
#define __TORSION_MALLOC __attribute__((malloc))
#else
#define __TORSION_MALLOC
#endif

void *
torsion_malloc(size_t size) __TORSION_MALLOC;

void *
torsion_calloc(size_t nmemb, size_t size) __TORSION_MALLOC;

void *
torsion_realloc(void *ptr, size_t size) __TORSION_MALLOC;

void
torsion_free(void *ptr);

void *
torsion_xmalloc(size_t size) __TORSION_MALLOC;

void *
torsion_xcalloc(size_t nmemb, size_t size) __TORSION_MALLOC;

void *
torsion_xrealloc(void *ptr, size_t size) __TORSION_MALLOC;

/*
 * Memzero
 */

void
cleanse(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _TORSION_UTIL_H */

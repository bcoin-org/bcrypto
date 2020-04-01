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
 * Types
 */

typedef void *torsion_malloc_t(size_t size);
typedef void *torsion_realloc_t(void *ptr, size_t size);
typedef void torsion_free_t(void *ptr);

/*
 * Util
 */

void
torsion_set_memory_functions(torsion_malloc_t *malloc_fn,
                             torsion_realloc_t *realloc_fn,
                             torsion_free_t *free_fn);

void
torsion_get_memory_functions(torsion_malloc_t **malloc_fn,
                             torsion_realloc_t **realloc_fn,
                             torsion_free_t **free_fn);

#ifdef __GNUC__
#define __TORSION_MALLOC __attribute__((malloc))
#else
#define __TORSION_MALLOC
#endif

void *
torsion_malloc(size_t size) __TORSION_MALLOC;

void *
torsion_alloc(size_t size) __TORSION_MALLOC;

void *
torsion_realloc(void *ptr, size_t size) __TORSION_MALLOC;

void
torsion_free(void *ptr);

void
cleanse(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _TORSION_UTIL_H */

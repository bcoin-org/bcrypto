/*!
 * util.c - utils for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
/* For SecureZeroMemory (actually defined in winbase.h). */
#include <windows.h>
#endif

#include <torsion/util.h>

/*
 * Constants
 */

static torsion_malloc_t *malloc_cb = &malloc;
static torsion_realloc_t *realloc_cb = &realloc;
static torsion_free_t *free_cb = &free;

/*
 * Allocation
 */

static void
torsion_die(const char *msg) {
  fprintf(stderr, "%s\n", msg);
  fflush(stderr);
  abort();
}

void
torsion_set_memory_functions(torsion_malloc_t *malloc_fn,
                             torsion_realloc_t *realloc_fn,
                             torsion_free_t *free_fn) {
  if (malloc_fn)
    malloc_cb = malloc_fn;

  if (realloc_fn)
    realloc_cb = realloc_fn;

  if (free_fn)
    free_cb = free_fn;
}

void
torsion_get_memory_functions(torsion_malloc_t **malloc_fn,
                             torsion_realloc_t **realloc_fn,
                             torsion_free_t **free_fn) {
  if (malloc_fn)
    *malloc_fn = malloc_cb;

  if (realloc_fn)
    *realloc_fn = realloc_cb;

  if (free_fn)
    *free_fn = free_cb;
}

void *
torsion_malloc(size_t size) {
  void *ptr;

  if (size == 0)
    return NULL;

  ptr = (*malloc_cb)(size);

  if (ptr == NULL)
    torsion_die("torsion_malloc: allocation failure.");

  return ptr;
}

void *
torsion_alloc(size_t size) {
  void *ptr = torsion_malloc(size);

  if (size > 0)
    memset(ptr, 0, size);

  return ptr;
}

void *
torsion_realloc(void *ptr, size_t size) {
  if (ptr == NULL)
    return torsion_malloc(size);

  if (size == 0) {
    torsion_free(ptr);
    return NULL;
  }

  ptr = (*realloc_cb)(ptr, size);

  if (ptr == NULL)
    torsion_die("torsion_realloc: allocation failure.");

  return ptr;
}

void
torsion_free(void *ptr) {
  if (ptr != NULL)
    (*free_cb)(ptr);
}

/*
 * Memzero
 */

void
cleanse(void *ptr, size_t len) {
#if defined(_WIN32)
  /* https://github.com/jedisct1/libsodium/blob/3b26a5c/src/libsodium/sodium/utils.c#L112 */
  SecureZeroMemory(ptr, len);
#elif defined(__GNUC__)
  /* https://github.com/torvalds/linux/blob/37d4e84/include/linux/string.h#L233 */
  /* https://github.com/torvalds/linux/blob/37d4e84/include/linux/compiler-gcc.h#L21 */
  /* https://github.com/bminor/glibc/blob/master/string/explicit_bzero.c */
  memset(ptr, 0, len);
  __asm__ __volatile__("": :"r"(ptr) :"memory");
#else
  /* http://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html */
  static void *(*const volatile memset_ptr)(void *, int, size_t) = memset;
  (memset_ptr)(ptr, 0, len);
#endif
}

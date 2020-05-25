/*!
 * bio.h - binary parsing & serialization for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Note that the endian checks here don't matter all
 * that much. Modern GCC and Clang will optimize the
 * below functions regardless of the endian checks,
 * assuming -O2 (gcc) or -O1 (clang).
 *
 * The only case where the endian checks matter is
 * for a lesser-optimizing compiler which may be
 * able to optimize the endianness checks but not
 * the read/write.
 */

#ifndef _TORSION_BIO_H
#define _TORSION_BIO_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "internal.h"

/*
 * Little Endian
 */

static TORSION_INLINE uint16_t
read16le(const void *src) {
  if (!TORSION_BIGENDIAN) {
    uint16_t w;
    memcpy(&w, src, sizeof(w));
    return w;
  } else {
    const uint8_t *p = (const uint8_t *)src;
    return ((uint16_t)p[1] << 8)
         | ((uint16_t)p[0] << 0);
  }
}

static TORSION_INLINE void
write16le(void *dst, uint16_t w) {
  if (!TORSION_BIGENDIAN) {
    memcpy(dst, &w, sizeof(w));
  } else {
    uint8_t *p = (uint8_t *)dst;
    p[1] = w >> 8;
    p[0] = w >> 0;
  }
}

static TORSION_INLINE uint32_t
read32le(const void *src) {
  if (!TORSION_BIGENDIAN) {
    uint32_t w;
    memcpy(&w, src, sizeof(w));
    return w;
  } else {
    const uint8_t *p = (const uint8_t *)src;
    return ((uint32_t)p[3] << 24)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[0] << 0);
  }
}

static TORSION_INLINE void
write32le(void *dst, uint32_t w) {
  if (!TORSION_BIGENDIAN) {
    memcpy(dst, &w, sizeof(w));
  } else {
    uint8_t *p = (uint8_t *)dst;
    p[3] = w >> 24;
    p[2] = w >> 16;
    p[1] = w >> 8;
    p[0] = w >> 0;
  }
}

static TORSION_INLINE uint64_t
read64le(const void *src) {
  if (!TORSION_BIGENDIAN) {
    uint64_t w;
    memcpy(&w, src, sizeof(w));
    return w;
  } else {
    const uint8_t *p = (const uint8_t *)src;
    return ((uint64_t)p[7] << 56)
         | ((uint64_t)p[6] << 48)
         | ((uint64_t)p[5] << 40)
         | ((uint64_t)p[4] << 32)
         | ((uint64_t)p[3] << 24)
         | ((uint64_t)p[2] << 16)
         | ((uint64_t)p[1] << 8)
         | ((uint64_t)p[0] << 0);
  }
}

static TORSION_INLINE void
write64le(void *dst, uint64_t w) {
  if (!TORSION_BIGENDIAN) {
    memcpy(dst, &w, sizeof(w));
  } else {
    uint8_t *p = (uint8_t *)dst;
    p[7] = w >> 56;
    p[6] = w >> 48;
    p[5] = w >> 40;
    p[4] = w >> 32;
    p[3] = w >> 24;
    p[2] = w >> 16;
    p[1] = w >> 8;
    p[0] = w >> 0;
  }
}

/*
 * Big Endian
 */

static TORSION_INLINE uint16_t
read16be(const void *src) {
  if (TORSION_BIGENDIAN) {
    uint16_t w;
    memcpy(&w, src, sizeof(w));
    return w;
  } else {
    const uint8_t *p = (const uint8_t *)src;
    return ((uint16_t)p[0] << 8)
         | ((uint16_t)p[1] << 0);
  }
}

static TORSION_INLINE void
write16be(void *dst, uint16_t w) {
  if (TORSION_BIGENDIAN) {
    memcpy(dst, &w, sizeof(w));
  } else {
    uint8_t *p = (uint8_t *)dst;
    p[0] = w >> 8;
    p[1] = w >> 0;
  }
}

static TORSION_INLINE uint32_t
read32be(const void *src) {
  if (TORSION_BIGENDIAN) {
    uint32_t w;
    memcpy(&w, src, sizeof(w));
    return w;
  } else {
    const uint8_t *p = (const uint8_t *)src;
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)
         | ((uint32_t)p[3] << 0);
  }
}

static TORSION_INLINE void
write32be(void *dst, uint32_t w) {
  if (TORSION_BIGENDIAN) {
    memcpy(dst, &w, sizeof(w));
  } else {
    uint8_t *p = (uint8_t *)dst;
    p[0] = w >> 24;
    p[1] = w >> 16;
    p[2] = w >> 8;
    p[3] = w >> 0;
  }
}

static TORSION_INLINE uint64_t
read64be(const void *src) {
  if (TORSION_BIGENDIAN) {
    uint64_t w;
    memcpy(&w, src, sizeof(w));
    return w;
  } else {
    const uint8_t *p = (const uint8_t *)src;
    return ((uint64_t)p[0] << 56)
         | ((uint64_t)p[1] << 48)
         | ((uint64_t)p[2] << 40)
         | ((uint64_t)p[3] << 32)
         | ((uint64_t)p[4] << 24)
         | ((uint64_t)p[5] << 16)
         | ((uint64_t)p[6] << 8)
         | ((uint64_t)p[7] << 0);
  }
}

static TORSION_INLINE void
write64be(void *dst, uint64_t w) {
  if (TORSION_BIGENDIAN) {
    memcpy(dst, &w, sizeof(w));
  } else {
    uint8_t *p = (uint8_t *)dst;
    p[0] = w >> 56;
    p[1] = w >> 48;
    p[2] = w >> 40;
    p[3] = w >> 32;
    p[4] = w >> 24;
    p[5] = w >> 16;
    p[6] = w >> 8;
    p[7] = w >> 0;
  }
}

#endif /* _TORSION_BIO_H */

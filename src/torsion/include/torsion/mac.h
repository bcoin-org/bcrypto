/*!
 * mac.h - macs for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef _TORSION_MAC_H
#define _TORSION_MAC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "common.h"

/*
 * Symbol Aliases
 */

#define poly1305_init torsion_poly1305_init
#define poly1305_update torsion_poly1305_update
#define poly1305_final torsion_poly1305_final
#define poly1305_auth torsion_poly1305_auth
#define poly1305_verify torsion_poly1305_verify
#define siphash torsion_siphash
#define siphash32 torsion_siphash32
#define siphash64 torsion_siphash64
#define siphash32k256 torsion_siphash32k256
#define siphash64k256 torsion_siphash64k256
#define sipmod torsion_sipmod

/*
 * Structs
 */

typedef struct _poly1305_s {
  size_t aligner;
  unsigned char opaque[136];
} poly1305_t;

/*
 * Poly1305
 */

TORSION_EXTERN void
poly1305_init(poly1305_t *ctx, const unsigned char *key);

TORSION_EXTERN void
poly1305_update(poly1305_t *ctx, const unsigned char *m, size_t bytes);

TORSION_EXTERN void
poly1305_final(poly1305_t *ctx, unsigned char *mac);

TORSION_EXTERN void
poly1305_auth(unsigned char *mac,
              const unsigned char *m,
              size_t bytes,
              const unsigned char *key);

TORSION_EXTERN int
poly1305_verify(const unsigned char *mac1, const unsigned char *mac2);

/*
 * Siphash
 */

TORSION_EXTERN uint64_t
siphash(const unsigned char *data, size_t len, const unsigned char *key);

TORSION_EXTERN uint32_t
siphash32(uint32_t num, const unsigned char *key);

TORSION_EXTERN uint64_t
siphash64(uint64_t num, const unsigned char *key);

TORSION_EXTERN uint32_t
siphash32k256(uint32_t num, const unsigned char *key);

TORSION_EXTERN uint64_t
siphash64k256(uint64_t num, const unsigned char *key);

TORSION_EXTERN uint64_t
sipmod(const unsigned char *data,
       size_t len,
       const unsigned char *key,
       uint64_t m);

#ifdef __cplusplus
}
#endif

#endif /* _TORSION_MAC_H */

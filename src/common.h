#ifndef _BCRYPTO_COMMON_H
#define _BCRYPTO_COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define READU32(b) \
  (((uint32_t)((b)[0])) | ((uint32_t)((b)[1]) << 8) \
  | ((uint32_t)((b)[2]) << 16) | ((uint32_t)((b)[3]) << 24))

#define READU64(b) ((uint64_t)(READU32(b + 4)) << 32) | (uint64_t)(READU32(b))

#define WRITEU32(b, n) \
  ((b)[0] = n & 0xff, (b)[1] = (n >> 8) & 0xff, \
  (b)[2] = (n >> 16) & 0xff, (b)[3] = (n >> 24) & 0xff)

#define WRITEU64(b, n) \
  (WRITEU32(b + 4, (n >> 32)), WRITEU32(b, (n & 0xffffffff)))

#endif // _BCRYPTO_COMMON_H

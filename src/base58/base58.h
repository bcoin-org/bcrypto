#ifndef _BCRYPTO_BASE58_H
#define _BCRYPTO_BASE58_H

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define base58_encode _bcrypto_base58_encode
#define base58_decode _bcrypto_base58_decode
#define base58_test _bcrypto_base58_test

#define BASE58_ENCODE_MAX 1073741823ul /* 2^30 - 1 */
#define BASE58_ENCODE_SIZE(n) ((uint64_t)(n) * 138 / 100 + 1)

#define BASE58_DECODE_MAX 1481763716ul /* (2^30 - 1) * 138 / 100 + 1 */
#define BASE58_DECODE_SIZE(n) ((uint64_t)(n) * 733 / 100 + 1)

int
base58_encode(char *str, size_t *str_len,
              const uint8_t *data, size_t data_len);

int
base58_decode(uint8_t *data, size_t *data_len,
              const char *str, size_t str_len);

int
base58_test(const char *str, size_t str_len);

#ifdef __cplusplus
}
#endif

#endif

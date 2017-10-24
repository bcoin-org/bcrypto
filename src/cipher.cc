#include <stdint.h>

#include "cipher.h"
#include "common.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/aes.h"
#include "common.h"

static inline void
XOR(uint8_t *out, uint8_t *a, uint8_t *b) {
  uint32_t i;
  for (i = 0; i < 16; i++)
    out[i] = a[i] ^ b[i];
}

#ifdef BCRYPTO_USE_CIPHER
bool
bcrypto_cipher(
  const char *name,
  const uint8_t *data,
  const uint32_t datalen,
  const uint8_t *key,
  const uint32_t keylen,
  const uint8_t *iv,
  const uint32_t ivlen,
  uint8_t **out,
  uint32_t *outlen,
  const bool encrypt
) {
  const EVP_CIPHER *cipher = EVP_get_cipherbyname(name);
  EVP_CIPHER_CTX ctx;

  if (cipher == NULL)
    return false;

  if (EVP_CIPHER_iv_length(cipher) != (int32_t)ivlen
      && !(EVP_CIPHER_mode(cipher) == EVP_CIPH_ECB_MODE && ivlen == 0)
      && !(EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE) && ivlen > 0) {
    return false;
  }

  EVP_CIPHER_CTX_init(&ctx);
  EVP_CipherInit_ex(&ctx, cipher, NULL, NULL, NULL, encrypt);

  if (EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE
      && (int32_t)ivlen != EVP_CIPHER_iv_length(cipher)) {
    if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL)) {
      EVP_CIPHER_CTX_cleanup(&ctx);
      return false;
    }
  }

  if (!EVP_CIPHER_CTX_set_key_length(&ctx, keylen)) {
    EVP_CIPHER_CTX_cleanup(&ctx);
    return false;
  }

  EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, encrypt);

  int32_t rlen = datalen + EVP_CIPHER_CTX_block_size(&ctx);
  uint8_t *rdata = (unsigned uint8_t *)malloc(rlen);

  if (rdata == NULL) {
    EVP_CIPHER_CTX_cleanup(&ctx);
    return false;
  }

  int32_t r = EVP_CipherUpdate(&ctx, rdata, &rlen, data, datalen);

  if (r <= 0) {
    free(rdata);
    EVP_CIPHER_CTX_cleanup(&ctx);
    return false;
  }

  *outlen = rlen;

  r = EVP_CipherFinal_ex(&ctx, rdata + rlen, &rlen);

  *outlen += rlen;
  *out = rdata;

  EVP_CIPHER_CTX_cleanup(&ctx);

  if (r <= 0) {
    free(rdata);
    return false;
  }

  return true;
}
#endif

bool
bcrypto_encipher(
  const uint8_t *data,
  const uint32_t datalen,
  const uint8_t *key,
  const uint8_t *iv,
  uint8_t *out,
  uint32_t *outlen
) {
  uint8_t *pblock = (uint8_t *)data;
  uint8_t *cblock = out;
  uint8_t *pprev = pblock;
  uint8_t *cprev = (uint8_t *)iv;
  uint32_t blocks = datalen / 16;
  uint32_t trailing = datalen % 16;
  uint32_t i;

  AES_KEY enckey;
  AES_set_encrypt_key(key, 256, &enckey);

  if (*outlen != datalen + (16 - trailing))
    return false;

  // Encrypt all blocks except for the last.
  for (i = 0; i < blocks; i++) {
    XOR(cblock, pblock, cprev);
    AES_encrypt(cblock, cblock, &enckey);
    cprev = cblock;
    cblock += 16;
    pblock += 16;
    pprev = pblock;
  }

  // Handle padding on the last block.
  uint8_t *last = cblock;
  uint32_t left = 16 - trailing;

  memcpy(last, pprev, trailing);

  for (i = trailing; i < 16; i++)
    last[i] = left;

  // Encrypt the last block,
  // as well as the padding.
  XOR(cblock, last, cprev);
  AES_encrypt(cblock, cblock, &enckey);

  return true;
}

bool
bcrypto_decipher(
  const uint8_t *data,
  const uint32_t datalen,
  const uint8_t *key,
  const uint8_t *iv,
  uint8_t *out,
  uint32_t *outlen
) {
  uint8_t *pblock = out;
  uint8_t *cblock = (uint8_t *)data;
  uint8_t *pprev = pblock;
  uint8_t *cprev = (uint8_t *)iv;
  uint32_t blocks = datalen / 16;
  uint32_t trailing = datalen % 16;
  uint32_t i;

  if (*outlen != datalen)
    return false;

  if (trailing != 0)
    return false;

  AES_KEY deckey;
  AES_set_decrypt_key(key, 256, &deckey);

  // Decrypt all blocks.
  for (i = 0; i < blocks; i++) {
    AES_decrypt(cblock, pblock, &deckey);
    XOR(pblock, pblock, cprev);
    cprev = cblock;
    pprev = pblock;
    cblock += 16;
    pblock += 16;
  }

  // Check padding on the last block.
  uint8_t *last = pprev;
  uint32_t b = 16;
  uint32_t n = last[b - 1];

  if (n == 0 || n > b)
    return false;

  for (i = 0; i < n; i++) {
    if (last[--b] != n)
      return false;
  }

  *outlen = datalen - n;

  return true;
}

#include "cipher.h"

size_t
bcrypto_cipher_block_size(int type) {
  switch (type) {
    case BCRYPTO_CIPHER_AES128:
    case BCRYPTO_CIPHER_AES192:
    case BCRYPTO_CIPHER_AES256:
      return 16;
    case BCRYPTO_CIPHER_BLOWFISH:
      return 8;
    case BCRYPTO_CIPHER_CAMELLIA128:
    case BCRYPTO_CIPHER_CAMELLIA192:
    case BCRYPTO_CIPHER_CAMELLIA256:
      return 16;
    case BCRYPTO_CIPHER_CAST5:
      return 8;
    case BCRYPTO_CIPHER_DES:
    case BCRYPTO_CIPHER_DES_EDE:
    case BCRYPTO_CIPHER_DES_EDE3:
      return 8;
    case BCRYPTO_CIPHER_IDEA:
      return 8;
    case BCRYPTO_CIPHER_RC2:
      return 8;
    case BCRYPTO_CIPHER_TWOFISH128:
    case BCRYPTO_CIPHER_TWOFISH192:
    case BCRYPTO_CIPHER_TWOFISH256:
      return 16;
    default:
      return 0;
  }
}

size_t
bcrypto_cipher_key_size(int type) {
  switch (type) {
    case BCRYPTO_CIPHER_AES128:
      return 16;
    case BCRYPTO_CIPHER_AES192:
      return 24;
    case BCRYPTO_CIPHER_AES256:
      return 32;
    case BCRYPTO_CIPHER_BLOWFISH:
      return 16;
    case BCRYPTO_CIPHER_CAMELLIA128:
      return 16;
    case BCRYPTO_CIPHER_CAMELLIA192:
      return 24;
    case BCRYPTO_CIPHER_CAMELLIA256:
      return 32;
    case BCRYPTO_CIPHER_CAST5:
      return 16;
    case BCRYPTO_CIPHER_DES:
      return 8;
    case BCRYPTO_CIPHER_DES_EDE:
      return 16;
    case BCRYPTO_CIPHER_DES_EDE3:
      return 24;
    case BCRYPTO_CIPHER_IDEA:
      return 16;
    case BCRYPTO_CIPHER_RC2:
      return 8;
    case BCRYPTO_CIPHER_TWOFISH128:
      return 16;
    case BCRYPTO_CIPHER_TWOFISH192:
      return 24;
    case BCRYPTO_CIPHER_TWOFISH256:
      return 32;
    default:
      return 0;
  }
}

const struct nettle_cipher *
bcrypto_cipher_get(int type) {
  switch (type) {
    case BCRYPTO_CIPHER_AES128:
      return &nettle_aes128;
    case BCRYPTO_CIPHER_AES192:
      return &nettle_aes192;
    case BCRYPTO_CIPHER_AES256:
      return &nettle_aes256;
    case BCRYPTO_CIPHER_BLOWFISH:
      return &nettle_blowfish128;
    case BCRYPTO_CIPHER_CAMELLIA128:
      return &nettle_camellia128;
    case BCRYPTO_CIPHER_CAMELLIA192:
      return &nettle_camellia192;
    case BCRYPTO_CIPHER_CAMELLIA256:
      return &nettle_camellia256;
    case BCRYPTO_CIPHER_CAST5:
      return NULL;
    case BCRYPTO_CIPHER_DES:
      return &nettle_des;
    case BCRYPTO_CIPHER_DES_EDE:
      return NULL;
    case BCRYPTO_CIPHER_DES_EDE3:
      return &nettle_des3;
    case BCRYPTO_CIPHER_IDEA:
      return NULL;
    case BCRYPTO_CIPHER_RC2:
      return &nettle_arctwo64;
    case BCRYPTO_CIPHER_TWOFISH128:
      return &nettle_twofish128;
    case BCRYPTO_CIPHER_TWOFISH192:
      return &nettle_twofish192;
    case BCRYPTO_CIPHER_TWOFISH256:
      return &nettle_twofish256;
    default:
      return 0;
  }
}

const struct nettle_aead *
bcrypto_cipher_gcm(int type) {
  switch (type) {
    case BCRYPTO_CIPHER_AES128:
      return &nettle_gcm_aes128;
    case BCRYPTO_CIPHER_AES192:
      return &nettle_gcm_aes192;
    case BCRYPTO_CIPHER_AES256:
      return &nettle_gcm_aes256;
    case BCRYPTO_CIPHER_CAMELLIA128:
      return &nettle_gcm_camellia128;
    case BCRYPTO_CIPHER_CAMELLIA192:
      return NULL;
    case BCRYPTO_CIPHER_CAMELLIA256:
      return &nettle_gcm_camellia256;
    default:
      return NULL;
  }
}

void
bcrypto_cipher_init(bcrypto_cipher_t *cipher) {
  memset((void *)cipher, 0x00, sizeof(bcrypto_cipher_t));
  cipher->ctx = NULL;
}

int
bcrypto_cipher_setup(bcrypto_cipher_t *cipher,
                     int type, int mode, int encrypt) {
  bcrypto_cipher_clear(cipher);

  cipher->type = type;
  cipher->desc = bcrypto_cipher_get(type);

  if (cipher->desc == NULL)
    return 0;

  if (mode == BCRYPTO_MODE_GCM) {
    cipher->aead = bcrypto_cipher_gcm(type);
    if (cipher->aead == NULL)
      return 0;
  } else {
    cipher->aead = NULL;
  }

  size_t ctx_size = cipher->aead != NULL
    ? cipher->aead->context_size
    : cipher->desc->context_size;

  cipher->ctx = (void *)malloc(ctx_size);

  if (cipher->ctx == NULL)
    return 0;

  memset(cipher->ctx, 0x00, ctx_size);

  cipher->mode = mode;
  assert(mode >= BCRYPTO_MODE_MIN && mode <= BCRYPTO_MODE_MAX);

  cipher->encrypt = encrypt;

  return 1;
}

void
bcrypto_cipher_clear(bcrypto_cipher_t *cipher) {
  cipher->type = 0;
  cipher->desc = NULL;
  cipher->aead = NULL;

  if (cipher->ctx != NULL) {
    free(cipher->ctx);
    cipher->ctx = NULL;
  }

  memset(&cipher->state[0], 0x00, BCRYPTO_CIPHER_MAX_BLOCK_SIZE);
  memset(&cipher->block[0], 0x00, BCRYPTO_CIPHER_MAX_BLOCK_SIZE);
  memset(&cipher->last[0], 0x00, BCRYPTO_CIPHER_MAX_BLOCK_SIZE);

  cipher->last_size = 0;
  cipher->mode = 0;
  cipher->encrypt = 0;
  cipher->block_pos = 0;
}

int
bcrypto_cipher_set_key(bcrypto_cipher_t *cipher,
                       const uint8_t *key, size_t length) {
  if (cipher->aead != NULL) {
    if (length != cipher->desc->key_size)
      return 0;

    if (cipher->encrypt)
      cipher->aead->set_encrypt_key(cipher->ctx, key);
    else
      cipher->aead->set_decrypt_key(cipher->ctx, key);

    return 1;
  }

  if (cipher->type == BCRYPTO_CIPHER_BLOWFISH) {
    if (length < 4 || length > 72)
      return 0;
    blowfish_set_key(cipher->ctx, length, key);
    return 1;
  }

  if (cipher->type == BCRYPTO_CIPHER_RC2) {
    if (length < 1 || length > 128)
      return 0;
    arctwo_set_key_ekb(cipher->ctx, length, key, length * 8);
    return 1;
  }

  if (length != cipher->desc->key_size)
    return 0;

  if (cipher->encrypt || cipher->mode > BCRYPTO_MODE_CBC)
    cipher->desc->set_encrypt_key(cipher->ctx, key);
  else
    cipher->desc->set_decrypt_key(cipher->ctx, key);

  return 1;
}

int
bcrypto_cipher_set_iv(bcrypto_cipher_t *cipher,
                      const uint8_t *iv, size_t length) {
  if (cipher->aead != NULL) {
    switch (cipher->type) {
      case BCRYPTO_CIPHER_AES128:
        gcm_aes128_set_iv(cipher->ctx, length, iv);
        return 1;
      case BCRYPTO_CIPHER_AES192:
        gcm_aes192_set_iv(cipher->ctx, length, iv);
        return 1;
      case BCRYPTO_CIPHER_AES256:
        gcm_aes256_set_iv(cipher->ctx, length, iv);
        return 1;
      case BCRYPTO_CIPHER_CAMELLIA128:
        gcm_camellia128_set_iv(cipher->ctx, length, iv);
        return 1;
      case BCRYPTO_CIPHER_CAMELLIA256:
        gcm_camellia256_set_iv(cipher->ctx, length, iv);
        return 1;
      default:
        return 0;
    }
  }

  if (length == 0)
    return 1;

  if (length != cipher->desc->block_size)
    return 0;

  memcpy(cipher->state, iv, cipher->desc->block_size);

  return 1;
}

int
bcrypto_cipher_auth(bcrypto_cipher_t *cipher, const uint8_t *data, size_t len) {
  if (cipher->aead == NULL)
    return 0;

  cipher->aead->update(cipher->ctx, len, data);
  return 1;
}

int
bcrypto_cipher_digest(bcrypto_cipher_t *cipher, uint8_t *data, size_t len) {
  if (cipher->aead == NULL)
    return 0;

  cipher->aead->digest(cipher->ctx, len, data);
  return 1;
}

size_t
bcrypto_cipher_update(bcrypto_cipher_t *cipher, uint8_t *dst,
                     const uint8_t *src, size_t length) {
  size_t block_size = cipher->desc->block_size;
  size_t block_pos = cipher->block_pos;
  size_t ilen = length;
  size_t olen = ilen - (ilen % block_size);
  size_t ipos = 0;
  size_t opos = 0;

  cipher->block_pos = (cipher->block_pos + ilen) % block_size;

  if (block_pos > 0) {
    size_t want = block_size - block_pos;

    if (want > ilen)
      want = ilen;

    memcpy(&cipher->block[block_pos], &src[ipos], want);

    block_pos += want;
    ilen -= want;
    ipos += want;

    if (block_pos < block_size)
      return 0;

    olen += block_size;
  }

  olen += cipher->last_size;
  memcpy(&dst[opos], &cipher->last[0], cipher->last_size);
  opos += cipher->last_size;

  if (ipos) {
    bcrypto_cipher_crypt(cipher, &dst[opos], &cipher->block[0], block_size);
    opos += block_size;
  }

  while (ilen >= block_size) {
    bcrypto_cipher_crypt(cipher, &dst[opos], &src[ipos], block_size);
    opos += block_size;
    ipos += block_size;
    ilen -= block_size;
  }

  if (ilen > 0)
    memcpy(&cipher->block[0], &src[ipos], ilen);

  if (!cipher->encrypt && cipher->mode <= BCRYPTO_MODE_CBC) {
    if (olen > 0) {
      cipher->last_size = block_size;
      memcpy(&cipher->last[0], &dst[olen - block_size], block_size);
      return olen - block_size;
    }

    cipher->last_size = 0;
    memset(&cipher->last[0], 0x00, block_size);
  }

  return olen;
}

void
bcrypto_cipher_crypt(bcrypto_cipher_t *cipher, uint8_t *dst,
                     const uint8_t *src, size_t length) {
  size_t block_size = cipher->desc->block_size;
  uint8_t *state = (uint8_t *)cipher->state;

  nettle_cipher_func *fn = cipher->encrypt || cipher->mode > BCRYPTO_MODE_CBC
    ? cipher->desc->encrypt
    : cipher->desc->decrypt;

  switch (cipher->mode) {
    case BCRYPTO_MODE_ECB: {
      fn(cipher->ctx, length, dst, src);
      break;
    }

    case BCRYPTO_MODE_CBC: {
      if (cipher->encrypt)
        cbc_encrypt(cipher->ctx, fn, block_size, state, length, dst, src);
      else
        cbc_decrypt(cipher->ctx, fn, block_size, state, length, dst, src);
      break;
    }

    case BCRYPTO_MODE_CTR: {
      ctr_crypt(cipher->ctx, fn, block_size, state, length, dst, src);
      break;
    }

    case BCRYPTO_MODE_CFB: {
      if (cipher->encrypt)
        cfb_encrypt(cipher->ctx, fn, block_size, state, length, dst, src);
      else
        cfb_decrypt(cipher->ctx, fn, block_size, state, length, dst, src);
      break;
    }

    case BCRYPTO_MODE_OFB: {
      assert(length % block_size == 0);

      for (size_t i = 0; i < length; i += block_size) {
        fn(cipher->ctx, block_size, state, state);
	      memxor3(dst, src, state, block_size);
      }

      break;
    }

    case BCRYPTO_MODE_GCM: {
      assert(cipher->aead != NULL);

      nettle_crypt_func *fn = cipher->encrypt
        ? cipher->aead->encrypt
        : cipher->aead->decrypt;

      fn(cipher->ctx, length, dst, src);

      break;
    }

    default: {
      assert(0 && "invalid mode");
      break;
    }
  }
}

int
bcrypto_cipher_final(bcrypto_cipher_t *cipher, uint8_t *out) {
  size_t block_size = cipher->desc->block_size;
  size_t block_pos = cipher->block_pos;

  switch (cipher->mode) {
    case BCRYPTO_MODE_ECB:
    case BCRYPTO_MODE_CBC: {
      if (cipher->encrypt) {
        size_t left = block_size - block_pos;
        uint8_t *block = cipher->block;

        memset(&block[block_pos], left, block_size - block_pos);

        bcrypto_cipher_crypt(cipher, out, block, block_size);

        return block_size;
      }

      if (cipher->block_pos != 0)
        return -1;

      size_t left = (size_t)cipher->last[block_size - 1];

      if (left == 0 || left > block_size)
        return -1;

      size_t end = block_size - left;

      for (size_t i = end; i < block_size; i++) {
        if (cipher->last[i] != left)
          return -1;
      }

      memcpy(&out[0], &cipher->last[0], end);

      return end;
    }

    case BCRYPTO_MODE_CTR: {
      bcrypto_cipher_crypt(cipher, out, cipher->block, block_pos);
      return block_pos;
    }

    case BCRYPTO_MODE_CFB: {
      bcrypto_cipher_crypt(cipher, out, cipher->block, block_pos);
      return block_pos;
    }

    case BCRYPTO_MODE_OFB: {
      bcrypto_cipher_crypt(cipher, out, cipher->block, block_size /* needed */);
      return block_pos;
    }

    case BCRYPTO_MODE_GCM: {
      bcrypto_cipher_crypt(cipher, out, cipher->block, block_pos);
      return block_pos;
    }

    default: {
      return -1;
    }
  }
}

int
bcrypto_cipher_verify(bcrypto_cipher_t *cipher,
                      const uint8_t *expect, size_t len) {
  uint8_t tag[BCRYPTO_CIPHER_MAX_BLOCK_SIZE];

  if (len == 0 || len > cipher->desc->block_size)
    return 0;

  if (!bcrypto_cipher_digest(cipher, tag, len))
    return 0;

  unsigned int v = 0;

  for (size_t i = 0; i < len; i++)
    v |= tag[i] ^ expect[i];

  return (v - 1) >> 31;
}

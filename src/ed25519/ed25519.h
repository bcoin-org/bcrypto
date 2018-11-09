#ifndef _BCRYPTO_ED25519_H
#define _BCRYPTO_ED25519_H

#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef unsigned char bcrypto_ed25519_signature[64];
typedef unsigned char bcrypto_ed25519_public_key[32];
typedef unsigned char bcrypto_ed25519_secret_key[32];
typedef unsigned char bcrypto_curved25519_key[32];

void
bcrypto_ed25519_publickey(
  const bcrypto_ed25519_secret_key sk,
  bcrypto_ed25519_public_key pk
);

int
bcrypto_ed25519_sign_open(
  const unsigned char *m,
  size_t mlen,
  const bcrypto_ed25519_public_key pk,
  const bcrypto_ed25519_signature RS
);

int
bcrypto_ed25519_verify_key(const bcrypto_ed25519_public_key pk);

void
bcrypto_ed25519_sign(
  const unsigned char *m,
  size_t mlen,
  const bcrypto_ed25519_secret_key sk,
  const bcrypto_ed25519_public_key pk,
  bcrypto_ed25519_signature RS
);

int
bcrypto_ed25519_sign_open_batch(
  const unsigned char **m,
  size_t *mlen,
  const unsigned char **pk,
  const unsigned char **RS,
  size_t num,
  int *valid
);

void
bcrypto_ed25519_randombytes_unsafe(void *out, size_t count);

void
bcrypto_curved25519_scalarmult_basepoint(
  bcrypto_curved25519_key pk,
  const bcrypto_curved25519_key e
);

void
bcrypto_ed25519_privkey_convert(
  bcrypto_ed25519_secret_key out,
  const bcrypto_ed25519_secret_key sk
);

int
bcrypto_ed25519_pubkey_convert(
  bcrypto_curved25519_key out,
  const bcrypto_ed25519_public_key pk
);

int
bcrypto_ed25519_pubkey_deconvert(
  bcrypto_ed25519_public_key out,
  const bcrypto_curved25519_key pk,
  int sign
);

int
bcrypto_ed25519_derive(
  bcrypto_curved25519_key out,
  const bcrypto_ed25519_public_key pk,
  const bcrypto_ed25519_secret_key sk
);

int
bcrypto_ed25519_exchange(
  bcrypto_curved25519_key out,
  const bcrypto_curved25519_key xpk,
  const bcrypto_ed25519_secret_key sk
);

int
bcrypto_ed25519_privkey_tweak_add(
  bcrypto_ed25519_secret_key out,
  const bcrypto_ed25519_secret_key sk,
  const bcrypto_ed25519_secret_key tweak
);

int
bcrypto_ed25519_pubkey_tweak_add(
  bcrypto_ed25519_public_key out,
  const bcrypto_ed25519_public_key pk,
  const bcrypto_ed25519_secret_key tweak
);

int
bcrypto_ed25519_sign_tweak(
  const unsigned char *m,
  size_t mlen,
  const bcrypto_ed25519_secret_key sk,
  const bcrypto_ed25519_public_key pk,
  const bcrypto_ed25519_secret_key tweak,
  bcrypto_ed25519_signature RS
);

#if defined(__cplusplus)
}
#endif

#endif // _BCRYPTO_ED25519_H

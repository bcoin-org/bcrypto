#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <mutex>
#include "nettle/yarrow.h"
#include "random.h"

static std::mutex m;
static struct yarrow_source source;
static struct yarrow256_ctx rng;
static int rounds = 0;

#if defined(__linux__) && (__GLIBC__ > 2 || __GLIBC_MINOR__ >= 25)
#include <sys/random.h>

static int
get_entropy(void *dst, size_t len) {
  const ssize_t ret = getrandom(dst, len, GRND_NONBLOCK);

  if (ret < 0 || (size_t)ret != len)
    return 0;

  return 1;
}

#elif defined(__APPLE__) && defined(HAVE_APPLE_FRAMEWORK)

#include <Security/Security.h>

static int
get_entropy(void *dst, size_t len) {
  if (SecRandomCopyBytes(kSecRandomDefault, len, dst) == errSecSuccess)
    return 1;
  return 0;
}

#elif defined(__linux__) || defined(__APPLE__)

#include <stdio.h>

static int
get_entropy(void *dst, size_t len) {
  FILE *urandom = fopen("/dev/urandom", "r");

  if (!urandom)
    return 0;

  size_t nbytes = fread(dst, 1, len, urandom);

  fclose(urandom);

  return nbytes == len;
}

#elif defined(_WIN16) || defined(_WIN32) || defined(_WIN64)

#if defined(HAVE_WINCRYPT_H)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

static int
get_entropy(void *dst, size_t len) {
  HCRYPTPROV prov;

  BOOL r = CryptAcquireContext(
    &prov,
    NULL,
    NULL,
    PROV_RSA_FULL,
    CRYPT_VERIFYCONTEXT
  );

  if (!r)
    return 0;

  CryptGenRandom(prov, len, (BYTE *)dst);
  CryptReleaseContext(prov, 0);

  return 1;
}
#else
#include <windows.h>

static int
get_entropy(void *dst, size_t len) {
  NTSTATUS r = BCryptGenRandom(NULL, dst, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

  if (!BCRYPT_SUCCESS(r))
    return 0;

  return 1;
}
#endif
#endif

static void
bcrypto__poll() {
  unsigned char slab[64];

  if (rounds == 0) {
    yarrow256_init(&rng, 1, &source);

    for (;;) {
      if (!get_entropy(&slab[0], 64))
        continue;

      yarrow256_seed(&rng, 64, &slab[0]);
      break;
    }

    rounds = 1;
  }

  for (;;) {
    if (!get_entropy(&slab[0], 64))
      continue;

    yarrow256_update(&rng, 0, 512, 64, &slab[0]);
    break;
  }
}

void
bcrypto_poll(void) {
  m.lock();
  bcrypto__poll();
  m.unlock();
}

int
bcrypto_random(void *dst, size_t len) {
  m.lock();

  if ((rounds % 1000) == 0)
    bcrypto__poll();

  yarrow256_random(&rng, len, (uint8_t *)dst);
  rounds += 1;

  m.unlock();

  return 1;
}

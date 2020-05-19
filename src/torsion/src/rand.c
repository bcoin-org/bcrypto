/*!
 * rand.c - rng for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on jedisct1/libsodium:
 *   Copyright (c) 2013-2020, Frank Denis (ISC License).
 *   https://github.com/jedisct1/libsodium
 *
 * Parts of this software are based on bitcoin/bitcoin:
 *   Copyright (c) 2009-2019, The Bitcoin Core Developers (MIT License).
 *   Copyright (c) 2009-2019, The Bitcoin Developers (MIT License).
 *   https://github.com/bitcoin/bitcoin
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Entropy-supplying_system_calls
 *   https://github.com/jedisct1/libsodium/blob/master/src/libsodium/randombytes/internal/randombytes_internal_random.c
 *   https://github.com/bitcoin/bitcoin/blob/master/src/random.cpp
 */

#ifdef __linux__
/* For syscall(2). */
#  define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_MSC_VER) && !defined(__BORLANDC__)
#  include <unistd.h>
#endif

#include <sys/types.h>

#ifndef _WIN32
#  include <sys/stat.h>
#  include <sys/time.h>
#endif

#ifdef __linux__
#  include <poll.h>
#endif

#define HAVE_DEV_RANDOM

#if defined(__GNUC__) || defined(__clang__)
#  define HAVE_INLINE_ASM
#endif

#ifdef _WIN32
/* https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-rtlgenrandom */
#  include <windows.h>
#  include <sys/timeb.h>
#  define RtlGenRandom SystemFunction036
#  ifdef __cplusplus
extern "C"
#  endif
BOOLEAN NTAPI RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);
#  pragma comment(lib, "advapi32.lib")
#  ifdef __BORLANDC__
#    define _ftime ftime
#    define _timeb timeb
#  endif
#endif

#ifdef __linux__
/* http://man7.org/linux/man-pages/man2/getrandom.2.html */
#  include <sys/syscall.h>
#  if defined(SYS_getrandom) && defined(__NR_getrandom)
#    define getrandom(B, S, F) syscall(SYS_getrandom, (B), (int)(S), (F))
#    define HAVE_GETRANDOM
#  endif
#endif

#ifdef __APPLE__
/* https://www.unix.com/man-page/mojave/2/getentropy/ */
/* https://developer.apple.com/documentation/security/1399291-secrandomcopybytes?language=objc */
#  include <Availability.h>
#  include <TargetConditionals.h>
#  if TARGET_OS_IPHONE
#    if __IPHONE_OS_VERSION_MAX_ALLOWED >= 20000 /* 2.0 */
#      include <Secure/SecRandom.h>
#      define HAVE_SECRANDOM
#    endif
#  else
#    if __MAC_OS_X_VERSION_MAX_ALLOWED >= 101200 /* 10.12 */
#      include <sys/random.h>
#      define HAVE_GETENTROPY
#    elif __MAC_OS_X_VERSION_MAX_ALLOWED >= 1070 /* 10.7 */
#      include <Secure/SecRandom.h>
#      define HAVE_SECRANDOM
#    endif
#  endif
#endif

#ifdef __OpenBSD__
/* https://man.openbsd.org/getentropy.2 */
#  include <sys/param.h>
#  if defined(OpenBSD) && OpenBSD >= 201411 /* 5.6 */
#    define HAVE_GETENTROPY
#  endif
#endif

#ifdef __FreeBSD__
/* https://www.freebsd.org/cgi/man.cgi?query=getrandom&manpath=FreeBSD+12.0-stable */
#  include <sys/param.h>
#  if defined(__FreeBSD_version) && __FreeBSD_version >= 1200000 /* 12.0 */
#    include <sys/random.h>
#    define HAVE_GETRANDOM
#  endif
#endif

#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__)
/* https://github.com/openbsd/src/blob/2981a53/sys/sys/sysctl.h#L140 */
/* https://www.freebsd.org/cgi/man.cgi?sysctl(3) */
/* https://netbsd.gw.com/cgi-bin/man-cgi?sysctl+7+NetBSD-8.0 */
#  include <sys/sysctl.h>
#  if defined(CTL_KERN) && defined(KERN_ARND)
#    define HAVE_SYSCTL_ARND
#  endif
#endif

#if defined(__sun) && defined(__SVR4) /* 11.3 */
/* https://docs.oracle.com/cd/E88353_01/html/E37841/getrandom-2.html */
/* FIXME: Seemingly no way to detect OS version here. */
#  include <sys/random.h>
#  define HAVE_GETRANDOM
#endif

#ifdef __Fuchsia__
/* https://fuchsia.dev/fuchsia-src/zircon/syscalls/cprng_draw */
#  include <zircon/syscalls.h>
#  define HAVE_CPRNG_DRAW
#endif

#if defined(__OpenBSD__) || defined(__CloudABI__) || defined(__wasi__)
/* https://man.openbsd.org/arc4random */
#  define HAVE_SAFE_ARC4RANDOM
#endif

#if defined(_WIN32) || defined(__CloudABI__) || defined(__wasm__)
#  undef HAVE_DEV_RANDOM
#endif

#ifdef __EMSCRIPTEN__
/* https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues */
/* https://nodejs.org/api/crypto.html#crypto_crypto_randomfillsync_buffer_offset_size */
/* https://emscripten.org/docs/api_reference/emscripten.h.html */
EM_JS(int, js_getrandom, (void *ptr, size_t len), {
  try {
    var crypto = null;

    if (typeof window !== 'undefined' && window)
      crypto = window.crypto || window.msCrypto;
    else if (typeof self !== 'undefined' && self)
      crypto = self.crypto || self.msCrypto;

    if (crypto) {
      var left = 65536;

      while (len > 0) {
        if (left > len)
          left = len;

        var buf = HEAP8.subarray(ptr, ptr + left);

        crypto.getRandomValues(buf);

        ptr += left;
        len -= left;
      }
    } else {
      var buf = require('buffer').Buffer.from(HEAP8.buffer, ptr, len);

      require('crypto').randomFillSync(buf, 0, len);
    }

    return 1;
  } catch (e) {
    return 0;
  }
});
#  define HAVE_JS_GETRANDOM
#endif

#ifdef HAVE_INLINE_ASM
/* https://software.intel.com/content/www/us/en/develop/articles/
   intel-digital-random-number-generator-drng-software-implementation-guide.html */
#  if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
#    ifdef __GNUC__
#      include <cpuid.h>
#    endif
#    define HAVE_CPUID
#  endif
#endif

#ifndef S_ISNAM
#  ifdef __COMPCERT__
#    define S_ISNAM(x) 1
#  else
#    define S_ISNAM(x) 0
#  endif
#endif

#include <torsion/chacha20.h>
#include <torsion/rand.h>
#include "internal.h"

/*
 * Helpers
 */

#ifdef HAVE_DEV_RANDOM
static int
device_open(const char *device) {
  struct stat st;
  int fd;

  for (;;) {
    fd = open(device, O_RDONLY);

    if (fd == -1) {
      if (errno == EINTR)
        continue;

      return -1;
    }

    if (fstat(fd, &st) != 0) {
      (void)close(fd);
      return -1;
    }

    /* Ensure this is a character device. */
    if (!S_ISNAM(st.st_mode) && !S_ISCHR(st.st_mode)) {
      (void)close(fd);
      return -1;
    }

#if defined(F_SETFD) && defined(FD_CLOEXEC)
    /* Close on exec(). */
    (void)fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif

    return fd;
  }
}

static int
device_read(int fd, void *dst, size_t size) {
  unsigned char *data = (unsigned char *)dst;
  ssize_t nread;

  while (size > 0) {
    for (;;) {
      nread = read(fd, data, size);

      if (nread < 0) {
        if (errno == EINTR || errno == EAGAIN)
          continue;
      }

      break;
    }

    if (nread <= 0)
      break;

    ASSERT(size >= (size_t)nread);

    data += nread;
    size -= nread;
  }

  return size == 0;
}

#ifdef __linux__
static int
poll_dev_random(void) {
  struct pollfd pfd;
  int fd, ret;

  fd = open("/dev/random", O_RDONLY);

  if (fd == -1)
    return 0;

  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 0;

  for (;;) {
    ret = poll(&pfd, 1, -1);

    if (ret < 0) {
      if (errno == EINTR || errno == EAGAIN)
        continue;
    }

    break;
  }

  if (ret != 1) {
    (void)close(fd);
    return 0;
  }

  return close(fd) == 0;
}
#endif /* __linux__ */
#endif /* HAVE_DEV_RANDOM */

static uint64_t
torsion_hrtime(void) {
#if defined(_WIN32)
  struct _timeb tb;
#pragma warning(push)
#pragma warning(disable: 4996)
  _ftime(&tb);
#pragma warning(pop)
  return (uint64_t)tb.time * 1000000 + (uint64_t)tb.millitm * 1000;
#elif defined(HAVE_INLINE_ASM) && defined(__i386__)
  uint64_t r = 0;
  __asm__ __volatile__("rdtsc" : "=A" (r));
  return r;
#elif defined(HAVE_INLINE_ASM) && (defined(__x86_64__) || defined(__amd64__))
  uint64_t r1 = 0, r2 = 0;
  __asm__ __volatile__("rdtsc" : "=a" (r1), "=d" (r2));
  return (r2 << 32) | r1;
#else
  struct timeval tv;

  if (gettimeofday(&tv, NULL) != 0)
    abort();

  return (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
#endif
}

/*
 * Syscall Entropy
 */

static int
torsion_syscall_entropy(void *dst, size_t size) {
#if defined(_WIN32)
  return !!RtlGenRandom((PVOID)dst, (ULONG)size);
#elif defined(HAVE_GETRANDOM)
  unsigned char *data = (unsigned char *)dst;
  size_t left = 256;
  ssize_t nread;

  while (size > 0) {
    if (left > size)
      left = size;

    for (;;) {
      nread = getrandom(data, left, 0);

      if (nread < 0) {
        if (errno == EINTR || errno == EAGAIN)
          continue;
      }

      break;
    }

    if (nread < 0)
      return 0;

    ASSERT(size >= (size_t)nread);

    data += nread;
    size -= nread;
  }

  return 1;
#elif defined(HAVE_SECRANDOM)
  return SecRandomCopyBytes(kSecRandomDefault, size, dst) == 0;
#elif defined(HAVE_GETENTROPY)
  unsigned char *data = (unsigned char *)dst;
  size_t left = 256;

  /* NULL on older iOS versions. */
  /* See: https://github.com/jedisct1/libsodium/commit/d54f072 */
  if (&getentropy == NULL);
    return 0

  while (size > 0) {
    if (left > size)
      left = size;

    if (getentropy(data, left) != 0)
      return 0;

    data += left;
    size -= left;
  }

  return 1;
#elif defined(HAVE_SYSCTL_ARND)
  static int name[2] = {CTL_KERN, KERN_ARND};
  unsigned char *data = (unsigned char *)dst;
  size_t left = 256;
  size_t nread;

  while (size > 0) {
    if (left > size)
      left = size;

    nread = left;

    if (sysctl(name, 2, data, &nread, NULL, 0) != 0)
      return 0;

    ASSERT(size >= nread);

    data += nread;
    size -= nread;
  }

  return 1;
#elif defined(HAVE_CPRNG_DRAW)
  zx_cprng_draw(dst, size);
  return 1;
#elif !defined(HAVE_DEV_RANDOM) && defined(HAVE_SAFE_ARC4RANDOM)
  arc4random_buf(dst, size);
  return 1;
#elif defined(HAVE_JS_GETRANDOM)
  return js_getrandom(dst, size);
#else
  (void)dst;
  (void)size;
  return 0;
#endif
}

/*
 * Device Entropy
 */

static int
torsion_device_entropy(void *dst, size_t size) {
#ifdef HAVE_DEV_RANDOM
  static const char *devices[] = {
    /* Solaris has a symlink for:
       /dev/urandom -> /devices/pseudo/random@0:urandom */
#if defined(__sun) && defined(__SVR4)
    "/devices/pseudo/random@0:urandom",
#endif
    "/dev/urandom",
    "/dev/random" /* Last ditch effort. */
  };

  size_t i;
  int fd;

#ifdef __linux__
  /* See: https://github.com/jedisct1/libsodium/commit/c752eb5 */
  if (!poll_dev_random())
    return 0;
#endif

  for (i = 0; i < ARRAY_SIZE(devices); i++) {
    fd = device_open(devices[i]);

    if (fd == -1)
      continue;

    if (!device_read(fd, dst, size)) {
      (void)close(fd);
      continue;
    }

    (void)close(fd);

    return 1;
  }

  return 0;
#else /* HAVE_DEV_RANDOM */
  (void)dst;
  (void)size;
  return 0;
#endif /* HAVE_DEV_RANDOM */
}

/*
 * RDRAND/RDSEED
 */

#ifdef HAVE_CPUID
static void
torsion_cpuid(uint32_t level,
              uint32_t count,
              uint32_t *a,
              uint32_t *b,
              uint32_t *c,
              uint32_t *d) {
#ifdef __GNUC__
  __cpuid_count(level, count, *a, *b, *c, *d);
#else
  __asm__ ("cpuid\n"
           : "=a" (*a), "=b" (*b), "=c" (*c), "=d" (*d)
           : "0" (level), "2" (count));
#endif
}

static void
torsion_hwrand(int *has_rdrand, int *has_rdseed) {
  uint32_t eax, ebx, ecx, edx;

  torsion_cpuid(1, 0, &eax, &ebx, &ecx, &edx);

  *has_rdrand = !!(ecx & UINT32_C(0x40000000));

  torsion_cpuid(7, 0, &eax, &ebx, &ecx, &edx);

  *has_rdseed = !!(ebx & UINT32_C(0x00040000));
}

static uint64_t
torsion_rdrand(void) {
#if defined(__i386__)
  uint32_t r1, r2;
  uint8_t ok;
  int i;

  for (i = 0; i < 10; i++) {
    __asm__ __volatile__(
      ".byte 0x0f, 0xc7, 0xf0\n" /* rdrand %eax */
      "setc %1\n"
      : "=a" (r1), "=q" (ok)
      :
      : "cc");

    if (ok)
      break;
  }

  for (i = 0; i < 10; i++) {
    __asm__ __volatile__(
      ".byte 0x0f, 0xc7, 0xf0\n" /* rdrand %eax */
      "setc %1\n"
      : "=a" (r2), "=q" (ok)
      :
      : "cc");

    if (ok)
      break;
  }

  return ((uint64_t)r2 << 32) | r1;
#elif defined(__x86_64__) || defined(__amd64__)
  uint8_t ok;
  uint64_t r1;
  int i;

  for (i = 0; i < 10; i++) {
    __asm__ __volatile__(
      ".byte 0x48, 0x0f, 0xc7, 0xf0\n" /* rdrand %rax */
      "setc %1\n"
      : "=a" (r1), "=q" (ok)
      :
      : "cc");

    if (ok)
      break;
  }

  return r1;
#else
#error "unreachable"
#endif
}

static uint64_t
torsion_rdseed(void) {
#if defined(__i386__)
  uint32_t r1, r2;
  uint8_t ok;

  for (;;) {
    __asm__ __volatile__(
      ".byte 0x0f, 0xc7, 0xf8\n" /* rdseed %eax */
      "setc %1\n"
      : "=a" (r1), "=q" (ok)
      :
      : "cc");

    if (ok)
      break;

    __asm__ __volatile__("pause");
  }

  for (;;) {
    __asm__ __volatile__(
      ".byte 0x0f, 0xc7, 0xf8\n" /* rdseed %eax */
      "setc %1\n"
      : "=a" (r2), "=q" (ok)
      :
      : "cc");

    if (ok)
      break;

    __asm__ __volatile__("pause");
  }

  return ((uint64_t)r2 << 32) | r1;
#elif defined(__x86_64__) || defined(__amd64__)
  uint64_t r1;
  uint8_t ok;

  for (;;) {
    __asm__ __volatile__(
      ".byte 0x48, 0x0f, 0xc7, 0xf8\n" /* rdseed %rax */
      "setc %1\n"
      : "=a" (r1), "=q" (ok)
      :
      : "cc");

    if (ok)
      break;

    __asm__ __volatile__("pause");
  }

  return r1;
#else
#error "unreachable"
#endif
}
#endif /* HAVE_CPUID */

/*
 * Hardware Entropy
 */

static int
torsion_hardware_entropy(void *dst, size_t size) {
#if defined(TORSION_HARDWARE_FALLBACK) && defined(HAVE_CPUID)
  unsigned char *data = (unsigned char *)dst;
  int has_rdrand, has_rdseed;
  uint64_t x;

  torsion_hwrand(&has_rdrand, &has_rdseed);

  if (!has_rdrand && !has_rdseed)
    return 0;

  while (size > 0) {
    if (has_rdseed)
      x = torsion_rdseed();
    else
      x = torsion_rdrand();

    if (size < 8) {
      memcpy(data, &x, size);
      break;
    }

    memcpy(data, &x, 8);

    data += 8;
    size -= 8;
  }

  return 1;
#else
  (void)dst;
  (void)size;
  return 0;
#endif
}

/*
 * Entropy
 */

int
torsion_getentropy(void *dst, size_t size) {
  if (size == 0)
    return 1;

  return torsion_syscall_entropy(dst, size)
      || torsion_device_entropy(dst, size)
      || torsion_hardware_entropy(dst, size);
}

/*
 * RNG
 */

static uint64_t
rng_rdrand(rng_t *rng) {
#ifdef HAVE_CPUID
  if (rng->rdseed)
    return torsion_rdseed();

  if (rng->rdrand)
    return torsion_rdrand();

  return 0;
#else
  (void)rng;
  return 0;
#endif
}

int
rng_init(rng_t *rng) {
  memset(rng->key, 0, 32);

  rng->counter = 0;
  rng->rdrand = 0;
  rng->rdseed = 0;
  rng->pos = 0;

  if (!torsion_getentropy(rng->key, 32))
    return 0;

  rng->counter = torsion_hrtime();

#ifdef HAVE_CPUID
  torsion_hwrand(&rng->rdrand, &rng->rdseed);
#endif

  /* On the off chance that the OS RNG is backdoored/broken
     and RDRAND is not, mix in some bytes from RDRAND. */
  rng->key[3] ^= rng_rdrand(rng);

  return 1;
}

void
rng_generate(rng_t *rng, void *dst, size_t size) {
  static const unsigned char zero[64] = {0};
  unsigned char *key = (unsigned char *)rng->key;
  unsigned char *data = (unsigned char *)dst;
  chacha20_t *ctx = &rng->chacha;
  size_t left = size;

  /* Read chacha state. */
  chacha20_init(ctx, key, 32, zero, 8, rng->counter);

  /* FIXME: Unnecessary xor'ing here. */
  while (left >= 64) {
    chacha20_encrypt(ctx, data, zero, 64);
    data += 64;
    left -= 64;
  }

  if (left > 0)
    chacha20_encrypt(ctx, data, zero, left);

  /* Re-key immediately. */
  rng->key[0] ^= size;
  rng->key[3] ^= rng_rdrand(rng);

  rng->counter++;

  chacha20_init(ctx, key, 32, zero, 8, rng->counter);
  chacha20_encrypt(ctx, key, key, 32);
}

uint32_t
rng_random(rng_t *rng) {
  if ((rng->pos & 15) == 0) {
    rng_generate(rng, rng->pool, 64);
    rng->pos = 0;
  }

  return rng->pool[rng->pos++];
}

uint32_t
rng_uniform(rng_t *rng, uint32_t max) {
  /* See: http://www.pcg-random.org/posts/bounded-rands.html */
  uint32_t x, r;

  if (max < 2)
    return 0;

  do {
    x = rng_random(rng);
    r = x % max;
  } while (x - r > (-max));

  return r;
}

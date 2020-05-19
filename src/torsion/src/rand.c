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

#ifndef _WIN32
#  include <sys/resource.h> /* getrusage */
#  include <sys/utsname.h> /* uname */
#endif

#ifdef __linux__
#  include <sys/auxv.h> /* getauxval */
#endif

#if defined(__APPLE__) || defined(__OpenBSD__) \
 || defined(__FreeBSD__) || defined(__NetBSD__)
#  include <sys/sysctl.h>
#  define HAVE_SYSCTL
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
#  include <vm/vm_param.h> /* VM_{LOADAVG,TOTAL,METER} */
#endif

#ifdef __APPLE__
#  include <crt_externs.h>
#  define environ (*_NSGetEnviron())
#else
#  ifndef environ
extern char **environ;
#  endif
#endif

#include <torsion/chacha20.h>
#include <torsion/hash.h>
#include <torsion/rand.h>
#include <torsion/util.h>
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
      close(fd);
      return -1;
    }

    /* Ensure this is a character device. */
    if (!S_ISNAM(st.st_mode) && !S_ISCHR(st.st_mode)) {
      close(fd);
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
    close(fd);
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
      close(fd);
      continue;
    }

    close(fd);

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
 * Hashing
 */

static void
sha256_write(sha256_t *hash, const void *data, size_t size) {
  sha256_update(hash, data, size);
}

static void
sha256_write_data(sha256_t *hash, const void *data, size_t size) {
  sha256_write(hash, &size, sizeof(size));
  sha256_write(hash, data, size);
}

static void
sha256_write_string(sha256_t *hash, const char *str) {
  sha256_write_data(hash, str, strlen(str));
}

static void
sha256_write_int(sha256_t *hash, uint64_t num) {
  sha256_write(hash, &num, sizeof(num));
}

static void
sha256_write_ptr(sha256_t *hash, const void *ptr) {
  uintptr_t uptr = (uintptr_t)ptr;

  sha256_write(hash, &uptr, sizeof(uptr));
}

static void
sha256_write_stat(sha256_t *hash, const char *file) {
  struct stat st;

  memset(&st, 0, sizeof(st));

  if (stat(file, &st) == 0) {
    sha256_write_string(hash, file);
    sha256_write(hash, &st, sizeof(st));
  }
}

static void
sha256_write_file(sha256_t *hash, const char *file) {
  unsigned char buf[4096];
  struct stat st;
  int fd, nread;
  size_t total;

  fd = open(file, O_RDONLY);

  if (fd == -1)
    return;

  memset(&st, 0, sizeof(st));

  if (fstat(fd, &st) == 0) {
    sha256_write_string(hash, file);
    sha256_write(hash, &st, sizeof(st));
  }

  total = 0;

  do {
    nread = read(fd, buf, sizeof(buf));

    if (nread <= 0)
      break;

    sha256_write(hash, buf, nread);

    total += nread;
  } while ((size_t)nread == sizeof(buf) && total < 1048576);

  close(fd);
}

#ifdef HAVE_SYSCTL
void
sha256_write_sysctl(sha256_t *hash, int c0, int c1) {
  unsigned char buf[65536];
  size_t size = 65536;
  int ctl[2];
  int ret;

  ctl[0] = c0;
  ctl[1] = c1;

  ret = sysctl(ctl, 2, buf, &size, NULL, 0);

  if (ret == 0 || (ret == -1 && errno == ENOMEM)) {
    sha256_write_data(hash, ctl, sizeof(ctl));

    if (size > sizeof(buf))
      size = sizeof(buf);

    sha256_write_data(hash, buf, size);
  }
}
#endif

#ifdef HAVE_CPUID
static void
sha256_write_cpuid(sha256_t *hash, uint32_t leaf, uint32_t subleaf,
                   uint32_t *ax, uint32_t *bx, uint32_t *cx, uint32_t *dx) {
  torsion_cpuid(leaf, subleaf, ax, bx, cx, dx);

  sha256_write_int(hash, leaf);
  sha256_write_int(hash, subleaf);
  sha256_write_int(hash, *ax);
  sha256_write_int(hash, *bx);
  sha256_write_int(hash, *cx);
  sha256_write_int(hash, *dx);
}

static void
sha256_write_cpuids(sha256_t *hash) {
  uint32_t max, leaf, maxsub, subleaf, maxext;
  uint32_t ax, bx, cx, dx;

  /* Iterate over all standard leaves. */
  /* Returns max leaf in ax. */
  sha256_write_cpuid(hash, 0, 0, &ax, &bx, &cx, &dx);

  max = ax;

  for (leaf = 1; leaf <= max && leaf <= 0xff; leaf++) {
    maxsub = 0;

    for (subleaf = 0; subleaf <= 0xff; subleaf++) {
      sha256_write_cpuid(hash, leaf, subleaf, &ax, &bx, &cx, &dx);

      /* Iterate subleafs for leaf values 4, 7, 11, 13. */
      if (leaf == 4) {
        if ((ax & 0x1f) == 0)
          break;
      } else if (leaf == 7) {
        if (subleaf == 0)
          maxsub = ax;

        if (subleaf == maxsub)
          break;
      } else if (leaf == 11) {
        if ((cx & 0xff00) == 0)
          break;
      } else if (leaf == 13) {
        if (ax == 0 && bx == 0 && cx == 0 && dx == 0)
          break;
      } else {
        /* For any other leaf, stop after subleaf 0. */
        break;
      }
    }
  }

  /* Iterate over all extended leaves. */
  /* Returns max extended leaf in ax. */
  sha256_write_cpuid(hash, 0x80000000, 0, &ax, &bx, &cx, &dx);

  maxext = ax;

  for (leaf = 0x80000001; leaf <= maxext && leaf <= 0x800000ff; leaf++)
    sha256_write_cpuid(hash, leaf, 0, &ax, &bx, &cx, &dx);
}
#endif

#ifdef _WIN32
static void
sha256_write_perfdata(sha256_t *hash) {
  static const size_t max = 10000000;
  unsigned char *data = malloc(250000);
  unsigned long nread = 0;
  size_t size = 250000;
  long ret = 0;
  size_t old;

  if (data == NULL)
    return;

  memset(data, 0, size);

  for (;;) {
    nread = size;
    ret = RegQueryValueExA(HKEY_PERFORMANCE_DATA,
                           "Global", NULL, NULL,
                           data, &nread);

    if (ret != ERROR_MORE_DATA || size >= max)
      break;

    old = size;
    size = (size * 3) / 2;

    if (size > max)
      size = max;

    data = realloc(data, size);

    if (data == NULL)
      break;

    memset(data + old, 0, size - old);
  }

  RegCloseKey(HKEY_PERFORMANCE_DATA);

  if (ret == ERROR_SUCCESS) {
    sha256_write_data(hash, data, size);
    cleanse(data, size);
  }

  if (data)
    free(data);
}
#endif

static void
sha256_write_static_env(sha256_t *hash) {
  /* Some compile-time static properties */
  sha256_write_int(hash, CHAR_MIN < 0);
  sha256_write_int(hash, sizeof(void *));
  sha256_write_int(hash, sizeof(long));
  sha256_write_int(hash, sizeof(int));

#if defined(__GNUC__) && defined(__GNUC_MINOR__) && defined(__GNUC_PATCHLEVEL__)
  sha256_write_int(hash, __GNUC__);
  sha256_write_int(hash, __GNUC_MINOR__);
  sha256_write_int(hash, __GNUC_PATCHLEVEL__);
#endif

#ifdef _MSC_VER
  sha256_write_int(hash, _MSC_VER);
#endif

#ifdef __linux__
  /* Information available through getauxval(). */
#ifdef AT_HWCAP
  sha256_write_int(hash, getauxval(AT_HWCAP));
#endif
#ifdef AT_HWCAP2
  sha256_write_int(hash, getauxval(AT_HWCAP2));
#endif
#ifdef AT_RANDOM
  {
    const unsigned char *random_aux =
      (const unsigned char *)getauxval(AT_RANDOM);

    if (random_aux)
      sha256_write(hash, random_aux, 16);
  }
#endif
#ifdef AT_PLATFORM
  {
    const char *platform_str = (const char *)getauxval(AT_PLATFORM);

    if (platform_str)
      sha256_write_string(hash, platform_str);
  }
#endif
#ifdef AT_EXECFN
  {
    const char *exec_str = (const char *)getauxval(AT_EXECFN);

    if (exec_str)
      sha256_write_string(hash, exec_str);
  }
#endif
#endif /* __linux__ */

#ifdef HAVE_CPUID
  sha256_write_cpuids(hash);
#endif

  /* Memory locations. */
  sha256_write_ptr(hash, hash);
  sha256_write_ptr(hash, &errno);
#ifndef environ
  sha256_write_ptr(hash, &environ);
#endif

  /* Hostname. */
  {
    char hname[256];

    memset(hname, 0, sizeof(hname));

    if (gethostname(hname, sizeof(hname) - 1) == 0)
      sha256_write_string(hash, hname);
  }

#ifndef _WIN32
  /* UNIX kernel information. */
  {
    struct utsname name;

    if (uname(&name) != -1) {
      sha256_write_string(hash, name.sysname);
      sha256_write_string(hash, name.nodename);
      sha256_write_string(hash, name.release);
      sha256_write_string(hash, name.version);
      sha256_write_string(hash, name.machine);
    }
  }

  /* Path and filesystem provided data. */
  sha256_write_stat(hash, "/");
  sha256_write_stat(hash, ".");
  sha256_write_stat(hash, "/tmp");
  sha256_write_stat(hash, "/home");
  sha256_write_stat(hash, "/proc");
#ifdef __linux__
  sha256_write_file(hash, "/proc/cmdline");
  sha256_write_file(hash, "/proc/cpuinfo");
  sha256_write_file(hash, "/proc/version");
#endif /* __linux__ */
  sha256_write_file(hash, "/etc/passwd");
  sha256_write_file(hash, "/etc/group");
  sha256_write_file(hash, "/etc/hosts");
  sha256_write_file(hash, "/etc/resolv.conf");
  sha256_write_file(hash, "/etc/timezone");
  sha256_write_file(hash, "/etc/localtime");
#endif /* !_WIN32 */

#ifdef HAVE_SYSCTL
#ifdef CTL_HW
#ifdef HW_MACHINE
  sha256_write_sysctl(hash, CTL_HW, HW_MACHINE);
#endif
#ifdef HW_MODEL
  sha256_write_sysctl(hash, CTL_HW, HW_MODEL);
#endif
#ifdef HW_NCPU
  sha256_write_sysctl(hash, CTL_HW, HW_NCPU);
#endif
#ifdef HW_PHYSMEM
  sha256_write_sysctl(hash, CTL_HW, HW_PHYSMEM);
#endif
#ifdef HW_USERMEM
  sha256_write_sysctl(hash, CTL_HW, HW_USERMEM);
#endif
#ifdef HW_MACHINE_ARCH
  sha256_write_sysctl(hash, CTL_HW, HW_MACHINE_ARCH);
#endif
#ifdef HW_REALMEM
  sha256_write_sysctl(hash, CTL_HW, HW_REALMEM);
#endif
#ifdef HW_CPU_FREQ
  sha256_write_sysctl(hash, CTL_HW, HW_CPU_FREQ);
#endif
#ifdef HW_BUS_FREQ
  sha256_write_sysctl(hash, CTL_HW, HW_BUS_FREQ);
#endif
#ifdef HW_CACHELINE
  sha256_write_sysctl(hash, CTL_HW, HW_CACHELINE);
#endif
#endif

#ifdef CTL_KERN
#ifdef KERN_BOOTFILE
  sha256_write_sysctl(hash, CTL_KERN, KERN_BOOTFILE);
#endif
#ifdef KERN_BOOTTIME
  sha256_write_sysctl(hash, CTL_KERN, KERN_BOOTTIME);
#endif
#ifdef KERN_CLOCKRATE
  sha256_write_sysctl(hash, CTL_KERN, KERN_CLOCKRATE);
#endif
#ifdef KERN_HOSTID
  sha256_write_sysctl(hash, CTL_KERN, KERN_HOSTID);
#endif
#ifdef KERN_HOSTUUID
  sha256_write_sysctl(hash, CTL_KERN, KERN_HOSTUUID);
#endif
#ifdef KERN_HOSTNAME
  sha256_write_sysctl(hash, CTL_KERN, KERN_HOSTNAME);
#endif
#ifdef KERN_OSRELDATE
  sha256_write_sysctl(hash, CTL_KERN, KERN_OSRELDATE);
#endif
#ifdef KERN_OSRELEASE
  sha256_write_sysctl(hash, CTL_KERN, KERN_OSRELEASE);
#endif
#ifdef KERN_OSREV
  sha256_write_sysctl(hash, CTL_KERN, KERN_OSREV);
#endif
#ifdef KERN_OSTYPE
  sha256_write_sysctl(hash, CTL_KERN, KERN_OSTYPE);
#endif
#ifdef KERN_POSIX1
  sha256_write_sysctl(hash, CTL_KERN, KERN_OSREV);
#endif
#ifdef KERN_VERSION
  sha256_write_sysctl(hash, CTL_KERN, KERN_VERSION);
#endif
#endif
#endif

  /* Environment variables. */
  if (environ) {
    size_t i;
    for (i = 0; environ[i] != NULL; i++)
      sha256_write_string(hash, environ[i]);
  }

#ifdef _WIN32
  sha256_write_int(hash, GetCurrentProcessId());
  sha256_write_int(hash, GetCurrentThreadId());
#else /* _WIN32 */
  sha256_write_int(hash, getpid());
  sha256_write_int(hash, getppid());
  sha256_write_int(hash, getsid(0));
  sha256_write_int(hash, getpgid(0));
  sha256_write_int(hash, getuid());
  sha256_write_int(hash, geteuid());
  sha256_write_int(hash, getgid());
  sha256_write_int(hash, getegid());
#endif /* _WIN32 */
}

static void
sha256_write_dynamic_env(sha256_t *hash) {
#ifdef _WIN32
  sha256_write_perfdata(hash);

  {
    FILETIME ftime;

    GetSystemTimeAsFileTime(&ftime);

    sha256_write_int(hash, ftime);
  }
#else
  {
    struct timeval tv;

    memset(&tv, 0, sizeof(tv));

    gettimeofday(&tv, NULL);

    sha256_write(hash, &tv, sizeof(tv));
  }

  /* Current resource usage. */
  {
    struct rusage usage;

    memset(&usage, 0, sizeof(usage));

    if (getrusage(RUSAGE_SELF, &usage) == 0)
      sha256_write(hash, &usage, sizeof(usage));
  }
#endif

#ifdef __linux__
  sha256_write_file(hash, "/proc/diskstats");
  sha256_write_file(hash, "/proc/vmstat");
  sha256_write_file(hash, "/proc/schedstat");
  sha256_write_file(hash, "/proc/zoneinfo");
  sha256_write_file(hash, "/proc/meminfo");
  sha256_write_file(hash, "/proc/softirqs");
  sha256_write_file(hash, "/proc/stat");
  sha256_write_file(hash, "/proc/self/schedstat");
  sha256_write_file(hash, "/proc/self/status");
#endif

#ifdef HAVE_SYSCTL
#ifdef CTL_HW
#ifdef HW_DISKSTATS
  sha256_write_sysctl(hash, CTL_HW, HW_DISKSTATS);
#endif
#endif
#ifdef CTL_VM
#ifdef VM_LOADAVG
  sha256_write_sysctl(hash, CTL_VM, VM_LOADAVG);
#endif
#ifdef VM_TOTAL
  sha256_write_sysctl(hash, CTL_VM, VM_TOTAL);
#endif
#ifdef VM_METER
  sha256_write_sysctl(hash, CTL_VM, VM_METER);
#endif
#endif
#endif

  /* Stack and heap location. */
  {
    void *addr = malloc(4097);

    if (addr) {
      sha256_write_ptr(hash, &addr);
      sha256_write_ptr(hash, addr);
      free(addr);
    }
  }
}

/*
 * RNG
 */

static int
rng_seed(rng_t *rng) {
  unsigned char entropy[32];
  sha256_t hash;

  if (!torsion_getentropy(entropy, 32))
    return 0;

  sha256_init(&hash);
  sha256_write_int(&hash, torsion_hrtime());
  sha256_write_ptr(&hash, rng);
  sha256_write_ptr(&hash, entropy);
  sha256_write(&hash, entropy, 32);

#ifdef HAVE_CPUID
  if (rng->rdseed) {
    size_t i;

    for (i = 0; i < 4; i++)
      sha256_write_int(&hash, torsion_rdseed());
  } else if (rng->rdrand) {
    size_t i;

    for (i = 0; i < 4; i++) {
      uint64_t out = 0;
      size_t j;

      for (j = 0; j < 1024; j++)
        out ^= torsion_rdrand();

      sha256_write_int(&hash, out);
    }
  }
#endif

  sha256_write_int(&hash, torsion_hrtime());
  sha256_write_static_env(&hash);
  sha256_write_dynamic_env(&hash);
  sha256_write_int(&hash, torsion_hrtime());
  sha256_final(&hash, (unsigned char *)rng->key);

  cleanse(entropy, sizeof(entropy));
  cleanse(&hash, sizeof(hash));

  return 1;
}

int
rng_init(rng_t *rng) {
  memset(rng->key, 0, 32);

  rng->counter = torsion_hrtime();
  rng->rdrand = 0;
  rng->rdseed = 0;
  rng->pos = 0;

#ifdef HAVE_CPUID
  torsion_hwrand(&rng->rdrand, &rng->rdseed);
#endif

  return rng_seed(rng);
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

  while (left >= 64) {
    chacha20_encrypt(ctx, data, zero, 64);
    data += 64;
    left -= 64;
  }

  if (left > 0)
    chacha20_encrypt(ctx, data, zero, left);

  /* Re-key immediately. */
  rng->key[0] ^= size;

#ifdef HAVE_CPUID
  if (rng->rdrand)
    rng->key[3] ^= torsion_rdrand();
#endif

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

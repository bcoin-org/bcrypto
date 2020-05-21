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

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN 1
#  endif
#  include <windows.h>
#  include <sys/timeb.h> /* _timeb */
#  ifdef __BORLANDC__
#    define _ftime ftime
#    define _timeb timeb
#  endif
#else
#  include <sys/stat.h>
#  ifdef __vxworks
#    include <time.h>
#  else
#    include <sys/time.h>
#  endif
#endif

#ifdef __linux__
#  include <poll.h>
#endif

#ifdef __EMSCRIPTEN__
#  include <emscripten.h>
#endif

#define HAVE_DEV_RANDOM
#define HAVE_MANUAL_ENTROPY

#if defined(__GNUC__) || defined(__clang__)
#  define HAVE_INLINE_ASM
#endif

#ifdef _WIN32
/* https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom */
/* https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-rtlgenrandom */
#  if defined(_MSC_VER) && _MSC_VER > 1500 /* VS 2008 */ \
   && defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0600 /* >= Vista (2007) */
#    include <bcrypt.h>
#    pragma comment(lib, "bcrypt.lib")
#    ifndef STATUS_SUCCESS
#      define STATUS_SUCCESS ((NTSTATUS)0)
#    endif
#    define HAVE_BCRYPTGENRANDOM
#  else
#    define RtlGenRandom SystemFunction036
BOOLEAN NTAPI RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);
#    pragma comment(lib, "advapi32.lib")
#    define HAVE_RTLGENRANDOM
#  endif
#  undef HAVE_DEV_RANDOM
#endif

#ifdef __linux__
/* http://man7.org/linux/man-pages/man2/getrandom.2.html */
#  include <sys/syscall.h>
#  if defined(SYS_getrandom) && defined(__NR_getrandom) /* 3.17 (2014) */
#    define getrandom(B, S, F) syscall(SYS_getrandom, (B), (int)(S), (F))
#    define HAVE_GETRANDOM
#  endif
#endif

#ifdef __APPLE__
/* https://www.unix.com/man-page/mojave/2/getentropy/ */
#  include <Availability.h>
#  include <TargetConditionals.h>
#  if TARGET_OS_IPHONE
#    if __IPHONE_OS_VERSION_MAX_ALLOWED >= 100000 /* 10.0 (2016) */
#      include <sys/random.h>
#      define HAVE_GETENTROPY
#    endif
#  else
#    if __MAC_OS_X_VERSION_MAX_ALLOWED >= 101200 /* 10.12 (2016) */
#      include <sys/random.h>
#      define HAVE_GETENTROPY
#    endif
#  endif
#endif

#ifdef __OpenBSD__
/* https://man.openbsd.org/getentropy.2 */
#  include <sys/param.h>
#  if defined(OpenBSD) && OpenBSD >= 201411 /* 5.6 (2014) */
#    define HAVE_GETENTROPY
#  endif
#endif

#ifdef __FreeBSD__
/* https://www.freebsd.org/cgi/man.cgi?query=getrandom&manpath=FreeBSD+12.0-stable */
/* https://www.freebsd.org/cgi/man.cgi?query=getentropy&manpath=FreeBSD+12.0-stable */
#  include <sys/param.h>
#  if defined(__FreeBSD_version) && __FreeBSD_version >= 1200000 /* 12.0 (2018) */
#    include <sys/random.h>
#    define HAVE_GETRANDOM
#    define HAVE_GETENTROPY
#  endif
#endif

#ifdef __NetBSD__
#  include <sys/param.h>
#endif

#ifdef __DragonFly__
/* https://www.dragonflybsd.org/release58/ */
/* https://github.com/DragonFlyBSD/DragonFlyBSD/blob/3af8070/sys/sys/random.h */
#  include <sys/param.h>
#  if defined(__DragonFly_version) && __DragonFly_version >= 500800 /* 5.8 (2020) */
#    include <sys/random.h>
#    define HAVE_GETRANDOM
#  endif
#endif

#if defined(__OpenBSD__) || defined(__FreeBSD__) \
 || (defined(__NetBSD__) && defined(__NetBSD_Version__) \
     && __NetBSD_Version__ >= 400000000) /* 4.0 (2007) */
/* https://github.com/openbsd/src/blob/2981a53/sys/sys/sysctl.h#L140 */
/* https://www.freebsd.org/cgi/man.cgi?sysctl(3) */
/* https://netbsd.gw.com/cgi-bin/man-cgi?sysctl+3+NetBSD-8.0 */
/* Note that ARND was an alias to URND prior to NetBSD 4.0 (2007).
   See: https://github.com/openssl/openssl/blob/ddec332/crypto/rand/rand_unix.c#L244 */
#  include <sys/sysctl.h>
#  if defined(CTL_KERN) && defined(KERN_ARND)
#    define HAVE_SYSCTL_ARND
#  endif
#endif

#if defined(__sun) && defined(__SVR4) /* 11.3 (2015) */
/* https://docs.oracle.com/cd/E88353_01/html/E37841/getrandom-2.html */
/* Note that Solaris 11 == SunOS 5.11. */
#  if defined(__SUNPRO_C) || defined(__SUNPRO_CC)
#    if (defined(__SunOS_RELEASE) && __SunOS_RELEASE >= 0x051103) \
      || defined(__SunOS_5_11)
#      include <sys/random.h>
#      define HAVE_GETRANDOM
#    endif
#  else
/* No way to verify the version without Sun Studio. */
#    include <sys/random.h>
#    define HAVE_GETRANDOM
#  endif
#endif

#ifdef __vxworks
/* https://docs.windriver.com/bundle/vxworks_7_application_core_os_sr0630-enus/page/CORE/randomNumGenLib.html */
#  include <version.h>
#  if defined(_WRS_VXWORKS_MAJOR) && _WRS_VXWORKS_MAJOR >= 7 /* 7 (2016) */
#    include <randomNumGen.h>
#    include <taskLib.h>
#    define HAVE_RANDBYTES
#  endif
#endif

#ifdef __fuchsia__
/* https://fuchsia.dev/fuchsia-src/zircon/syscalls/cprng_draw */
#  include <zircon/syscalls.h>
#  define HAVE_CPRNG_DRAW
#endif

#ifdef __redox__
/* https://github.com/redox-os/randd/blob/276270f/src/main.rs */
#  define DEV_RANDOM_NAME ":rand"
#endif

#ifdef __CloudABI__
/* https://nuxi.nl/cloudabi/#random_get */
/* https://github.com/NuxiNL/cloudabi/blob/d283c05/headers/cloudabi_syscalls.h#L193 */
/* https://github.com/NuxiNL/cloudabi/blob/d283c05/headers/cloudabi_types_common.h#L89 */
uint16_t cloudabi_sys_random_get(void *buf, size_t buf_len);
#  define HAVE_SYS_RANDOM_GET
#endif

#ifdef __wasi__
/* https://github.com/WebAssembly/WASI/blob/5d10b2c/design/WASI-core.md#random_get */
/* https://github.com/WebAssembly/WASI/blob/2627acd/phases/snapshot/witx/typenames.witx#L34 */
/* https://github.com/WebAssembly/WASI/blob/2627acd/phases/snapshot/witx/wasi_snapshot_preview1.witx#L481 */
uint16_t __wasi_random_get(void *buf, size_t buf_len);
#  define HAVE_WASI_RANDOM_GET
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
      var max = 65536;

      while (len > 0) {
        if (max > len)
          max = len;

        var buf = HEAP8.subarray(ptr, ptr + max);

        crypto.getRandomValues(buf);

        ptr += max;
        len -= max;
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

#if defined(__CloudABI__) || defined(__wasm__) || defined(__asmjs__)
#  undef HAVE_DEV_RANDOM
#  undef HAVE_MANUAL_ENTROPY
#  undef HAVE_INLINE_ASM
#  undef HAVE_BCRYPTGENRANDOM
#  undef HAVE_RTLGENRANDOM
#  undef HAVE_GETRANDOM
#  undef HAVE_GETENTROPY
#  undef HAVE_SYSCTL_ARND
#  undef HAVE_RANDBYTES
#  undef HAVE_CPRNG_DRAW
#endif

#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
/* https://docs.microsoft.com/en-us/cpp/intrinsics/rdtsc?view=vs-2019 */
#  include <intrin.h>
#  pragma intrinsic(__rdtsc)
#  define HAVE_RDTSC
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
#  include <time.h> /* clock_gettime */
#endif

#ifdef __linux__
#  include <sys/auxv.h> /* getauxval */
#endif

#if defined(__APPLE__) \
 || defined(__OpenBSD__) \
 || defined(__FreeBSD__) \
 || defined(__NetBSD__) \
 || defined(__DragonFly__)
#  include <sys/sysctl.h>
#  define HAVE_SYSCTL
#endif

#ifdef __FreeBSD__
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

#if defined(__APPLE__) \
 || defined(__OpenBSD__) \
 || defined(__FreeBSD__) \
 || defined(__NetBSD__) \
 || defined(__DragonFly__)
#  include <sys/socket.h> /* AF_INET{,6} */
#  include <netinet/in.h> /* sockaddr_in{,6} */
#  include <ifaddrs.h> /* getifaddrs */
#  define HAVE_GETIFADDRS
#endif

#ifdef _WIN32
#  include <winsock2.h> /* gethostname */
#  pragma comment(lib, "ws2_32.lib") /* gethostname */
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
    if (!S_ISCHR(st.st_mode) && !S_ISNAM(st.st_mode)) {
      close(fd);
      return -1;
    }

#if defined(F_SETFD) && defined(FD_CLOEXEC)
    /* Close on exec(). */
    fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
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

#ifdef HAVE_MANUAL_ENTROPY
static uint64_t
torsion_hrtime(void) {
  /* See: https://en.wikipedia.org/wiki/Time_Stamp_Counter */
#if defined(HAVE_RDTSC)
  return __rdtsc();
#elif defined(HAVE_INLINE_ASM) && defined(__i386__)
  uint64_t r = 0;
  __asm__ __volatile__("rdtsc" : "=A" (r));
  return r;
#elif defined(HAVE_INLINE_ASM) && (defined(__x86_64__) || defined(__amd64__))
  uint64_t r1 = 0, r2 = 0;
  __asm__ __volatile__("rdtsc" : "=a" (r1), "=d" (r2));
  return (r2 << 32) | r1;
#elif defined(_WIN32)
  struct _timeb tb;
#pragma warning(push)
#pragma warning(disable: 4996)
  _ftime(&tb);
#pragma warning(pop)
  return (uint64_t)tb.time * 1000000 + (uint64_t)tb.millitm * 1000;
#else
  struct timeval tv;

  if (gettimeofday(&tv, NULL) != 0)
    abort();

  return (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
#endif
}
#endif /* HAVE_MANUAL_ENTROPY */

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
#endif /* HAVE_CPUID */

/*
 * Syscall Entropy
 */

static int
torsion_syscall_entropy(void *dst, size_t size) {
#if defined(HAVE_BCRYPTGENRANDOM)
  return BCryptGenRandom(NULL, (PUCHAR)dst, (ULONG)size,
                         BCRYPT_USE_SYSTEM_PREFERRED_RNG) == STATUS_SUCCESS;
#elif defined(HAVE_RTLGENRANDOM)
  return RtlGenRandom((PVOID)dst, (ULONG)size) == TRUE;
#elif defined(HAVE_GETRANDOM)
  unsigned char *data = (unsigned char *)dst;
  size_t max = 256;
  ssize_t nread;

  while (size > 0) {
    if (max > size)
      max = size;

    for (;;) {
      nread = getrandom(data, max, 0);

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
#elif defined(HAVE_GETENTROPY)
  unsigned char *data = (unsigned char *)dst;
  size_t max = 256;

  /* NULL on older iOS versions. */
  /* See: https://github.com/jedisct1/libsodium/commit/d54f072 */
  if (&getentropy == NULL)
    return 0;

  while (size > 0) {
    if (max > size)
      max = size;

    if (getentropy(data, max) != 0)
      return 0;

    data += max;
    size -= max;
  }

  return 1;
#elif defined(HAVE_SYSCTL_ARND)
  static int name[2] = {CTL_KERN, KERN_ARND};
  unsigned char *data = (unsigned char *)dst;
  size_t max = 256;
  size_t nread;

  /* Older FreeBSD versions returned longs.
     Error if we're not properly aligned. */
#ifdef __FreeBSD__
  /* See: https://github.com/openssl/openssl/blob/ddec332/crypto/rand/rand_unix.c#L231 */
  if ((size % sizeof(long)) != 0)
    return 0;
#endif

  while (size > 0) {
    if (max > size)
      max = size;

    nread = max;

    if (sysctl(name, 2, data, &nread, NULL, 0) != 0)
      return 0;

    ASSERT(size >= nread);

    data += nread;
    size -= nread;
  }

  return 1;
#elif defined(HAVE_RANDBYTES)
  size_t i;

  if (size > (size_t)INT_MAX)
    return 0;

  for (i = 0; i < 10; i++) {
    RANDOM_NUM_GEN_STATUS status = randStatus();

    if (status != RANDOM_NUM_GEN_ENOUGH_ENTROPY
        && status != RANDOM_NUM_GEN_MAX_ENTROPY) {
      taskDelay(5);
      continue;
    }

    if (randBytes((unsigned char *)dst, (int)size) == OK)
      return 1;
  }

  return 0;
#elif defined(HAVE_CPRNG_DRAW)
  zx_cprng_draw(dst, size);
  return 1;
#elif defined(HAVE_SYS_RANDOM_GET)
  return cloudabi_sys_random_get(dst, size) == 0;
#elif defined(HAVE_WASI_RANDOM_GET)
  return __wasi_random_get(dst, size) == 0;
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
#ifdef DEV_RANDOM_NAME
    DEV_RANDOM_NAME
#else
    /* Solaris has a symlink for:
       /dev/urandom -> /devices/pseudo/random@0:urandom */
#if defined(__sun) && defined(__SVR4)
    "/devices/pseudo/random@0:urandom",
#endif
    "/dev/urandom",
    "/dev/random" /* Last ditch effort. */
#endif
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
static int
torsion_has_rdrand(void) {
  uint32_t eax, ebx, ecx, edx;
  torsion_cpuid(1, 0, &eax, &ebx, &ecx, &edx);
  return !!(ecx & UINT32_C(0x40000000));
}

static int
torsion_has_rdseed(void) {
  uint32_t eax, ebx, ecx, edx;
  torsion_cpuid(7, 0, &eax, &ebx, &ecx, &edx);
  return !!(ebx & UINT32_C(0x00040000));
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
#ifdef HAVE_CPUID
  unsigned char *data = (unsigned char *)dst;
  int has_rdrand = torsion_has_rdrand();
  int has_rdseed = torsion_has_rdseed();
  uint64_t x;

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
 * Manual Entropy Gathering
 */

#ifdef HAVE_MANUAL_ENTROPY
static void
sha512_write(sha512_t *hash, const void *data, size_t size) {
  sha512_update(hash, data, size);
}

static void
sha512_write_data(sha512_t *hash, const void *data, size_t size) {
  sha512_write(hash, &size, sizeof(size));
  sha512_write(hash, data, size);
}

static void
sha512_write_string(sha512_t *hash, const char *str) {
  sha512_write_data(hash, str, str == NULL ? 0 : strlen(str));
}

static void
sha512_write_int(sha512_t *hash, uint64_t num) {
  sha512_write(hash, &num, sizeof(num));
}

static void
sha512_write_ptr(sha512_t *hash, const void *ptr) {
  uintptr_t uptr = (uintptr_t)ptr;

  sha512_write(hash, &uptr, sizeof(uptr));
}

#ifndef _WIN32
static void
sha512_write_stat(sha512_t *hash, const char *file) {
  struct stat st;

  memset(&st, 0, sizeof(st));

  if (stat(file, &st) == 0) {
    sha512_write_string(hash, file);
    sha512_write(hash, &st, sizeof(st));
  }
}

static void
sha512_write_file(sha512_t *hash, const char *file) {
  unsigned char buf[4096];
  struct stat st;
  int fd, nread;
  size_t total;

  fd = open(file, O_RDONLY);

  if (fd == -1)
    return;

  memset(&st, 0, sizeof(st));

  if (fstat(fd, &st) == 0) {
    sha512_write_string(hash, file);
    sha512_write(hash, &st, sizeof(st));
  }

  total = 0;

  do {
    nread = read(fd, buf, sizeof(buf));

    if (nread <= 0)
      break;

    sha512_write(hash, buf, nread);

    total += nread;
  } while ((size_t)nread == sizeof(buf) && total < 1048576);

  close(fd);
}
#endif /* !_WIN32 */

#ifdef HAVE_GETIFADDRS
static void
sha512_write_sockaddr(sha512_t *hash, const struct sockaddr *addr) {
  if (addr == NULL)
    return;

  switch (addr->sa_family) {
    case AF_INET:
      sha512_write(hash, addr, sizeof(struct sockaddr_in));
      break;
    case AF_INET6:
      sha512_write(hash, addr, sizeof(struct sockaddr_in6));
      break;
    default:
      sha512_write(hash, &addr->sa_family, sizeof(addr->sa_family));
      break;
  }
}
#endif /* HAVE_GETIFADDRS */

#ifdef HAVE_SYSCTL
static void
sha512_write_sysctl(sha512_t *hash, int *name, unsigned int namelen) {
  unsigned char buf[65536];
  size_t size = sizeof(buf);
  int ret;

  ret = sysctl(name, namelen, buf, &size, NULL, 0);

  if (ret == 0 || (ret == -1 && errno == ENOMEM)) {
    sha512_write_data(hash, name, sizeof(name));

    if (size > sizeof(buf))
      size = sizeof(buf);

    sha512_write_data(hash, buf, size);
  }
}

static void
sha512_write_sysctl2(sha512_t *hash, int ctl, int opt) {
  int name[2];

  name[0] = ctl;
  name[1] = opt;

  sha512_write_sysctl(hash, name, 2);
}

static void
sha512_write_sysctl3(sha512_t *hash, int ctl, int opt, int sub) {
  int name[3];

  name[0] = ctl;
  name[1] = opt;
  name[2] = sub;

  sha512_write_sysctl(hash, name, 3);
}
#endif /* HAVE_SYSCTL */

#ifdef HAVE_CPUID
static void
sha512_write_cpuid(sha512_t *hash, uint32_t leaf, uint32_t subleaf,
                   uint32_t *ax, uint32_t *bx, uint32_t *cx, uint32_t *dx) {
  torsion_cpuid(leaf, subleaf, ax, bx, cx, dx);

  sha512_write_int(hash, leaf);
  sha512_write_int(hash, subleaf);
  sha512_write_int(hash, *ax);
  sha512_write_int(hash, *bx);
  sha512_write_int(hash, *cx);
  sha512_write_int(hash, *dx);
}

static void
sha512_write_cpuids(sha512_t *hash) {
  uint32_t max, leaf, maxsub, subleaf, maxext;
  uint32_t ax, bx, cx, dx;

  /* Iterate over all standard leaves. */
  /* Returns max leaf in ax. */
  sha512_write_cpuid(hash, 0, 0, &ax, &bx, &cx, &dx);

  max = ax;

  for (leaf = 1; leaf <= max && leaf <= 0xff; leaf++) {
    maxsub = 0;

    for (subleaf = 0; subleaf <= 0xff; subleaf++) {
      sha512_write_cpuid(hash, leaf, subleaf, &ax, &bx, &cx, &dx);

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
  sha512_write_cpuid(hash, 0x80000000, 0, &ax, &bx, &cx, &dx);

  maxext = ax;

  for (leaf = 0x80000001; leaf <= maxext && leaf <= 0x800000ff; leaf++)
    sha512_write_cpuid(hash, leaf, 0, &ax, &bx, &cx, &dx);
}
#endif /* HAVE_CPUID */

#ifdef _WIN32
static void
sha512_write_perfdata(sha512_t *hash) {
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
    sha512_write_data(hash, data, size);
    cleanse(data, size);
  }

  if (data)
    free(data);
}
#endif /* _WIN32 */

static void
sha512_write_static_env(sha512_t *hash) {
  /* Some compile-time static properties. */
  sha512_write_int(hash, CHAR_MIN < 0);
  sha512_write_int(hash, sizeof(void *));
  sha512_write_int(hash, sizeof(long));
  sha512_write_int(hash, sizeof(int));

#if defined(__GNUC__) && defined(__GNUC_MINOR__) && defined(__GNUC_PATCHLEVEL__)
  sha512_write_int(hash, __GNUC__);
  sha512_write_int(hash, __GNUC_MINOR__);
  sha512_write_int(hash, __GNUC_PATCHLEVEL__);
#endif

#ifdef _MSC_VER
  sha512_write_int(hash, _MSC_VER);
#endif

#ifdef _XOPEN_VERSION
  sha512_write_int(hash, _XOPEN_VERSION);
#endif

#ifdef __VERSION__
  sha512_write_string(hash, __VERSION__);
#endif

#ifdef __linux__
  /* Information available through getauxval(). */
#ifdef AT_HWCAP
  sha512_write_int(hash, getauxval(AT_HWCAP));
#endif
#ifdef AT_HWCAP2
  sha512_write_int(hash, getauxval(AT_HWCAP2));
#endif
#ifdef AT_RANDOM
  {
    const unsigned char *random_aux =
      (const unsigned char *)getauxval(AT_RANDOM);

    if (random_aux)
      sha512_write(hash, random_aux, 16);
  }
#endif
#ifdef AT_PLATFORM
  {
    const char *platform_str = (const char *)getauxval(AT_PLATFORM);

    if (platform_str)
      sha512_write_string(hash, platform_str);
  }
#endif
#ifdef AT_EXECFN
  {
    const char *exec_str = (const char *)getauxval(AT_EXECFN);

    if (exec_str)
      sha512_write_string(hash, exec_str);
  }
#endif
#endif /* __linux__ */

#ifdef HAVE_CPUID
  sha512_write_cpuids(hash);
#endif

  /* Memory locations. */
  sha512_write_ptr(hash, hash);
  sha512_write_ptr(hash, &errno);
#ifndef environ
  sha512_write_ptr(hash, &environ);
#endif

  /* Hostname. */
  {
    char hname[256];

    memset(hname, 0, sizeof(hname));

    if (gethostname(hname, sizeof(hname) - 1) == 0)
      sha512_write_string(hash, hname);
  }

#ifdef HAVE_GETIFADDRS
  /* Network interfaces. */
  {
    struct ifaddrs *ifad = NULL;

    if (getifaddrs(&ifad) == 0) {
      struct ifaddrs *ifit = ifad;

      while (ifit != NULL) {
        sha512_write_string(hash, ifit->ifa_name);
        sha512_write_int(hash, ifit->ifa_flags);
        sha512_write_sockaddr(hash, ifit->ifa_addr);
        sha512_write_sockaddr(hash, ifit->ifa_netmask);
        sha512_write_sockaddr(hash, ifit->ifa_dstaddr);

        ifit = ifit->ifa_next;
      }

      freeifaddrs(ifad);
    }
  }
#endif /* HAVE_GETIFADDRS */

#ifndef _WIN32
  /* UNIX kernel information. */
  {
    struct utsname name;

    if (uname(&name) != -1) {
      sha512_write_string(hash, name.sysname);
      sha512_write_string(hash, name.nodename);
      sha512_write_string(hash, name.release);
      sha512_write_string(hash, name.version);
      sha512_write_string(hash, name.machine);
    }
  }

  /* Path and filesystem provided data. */
  sha512_write_stat(hash, "/");
  sha512_write_stat(hash, ".");
  sha512_write_stat(hash, "/tmp");
  sha512_write_stat(hash, "/home");
  sha512_write_stat(hash, "/proc");
#ifdef __linux__
  sha512_write_file(hash, "/proc/cmdline");
  sha512_write_file(hash, "/proc/cpuinfo");
  sha512_write_file(hash, "/proc/version");
#endif /* __linux__ */
  sha512_write_file(hash, "/etc/passwd");
  sha512_write_file(hash, "/etc/group");
  sha512_write_file(hash, "/etc/hosts");
  sha512_write_file(hash, "/etc/resolv.conf");
  sha512_write_file(hash, "/etc/timezone");
  sha512_write_file(hash, "/etc/localtime");
#endif /* !_WIN32 */

#ifdef HAVE_SYSCTL
#ifdef CTL_HW
#ifdef HW_MACHINE
  sha512_write_sysctl2(hash, CTL_HW, HW_MACHINE);
#endif
#ifdef HW_MODEL
  sha512_write_sysctl2(hash, CTL_HW, HW_MODEL);
#endif
#ifdef HW_NCPU
  sha512_write_sysctl2(hash, CTL_HW, HW_NCPU);
#endif
#ifdef HW_PHYSMEM
  sha512_write_sysctl2(hash, CTL_HW, HW_PHYSMEM);
#endif
#ifdef HW_USERMEM
  sha512_write_sysctl2(hash, CTL_HW, HW_USERMEM);
#endif
#ifdef HW_MACHINE_ARCH
  sha512_write_sysctl2(hash, CTL_HW, HW_MACHINE_ARCH);
#endif
#ifdef HW_REALMEM
  sha512_write_sysctl2(hash, CTL_HW, HW_REALMEM);
#endif
#ifdef HW_CPU_FREQ
  sha512_write_sysctl2(hash, CTL_HW, HW_CPU_FREQ);
#endif
#ifdef HW_BUS_FREQ
  sha512_write_sysctl2(hash, CTL_HW, HW_BUS_FREQ);
#endif
#ifdef HW_CACHELINE
  sha512_write_sysctl2(hash, CTL_HW, HW_CACHELINE);
#endif
#endif

#ifdef CTL_KERN
#ifdef KERN_BOOTFILE
  sha512_write_sysctl2(hash, CTL_KERN, KERN_BOOTFILE);
#endif
#ifdef KERN_BOOTTIME
  sha512_write_sysctl2(hash, CTL_KERN, KERN_BOOTTIME);
#endif
#ifdef KERN_CLOCKRATE
  sha512_write_sysctl2(hash, CTL_KERN, KERN_CLOCKRATE);
#endif
#ifdef KERN_HOSTID
  sha512_write_sysctl2(hash, CTL_KERN, KERN_HOSTID);
#endif
#ifdef KERN_HOSTUUID
  sha512_write_sysctl2(hash, CTL_KERN, KERN_HOSTUUID);
#endif
#ifdef KERN_HOSTNAME
  sha512_write_sysctl2(hash, CTL_KERN, KERN_HOSTNAME);
#endif
#ifdef KERN_OSRELDATE
  sha512_write_sysctl2(hash, CTL_KERN, KERN_OSRELDATE);
#endif
#ifdef KERN_OSRELEASE
  sha512_write_sysctl2(hash, CTL_KERN, KERN_OSRELEASE);
#endif
#ifdef KERN_OSREV
  sha512_write_sysctl2(hash, CTL_KERN, KERN_OSREV);
#endif
#ifdef KERN_OSTYPE
  sha512_write_sysctl2(hash, CTL_KERN, KERN_OSTYPE);
#endif
#ifdef KERN_POSIX1
  sha512_write_sysctl2(hash, CTL_KERN, KERN_OSREV);
#endif
#ifdef KERN_VERSION
  sha512_write_sysctl2(hash, CTL_KERN, KERN_VERSION);
#endif
#endif
#endif

  /* Environment variables. */
  if (environ) {
    size_t i;
    for (i = 0; environ[i] != NULL; i++)
      sha512_write_string(hash, environ[i]);
  }

#ifdef _WIN32
  sha512_write_int(hash, GetCurrentProcessId());
  sha512_write_int(hash, GetCurrentThreadId());
#else /* _WIN32 */
  sha512_write_int(hash, getpid());
  sha512_write_int(hash, getppid());
  sha512_write_int(hash, getsid(0));
  sha512_write_int(hash, getpgid(0));
  sha512_write_int(hash, getuid());
  sha512_write_int(hash, geteuid());
  sha512_write_int(hash, getgid());
  sha512_write_int(hash, getegid());
#endif /* _WIN32 */
}

static void
sha512_write_dynamic_env(sha512_t *hash) {
#ifdef _WIN32
  /* System time. */
  {
    FILETIME ftime;

    memset(&ftime, 0, sizeof(ftime));

    GetSystemTimeAsFileTime(&ftime);

    sha512_write(hash, &ftime, sizeof(ftime));
  }

  /* Performance data. */
  sha512_write_perfdata(hash);
#else /* _WIN32 */
  /* Various clocks. */
  {
    struct timespec ts;
    struct timeval tv;

    memset(&ts, 0, sizeof(ts));
    memset(&tv, 0, sizeof(tv));

#ifdef CLOCK_MONOTONIC
    clock_gettime(CLOCK_MONOTONIC, &ts);
    sha512_write(hash, &ts, sizeof(ts));
#endif

#ifdef CLOCK_REALTIME
    clock_gettime(CLOCK_REALTIME, &ts);
    sha512_write(hash, &ts, sizeof(ts));
#endif

#ifdef CLOCK_BOOTTIME
    clock_gettime(CLOCK_BOOTTIME, &ts);
    sha512_write(hash, &ts, sizeof(ts));
#endif

    gettimeofday(&tv, NULL);
    sha512_write(hash, &tv, sizeof(tv));
  }

  /* Current resource usage. */
  {
    struct rusage usage;

    memset(&usage, 0, sizeof(usage));

    if (getrusage(RUSAGE_SELF, &usage) == 0)
      sha512_write(hash, &usage, sizeof(usage));
  }
#endif /* _WIN32 */

#ifdef __linux__
  sha512_write_file(hash, "/proc/diskstats");
  sha512_write_file(hash, "/proc/vmstat");
  sha512_write_file(hash, "/proc/schedstat");
  sha512_write_file(hash, "/proc/zoneinfo");
  sha512_write_file(hash, "/proc/meminfo");
  sha512_write_file(hash, "/proc/softirqs");
  sha512_write_file(hash, "/proc/stat");
  sha512_write_file(hash, "/proc/self/schedstat");
  sha512_write_file(hash, "/proc/self/status");
#endif

#ifdef HAVE_SYSCTL
#ifdef CTL_KERN
#if defined(KERN_PROC) && defined(KERN_PROC_ALL)
  sha512_write_sysctl3(hash, CTL_KERN, KERN_PROC, KERN_PROC_ALL);
#endif
#endif
#ifdef CTL_HW
#ifdef HW_DISKSTATS
  sha512_write_sysctl2(hash, CTL_HW, HW_DISKSTATS);
#endif
#endif
#ifdef CTL_VM
#ifdef VM_LOADAVG
  sha512_write_sysctl2(hash, CTL_VM, VM_LOADAVG);
#endif
#ifdef VM_TOTAL
  sha512_write_sysctl2(hash, CTL_VM, VM_TOTAL);
#endif
#ifdef VM_METER
  sha512_write_sysctl2(hash, CTL_VM, VM_METER);
#endif
#endif
#endif

  /* Stack and heap location. */
  {
    void *addr = malloc(4097);

    sha512_write_ptr(hash, &addr);

    if (addr) {
      sha512_write_ptr(hash, addr);
      free(addr);
    }
  }
}
#endif /* HAVE_MANUAL_ENTROPY */

/*
 * RNG
 */

int
rng_init(rng_t *rng) {
  unsigned char seed[64];
#ifdef HAVE_MANUAL_ENTROPY
  sha512_t hash;
  size_t i;
#endif

  memset(rng, 0, sizeof(*rng));

  /* OS entropy (64 bytes). */
  if (!torsion_getentropy(seed, 64))
    return 0;

#ifdef HAVE_MANUAL_ENTROPY
  sha512_init(&hash);
  sha512_write_int(&hash, torsion_hrtime());
  sha512_write_ptr(&hash, rng);
  sha512_write_ptr(&hash, seed);
  sha512_write(&hash, seed, 64);

  /* Hardware entropy (32 bytes). */
#ifdef HAVE_CPUID
  rng->rdrand = torsion_has_rdrand();
  rng->rdseed = torsion_has_rdseed();

  if (rng->rdseed) {
    for (i = 0; i < 4; i++)
      sha512_write_int(&hash, torsion_rdseed());
  } else if (rng->rdrand) {
    for (i = 0; i < 4; i++) {
      uint64_t out = 0;
      size_t j;

      for (j = 0; j < 1024; j++)
        out ^= torsion_rdrand();

      sha512_write_int(&hash, out);
    }
  }

  sha512_write_int(&hash, torsion_hrtime());
#endif /* HAVE_CPUID */

  /* Manual entropy (potentially ~10mb). */
  sha512_write_static_env(&hash);
  sha512_write_dynamic_env(&hash);

  /* At this point, only one of the above
     entropy sources needs to be strong in
     order for our RNG to work. It's extremely
     unlikely that all three would somehow
     be compromised. */
  sha512_write_int(&hash, torsion_hrtime());
  sha512_final(&hash, seed);

  /* Strengthen the seed a bit. */
  for (i = 0; i < 500; i++) {
    sha512_init(&hash);
    sha512_write(&hash, seed, 64);

    if (i == 500 - 1)
      sha512_write_int(&hash, torsion_hrtime());

    sha512_final(&hash, seed);
  }
#endif /* HAVE_MANUAL_ENTROPY */

  /* We use XChaCha20 to reduce the first
     48 bytes down to 32. This allows us to
     use the entire 64 byte hash as entropy. */
  chacha20_derive(seed, seed, 32, seed + 32);

  /* Read our initial ChaCha20 state. */
  memcpy(rng->key, seed, 32);
  memcpy(&rng->zero, seed + 48, 8);
  memcpy(&rng->nonce, seed + 56, 8);

  cleanse(seed, sizeof(seed));
#ifdef HAVE_MANUAL_ENTROPY
  cleanse(&hash, sizeof(hash));
#endif

  return 1;
}

void
rng_generate(rng_t *rng, void *dst, size_t size) {
  unsigned char *key = (unsigned char *)rng->key;
  unsigned char *nonce = (unsigned char *)&rng->nonce;
  chacha20_t ctx;

  if (size == 0)
    return;

  memset(dst, 0, size);

  /* Read the keystream. */
  chacha20_init(&ctx, key, 32, nonce, 8, rng->zero);
  chacha20_encrypt(&ctx, dst, dst, size);

  /* Re-key immediately. */
  rng->key[0] ^= size;

#ifdef HAVE_CPUID
  /* Mix in some hardware entropy. */
  if (rng->rdrand)
    rng->key[3] ^= torsion_rdrand();
#endif

  rng->nonce++;

  /* XOR the current key with the keystream. */
  chacha20_init(&ctx, key, 32, nonce, 8, rng->zero);
  chacha20_encrypt(&ctx, key, key, 32);

  /* Cleanse the chacha state. */
  cleanse(&ctx, sizeof(ctx));
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

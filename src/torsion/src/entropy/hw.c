/*!
 * hw.c - hardware entropy for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Time_Stamp_Counter
 *   https://en.wikipedia.org/wiki/RDRAND
 *
 * Windows:
 *   https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/ftime-ftime32-ftime64?view=vs-2019
 *   https://docs.microsoft.com/en-us/cpp/intrinsics/rdtsc?view=vs-2019
 *
 * Unix:
 *   http://man7.org/linux/man-pages/man2/gettimeofday.2.html
 *
 * VxWorks:
 *   https://docs.windriver.com/bundle/vxworks_7_application_core_os_sr0630-enus/page/CORE/clockLib.html
 *
 * Fuchsia:
 *   https://fuchsia.dev/fuchsia-src/reference/syscalls/clock_get_monotonic
 *
 * CloudABI:
 *   https://nuxi.nl/cloudabi/#clock_time_get
 *
 * WASI:
 *   https://github.com/WebAssembly/WASI/blob/5d10b2c/design/WASI-core.md#clock_time_get
 *   https://github.com/WebAssembly/WASI/blob/2627acd/phases/snapshot/witx/wasi_snapshot_preview1.witx#L58
 *
 * Emscripten (wasm, asm.js):
 *   https://emscripten.org/docs/api_reference/emscripten.h.html
 *   https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/now
 *   https://nodejs.org/api/process.html#process_process_hrtime_time
 *
 * x86{,-64}:
 *   https://www.felixcloutier.com/x86/rdtsc
 *   https://www.felixcloutier.com/x86/rdrand
 *   https://www.felixcloutier.com/x86/rdseed
 */

/**
 * Hardware Entropy
 *
 * One simple source of hardware entropy is the current cycle
 * count. This is accomplished via RDTSC on x86 CPUs. We only
 * call RDTSC if there is an instrinsic for it (win32) or if
 * the compiler supports inline ASM (gcc/clang).
 *
 * For non-x86 hardware, we fallback to whatever system clocks
 * are available. This includes:
 *
 *   - _ftime (win32)
 *   - gettimeofday (unix)
 *   - clock_gettime (vxworks)
 *   - zx_clock_get_monotonic (fuchsia)
 *   - cloudabi_sys_clock_time_get (cloud abi)
 *   - __wasi_clock_time_get (wasi)
 *   - Date.now, process.hrtime (wasm, asm.js)
 *
 * Note that the only clocks which do not have nanosecond
 * precision are `_ftime`, `gettimeofday`, and `Date.now`.
 *
 * The CPUID instruction can serve as good source of "static"
 * entropy for seeding (see env.c).
 *
 * x86{,-64} also offers hardware entropy in the form of RDRAND
 * and RDSEED. There are concerns that these instructions may
 * be backdoored in some way. This is not an issue as we only
 * use hardware entropy to supplement our full entropy pool.
 *
 * For non-x86 hardware, torsion_rdrand and torsion_rdseed are
 * no-ops returning zero. torsion_has_rd{rand,seed} MUST be
 * checked before calling torsion_rd{rand,seed}.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "entropy.h"

#if defined(__CloudABI__)
uint16_t cloudabi_sys_clock_time_get(uint32_t clock_id,
                                     uint64_t precision,
                                     uint64_t *time);
#  define CLOUDABI_CLOCK_MONOTONIC 1
#elif defined(__wasi__)
uint16_t __wasi_clock_time_get(uint32_t clock_id,
                               uint64_t precision,
                               uint64_t *time);
#  define __WASI_CLOCK_MONOTONIC 1
#elif defined(__EMSCRIPTEN__)
#  include <emscripten.h> /* EM_ASM_INT */
#elif defined(__wasm__) || defined(__asmjs__)
/* nothing */
#elif defined(_WIN32)
#  include <sys/timeb.h> /* _timeb, _ftime */
#  ifdef __BORLANDC__
#    define _timeb timeb
#    define _ftime ftime
#  endif
#  if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
#    include <intrin.h> /* __rdtsc */
#    pragma intrinsic(__rdtsc)
#    define HAVE_RDTSC
#  endif
#elif defined(__vxworks)
#  include <time.h> /* clock_gettime */
#elif defined(__fuchsia__)
#  include <zircon/syscalls.h> /* zx_clock_get_monotonic */
#else
#  include <sys/time.h> /* gettimeofday */
#  if defined(__GNUC__)
#    define HAVE_INLINE_ASM
#    if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
#      define HAVE_CPUID
#    endif
#  endif
#endif

/*
 * Timestamp Counter
 */

uint64_t
torsion_rdtsc(void) {
#if defined(__CloudABI__)
  uint64_t time;

  if (cloudabi_sys_clock_time_get(CLOUDABI_CLOCK_MONOTONIC, 0, &time) != 0)
    abort();

  return time;
#elif defined(__wasi__)
  uint64_t time;

  if (__wasi_clock_time_get(__WASI_CLOCK_MONOTONIC, 0, &time) != 0)
    abort();

  return time;
#elif defined(__EMSCRIPTEN__)
  uint32_t sec, nsec;

  int ret = EM_ASM_INT({
    try {
      if (typeof process !== 'undefined' && process
          && typeof process.hrtime === 'function') {
        var times = process.hrtime();

        HEAPU32[$0 >>> 2] = times[0];
        HEAPU32[$1 >>> 2] = times[1];

        return 1;
      }

      var now = Date.now ? Date.now() : +new Date();
      var ms = now % 1000;

      HEAPU32[$0 >>> 2] = (now - ms) / 1000;
      HEAPU32[$1 >>> 2] = ms * 1e6;

      return 1;
    } catch (e) {
      return 0;
    }
  }, (void *)&sec, (void *)&nsec);

  if (ret != 1)
    abort();

  return (uint64_t)sec * 1000000000 + (uint64_t)nsec;
#elif defined(__wasm__) || defined(__asmjs__)
  return 0;
#elif defined(_WIN32)
#ifdef HAVE_RDTSC
  return __rdtsc();
#else /* HAVE_RDTSC */
  /* Borrowed from libsodium. */
  /* FIXME: Figure out how to get nanosecond precision. */
  struct _timeb tb;
#pragma warning(push)
#pragma warning(disable: 4996)
  _ftime(&tb);
#pragma warning(pop)
  return (uint64_t)tb.time * 1000000 + (uint64_t)tb.millitm * 1000;
#endif /* HAVE_RDTSC */
#elif defined(__vxworks)
  struct timespec ts;

  if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
    abort();

  return (uint64_t)ts.tv_sec * 1000000000 + (uint64_t)ts.tv_nsec;
#elif defined(__fuchsia__)
  return zx_clock_get_monotonic();
#elif defined(HAVE_INLINE_ASM) && defined(__i386__)
  /* Borrowed from Bitcoin Core. */
  uint64_t r = 0;
  __asm__ __volatile__("rdtsc" : "=A" (r));
  return r;
#elif defined(HAVE_INLINE_ASM) && (defined(__x86_64__) || defined(__amd64__))
  /* Borrowed from Bitcoin Core. */
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
 * CPUID
 */

int
torsion_has_cpuid(void) {
#ifdef HAVE_CPUID
  return 1;
#else
  return 0;
#endif
}

void
torsion_cpuid(uint32_t level,
              uint32_t count,
              uint32_t *a,
              uint32_t *b,
              uint32_t *c,
              uint32_t *d) {
#ifdef HAVE_CPUID
  __asm__ ("cpuid\n"
           : "=a" (*a), "=b" (*b), "=c" (*c), "=d" (*d)
           : "0" (level), "2" (count));
#else /* HAVE_CPUID */
  (void)level;
  (void)count;
  *a = 0;
  *b = 0;
  *c = 0;
  *d = 0;
#endif /* HAVE_CPUID */
}

/*
 * RDRAND/RDSEED
 */

int
torsion_has_rdrand(void) {
#ifdef HAVE_CPUID
  uint32_t eax, ebx, ecx, edx;
  torsion_cpuid(1, 0, &eax, &ebx, &ecx, &edx);
  return !!(ecx & UINT32_C(0x40000000));
#else
  return 0;
#endif
}

int
torsion_has_rdseed(void) {
#ifdef HAVE_CPUID
  uint32_t eax, ebx, ecx, edx;
  torsion_cpuid(7, 0, &eax, &ebx, &ecx, &edx);
  return !!(ebx & UINT32_C(0x00040000));
#else
  return 0;
#endif
}

uint64_t
torsion_rdrand(void) {
  /* Borrowed from Bitcoin Core. */
#ifdef HAVE_CPUID
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
#else /* HAVE_CPUID */
  return 0;
#endif /* HAVE_CPUID */
}

uint64_t
torsion_rdseed(void) {
  /* Borrowed from Bitcoin Core. */
#ifdef HAVE_CPUID
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
#else /* HAVE_CPUID */
  return 0;
#endif /* HAVE_CPUID */
}

/*
 * Hardware Entropy
 */

int
torsion_hwrand(void *dst, size_t size) {
#ifdef HAVE_CPUID
  unsigned char *data = (unsigned char *)dst;
  int has_rdrand = torsion_has_rdrand();
  int has_rdseed = torsion_has_rdseed();
  uint64_t x;
  size_t i;

  if (!has_rdrand && !has_rdseed)
    return 0;

  while (size > 0) {
    if (has_rdseed) {
      x = torsion_rdseed();
    } else {
      x = 0;

      /* Idea from Bitcoin Core: force rdrand to reseed. */
      for (i = 0; i < 1024; i++)
        x ^= torsion_rdrand();
    }

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

/*!
 * hrt.c - high-resolution time for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Windows:
 *   https://docs.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter
 *   https://docs.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancefrequency
 *   https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimeasfiletime
 *
 * OSX/iOS/tvOS/watchOS:
 *   https://developer.apple.com/documentation/kernel/1462446-mach_absolute_time
 *
 * Solaris/Illumos:
 *   https://docs.oracle.com/cd/E86824_01/html/E54766/gethrtime-3c.html
 *
 * HP-UX:
 *   https://docstore.mik.ua/manuals/hp-ux/en/B2355-60130/gethrtime.3C.html
 *
 * AIX:
 *   https://www.ibm.com/docs/en/aix/7.1?topic=r-read-real-time-read-wall-timetime-base-time-mread-real-time-subroutine
 *
 * z/OS:
 *   https://www.ibm.com/docs/en/zos/2.3.0?topic=functions-general-instructions
 *
 * Unix:
 *   https://pubs.opengroup.org/onlinepubs/009604599/functions/gettimeofday.html
 *   https://pubs.opengroup.org/onlinepubs/009695399/functions/clock_getres.html
 *
 * VMS:
 *   http://uprpon.upr.edu/help?key=System_Services~$GETTIM
 *   http://uprpon.upr.edu/help?key=System_Services~$GETTIM_PREC
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
 *   https://github.com/emscripten-core/emscripten/blob/b45948b/system/include/wasi/api.h#L1751
 *
 * Emscripten (wasm, asm.js):
 *   https://emscripten.org/docs/api_reference/emscripten.h.html
 *
 * ANSI C:
 *   http://port70.net/~nsz/c/c89/c89-draft.html#4.12.2.4
 */

/**
 * High-resolution Time
 *
 * We utilize to whatever system clocks are available.
 *
 * This includes:
 *
 *   - QueryPerformanceCounter (win32)
 *   - GetSystemTimeAsFileTime (win32 legacy)
 *   - mach_absolute_time (apple)
 *   - gethrtime (solaris, hpux)
 *   - read_wall_time (aix)
 *   - __stckf (zos)
 *   - __stck (zos legacy)
 *   - clock_gettime (unix)
 *   - gettimeofday (unix legacy)
 *   - sys$gettim_prec (vms)
 *   - sys$gettim (vms legacy)
 *   - clock_gettime (vxworks)
 *   - zx_clock_get_monotonic (fuchsia)
 *   - cloudabi_sys_clock_time_get (cloudabi)
 *   - __wasi_clock_time_get (wasi)
 *   - emscripten_get_now (emscripten)
 *
 * Note that the only clocks which do not have nanosecond
 * precision are `GetSystemTimeAsFileTime`, `gettimeofday`,
 * and `sys$gettim`.
 *
 * If no OS clocks are present, we fall back to standard
 * ANSI time functions (i.e. time(2)).
 *
 * Furthermore, QueryPerformance{Counter,Frequency} may fail
 * on Windows 2000. For this reason, we require Windows XP or
 * above (otherwise we fall back to GetSystemTimeAsFileTime).
 */

#include "ftm.h"

#include <stddef.h>
#include <stdint.h>
#include "entropy.h"

#undef HAVE_QUERYPERFORMANCECOUNTER
#undef HAVE_CLOCK_GETTIME
#undef HAVE_GETHRTIME
#undef HAVE_REALTIME
#undef HAVE_GETTIMEOFDAY

/* High-resolution time. */
#if defined(_WIN32)
#  include <windows.h> /* QueryPerformanceCounter, GetSystemTimeAsFileTime */
#  pragma comment(lib, "kernel32.lib")
#  if defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0501 /* Windows XP */
#    define HAVE_QUERYPERFORMANCECOUNTER
#  endif
#elif defined(__VMS)
#  include <ssdef.h> /* SS$_NORMAL */
#  include <starlet.h> /* sys$gettim{,_prec} */
#  ifdef __DECC
#    pragma message disable DOLLARID
#  endif
#elif defined(__vxworks)
#  include <time.h> /* clock_gettime, time */
#  if defined(CLOCK_REALTIME) || defined(CLOCK_MONOTONIC)
#    define HAVE_CLOCK_GETTIME
#  endif
#elif defined(__Fuchsia__)
#  include <zircon/syscalls.h> /* zx_clock_get_monotonic */
#elif defined(__CloudABI__)
#  include <cloudabi_syscalls.h> /* cloudabi_sys_clock_time_get */
#elif defined(__EMSCRIPTEN__)
#  include <emscripten.h> /* emscripten_get_now */
#elif defined(__wasi__)
#  include <wasi/api.h> /* __wasi_clock_time_get */
#elif defined(__APPLE__) && defined(__MACH__)
#  include <mach/mach.h> /* KERN_SUCCESS */
#  include <mach/mach_time.h> /* mach_timebase_{info,time} */
#elif defined(__sun) && defined(__SVR4)
#  include <sys/time.h> /* gethrtime */
#  define HAVE_GETHRTIME
#elif defined(__hpux)
#  include <time.h> /* gethrtime */
#  define HAVE_GETHRTIME
#elif defined(_AIX)
#  include <sys/time.h> /* read_wall_time */
#elif defined(__MVS__) && defined(_MI_BUILTIN)
#  include <builtins.h> /* __stck{,f} */
#else
#  include <time.h> /* clock_gettime, time */
#  include <unistd.h> /* _POSIX_TIMERS, _XOPEN_VERSION */
#  if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#    if __GLIBC_PREREQ(2, 17)
#      define HAVE_REALTIME
#    endif
#  endif
#  if defined(_POSIX_TIMERS) && (_POSIX_TIMERS + 0) > 0
#    if !defined(__GLIBC__) || defined(HAVE_REALTIME)
#      if defined(CLOCK_REALTIME) || defined(CLOCK_MONOTONIC)
#        define HAVE_CLOCK_GETTIME
#      endif
#    endif
#  endif
#  ifndef HAVE_CLOCK_GETTIME
#    if defined(_XOPEN_VERSION) && _XOPEN_VERSION >= 500
#      include <sys/time.h> /* gettimeofday */
#      define HAVE_GETTIMEOFDAY
#    endif
#  endif
#endif

/*
 * High-Resolution Time
 */

uint64_t
torsion_hrtime(void) {
#if defined(HAVE_QUERYPERFORMANCECOUNTER) /* _WIN32 */
  LARGE_INTEGER freq, ctr;

  if (!QueryPerformanceFrequency(&freq))
    return 0;

  if (!QueryPerformanceCounter(&ctr))
    return 0;

  if (freq.QuadPart == 0)
    return 0;

  /* We have no idea of the magnitude of `freq`,
   * so we must resort to double arithmetic[1].
   * Furthermore, we use some wacky arithmetic
   * to avoid a bug in Visual Studio 2019[2][3].
   *
   * [1] https://github.com/libuv/libuv/blob/7967448/src/win/util.c#L503
   * [2] https://github.com/libuv/libuv/issues/1633
   * [3] https://github.com/libuv/libuv/pull/2866
   */
#if defined(_MSC_VER)
  {
    static unsigned int scale = 1000000000;
    double scaled = (double)freq.QuadPart / scale;
    double result = (double)ctr.QuadPart / scaled;

    return (uint64_t)result;
  }
#else
  {
    double sec = (double)ctr.QuadPart / (double)freq.QuadPart;

    return (uint64_t)(sec * 1000000000.0);
  }
#endif
#elif defined(_WIN32)
  /* There was no reliable nanosecond precision
   * time available on Windows prior to XP. We
   * borrow some more code from libuv[1] in order
   * to convert NT time to unix time. Note that the
   * libuv code was originally based on postgres[2].
   *
   * NT's epoch[3] begins on January 1st, 1601: 369
   * years earlier than the unix epoch.
   *
   * [1] https://github.com/libuv/libuv/blob/7967448/src/win/util.c#L1942
   * [2] https://doxygen.postgresql.org/gettimeofday_8c_source.html
   * [3] https://en.wikipedia.org/wiki/Epoch_(computing)
   */
  static const uint64_t epoch = UINT64_C(116444736000000000);
  ULARGE_INTEGER ul;
  FILETIME ft;

  GetSystemTimeAsFileTime(&ft);

  ul.LowPart = ft.dwLowDateTime;
  ul.HighPart = ft.dwHighDateTime;

  return ((uint64_t)ul.QuadPart - epoch) * 100;
#elif defined(__VMS)
  /* VMS is similar to Windows time in that it uses
   * 100ns units. The only difference is that it
   * picks a time epoch of November 17th, 1858[1].
   *
   * [1] https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.362.7968&rep=rep1&type=pdf
   */
  static const uint64_t epoch = UINT64_C(35067168000000000);
  uint64_t ts;

#if defined(__CRTL_VER) && __CRTL_VER >= 80400000 /* 8.4 */
  ret = sys$gettim_prec((void *)&ts);

  if (ret == SS$_LOWPREC)
    ret = SS$_NORMAL;
#else
  ret = sys$gettim((void *)&ts);
#endif

  if (ret != SS$_NORMAL)
    return 0;

  return (ts - epoch) * 100;
#elif defined(__Fuchsia__)
  return zx_clock_get_monotonic();
#elif defined(__CloudABI__)
  uint64_t ts;

  if (cloudabi_sys_clock_time_get(CLOUDABI_CLOCK_MONOTONIC, 1, &ts) != 0)
    return 0;

  return ts;
#elif defined(__EMSCRIPTEN__)
  return emscripten_get_now() * 1000000.0;
#elif defined(__wasi__)
  uint64_t ts = 0;

#ifdef TORSION_WASM_BIGINT
  /* Requires --experimental-wasm-bigint at the moment. */
  if (__wasi_clock_time_get(__WASI_CLOCKID_MONOTONIC, 1, &ts) != 0)
    return 0;
#endif

  return ts;
#elif defined(__APPLE__) && defined(__MACH__)
  mach_timebase_info_data_t info;

  if (mach_timebase_info(&info) != KERN_SUCCESS)
    return 0;

  if (info.denom == 0)
    return 0;

  return mach_absolute_time() * info.numer / info.denom;
#elif defined(HAVE_GETHRTIME)
  hrtime_t ts = gethrtime();

  if (ts == (hrtime_t)-1)
    return 0;

  return ts;
#elif defined(_AIX)
  timebasestruct_t tb;

  read_wall_time(&tb, TIMEBASE_SZ); /* == RTC_POWER_PC */

  return (uint64_t)tb.tb_high * 1000000000 + (uint64_t)tb.tb_low;
#elif defined(__MVS__) && defined(_MI_BUILTIN)
  /* The z/arch clock is so high precision that we
   * actually need to downgrade it by dividing the
   * units by 4.096 in order to get nanoseconds.
   *
   * It picks a time epoch of January 1st, 1900.
   */
  static const uint64_t epoch = UINT64_C(2208988800000000000);
  unsigned long long ts;
  int ret;

  /* Condition Codes[1]:
   *
   *   0 = clock set
   *   1 = clock not set
   *   2 = clock error
   *   3 = clock stopped
   *
   * [1] https://groups.google.com/g/bit.listserv.ibm-main/c/qWWkdociQMQ
   */
#if defined(__ARCH__) && __ARCH__ >= 7
  ret = __stckf(&ts);
#else
  ret = __stck(&ts);
#endif

  if (ret < 0 || ret > 1)
    return 0;

  ts = (ts / 512) * 125; /* ts /= 4.096 */

  if (ret == 0)
    ts -= epoch;

  return ts;
#elif defined(HAVE_CLOCK_GETTIME)
  struct timespec ts;

#ifdef CLOCK_BOOTTIME
  if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0)
#endif
  {
#ifdef CLOCK_MONOTONIC /* _POSIX_MONOTONIC_CLOCK */
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
#endif
    {
#ifdef CLOCK_REALTIME
      if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
#endif
      {
        return 0;
      }
    }
  }

  return (uint64_t)ts.tv_sec * 1000000000 + (uint64_t)ts.tv_nsec;
#elif defined(HAVE_GETTIMEOFDAY)
  struct timeval tv;

  if (gettimeofday(&tv, NULL) != 0)
    return 0;

  return (uint64_t)tv.tv_sec * 1000000000 + (uint64_t)tv.tv_usec * 1000;
#else
  /* The encoding of the value returned from
     time(2) is unspecified according to C89.
     However, on most systems, it is the number
     of seconds elapsed since the unix epoch. */
  time_t ts = time(NULL);

  if (ts == (time_t)-1)
    return 0;

  return (uint64_t)ts * 1000000000;
#endif
}

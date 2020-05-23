/*!
 * env.c - entropy gathering for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on bitcoin/bitcoin:
 *   Copyright (c) 2009-2019, The Bitcoin Core Developers (MIT License).
 *   Copyright (c) 2009-2019, The Bitcoin Developers (MIT License).
 *   https://github.com/bitcoin/bitcoin
 *
 * Resources:
 *   https://github.com/bitcoin/bitcoin/blob/master/src/randomenv.cpp
 */

/**
 * Entropy Gathering
 *
 * Most ideas for entropy gathering here are taken from Bitcoin Core.
 * We more or less faithfully port randomenv.cpp to C (see above).
 *
 * There are many sources of entropy on a given OS. This includes:
 *
 *   - Clocks (GetSystemTimeAsFileTime, gettimeofday, clock_gettime)
 *   - Environment Variables (char **environ)
 *   - Network Interfaces (getifaddrs(3))
 *   - Kernel Information (uname(2))
 *   - Machine Hostname (gethostname(3))
 *   - Process/User/Group IDs (pid, ppid, sid, pgid, uid, euid, gid, egid)
 *   - Resource Usage (getrusage(3))
 *   - Pointers (stack and heap locations)
 *   - stat(2) calls on system files & directories
 *   - System files (/etc/{passwd,group,hosts,resolv.conf,timezone})
 *   - HKEY_PERFORMANCE_DATA (win32)
 *   - The /proc filesystem (linux)
 *   - sysctl(2) (osx, ios, bsd)
 *   - I/O timing, system load
 *
 * We use whatever data we can get our hands on and hash
 * it into a single 64 byte seed for use with a PRNG.
 */

#ifdef __linux__
/* For gethostname(3), getsid(3), getpgid(3), clock_gettime(2). */
#  define _GNU_SOURCE
#endif

#ifdef _WIN32
/* winsock2.h must be included before windows.h. */
/* See: https://stackoverflow.com/a/9168850/716248 */
#  include <winsock2.h> /* gethostname */
#  pragma comment(lib, "ws2_32.lib")
#endif

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <torsion/hash.h>
#include "entropy.h"

#if defined(__CloudABI__)
/* nothing */
#elif defined(__wasi__)
/* nothing */
#elif defined(__EMSCRIPTEN__)
/* nothing */
#elif defined(__wasm__) || defined(__asmjs__)
/* nothing */
#elif defined(_WIN32)
#  include <windows.h>
#  ifndef environ
extern char **environ;
#  endif
#  define HAVE_MANUAL_ENTROPY
#elif defined(__vxworks)
/* nothing */
#elif defined(__fuchsia__)
/* nothing */
#else
#  include <sys/types.h> /* open */
#  include <fcntl.h> /* open */
#  include <sys/resource.h> /* getrusage */
#  include <sys/stat.h> /* open, stat */
#  include <sys/utsname.h> /* uname */
#  include <sys/time.h> /* gettimeofday */
#  include <time.h> /* clock_gettime */
#  include <unistd.h> /* stat, read, close, gethostname */
#  ifdef __linux__
#    include <sys/auxv.h> /* getauxval */
#    ifdef __GLIBC_PREREQ
#      define TORSION_GLIBC_PREREQ(maj, min) __GLIBC_PREREQ(maj, min)
#    else
#      define TORSION_GLIBC_PREREQ(maj, min) 0
#    endif
#    if TORSION_GLIBC_PREREQ(2, 3)
#      include <sys/socket.h> /* AF_INET{,6} */
#      include <netinet/in.h> /* sockaddr_in{,6} */
#      include <ifaddrs.h> /* getifaddrs */
#      define HAVE_GETIFADDRS
#    endif
#  endif
#  if defined(__APPLE__) \
   || defined(__OpenBSD__) \
   || defined(__FreeBSD__) \
   || defined(__NetBSD__) \
   || defined(__DragonFly__)
#    include <sys/sysctl.h> /* sysctl */
#    include <sys/socket.h> /* AF_INET{,6} */
#    include <netinet/in.h> /* sockaddr_in{,6} */
#    include <ifaddrs.h> /* getifaddrs */
#    define HAVE_SYSCTL
#    define HAVE_GETIFADDRS
#  endif
#  if defined(__FreeBSD__) || defined(__DragonFly__)
#    include <vm/vm_param.h> /* VM_{LOADAVG,TOTAL,METER} */
#  endif
#  ifdef __APPLE__
#    include <crt_externs.h>
#    define environ (*_NSGetEnviron())
#  else
#    ifndef environ
extern char **environ;
#    endif
#  endif
#  define HAVE_MANUAL_ENTROPY
#endif

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
    sha512_write_data(hash, name, namelen * sizeof(int));

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
  sha512_write_cpuid(hash, 0, 0, &ax, &bx, &cx, &dx);

  /* Max leaf in ax. */
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
  sha512_write_cpuid(hash, 0x80000000, 0, &ax, &bx, &cx, &dx);

  /* Max extended leaf in ax. */
  maxext = ax;

  for (leaf = 0x80000001; leaf <= maxext && leaf <= 0x800000ff; leaf++)
    sha512_write_cpuid(hash, leaf, 0, &ax, &bx, &cx, &dx);
}

#ifdef _WIN32
static void
sha512_write_perfdata(sha512_t *hash) {
  static const size_t max = 10000000;
  unsigned char *data = malloc(250000);
  unsigned long nsize = 0;
  size_t size = 250000;
  long ret = 0;
  size_t old;

  if (data == NULL)
    return;

  memset(data, 0, size);

  for (;;) {
    nsize = size;
    ret = RegQueryValueExA(HKEY_PERFORMANCE_DATA,
                           "Global", NULL, NULL,
                           data, &nsize);

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
    sha512_write_data(hash, data, nsize);
    memset(data, 0, nsize);
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

  /* CPU features. */
  if (torsion_has_cpuid())
    sha512_write_cpuids(hash);

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

int
torsion_envrand(unsigned char *seed) {
#ifdef HAVE_MANUAL_ENTROPY
  sha512_t hash;
  sha512_init(&hash);
  sha512_write_ptr(&hash, seed);
  sha512_write_static_env(&hash);
  sha512_write_dynamic_env(&hash);
  sha512_final(&hash, seed);
  return 1;
#else
  (void)seed;
  return 0;
#endif /* HAVE_MANUAL_ENTROPY */
}

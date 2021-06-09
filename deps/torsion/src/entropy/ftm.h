/*!
 * ftm.h - feature test macros for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef TORSION_FTM_H
#define TORSION_FTM_H

/**
 * Feature Test Macros
 *
 * Several C standard libraries determine the set of POSIX
 * features based on the language standard. In particular,
 * a number of them disable almost every feature if
 * `__STRICT_ANSI__` (or `__STDC__=1`) is defined.
 *
 * This includes (but is probably not limited to): glibc,
 * sun/solaris, cygwin, hpux, qnx, and haiku (sort of).
 *
 * I'm uncertain whether the IBM OSes base their POSIX
 * features on the language standard, but they're
 * nevertheless some of the worst offenders (especially
 * z/OS) in that they require a feature test macro for
 * damn near everything (including POSIX.1).
 *
 * In my opinion, this is one aspect of C that the BSDs
 * get right: they don't go in for any of this nonsense
 * (the default always includes everything).
 *
 * GCC and Clang try to fix a lot of this on their own,
 * especially when compiling C++, but they fall short for
 * our needs.
 *
 * We want our code to be able to access the same POSIX
 * APIs regardless of the language standard chosen.
 *
 * Resources:
 *
 * Windows:
 *   https://docs.microsoft.com/en-us/cpp/porting/modifying-winver-and-win32-winnt
 *   https://docs.microsoft.com/en-us/windows/win32/winprog/using-the-windows-headers
 *
 * glibc:
 *   https://man7.org/linux/man-pages/man7/feature_test_macros.7.html
 *   https://github.com/bminor/glibc/blob/6c57d32/include/features.h
 *   https://github.com/bminor/glibc/blob/6c57d32/include/unistd.h
 *
 * musl:
 *   https://github.com/ifduyue/musl/blob/1febd21/include/features.h
 *   https://github.com/ifduyue/musl/blob/1febd21/include/unistd.h
 *
 * Bionic:
 *   https://github.com/aosp-mirror/platform_bionic/blob/a1112fd/libc/include/sys/cdefs.h#L162
 *   https://github.com/aosp-mirror/platform_bionic/blob/a1112fd/libc/include/unistd.h
 *
 * Darwin:
 *   https://github.com/apple/darwin-xnu/blob/d4061fb/bsd/sys/cdefs.h#L792
 *   https://github.com/apple/darwin-xnu/blob/d4061fb/bsd/sys/unistd.h
 *   https://opensource.apple.com/source/Libc/Libc-1439.40.11/include/unistd.h.auto.html
 *
 * FreeBSD:
 *   https://github.com/freebsd/freebsd-src/blob/cfad8bd/sys/sys/cdefs.h#L638
 *   https://github.com/freebsd/freebsd-src/blob/cfad8bd/include/unistd.h
 *
 * OpenBSD:
 *   https://github.com/openbsd/src/blob/43b1a0f/sys/sys/cdefs.h#L261
 *   https://github.com/openbsd/src/blob/43b1a0f/include/unistd.h
 *
 * NetBSD:
 *   https://github.com/NetBSD/src/blob/ee650a6/sys/sys/featuretest.h
 *   https://github.com/NetBSD/src/blob/ee650a6/include/unistd.h
 *
 * DragonFly BSD:
 *   https://github.com/DragonFlyBSD/DragonFlyBSD/blob/c97dc9d/sys/sys/cdefs.h#L597
 *   https://github.com/DragonFlyBSD/DragonFlyBSD/blob/c97dc9d/include/unistd.h
 *
 * Solaris/Illumos:
 *   https://docs.oracle.com/cd/E19253-01/816-5175/standards-5/index.html
 *   https://github.com/illumos/illumos-gate/blob/9ecd05b/usr/src/uts/common/sys/feature_tests.h
 *   https://github.com/illumos/illumos-gate/blob/9ecd05b/usr/src/uts/common/sys/unistd.h
 *   https://github.com/illumos/illumos-gate/blob/9ecd05b/usr/src/head/unistd.h
 *
 * Cygwin:
 *   https://github.com/cygwin/cygwin/blob/8050ef2/newlib/libc/include/sys/features.h
 *   https://github.com/cygwin/cygwin/blob/8050ef2/newlib/libc/include/sys/unistd.h
 *
 * HP-UX:
 *   https://nixdoc.net/man-pages/HP-UX/man5/stdsyms.5.html
 *   https://nixdoc.net/man-pages/HP-UX/man5/unistd.5.html
 *
 * NonStop:
 *   https://www.gnu.org/software/autoconf/manual/autoconf-2.67/html_node/Posix-Variants.html
 *
 * AIX:
 *   https://www.ibm.com/docs/en/aix/7.2?topic=files-unistdh-file
 *
 * z/OS:
 *   https://www.ibm.com/docs/en/zos/2.3.0?topic=files-feature-test-macros
 *   https://www.ibm.com/docs/en/zos/2.2.0?topic=files-featuresh
 *   https://www.ibm.com/docs/en/zos/2.2.0?topic=files-unistdh
 *
 * QNX:
 *   http://www.qnx.com/developers/docs/6.5.0_sp1/topic/com.qnx.doc.neutrino_prog/devel.html
 *   https://github.com/vocho/openqnx/blob/cc95df3/trunk/lib/c/public/sys/platform.h
 *   https://github.com/vocho/openqnx/blob/cc95df3/trunk/lib/c/public/unistd.h
 *
 * Haiku:
 *   https://github.com/haiku/haiku/blob/144f45a/headers/compatibility/bsd/features.h
 *   https://github.com/haiku/haiku/blob/144f45a/headers/posix/unistd.h
 *
 * Minix:
 *   https://github.com/Stichting-MINIX-Research-Foundation/minix/blob/4db99f4/sys/sys/featuretest.h
 *   https://github.com/Stichting-MINIX-Research-Foundation/minix/blob/4db99f4/sys/sys/unistd.h
 *
 * Redox:
 *   https://github.com/redox-os/relibc/blob/9790289/include/bits/unistd.h
 *
 * DJGPP:
 *   http://www.delorie.com/djgpp/zip-picker.html
 *   https://www.mirrorservice.org/sites/ftp.delorie.com/pub/djgpp/current/v2/
 *
 * VMS:
 *   https://www.google.com/search?q="__NEW_STARLET"
 *
 * VxWorks:
 *   https://usermanual.wiki/Document/vxworksapplicationprogrammersguide67.1056677699/view
 *   https://www.google.com/search?q=vxworks+"_POSIX_SOURCE"
 *   https://www.google.com/search?q=vxworks+"_POSIX_C_SOURCE"
 *   https://www.google.com/search?q=vxworks+"_XOPEN_SOURCE"
 *
 * Fuchsia:
 *   No information available.
 *
 * CloudABI:
 *   https://github.com/NuxiNL/cloudlibc/blob/7e5c649/src/include/unistd.h
 *
 * WASI:
 *   https://github.com/WebAssembly/wasi-libc/blob/575e157/libc-top-half/musl/include/features.h
 *   https://github.com/WebAssembly/wasi-libc/blob/575e157/libc-top-half/musl/include/unistd.h
 *
 * Emscripten:
 *   https://github.com/emscripten-core/emscripten/blob/dee59ba/system/lib/libc/musl/include/features.h
 *   https://github.com/emscripten-core/emscripten/blob/dee59ba/system/lib/libc/musl/include/unistd.h
 *
 * POSIX:
 *   https://pubs.opengroup.org/onlinepubs/7908799/xsh/compilation.html
 *   https://pubs.opengroup.org/onlinepubs/007904975/functions/xsh_chap02_02.html
 *   https://pubs.opengroup.org/onlinepubs/007904875/basedefs/unistd.h.html
 */

#if defined(_WIN32)
/* Unnecessary (defaults to everything). */
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0501
#  endif
#elif defined(__linux__)
#  undef _GNU_SOURCE
#  undef _DEFAULT_SOURCE
#  define _GNU_SOURCE
#  define _DEFAULT_SOURCE
#elif defined(__gnu_hurd__)
#  undef _GNU_SOURCE
#  define _GNU_SOURCE
#elif defined(__FreeBSD_kernel__) && defined(__GLIBC__)
#  undef _GNU_SOURCE
#  define _GNU_SOURCE
#elif defined(__NetBSD_kernel__) && defined(__GLIBC__)
#  undef _GNU_SOURCE
#  define _GNU_SOURCE
#elif defined(__APPLE__) && defined(__MACH__)
/* Unnecessary (defaults to everything). */
#  undef _DARWIN_C_SOURCE
#  define _DARWIN_C_SOURCE
#elif defined(__FreeBSD__)
/* Unnecessary (defaults to everything). */
#elif defined(__OpenBSD__)
/* Unnecessary (defaults to everything). */
#elif defined(__NetBSD__)
/* Unnecessary (defaults to everything). */
#  undef _NETBSD_SOURCE
#  undef _XOPEN_SOURCE
#  define _NETBSD_SOURCE
#  define _XOPEN_SOURCE 500
#elif defined(__DragonFly__)
/* Unnecessary (defaults to everything). */
#elif defined(__sun) && defined(__SVR4)
#  undef __EXTENSIONS__
#  undef _XOPEN_SOURCE
#  define __EXTENSIONS__
#  define _XOPEN_SOURCE 500
#elif defined(__CYGWIN__)
#  undef _GNU_SOURCE
#  define _GNU_SOURCE
#elif defined(__hpux)
#  undef _HPUX_SOURCE
#  undef _XOPEN_SOURCE
#  define _HPUX_SOURCE
#  define _XOPEN_SOURCE 500
#elif defined(__TANDEM)
#  undef _TANDEM_SOURCE
#  undef _XOPEN_SOURCE
#  define _TANDEM_SOURCE
#  define _XOPEN_SOURCE 500
#elif defined(_AIX)
#  undef _ALL_SOURCE
#  define _ALL_SOURCE
#elif defined(__MVS__)
#  undef _ALL_SOURCE
#  undef _UNIX03_SOURCE
#  undef _UNIX03_THREADS
#  define _ALL_SOURCE
#  define _UNIX03_SOURCE
#  define _UNIX03_THREADS
#elif defined(__QNX__)
#  undef _QNX_SOURCE
#  define _QNX_SOURCE
#elif defined(__HAIKU__)
#  undef _BSD_SOURCE
#  define _BSD_SOURCE
#elif defined(__minix)
/* Unnecessary (defaults to everything). */
#  undef _MINIX
#  define _MINIX
#elif defined(__redox__)
/* Unnecessary (defaults to everything). */
#elif defined(__DJGPP__)
/* Unnecessary (defaults to everything). */
#elif defined(__VMS)
#  undef __NEW_STARLET
#  define __NEW_STARLET 1
#elif defined(__vxworks)
/* VxWorks supports the standard macros, but
   I'm current unsure whether _POSIX_C_SOURCE
   would disable earlier versions of clock_*. */
#elif defined(__Fuchsia__)
/* Unknown. */
#elif defined(__CloudABI__)
/* Nothing. */
#elif defined(__wasi__) || defined(__EMSCRIPTEN__)
#  undef _GNU_SOURCE
#  undef _DEFAULT_SOURCE
#  define _GNU_SOURCE
#  define _DEFAULT_SOURCE
#else
/* Fall back to standard macros. */
#  ifndef _POSIX_SOURCE
#    define _POSIX_SOURCE
#  endif
#  ifndef _POSIX_C_SOURCE
#    define _POSIX_C_SOURCE 200112L
#  endif
#  ifndef _XOPEN_SOURCE
#    define _XOPEN_SOURCE 600
#  endif
#endif

#endif /* TORSION_FTM_H */

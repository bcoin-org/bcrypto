/*
 * When this file is linked to a DLL, it sets up a delay-load hook that
 * intervenes when the DLL is trying to load the host executable
 * dynamically. Instead of trying to locate the .exe file it'll just
 * return a handle to the process image.
 *
 * This allows compiled addons to work when the host executable is renamed.
 *
 * Modified to compile as C.
 */

#ifdef _MSC_VER

#pragma managed(push, off)

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif

#ifndef DELAYIMP_INSECURE_WRITABLE_HOOKS
/* Hooks were non-const prior to VS 2015 Update 3. */
/* Revert to this behavior for compatibility. */
#  define DELAYIMP_INSECURE_WRITABLE_HOOKS
#endif

#include <windows.h>
#include <delayimp.h>
#include <string.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "delayimp.lib")

static FARPROC WINAPI
load_exe_hook(unsigned int event, DelayLoadInfo *info) {
  HMODULE m;

  if (event != dliNotePreLoadLibrary)
    return NULL;

  if (_stricmp(info->szDll, HOST_BINARY) != 0)
    return NULL;

  m = GetModuleHandle(NULL);

  return (FARPROC)m;
}

ExternC PfnDliHook __pfnDliNotifyHook2 = load_exe_hook;

#pragma managed(pop)

#endif

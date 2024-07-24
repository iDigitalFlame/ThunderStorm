// Copyright (C) 2020 - 2024 iDigitalFlame
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

#define UNICODE

#include <windows.h>
#include <winsock.h>

#include "flurry.h"

int isLoginScreen(void) {
    // NOTE(dij): The login screen screensaver is sandboxed (good job Microsoft!)
    //            and runs as LocalService. It /always/ runs under winlogon.exe
    //            but only runs under the user when logged in.
    //            The sandboxed one has no permissions so it hangs trying to do
    //            something. So we should fail quickly if we can detect:
    //             1. We're a screensaver (filepath ends in ".scr")
    //             2. If we're running in the well known SID for LocalService.
    //            The code below accomplishes this and returns '1/TRUE' if we're
    //            the login screensaver.
    WCHAR s[MAX_PATH];
    int n = GetModuleFileNameW(NULL, (LPWSTR)s, MAX_PATH);
    if (n <= 4 || s[n - 4] != '.' || s[n - 3] != 's' || s[n - 2] != 'c' || s[n - 1] != 'r') {
        return 0;
    }
    HANDLE t;
    if (!OpenProcessToken(GetCurrentProcess(), 0x8, &t)) {
        return 0;
    }
    DWORD c;
    int r = 0;
    unsigned char b[256];
    if (GetTokenInformation(t, 1, &b, 256, &c) && c > 0) {
        r = IsWellKnownSid(((PTOKEN_USER)&b)->User.Sid, 0x17);
    }
    CloseHandle(t);
    return r;
}
int main(int argc, char *argv[]) {
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {
        ShowWindow(c, 0);
    }
    // NOTE(dij): Check screensaver when args are just two.
    //            IE: <file> /s
    //                ^ That's how screensavers are triggered in Windows.
    if (argc == 2 && isLoginScreen()) {
        return 0;
    }
    if (argc > 2) {
        $secondary();
    } else {
        $export();
    }
    return 0;
}

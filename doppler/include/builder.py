#!/usr/bin/python
# Copyright (C) 2021 - 2022 iDigitalFlame
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

from os import environ
from random import choice
from tempfile import mkdtemp
from sys import stderr, exit
from shutil import which, rmtree
from os.path import isdir, isfile, join
from traceback import format_exc
from subprocess import check_call
from string import ascii_lowercase
from argparse import ArgumentParser

C_SRC = """#define WINVER 0x0501
#define _WIN32_WINNT 0x0501

#define NOMB
#define NOMSG
#define NONLS
#define NOGDI
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

#include "{name}.h"

"""
C_DLL = """DWORD {thread}() {{
    Sleep(1000);
    {export}();
    return 0;
}}
EXPORT void {func}(HWND h, HINSTANCE i, LPSTR a, int s) {{
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {{
        ShowWindow(c, 0);
    }}
    {export}();
}}
EXPORT BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID args) {{
    if (r == DLL_PROCESS_ATTACH) {{
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE){thread}, NULL, 0, NULL);
    }}
    return TRUE;
}}
"""
C_BINARY = """int main(int argc, char *argv[]) {{
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {{
        ShowWindow(c, 0);
    }}
    {export}();
    return 0;
}}"""
C_COMPILER = "x86_64-w64-mingw32-gcc"


def _main():
    a = ArgumentParser(description="Golang DLL Build Helper")
    a.add_argument("-D", "--dll", dest="dll", action="store_true")
    a.add_argument(
        "-o", "--out", type=str, dest="output", metavar="output_file", required=True
    )
    a.add_argument(
        "-e", "--export", type=str, dest="export", metavar="export_name", required=True
    )
    a.add_argument("-r", "--root", type=str, dest="goroot", metavar="GOROOT")
    a.add_argument("-f", "--func", type=str, dest="func", metavar="func_name")
    a.add_argument("-t", "--thread", type=str, dest="thread", metavar="thread_name")
    a.add_argument("-l", "-ldflags", type=str, dest="flags", metavar="ldflags")
    a.add_argument("-g", "-gcflags", type=str, dest="gcflags", metavar="gcflags")
    a.add_argument("-T", "-tags", type=str, dest="tags", metavar="tags")
    a.add_argument("-m", "-trimpath", dest="trim", action="store_true")
    a.add_argument(nargs=1, type=str, dest="input", metavar="go file")

    p = a.parse_args()
    if len(p.input) != 1:
        print("Invalid input file!", file=stderr)
        return exit(1)
    p.input = p.input[0]

    if not isfile(p.input):
        print(f'"{p.input}" is not a file!', file=stderr)
        return exit(1)
    if len(p.output) == 0:
        print("Output path cannot be empty!", file=stderr)
        return exit(1)
    if len(p.export) == 0:
        print("Export function name cannot be empty!", file=stderr)
        return exit(1)

    if which("go") is None:
        print('Golang "go" not found!', file=stderr)
        return exit(1)
    if which(C_COMPILER) is None:
        print(f'Compiler "{C_COMPILER}" not found!', file=stderr)
        return exit(1)

    with open(p.input, "r") as f:
        b = f.read()
    if 'import "C"\n' not in b:
        print(f'"import "C"" must be declared in "{p.input}"!', file=stderr)
        return exit(1)
    if f"//export {p.export}\nfunc {p.export}(" not in b:
        print(f'Export function "{p.export}" not found in "{p.input}"!', file=stderr)
        return exit(1)
    del b

    e = environ
    e["CC"] = C_COMPILER
    e["GOOS"] = "windows"
    e["CGO_ENABLED"] = "1"
    if isinstance(p.goroot, str) and len(p.goroot) > 0 and isdir(p.goroot):
        e["GOROOT"] = p.goroot

    d = mkdtemp()
    print(f'Work dir "{d}"..')

    o = "".join([choice(ascii_lowercase) for _ in range(8)])
    if not isinstance(p.func, str) or len(p.func) == 0:
        p.func = "".join([choice(ascii_lowercase) for _ in range(12)])
    if not isinstance(p.thread, str) or len(p.thread) == 0:
        p.thread = "".join([choice(ascii_lowercase) for _ in range(12)])

    if p.dll:
        print(f'DLL: "{p.output}" entry "{p.export}" => "{p.func}/DllMain"')
    else:
        print(f'Binary: "{p.output}"')

    try:
        print(f'Building go archive "{o}.a"..')
        x = ["go", "build", "-buildmode=c-archive", "-buildvcs=false"]
        if p.trim:
            x.append("-trimpath")
        if isinstance(p.tags, str) and len(p.tags) > 0:
            x += ["-tags", p.tags]
        if isinstance(p.flags, str) and len(p.flags) > 0:
            x += ["-ldflags", p.flags]
        if isinstance(p.gcflags, str) and len(p.gcflags) > 0:
            x += ["-gcflags", p.gcflags]
        x += ["-o", f"{join(d, o)}.a", p.input]
        check_call(x, env=e)
        del x

        print(f'Creating C stub "{o}.c"..')
        with open(f"{join(d, o)}.c", "w") as f:
            f.write(C_SRC.format(name=o))
            if p.dll:
                f.write(
                    C_DLL.format(
                        export=p.export,
                        thread=p.thread,
                        func=p.func,
                    )
                )
            else:
                f.write(C_BINARY.format(export=p.export))
        if not p.dll:
            return check_call(
                [
                    C_COMPILER,
                    "-mwindows",
                    "-o",
                    p.output,
                    "-fPIC",
                    "-pthread",
                    "-lwinmm",
                    "-lntdll",
                    "-lws2_32",
                    "-Wl,-x,-s,-nostdlib",
                    f"{join(d, o)}.c",
                    f"{join(d, o)}.a",
                ],
                env=e,
            )
        check_call(
            [
                C_COMPILER,
                "-c",
                "-o",
                f"{join(d, o)}.o",
                "-mwindows",
                "-fPIC",
                "-pthread",
                "-lwinmm",
                "-lntdll",
                "-lws2_32",
                "-Wl,-x,-s,-nostdlib",
                f"{join(d, o)}.c",
            ],
            env=e,
        )
        check_call(
            [
                C_COMPILER,
                "-shared",
                "-o",
                p.output,
                "-mwindows",
                "-fPIC",
                "-pthread",
                "-lwinmm",
                "-lntdll",
                "-lws2_32",
                "-Wl,-x,-s,-nostdlib",
                f"{join(d, o)}.o",
                f"{join(d, o)}.a",
            ],
            env=e,
        )
    finally:
        rmtree(d)
        del d
        del e


if __name__ == "__main__":
    try:
        _main()
    except Exception as err:
        print(f"Error: {err}\n{format_exc(limit=3)}", file=stderr)
        exit(1)

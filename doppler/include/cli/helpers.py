#!/usr/bin/python3
# Copyright (C) 2020 - 2023 iDigitalFlame
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

from os import getcwd
from shlex import split
from base64 import b64decode
from fnmatch import translate
from datetime import datetime
from re import compile, Pattern, I
from include.errors import find_error
from os.path import expanduser, expandvars, join
from include.util import nes, ip_str, is_true, perm_str, size_str, time_str

_DONE = [
    "cd",
    "elevate",
    "empty",
    "evade",
    "funcmap",
    "login_user",
    "logins_action",
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
]


def _ex(v):
    return isinstance(v, Pattern) or (isinstance(v, str) and len(v) > 0)


def _strip_rn(v):
    if not nes(v):
        return v
    if v[-1] == "\n":
        return v[:-1]
    return v


def parse_exp(v):
    if not nes(v):
        return None
    s = split(v)
    if len(s) == 0:
        return None
    h, i, o, u, a, b = None, None, None, None, None, None
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
        if x[0] == "d":
            if not nes(b):
                b = e[n + 1 :]
                continue
            raise ValueError('"device" expression specified multiple times')
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
    e = Exp(h, i, o, u, a, b)
    del h, i, o, u, a, b
    return e


def _is_match(m, v):
    if not nes(v):
        return False
    if isinstance(m, Pattern):
        return m.match(v) is not None
    if nes(m) and m in v.lower():
        return True
    return False


def complete_with_all(e, n):
    if len(n) == 0:
        return e + ["all"]
    if len(n) == 1 and n[0] == "a":
        return e + ["all"]
    if len(n) == 2 and n[0] == "a" and n[1] == "l":
        return e + ["all"]
    if len(n) >= 3 and n[0] == "a" and n[1] == "l" and n[2] == "l":
        return e + ["all"]
    return e


def is_valid_name(s, size=0):
    if not isinstance(s, str) or len(s) < size:
        return False
    for i in s:
        if ord(i) <= 57 and ord(i) >= 48:  # 9 - 0
            continue
        if ord(i) <= 90 and ord(i) >= 65:  # Z - A
            continue
        if ord(i) <= 122 and ord(i) >= 97:  # z - a
            continue
        if ord(i) == 45 or ord(i) == 46 or ord(i) == 95:  # '-' or '.' or '_'
            continue
        return False
    return True


def make_menu(v, menu, inv=False):
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
        # Make it so that "all" is only matched when there is more than one
        # character in inverted menus.
        #
        # This helps with Bolt IDs that start with "A" not autocompleting to "all".
        #
        # "A"  == no all
        # "Al" == has all
        if e == "all" and inv and (s[0] == "A" and len(s) == 1):
            continue
        if inv and e.upper().startswith(s):
            r.append(e)
        elif not inv and e.startswith(s):
            r.append(e)
    return r


def _print_job_result(id, job, type, res, out, script):
    if type in _DONE:
        return print("done.")
    if type == "pwd":
        return print(f'returned: {res["path"]}')
    if type == "pull":
        print("returned.")
        if not nes(out) and not script:
            try:
                return print(
                    _strip_rn(b64decode(res["data"], validate=True).decode("UTF-8"))
                )
            except UnicodeDecodeError:
                pass  # Save to a file if it looks like binary.
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
    if type == "list":
        if "entries" not in res or len(res["entries"]) == 0:
            return print("returned: 0 entries")
        print(f'returned: {len(res["entries"])} entries')
        t = datetime.now()
        for i in res["entries"]:
            v, y = (
                datetime.fromisoformat(i["modtime"].replace("Z", "")).replace(
                    tzinfo=None
                ),
                None,
            )
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
        if "\n" in v:
            v = v.replace("\n", " ")
        return print(f"error: {v}")
    if type == "spawn":
        return print(f'spawned PID: {res.get("pid", 0)}.')
    if type == "netcat":
        print(f'received {size_str(len(res["data"]))}')
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
    if type == "logins":
        if "entries" not in res or len(res["entries"]) == 0:
            return print("returned: 0 entries")
        print(
            f'returned: {len(res["entries"])} entries.\n'
            f'{"ID":<8}{"User":28}{"Status":16}{"Host":10}{"From":16}{"Login":10}{"Last Input":10}\n{"=" * 100}'
        )
        t = datetime.now()
        for i in res["entries"]:
            print(f'{i["id"]:<8}', end="")
            if len(i["user"]) > 28:
                print(f'{i["user"][:27]:28}', end="")
            else:
                print(f'{i["user"]:28}', end="")
            print(f'{i["status"]:16}', end="")
            if len(i["host"]) > 10:
                print(f'{i["host"][:9]:10}', end="")
            else:
                print(f'{i["host"]:10}', end="")
            print(
                f'{i["from"]:16}{time_str(t, i["login_time"]):10}{time_str(t, i["last_input_time"]):10}',
            )
        del t
        return
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
    if type == "whoami":
        return print(f'returned.\nUser: {res["user"]}\nPath: {res["path"]}')
    if type == "execute":
        return print(
            f'returned.\n[+] PID: {res.get("pid", "n/a")}, Exit Result: {res.get("exit", 0)}\n'
            f'{_strip_rn(b64decode(res["data"], validate=True).decode("UTF-8", errors="replace"))}'
        )
    if type == "registry":
        if "status" in res:
            if not res["status"]:
                return print("set/update failed!")
            return print("done.")
        if "entries" not in res:
            return print("done.")
        print(
            f'returned {len(res["entries"])} entries.\n{"Name":32}{"Type":16}Value\n{"=" * 85}'
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
            try:
                return print(
                    _strip_rn(b64decode(res["data"], validate=True).decode("UTF-8"))
                )
            except UnicodeDecodeError:
                pass  # Save to a file if it looks like binary.
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
            f'{"Handle":10}{"Name":40}Min Max {"Width":8}{"Height":8}{"X":>8}{"Y":>8}\n{"=" * 92}'
        )
        for i in res["entries"]:
            print(f'{(0xFFFFFFF & i["handle"]):<10X}', end="")
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
    if type == "funcmap_list":
        if "entries" not in res or len(res["entries"]) == 0:
            return print("returned: 0 entries")
        print(f'returned: {len(res["entries"])} entries.')
        print(f'{"Hash":12}{"Original":18}{"Swapped":18}\n{"=" * 45}')
        for i in res["entries"]:
            print(f'0x{i["hash"]:<10X}0x{i["original"]:<16X}0x{i["swapped"]:<16X}')
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
    if type == "processes" or type == "logins_processes":
        w = max(max([len(i["name"]) for i in res["entries"]]), 64) + 2
        print(f"max is {w}")
        if "entries" not in res or len(res["entries"]) == 0:
            return print("returned: 0 entries")
        print(
            f'returned: {len(res["entries"])} entries.\n{"Process":{w}} {"PID":<10}{"PPID":<10} '
            f'{"User":35}\n{"=" * 160}'
        )
        for i in res["entries"]:
            if len(i["name"]) > w:
                print(f'{i["name"][:w - 1]:{w}} ', end="")
            else:
                print(f'{i["name"]:{w}} ', end="")
            print(f'{i["pid"]:<10}{i["ppid"]:<10} ', end="")
            if len(i["user"]) > 35:
                print(f'{i["user"][:34]:35}')
            else:
                print(f'{i["user"]:35}')
        return
    print(f'returned an unknown result type: "{type}"!')


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
        if "\n" in v:
            v = v.replace("\n", " ")
        return print(f"error: {v}")
    if res["type"] != "script":
        return _print_job_result(id, job, res["type"], res, out, multi)
    print(f'returned {res["count"]} results.')
    d = res["entries"]
    for x in range(0, len(d)):
        print(f"[+] {x + 1:>2}: ", end="")
        _print_job_result(id, job, d[x].get("type", "unknown"), d[x], None, True)
    del d


class Exp(object):
    __slots__ = ("ip", "os", "hw", "user", "host", "elevated")

    def __init__(self, host, ip, os, user, elevated, hw):
        self.elevated = elevated
        self.ip = Exp._compile(ip)
        self.os = Exp._compile(os)
        self.hw = Exp._compile(hw)
        self.user = Exp._compile(user)
        self.host = Exp._compile(host)

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
        if "*" in v or "?" in v:
            try:
                return compile(translate(v), I)
            except Exception:
                pass
        if v[0] == "^" or "[" in v or "]" in v or "(" in v or ")" in v or "+" in v:
            try:
                if v[0] == "^":
                    return compile(v[1:], I)
                return compile(v, I)
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
            and self.hw is None
            and self.user is None
            and self.host is None
            and self.elevated is None
        ):
            return v
        if not isinstance(v, list) or len(v) == 0:
            return v
        n = list()
        for x in v:
            i = x["session"]
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
            if _ex(self.hw) and not _is_match(self.hw, i["device"]["id"]):
                continue
            if _ex(self.user) and not _is_match(self.user, i["device"]["user"]):
                continue
            if (
                _ex(self.host)
                and not _is_match(self.host, i["device"]["hostname"])
                and nes(x["name"])
                and not _is_match(self.host, x["name"])
            ):
                continue
            n.append(x)
        return n

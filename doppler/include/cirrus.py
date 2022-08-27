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

from requests import session
from json import dumps, loads
from datetime import datetime
from genericpath import exists
from websocket import WebSocketApp
from threading import Thread, Event
from base64 import b64decode, b64encode
from include.config import Config, Utils
from os.path import expanduser, expandvars, isfile
from selectors import DefaultSelector, EVENT_READ, EVENT_WRITE
from include.util import nes, split_user_domain, do_ask, time_str

SYSTEM_COMMANDS = [
    "cd",
    "chan",
    "check-debug",
    "check-dll",
    "elevate",
    "jitter",
    "ls",
    "mounts",
    "procdump",
    "procname",
    "ps",
    "pwd",
    "refresh",
    "reload-dll",
    "rev2self",
    "screenshot",
    "sleep",
    "untrust",
    "wait",
    "zerotrace",
]

TYPES_REG = [
    "bin",
    "binary",
    "dword",
    "exp_sz",
    "expand_string",
    "multi",
    "multi_sz",
    "qword",
    "string",
    "sz",
    "uint32",
    "uint64",
]
TYPES_EXEC = ["", "dll", "asm", "exec", "pexec", "zombie"]

ACTIONS_REG = ["del", "delete", "dir", "get", "set", "ls", "rem", "remove", "rm"]
ACTIONS_TROLL = ["bi", "block_input", "hc", "high_contrast", "sm", "swap_mouse", "wtf"]
ACTIONS_WINDOW = [
    "cl",
    "close",
    "dis",
    "disable",
    "en",
    "enable",
    "fg",
    "focus",
    "get",
    "ls",
    "mb",
    "message",
    "messagebox",
    "move",
    "msg",
    "msgbox",
    "mv",
    "pos",
    "resize",
    "show",
    "size",
    "sw",
    "tr",
    "trans",
    "transparent",
    "in",
    "send",
    "type",
    "text",
    "input",
]


def split_path(p, f):
    if f[0] == "!":
        v = expanduser(expandvars(f[1:]))
        if not isfile(v):
            raise ValueError(f'file "{v}" does not exist')
        with open(v, "rb") as f:
            p["data"] = b64encode(f.read()).decode("UTF-8")
        del v
        return
    v = expanduser(expandvars(f))
    if not isfile(v):
        p["path"] = f
        return
    with open(v, "rb") as f:
        p["data"] = b64encode(f.read()).decode("UTF-8")
    del v


def _try_hex_first(v):
    try:
        return int(v, 16)
    except ValueError:
        pass
    try:
        return int(v)
    except ValueError:
        pass
    return None


def _err_from_stat(r, url, ex):
    if r.status_code == ex:
        return
    try:
        d = r.json()
        r.close()
    except Exception:
        raise CirrusError(f'"{url}" returned non-{ex} status: {r.status_code}')
    if not isinstance(d, dict) or len(d) == 0 or not nes(d.get("error")):
        raise CirrusError(f'"{url}" returned non-{ex} status: {r.status_code}')
    raise CirrusError(
        f'"{url}" returned non-{ex} status: ({r.status_code}) {d["error"]}',
        sub=d["error"],
    )


def _pkg_touch(path, line=None):
    if not nes(path):
        raise ValueError('"path" must be a non-empty string')
    p = {"action": "touch", "path": path}
    if nes(line):
        p["line"] = line
    return p


def _pkg_script(script, line=None):
    if not nes(script):
        raise ValueError('"script" must be a non-empty string')
    p = {"script": script}
    if nes(line):
        p["line"] = line
    return p


def _pkg_copy(src, dest, line=None):
    if not nes(src):
        raise ValueError('"src" must be a non-empty string')
    if not nes(dest):
        raise ValueError('"dest" must be a non-empty string')
    p = {"action": "copy", "source": src, "dest": dest}
    if nes(line):
        p["line"] = line
    return p


def _pkg_move(src, dest, line=None):
    if not nes(src):
        raise ValueError('"src" must be a non-empty string')
    if not nes(dest):
        raise ValueError('"dest" must be a non-empty string')
    p = {"action": "move", "source": src, "dest": dest}
    if nes(line):
        p["line"] = line
    return p


def _pkg_profile(profile, line=None):
    if not nes(profile):
        raise ValueError('"profile" must be a non-empty string')
    p = {"profile": profile}
    if nes(line):
        p["line"] = line
    return p


def _pkg_download(target, line=None):
    if not nes(target):
        raise ValueError('"target" must be a non-empty string')
    p = {"path": target}
    if nes(line):
        p["line"] = line
    return p


def _pkg_troll(action, arg1=None, line=None):
    if not nes(action):
        raise ValueError('"action" must be a non-empty string')
    a = action.lower()
    if a not in ACTIONS_TROLL:
        raise ValueError(f'action "{action}" is not valid')
    p = {"action": a}
    if a == "wtf":
        if isinstance(arg1, int) and arg1 > 0:
            p["seconds"] = arg1
        elif nes(arg1):
            try:
                p["seconds"] = int(arg1)
            except ValueError:
                pass
    else:
        if arg1 is None:
            p["enable"] = True
        else:
            p["enable"] = bool(arg1)
    del a
    if nes(line):
        p["line"] = line
    return p


def _pkg_system(cmd, filter=None, line=None):
    if not nes(cmd):
        raise ValueError('"cmd" must be a non-empty string')
    if filter is not None and not isinstance(filter, Filter):
        raise ValueError('"filter" must be a Filter type')
    if " " in cmd:
        v = cmd.find(" ")
        p = {"cmd": cmd[:v], "args": cmd[v + 1 :]}
        del v
    else:
        p = {"cmd": cmd}
    if nes(line):
        p["line"] = line
    if isinstance(filter, Filter):
        p["filter"] = filter.json()
    return p


def _pkg_delete(path, force=False, line=None):
    if not nes(path):
        raise ValueError('"path" must be a non-empty string')
    p = {"action": "delete", "path": path, "force": force}
    if nes(line):
        p["line"] = line
    return p


def _pkg_kill(pid=None, proc=None, line=None):
    if (not isinstance(pid, int) or pid <= 0) and not nes(proc):
        raise ValueError('"pid" or "proc" must be specified')
    if isinstance(pid, int) and pid > 0:
        p = {"action": "kill", "pid": pid}
    else:
        p = {"action": "kill_name", "name": proc}
    if nes(line):
        p["line"] = line
    return p


def _pkg_wallpaper(file, raw=None, line=None):
    p = {"action": "wallpaper"}
    if not isinstance(raw, (bytes, bytearray)):
        if not nes(file):
            raise ValueError('"file" must be a non-empty string')
        split_path(p, file)
    else:
        p["data"] = b64encode(raw).decode("UTF-8")
    if nes(line):
        p["line"] = line
    return p


def _pkg_pull(url, dest, agent=None, line=None):
    if not nes(url):
        raise ValueError('"url" must be a non-empty string')
    if not nes(dest):
        raise ValueError('"dest" must be a non-empty string')
    p = {"path": dest, "url": url}
    if nes(line):
        p["line"] = line
    if nes(agent):
        p["agent"] = agent
    return p


def _pkg_login(user, domain="", pw="", line=None):
    if not nes(user):
        raise ValueError('"user" must be a non-empty string')
    p = dict()
    u, d = split_user_domain(user, domain)
    p["user"], p["domain"] = u, d
    if nes(pw):
        p["pass"] = pw
    del u, d
    if nes(line):
        p["line"] = line
    return p


def _pkg_upload(target, dest, raw=None, line=None):
    if not nes(dest):
        raise ValueError('"dest" must be a non-empty string')
    if not isinstance(raw, (bytes, bytearray)):
        if not nes(target):
            raise ValueError('"target" must be a non-empty string')
        if target[0] == "!":
            target = target[1:]
        p = expanduser(expandvars(target))
        if not exists(p):
            raise ValueError(f'target "{p}" does not exist')
        with open(p, "rb") as f:
            b = b64encode(f.read()).decode("UTF-8")
        del p
    else:
        b = b64encode(raw).decode("UTF-8")
    p = {"path": dest, "data": b}
    if nes(line):
        p["line"] = line
    return p


def _pkg_assembly(file, raw=None, show=False, detach=False, filter=None, line=None):
    if filter is not None and not isinstance(filter, Filter):
        raise ValueError('"filter" must be a Filter type')
    if not isinstance(raw, (bytes, bytearray)):
        if not nes(file):
            raise ValueError('"file" must be a non-empty string')
        if file[0] == "!":
            file = file[1:]
        p = expanduser(expandvars(file))
        if not exists(p):
            raise ValueError(f'file "{p}" does not exist')
        with open(p, "rb") as f:
            b = b64encode(f.read()).decode("UTF-8")
        del p
    else:
        b = b64encode(raw).decode("UTF-8")
    p = {"show": show, "detach": detach, "data": b}
    del b
    if nes(line):
        p["line"] = line
    if isinstance(filter, Filter):
        p["filter"] = filter.json()
    return p


def _pkg_pull_exec(url, agent=None, show=False, detach=False, filter=None, line=None):
    if not nes(url):
        raise ValueError('"url" must be a non-empty string')
    if filter is not None and not isinstance(filter, Filter):
        raise ValueError('"filter" must be a Filter type')
    p = {"url": url, "show": show, "detach": detach}
    if nes(line):
        p["line"] = line
    if nes(agent):
        p["agent"] = agent
    if isinstance(filter, Filter):
        p["filter"] = filter.json()
    return p


def _pkg_dll(
    file,
    raw=None,
    reflect=True,
    show=False,
    detach=False,
    filter=None,
    line=None,
):
    if filter is not None and not isinstance(filter, Filter):
        raise ValueError('"filter" must be a Filter type')
    p = {"show": show, "detach": detach, "reflect": reflect}
    if not isinstance(raw, (bytes, bytearray)):
        if not nes(file):
            raise ValueError('"file" must be a non-empty string')
        split_path(p, file)
    else:
        p["data"] = b64encode(raw).decode("UTF-8")
    if nes(line):
        p["line"] = line
    if isinstance(filter, Filter):
        p["filter"] = filter.json()
    return p


def _pkg_spawn(
    pipe,
    method=None,
    profile=None,
    exec=None,
    show=False,
    filter=None,
    line=None,
):
    if not nes(pipe):
        raise ValueError('"pipe" must be a non-empty string')
    if nes(method) and exec is None:
        raise ValueError('"exec" cannot be None when "method" is set')
    if filter is not None and not isinstance(filter, Filter):
        raise ValueError('"filter" must be a Filter type')
    e = exec
    if exec is not None and not isinstance(exec, dict):
        if not nes(exec):
            raise ValueError('cannot guess empty/non-string "exec" value')
        if not nes(method):
            if exec.lower().startswith("http") and "://" in exec:
                method, e = "pexec", exec
            else:
                method, e = "exec", {"show": show, "cmd": exec}
        elif method.lower() == "exec":
            e = {"show": show, "cmd": exec}
        elif method.lower() == "pexec":
            e = exec
        elif method.lower() == "url":  # "url" is only accepted here as a simple method
            method, e = "pexec", exec
        else:
            raise ValueError('"method" value is not valid for string "exec" type')
    if not isinstance(method, str):
        v = ""
    else:
        v = method.lower()
    if v not in TYPES_EXEC:
        raise ValueError('"method" value is not a valid type')
    p = {"name": pipe, "method": v}
    del v
    if e is not None:
        p["payload"] = e
    del e
    if nes(line):
        p["line"] = line
    if nes(profile):
        p["profile"] = profile
    if isinstance(filter, Filter):
        p["filter"] = filter.json()
    return p


def _pkg_zombie(
    file,
    fake_args,
    raw=None,
    show=False,
    detach=False,
    filter=None,
    user="",
    domain="",
    pw="",
    line=None,
):
    if not nes(fake_args):
        raise ValueError('"fake_args" must be a non-empty string')
    if filter is not None and not isinstance(filter, Filter):
        raise ValueError('"filter" must be a Filter type')
    if (nes(domain) or nes(pw)) and not nes(user):
        raise ValueError(
            '"user" cannot be empty when a domain or password is specified'
        )
    if not isinstance(raw, (bytes, bytearray)):
        if not nes(file):
            raise ValueError('"file" must be a non-empty string')
        if file[0] == "!":
            file = file[1:]
        p = expanduser(expandvars(file))
        if not exists(p):
            raise ValueError(f'file "{p}" does not exist')
        with open(p, "rb") as f:
            b = b64encode(f.read()).decode("UTF-8")
        del p
    else:
        b = b64encode(raw).decode("UTF-8")
    u, d = split_user_domain(user, domain)
    if pw is None:
        pw = ""
    p = {
        "show": show,
        "detach": detach,
        "data": b,
        "fake": fake_args,
        "user": u,
        "domain": d,
        "pass": pw,
    }
    del u, b, d
    if nes(line):
        p["line"] = line
    if isinstance(filter, Filter):
        p["filter"] = filter.json()
    return p


def _pkg_window(
    action,
    handle=None,
    arg1=None,
    arg2=None,
    arg3=None,
    arg4=None,
    line=None,
):
    if not nes(action):
        raise ValueError('"action" must be a non-empty string')
    a = action.lower()
    if a not in ACTIONS_WINDOW:
        raise ValueError(f'action "{action}" is not valid')
    if isinstance(handle, int) and handle < 0:
        if a[0] != "m" or (a[0] == "m" and (a[1] == "v" or a[1] == "o")):
            raise ValueError('"handle" integer must be greater than or equal to zero')
    elif handle == "desktop" or handle == "wm":
        handle = -1
    elif handle == "all" or handle == "*" or handle == "0":
        handle = 0
    elif nes(handle):
        v = _try_hex_first(handle)
        if v is None:
            raise ValueError(
                '"handle" string value must be a base-16 or 10 positive integer'
            )
        handle = v
        del v
    else:
        handle = 0
    p = {"action": a, "handle": handle}
    if a in ["sw", "show"]:
        if arg1 is None:
            p["state"] = ""
        elif nes(arg1):
            try:
                p["state"] = int(arg1)
            except ValueError:
                p["state"] = arg1
        elif isinstance(arg1, int) and arg1 < 12 and arg1 >= 0:
            p["state"] = arg1
        else:
            raise ValueError('"arg1" must be a str or int between 0-12')
    elif a in ["tr", "trans", "transparent"]:
        if arg1 is None:
            raise ValueError('"arg1" must be a value between 0-255 or a percentage')
        if isinstance(arg1, int) and (arg1 > 255 or arg1 < 0):
            raise ValueError('"arg1" must be a value between 0-255 or a percentage')
        if nes(arg1):
            try:
                if arg1[-1] == "%":
                    p["level"] = max(
                        255, int(round((float(int(arg1[:-1])) / 100.0) * 255))
                    )
                else:
                    p["level"] = int(arg1)
            except ValueError:
                raise ValueError('"arg1" must be a value between 0-255 or a percentage')
        else:
            p["level"] = arg1
    elif a in ["mv", "pos", "move", "size", "resize"]:
        if nes(arg1):
            try:
                arg1 = int(arg1)
            except ValueError:
                pass
        if nes(arg2):
            try:
                arg2 = int(arg2)
            except ValueError:
                pass
        if nes(arg3):
            try:
                arg3 = int(arg3)
            except ValueError:
                pass
        if nes(arg4):
            try:
                arg4 = int(arg4)
            except ValueError:
                pass
        if arg1 is not None and not isinstance(arg1, int):
            raise ValueError('"arg1" must be none or a integer')
        if arg2 is not None and not isinstance(arg2, int):
            raise ValueError('"arg2" must be none or a integer')
        if arg3 is not None and not isinstance(arg3, int):
            raise ValueError('"arg3" must be none or a integer')
        if arg4 is not None and not isinstance(arg4, int):
            raise ValueError('"arg4" must be none or a integer')
        if isinstance(arg1, int):
            p["x"] = arg1
        if isinstance(arg2, int):
            p["y"] = arg2
        if isinstance(arg3, int):
            p["width"] = arg3
        if isinstance(arg4, int):
            p["height"] = arg4
    elif a in ["in", "send", "type", "text", "input"]:
        if nes(arg1):
            p["text"] = arg1
    elif a in ["mb", "msg", "msgbox", "message", "messagebox"]:
        if not nes(arg1):
            raise ValueError('"arg1" must be a non-empty string')
        if nes(arg3):
            try:
                arg3 = int(arg3)
            except ValueError:
                pass
        if arg2 is not None and not isinstance(arg2, str):
            raise ValueError('"arg2" must be none or a string')
        if arg3 is not None and not isinstance(arg3, int):
            raise ValueError('"arg3" must be none or a integer')
        p["title"] = arg1
        if nes(arg2):
            p["text"] = arg2
        if isinstance(arg3, int):
            p["flags"] = arg3
    del a
    if nes(line):
        p["line"] = line
    return p


def _pkg_execute(
    cmd,
    show=False,
    detach=False,
    filter=None,
    stdin=None,
    user="",
    domain="",
    pw="",
    line=None,
):
    if not nes(cmd):
        raise ValueError('"cmd" must be a non-empty string')
    if filter is not None and not isinstance(filter, Filter):
        raise ValueError('"filter" must be a Filter type')
    if (nes(domain) or nes(pw)) and not nes(user):
        raise ValueError(
            '"user" cannot be empty when a domain or password is specified'
        )
    if stdin is not None and not isinstance(stdin, (str, bytes, bytearray)):
        raise ValueError('"stdin" must be a string, bytes or bytearray type')
    u, d = split_user_domain(user, domain)
    if pw is None:
        pw = ""
    p = {
        "cmd": cmd,
        "show": show,
        "detach": detach,
        "user": u,
        "domain": d,
        "pass": pw,
    }
    del u, d
    if nes(line):
        p["line"] = line
    if stdin is not None:
        if isinstance(stdin, str):
            try:
                b64decode(stdin, validate=True)
            except ValueError:
                p["stdin"] = b64encode(stdin.encode("UTF-8")).decode("UTF-8")
            else:
                p["stdin"] = stdin
        else:
            p["stdin"] = b64encode(stdin).decode("UTF-8")
    if isinstance(filter, Filter):
        p["filter"] = filter.json()
    return p


def _pkg_migrate(
    pipe,
    method=None,
    profile=None,
    exec=None,
    show=False,
    filter=None,
    wait=True,
    line=None,
):
    p = _pkg_spawn(pipe, method, profile, exec, show, filter, line)
    p["wait"] = wait
    return p


def _pkg_registry(
    action,
    key,
    value=None,
    type=None,
    data=None,
    force=False,
    line=None,
):
    if not nes(key):
        raise ValueError('"key" must be a non-empty string')
    if not nes(action):
        raise ValueError('"action" must be a non-empty string')
    a = action.lower()
    if a == "get" and not nes(value):
        raise ValueError('"value" must be a non-empty string for a get action')
    elif a == "set" or a == "edit" or a == "update":
        if not nes(value):
            raise ValueError('"value" must be a non-empty string for a set action')
        if not nes(type):
            raise ValueError('"type" must be a non-empty string for a set action')
        if type.lower() not in TYPES_REG:
            raise ValueError(f'type "{type}" is not valid')
    elif a not in ACTIONS_REG:
        raise ValueError(f'action "{action}" is not valid')
    p = {"key": key, "force": force, "action": a}
    if a == "set" or a == "edit" or a == "update":
        if data is not None:
            if isinstance(data, (bytes, bytearray)):
                p["data"] = b64encode(data).decode("UTF-8")
            elif isinstance(data, (int, float)):
                p["data"] = str(data)
            elif not isinstance(data, str):
                raise ValueError('"data" type is not valid')
            else:
                p["data"] = data
        p["type"] = type
    if nes(value):
        p["value"] = value
    del a
    if nes(line):
        p["line"] = line
    return p


class Api(object):
    __slots__ = ("_s", "_host", "_base", "_ws", "_events", "_trigger")

    def __init__(self, base_url, password=None):
        if not nes(base_url):
            raise ValueError('"base_url" must be a non-empty string')
        if base_url.startswith("http"):
            if base_url[5] == ":":
                i = 8
            else:
                i = 7
            self._host = base_url[i:].rstrip("/")
            del i
        else:
            self._host = base_url.rstrip("/")
        if len(base_url) <= 4 or len(self._host) <= 4:
            raise ValueError(f'invalid "base_url" "{base_url}"')
        if base_url[4] == "s":
            self._base = f"https://{self._host}/api/v1"
            self._ws = WebSocketApp(f"wss://{self._host}/api/v1/events")
        else:
            self._base = f"http://{self._host}/api/v1"
            self._ws = WebSocketApp(f"ws://{self._host}/api/v1/events")
        self._s = session()
        if nes(password):
            self._s.headers["X-CirrusAuth"] = password
            self._ws.header = {"X-CirrusAuth": password}
        self._events = None

    def close(self):
        if self._events is None:
            return
        self._events.close()

    def alive(self):
        return self._events is not None and self._events._sock is not None

    def _detect_open(self, _):
        try:
            self._trigger.set()
        except AttributeError:
            pass

    def start_events(self, on_msg, on_close=None):
        self._ws.on_close = on_close
        self._ws.on_message = on_msg
        self._events = _Events(self._ws)
        self._trigger = Event()
        self._ws.on_open = self._detect_open
        self._events.start()
        try:
            if self._trigger.wait(2):
                return
            self._ws.close()
            raise CirrusError(f'Timeout connecting to "{self._ws.url}"')
        except KeyboardInterrupt:
            raise CirrusError(f'Timeout connecting to "{self._ws.url}"')
        finally:
            del self._trigger

    def _req(self, url, exp, method, data=None, json=None):
        if not nes(method):
            raise ValueError("invalid method")
        try:
            f = getattr(self._s, method)
        except AttributeError:
            raise ValueError(f'unsupported method: "{method}"')
        if not callable(f):
            raise ValueError(f'invalid method: "{method}"')
        if json:
            r = f(f"{self._base}/{url}", json=json)
        else:
            r = f(f"{self._base}/{url}", data=data)
        if isinstance(exp, list) and r.status_code not in exp:
            _err_from_stat(r, f"{self._base}/{url}", "|".join([str(e) for e in exp]))
        if isinstance(exp, int):
            if exp == -1:
                return r
            _err_from_stat(r, f"{self._base}/{url}", exp)
        if r.content is None or len(r.content) == 0:
            r.close()
            del r
            return None
        if isinstance(json, bool) and not json:
            d = r.content
            r.close()
            del r
            return d
        d = r.json()
        r.close()
        del r
        return d

    def _script(self, name, res, cmd, data, stop_on_error, output, marks, chan):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if cmd is not None and not isinstance(cmd, list):
            raise ValueError('"cmd" must be a non-empty string list')
        if marks is not None and not isinstance(marks, list):
            raise ValueError('"marks" must be a non-empty integer list')
        p = dict()
        if isinstance(chan, bool):
            p["channel"] = chan
        if isinstance(output, bool):
            p["return_output"] = output
        if isinstance(stop_on_error, bool):
            p["stop_on_error"] = stop_on_error
        if isinstance(cmd, list) and len(cmd) > 0:
            p["commands"] = cmd
        if isinstance(marks, list) and len(marks) > 0:
            p["marks"] = marks
        if isinstance(data, (bytes, bytearray)):
            if len(data) == 0:
                raise ValueError('"content" must be a non-empty byte type or string')
            p["data"] = b64encode(data).decode("UTF-8")
        elif isinstance(data, str):
            if len(data) == 0:
                raise ValueError('"data" must be a non-empty byte type or string')
            p["data"] = data
        if p == 200 and len(p) == 0:
            raise ValueError("empty script update")
        if len(p) == 0:
            p["return_output"] = True
        try:
            return self._req(
                f"script/{name}", res, "put" if res == 201 else "post", json=p
            )
        finally:
            del p

    def packets(self):
        return self._req("packet", 200, "get")

    def packet_delete(self, name):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        return self._req(f"packet/{name}", 200, "delete")

    def packet(self, name, delete=False):
        if delete:
            return self.packet_delete(name)
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        return self._req(f"packet/{name}", 200, "get")

    def jobs(self, id):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        return self._req(f"session/{id}/job", 200, "get")

    def job(self, id, job):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not isinstance(job, int) or job < 1 or job > 0xFFFF:
            raise ValueError('"job" must be a positive number between [1-65535]')
        return self._req(f"session/{id}/job/{job}", 200, "get")

    def job_remove(self, id, job):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not isinstance(job, int) or job < 1 or job > 0xFFFF:
            raise ValueError('"job" must be a positive number between [1-65535]')
        return self._req(f"session/{id}/job/{job}", 200, "delete")

    def job_result(self, id, job, delete=False):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not isinstance(job, int) or job < 1 or job > 0xFFFF:
            raise ValueError('"job" must be a positive number between [1-65535]')
        r = self._req(
            f"session/{id}/job/{job}/result", -1, "delete" if delete else "get"
        )
        if r.status_code == 404 or r.status_code == 500:
            _err_from_stat(r, f"{self._base}/session/{id}/job/{job}/result", "200X")
        if r.status_code == 425:
            return False
        if r.status_code == 204:
            return None
        d = r.json()
        r.close()
        if r.status_code == 206:
            if "error" not in d:
                raise ValueError(
                    f'"{self._base}/session/{id}/job/{job}/result" returned an invalid result'
                )
        del r
        return d

    def scripts(self):
        return dict(sorted(self._req("script", 200, "get").items()))

    def script(self, name):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        return self._req(f"script/{name}", 200, "get")

    def script_remove(self, name):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        return self._req(f"script/{name}", 200, "delete")

    def script_note(self, name, line):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(f"script/{name}/note", 200, "put", json={"line": line})

    def script_rename(self, src, dest):
        self.script_duplicate(src, dest)
        self.script_remove(src)

    def script_import(self, name, file):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(file):
            raise ValueError('"file" must be a non-empty string')
        if file[0] == "!":
            file = file[1:]
        with open(expanduser(expandvars(file))) as f:
            d = loads(f.read())
        self.script_add(
            name,
            d.get("commands"),
            d.get("data"),
            d.get("stop_on_error"),
            d.get("return_output"),
            d.get("marks"),
            d.get("channel"),
        )

    def script_replace(self, name, file):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(file):
            raise ValueError('"file" must be a non-empty string')
        if file[0] == "!":
            file = file[1:]
        with open(expanduser(expandvars(file))) as f:
            d = loads(f.read())
        self.script_update(
            name,
            d.get("commands"),
            d.get("data"),
            d.get("stop_on_error"),
            d.get("return_output"),
            d.get("marks"),
            d.get("channel"),
        )

    def script_duplicate(self, src, dest):
        if not nes(src):
            raise ValueError('"src" must be a non-empty string')
        if not nes(dest):
            raise ValueError('"dest" must be a non-empty string')
        d = self.script(src)
        self.script_add(
            dest,
            d.get("commands"),
            d.get("data"),
            d.get("stop_on_error"),
            d.get("return_output"),
            d.get("marks"),
            d.get("channel"),
        )
        del d

    def script_touch(self, name, line, path):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(f"script/{name}/io", 201, "put", json=_pkg_touch(path, line))

    def script_export(self, name, file=None):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        r = self.script(name)
        if not isinstance(r, dict) or len(r) == 0:
            raise ValueError(f'script "{name}" returned invalid data')
        if "size" in r:
            del r["size"]
        if "rollbacks" in r:
            del r["rollbacks"]
        if not nes(file):
            print(dumps(r, indent=4, sort_keys=True))
        else:
            with open(expanduser(expandvars(file)), "w") as f:
                f.write(dumps(r, sort_keys=True))
        del r

    def script_rollback(self, name, pos=None):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        p = dict()
        if isinstance(pos, int) and pos >= 0:
            p["pos"] = pos
        try:
            return self._req(f"script/{name}", 200, "patch", json=p)
        finally:
            del p

    def script_copy(self, name, line, src, dest):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/io", 201, "put", json=_pkg_copy(src, dest, line)
        )

    def script_move(self, name, line, src, dest):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/io", 201, "put", json=_pkg_move(src, dest, line)
        )

    def script_profile(self, name, line, profile):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/profile", 201, "put", json=_pkg_profile(profile, line)
        )

    def script_download(self, name, line, target):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/download", 201, "put", json=_pkg_download(target, line)
        )

    def script_troll(self, name, line, action, arg1=None):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/ui", 201, "put", json=_pkg_troll(action, arg1, line)
        )

    def script_system(self, name, line, cmd, filter=None):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/sys", 201, "put", json=_pkg_system(cmd, filter, line)
        )

    def script_delete(self, name, line, path, force=False):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/io", 201, "put", json=_pkg_delete(path, force, line)
        )

    def script_wallpaper(self, name, line, file, raw=None):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/ui", 201, "put", json=_pkg_wallpaper(file, raw, line)
        )

    def script_kill(self, name, line, pid=None, proc=None):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/io", 201, "put", json=_pkg_kill(pid, proc, line)
        )

    def script_pull(self, name, line, url, dest, agent=None):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/pull", 201, "put", json=_pkg_pull(url, dest, agent, line)
        )

    def script_login(self, name, line, user, domain="", pw=""):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/login", 201, "put", json=_pkg_login(user, domain, pw, line)
        )

    def script_upload(self, name, line, target, dest, raw=None):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/upload",
            201,
            "put",
            json=_pkg_upload(target, dest, raw, line),
        )

    def script_add(
        self,
        name,
        cmd=None,
        data=None,
        stop_on_error=None,
        output=None,
        marks=None,
        chan=None,
    ):
        return self._script(name, 201, cmd, data, stop_on_error, output, marks, chan)

    def script_dll(
        self,
        name,
        line,
        file,
        raw=None,
        reflect=True,
        show=False,
        detach=False,
        filter=None,
    ):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/dll",
            201,
            "put",
            json=_pkg_dll(file, raw, reflect, show, detach, filter, line),
        )

    def script_spawn(
        self,
        name,
        line,
        pipe,
        method=None,
        profile=None,
        exec=None,
        show=False,
        filter=None,
    ):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/spawn",
            201,
            "put",
            json=_pkg_spawn(pipe, method, profile, exec, show, filter, line),
        )

    def script_update(
        self,
        name,
        cmd=None,
        data=None,
        stop_on_error=None,
        output=None,
        marks=None,
        chan=None,
    ):
        return self._script(name, 200, cmd, data, stop_on_error, output, marks, chan)

    def script_zombie(
        self,
        name,
        line,
        file,
        fake_args,
        raw=None,
        show=False,
        detach=False,
        filter=None,
        user="",
        domain="",
        pw="",
    ):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/zombie",
            201,
            "put",
            json=_pkg_zombie(
                file, fake_args, raw, show, detach, filter, user, domain, pw, line
            ),
        )

    def script_window(
        self,
        name,
        line,
        action,
        handle=None,
        arg1=None,
        arg2=None,
        arg3=None,
        arg4=None,
    ):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/ui",
            201,
            "put",
            json=_pkg_window(action, handle, arg1, arg2, arg3, arg4, line),
        )

    def script_execute(
        self,
        name,
        line,
        cmd,
        show=False,
        detach=False,
        filter=None,
        stdin=None,
        user="",
        domain="",
        pw="",
    ):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/exec",
            201,
            "put",
            json=_pkg_execute(cmd, show, detach, filter, stdin, user, domain, pw, line),
        )

    def script_migrate(
        self,
        name,
        line,
        pipe,
        method=None,
        profile=None,
        exec=None,
        show=False,
        filter=None,
        wait=True,
    ):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/migrate",
            201,
            "put",
            json=_pkg_migrate(pipe, method, profile, exec, show, filter, wait, line),
        )

    def script_registry(
        self,
        name,
        line,
        action,
        key,
        value=None,
        type=None,
        data=None,
        force=False,
    ):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/regedit",
            201,
            "put",
            json=_pkg_registry(action, key, value, type, data, force, line),
        )

    def script_assembly(
        self,
        name,
        line,
        file,
        raw=None,
        show=False,
        detach=False,
        filter=None,
    ):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/asm",
            201,
            "put",
            json=_pkg_assembly(file, raw, show, detach, filter, line),
        )

    def script_pull_exec(
        self,
        name,
        line,
        url,
        agent=None,
        show=False,
        detach=False,
        filter=None,
    ):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/pexec",
            201,
            "put",
            json=_pkg_pull_exec(url, agent, show, detach, filter, line),
        )

    def profiles(self):
        r = dict()
        for k, v in self._req("profile", 200, "get").items():
            r[k] = Config(b64decode(v, validate=True))
        return dict(sorted(r.items()))

    def profile(self, name):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        return Config(
            b64decode(
                self._req(f"profile/{name}", 200, "get", json=False), validate=True
            )
        )

    def profile_remove(self, name):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        return self._req(f"profile/{name}", 200, "delete")

    def profile_add(self, name, config):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not isinstance(config, (Config, bytearray, bytes)):
            raise ValueError('"config" must be a Config, bytearray or bytes type')
        r = self._req(f"profile/{name}", 201, "put", b64encode(config))
        if not isinstance(r, dict):
            raise ValueError(f'"{self._base}/profile/{name}" returned invalid data')
        return r

    def profile_update(self, name, config):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not isinstance(config, (Config, bytearray, bytes)):
            raise ValueError('"config" must be a Config, bytearray or bytes type')
        r = self._req(f"profile/{name}", 200, "post", b64encode(config))
        if not isinstance(r, dict):
            raise ValueError(f'"{self._base}/profile/{name}" returned invalid data')
        return r

    def profile_build_add(self, name, data):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if data is None:
            raise ValueError('"data" must be specified and non-empty')
        p = expanduser(expandvars(data))
        if isfile(p):
            with open(p, "rb") as f:
                c = Config(f.read())
        else:
            c = Config(data)
        del p
        return self.profile_add(name, c)

    def profile_build_update(self, name, data):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if data is None:
            raise ValueError('"data" must be specified and non-empty')
        p = expanduser(expandvars(data))
        if isfile(p):
            with open(p, "rb") as f:
                c = Config(f.read())
        else:
            c = Config(data)
        del p
        return self.profile_update(name, c)

    def sessions(self):
        v = self._req("session", 200, "get")
        v.sort(key=lambda x: x["id"], reverse=True)
        return v

    def session(self, id):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        return self._req(f"session/{id}", 200, "get")

    def session_prune(self, duration):
        # NOTE(dij): Should this be in this section?
        #            or does it make more sense in doppler?
        #            Since it's more interactive than API-ish.
        if nes(duration) and duration[-1] not in Utils.UNITS:
            duration += "m"  # Make it default to mins.
        v = Utils.str_to_dur(duration) / 1000000000
        r = list()
        n = datetime.now()
        for i in self.sessions():
            x = n - datetime.fromisoformat(i["last"].replace("Z", "")).replace(
                tzinfo=None
            )
            if x.total_seconds() > v:
                r.append((i["id"], i["last"]))
            del x
        del v
        if len(r) == 0:
            del r
            print("[-] There were no Bolts matching the prune limit.")
            return False
        print(f'{"ID":9}Last\n{"="*20}')
        for i in r:
            print(f"{i[0]:9}{time_str(n, i[1], True)}")
        print()
        del n
        if not do_ask(f"Prune {len(r)} Bolts"):
            del r
            print("[-] Aborting prune!")
            return False
        for i in r:
            self.session_remove(i[0])
            print(f"[+] Removed Bolt {i[0]}")
        print(f"[+] Removed {len(r)} Bolts")
        del r
        return True

    def session_proxy_remove(self, id, name):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not isinstance(name, str):
            raise ValueError('"name" must be a string')
        r = self._req(
            f"session/{id}/proxy/{name}",
            200,
            "delete",
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/proxy/{name}" returned an invalid result'
            )
        return int(r["id"])

    def session_remove(self, id, shutdown=False):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        return self._req(f"session/{id}", 200, "delete", json={"shutdown": shutdown})

    def session_proxy_add(self, id, name, address, profile):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not nes(address):
            raise ValueError('"address" must be a non-empty string')
        if not nes(profile):
            raise ValueError('"profile" must be a non-empty string')
        if not isinstance(name, str):
            raise ValueError('"name" must be a string')
        r = self._req(
            f"session/{id}/proxy/{name}",
            201,
            "put",
            json={"address": address, "profile": profile},
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/proxy/{name}" returned an invalid result'
            )
        return int(r["id"])

    def session_proxy_update(self, id, name, address, profile=None):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not nes(address):
            raise ValueError('"address" must be a non-empty string')
        if not isinstance(name, str):
            raise ValueError('"name" must be a string')
        r = self._req(
            f"session/{id}/proxy/{name}",
            200,
            "post",
            json={"address": address, "profile": profile},
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/proxy/{name}" returned an invalid result'
            )
        return int(r["id"])

    def listeners(self):
        r = self._req("listener", 200, "get")
        if not isinstance(r, dict) or len(r) == 0:
            return dict()
        return dict(sorted(r.items()))

    def listener(self, name):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        return self._req(f"listener/{name}", 200, "get")

    def listener_remove(self, name):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        return self._req(f"listener/{name}", 200, "delete")

    def listener_update_script(self, name, script):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not isinstance(script, str):
            raise ValueError('"script" must be a string')
        return self._req(
            f"listener/{name}/script", 200, "post", json={"script": script}
        )

    def listener_add(self, name, address, profile, script=None):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(profile):
            raise ValueError('"profile" must be a non-empty string')
        p = {"profile": profile, "address": address}
        if nes(script):
            p["script"] = script
        try:
            return self._req(f"listener/{name}", 201, "put", json=p)
        finally:
            del p

    def listener_update(self, name, address, profile, script=None):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        p = dict()
        if nes(profile):
            p["profile"] = profile
        if nes(address):
            p["address"] = address
        if script is not None:
            p["script"] = script
        if len(p) == 1 and "script" in p:
            return self._req(f"listener/{name}/script", 200, "post", json=p)
        try:
            return self._req(f"listener/{name}", 200, "post", json=p)
        finally:
            del p

    def task_touch(self, id, path):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(f"session/{id}/io", 201, "put", json=_pkg_touch(path))
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/io" returned an invalid result'
            )
        return int(r["id"])

    def task_script(self, id, script):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(f"session/{id}/script", 201, "put", json=_pkg_script(script))
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/script" returned an invalid result'
            )
        return int(r["id"])

    def task_copy(self, id, src, dest):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(f"session/{id}/io", 201, "put", json=_pkg_copy(src, dest))
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/io" returned an invalid result'
            )
        return int(r["id"])

    def task_move(self, id, src, dest):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(f"session/{id}/io", 201, "put", json=_pkg_move(src, dest))
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/io" returned an invalid result'
            )
        return int(r["id"])

    def task_profile(self, id, profile):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(f"session/{id}/profile", 201, "put", json=_pkg_profile(profile))
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/profile" returned an invalid result'
            )
        return int(r["id"])

    def task_download(self, id, target):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(f"session/{id}/download", 201, "put", json=_pkg_download(target))
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/download" returned an invalid result'
            )
        return int(r["id"])

    def task_troll(self, id, action, arg1=None):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(f"session/{id}/ui", 201, "put", json=_pkg_troll(action, arg1))
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/ui" returned an invalid result'
            )
        return int(r["id"])

    def task_system(self, id, cmd, filter=None):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/sys", [200, 201], "put", json=_pkg_system(cmd, filter)
        )
        if r is None:
            return None
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/sys" returned an invalid result'
            )
        return int(r["id"])

    def task_delete(self, id, path, force=False):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(f"session/{id}/io", 201, "put", json=_pkg_delete(path, force))
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/io" returned an invalid result'
            )
        return int(r["id"])

    def task_kill(self, id, pid=None, proc=None):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(f"session/{id}/io", 201, "put", json=_pkg_kill(pid, proc))
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/io" returned an invalid result'
            )
        return int(r["id"])

    def task_wallpaper(self, id, file, raw=None):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(f"session/{id}/ui", 201, "put", json=_pkg_wallpaper(file, raw))
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/ui" returned an invalid result'
            )
        return int(r["id"])

    def task_pull(self, id, url, dest, agent=None):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/pull", 201, "put", json=_pkg_pull(url, dest, agent)
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/pull" returned an invalid result'
            )
        return int(r["id"])

    def task_login(self, id, user, domain="", pw=""):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/login", 201, "put", json=_pkg_login(user, domain, pw)
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/login" returned an invalid result'
            )
        return int(r["id"])

    def task_upload(self, id, target, dest, raw=None):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/upload", 201, "put", json=_pkg_upload(target, dest, raw)
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/upload" returned an invalid result'
            )
        return int(r["id"])

    def task_assembly(self, id, file, raw=None, show=False, detach=False, filter=None):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/asm",
            201,
            "put",
            json=_pkg_assembly(file, raw, show, detach, filter),
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/asm" returned an invalid result'
            )
        return int(r["id"])

    def task_dll(
        self,
        id,
        file,
        raw=None,
        reflect=True,
        show=False,
        detach=False,
        filter=None,
    ):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/dll",
            201,
            "put",
            json=_pkg_dll(file, raw, reflect, show, detach, filter),
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/dll" returned an invalid result'
            )
        return int(r["id"])

    def task_spawn(
        self,
        id,
        pipe,
        method=None,
        profile=None,
        exec=None,
        show=False,
        filter=None,
    ):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/spawn",
            201,
            "put",
            json=_pkg_spawn(pipe, method, profile, exec, show, filter),
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/spawn" returned an invalid result'
            )
        return int(r["id"])

    def task_zombie(
        self,
        id,
        file,
        fake_args,
        raw=None,
        show=False,
        detach=False,
        filter=None,
        user="",
        domain="",
        pw="",
    ):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/zombie",
            201,
            "put",
            json=_pkg_zombie(
                file, fake_args, raw, show, detach, filter, user, domain, pw
            ),
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/zombie" returned an invalid result'
            )
        return int(r["id"])

    def task_window(
        self,
        id,
        action,
        handle=None,
        arg1=None,
        arg2=None,
        arg3=None,
        arg4=None,
    ):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/ui",
            201,
            "put",
            json=_pkg_window(action, handle, arg1, arg2, arg3, arg4),
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/ui" returned an invalid result'
            )
        return int(r["id"])

    def task_execute(
        self,
        id,
        cmd,
        show=False,
        detach=False,
        filter=None,
        stdin=None,
        user="",
        domain="",
        pw="",
    ):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/exec",
            201,
            "put",
            json=_pkg_execute(cmd, show, detach, filter, stdin, user, domain, pw),
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/exec" returned an invalid result'
            )
        return int(r["id"])

    def task_migrate(
        self,
        id,
        pipe,
        method=None,
        profile=None,
        exec=None,
        show=False,
        filter=None,
        wait=True,
    ):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/migrate",
            201,
            "put",
            json=_pkg_migrate(pipe, method, profile, exec, show, filter, wait),
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/migrate" returned an invalid result'
            )
        return int(r["id"])

    def task_registry(
        self,
        id,
        action,
        key,
        value=None,
        type=None,
        data=None,
        force=False,
    ):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/regedit",
            201,
            "put",
            json=_pkg_registry(action, key, value, type, data, force),
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/regedit" returned an invalid result'
            )
        return int(r["id"])

    def task_pull_exec(
        self,
        id,
        url,
        agent=None,
        show=False,
        detach=False,
        filter=None,
    ):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/pexec",
            201,
            "put",
            json=_pkg_pull_exec(url, agent, show, detach, filter),
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/pexec" returned an invalid result'
            )
        return int(r["id"])


class Filter(object):
    __slots__ = ("pid", "session", "fallback", "elevated", "exclude", "include")

    def __init__(self):
        self.pid = None
        self.session = None
        self.fallback = None
        self.elevated = None
        self.exclude = list()
        self.include = list()

    def json(self):
        r = dict()
        if isinstance(self.session, bool):
            r["session"] = self.session
        if isinstance(self.elevated, bool):
            r["elevated"] = self.elevated
        if isinstance(self.fallback, bool):
            r["fallback"] = self.fallback
        if isinstance(self.pid, int) and self.pid > 0:
            r["pid"] = self.pid
        if isinstance(self.exclude, list) and len(self.exclude) > 0:
            r["exclude"] = self.exclude
        if isinstance(self.include, list) and len(self.include) > 0:
            r["include"] = self.include
        return r

    def clear(self):
        self.pid = None
        self.session = None
        self.fallback = None
        self.elevated = None
        self.exclude = list()
        self.include = list()

    def __str__(self):
        b = list()
        if isinstance(self.pid, int) and self.pid > 0:
            b.append(f"PID:      {self.pid}")
        if isinstance(self.include, list) and len(self.include) > 0:
            b.append(f"Include:  {', '.join(self.include)}")
        if isinstance(self.exclude, list) and len(self.exclude) > 0:
            b.append(f"Exclude:  {', '.join(self.exclude)}")
        if isinstance(self.session, bool):
            b.append(f"Desktop:  {str(self.session)}")
        if isinstance(self.elevated, bool):
            b.append(f"Elevated: {str(self.elevated)}")
        if isinstance(self.fallback, bool):
            b.append(f"Fallback: {str(self.fallback)}")
        if len(b) == 0:
            return "<empty>"
        return "\n   ".join(b)

    def is_empty(self):
        if isinstance(self.session, bool):
            return False
        if isinstance(self.elevated, bool):
            return False
        if isinstance(self.pid, int) and self.pid > 0:
            return False
        if isinstance(self.exclude, list) and len(self.exclude) > 0:
            return False
        if isinstance(self.include, list) and len(self.include) > 0:
            return False
        return True


class _Events(Thread):
    __slots__ = ("_sock", "_handle", "_running", "_select")

    def __init__(self, sock):
        Thread.__init__(self)
        self._sock = sock
        self.daemon = False
        self._handle = None
        self._running = Event()
        self._select = DefaultSelector()
        self.name = "Cirrus Events Thread"

    def run(self):
        try:
            self._sock.run_forever(
                ping_interval=None,
                skip_utf8_validation=True,
                dispatcher=self,
            )
        except Exception as err:
            print(f"[!] Socket error: {err}!")
        self._sock = None
        if self._running.is_set():
            print("[-] Socket closed.")

    def close(self):
        self._running.set()
        if self._sock is None:
            return
        try:
            self._select.modify(self._handle, EVENT_WRITE)
            self._select.close()
            self._sock.sock.close()
            # NOTE(dij): Causes a slow quit
            self._sock.close()
        except (ValueError, AttributeError):
            pass

    def read(self, s, f):
        self._handle = s
        try:
            self._select.register(s, EVENT_READ)
            while self._select.select(None):
                if self._running.is_set():
                    return
                f()
        finally:
            self._handle = None
            self._select.close()
            del self._select, self._handle


class CirrusError(ValueError):
    def __init__(self, val, sub=None):
        ValueError.__init__(self, val)
        if nes(sub):
            self.sub = sub[0].upper() + sub[1:]
        else:
            self.sub = None

    def __str__(self):
        if nes(self.sub):
            return self.sub
        return super(__class__, self).__str__()

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

import threading

from sys import stderr
from signal import SIGINT
from os import getpid, kill
from requests import session
from json import dumps, loads
from datetime import datetime
from websocket import WebSocketApp
from threading import Thread, Event
from selectors import DefaultSelector
from base64 import b64decode, b64encode
from include.config import Config, Utils
from requests.exceptions import ConnectionError
from os.path import expanduser, expandvars, isfile
from include.util import (
    nes,
    do_ask,
    is_true,
    time_str,
    bytes_from_src,
    split_user_domain,
)

SYSTEM_COMMANDS = [
    "cd",
    "chan",
    "check_debug",
    "elevate",
    "jitter",
    "ls",
    "mounts",
    "procdump",
    "procname",
    "ps",
    "pwd",
    "refresh",
    "rev2self",
    "screenshot",
    "sleep",
    "untrust",
    "wait",
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
TYPES_NETCAT = ["icmp", "tcp", "tcp", "tls", "tls-insecure", "udp"]
TYPES_REG_NO_DATA = [
    "dword",
    "exp_sz",
    "expand_string",
    "qword",
    "string",
    "sz",
    "uint32",
    "uint64",
]

ACTIONS_WTS = ["dis", "disconnect", "logoff", "ls", "message", "msg", "ps"]
ACTIONS_REG = ["del", "delete", "dir", "get", "set", "ls", "rem", "remove", "rm"]
ACTIONS_TROLL = ["bi", "block_input", "hc", "high_contrast", "sm", "swap_mouse", "wtf"]
ACTIONS_POWER = ["restart", "shutdown"]
ACTIONS_FUNCMAP = ["add", "del", "delete", "list", "ls", "remove", "remove_all"]
ACTIONS_WINDOW = [
    "cl",
    "close",
    "desktop",
    "dis",
    "disable",
    "en",
    "enable",
    "fg",
    "focus",
    "get",
    "in",
    "input",
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
    "send",
    "show",
    "size",
    "sw",
    "text",
    "tr",
    "trans",
    "transparent",
    "type",
]


def _thread_except(args):
    print(f"Received an uncaught Thread error {args.exc_type} ({args.exc_value})!")
    kill(getpid(), SIGINT)


def _socket_except(_, err):
    print(f"websocket exception: {err}!")


def _err_from_stat(r, url, ex):
    if r.status_code == ex:
        return
    try:
        d = r.json()
        r.close()
    except Exception:
        raise CirrusError(
            f'"{url}" returned non-{ex} status: {r.status_code}', code=r.status_code
        ) from None
    if not isinstance(d, dict) or len(d) == 0 or not nes(d.get("error")):
        raise CirrusError(
            f'"{url}" returned non-{ex} status: {r.status_code}', code=r.status_code
        ) from None
    raise CirrusError(
        f'"{url}" returned non-{ex} status: ({r.status_code}) {d["error"]}',
        sub=d["error"],
        code=r.status_code,
    ) from None


def _pkg_touch(path, line=None):
    if not nes(path):
        raise ValueError('"path" must be a non-empty string')
    p = {"action": "touch", "path": path}
    if nes(line):
        p["line"] = line
    return p


def _pkg_evade(action, line=None):
    if not nes(action):
        raise ValueError('"action" must be a non-empty string')
    p = {"action": action.lower()}
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


def _pkg_wallpaper(data, line=None):
    p = {"action": "wallpaper"}
    b, r = bytes_from_src(data, cb64=True, ext=True, raw=False, empty=False)
    if r:
        p["path"] = b
    else:
        p["data"] = b64encode(b).decode("UTF-8")
    del b, r
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


def _pkg_upload(data, dest, line=None):
    if not nes(dest):
        raise ValueError('"dest" must be a non-empty string')
    b, _ = bytes_from_src(data, cb64=True, raw=False)
    p = {"path": dest, "data": b64encode(b).decode("UTF-8")}
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
    if isinstance(filter, Filter):
        p["filter"] = filter.json()
    if nes(line):
        p["line"] = line
    return p


def _pkg_delete(path, force=False, line=None):
    if not nes(path):
        raise ValueError('"path" must be a non-empty string')
    p = {"action": "delete", "path": path, "force": is_true(force)}
    if nes(line):
        p["line"] = line
    return p


def _pkg_kill(pid=None, pname=None, line=None):
    if (not isinstance(pid, int) or not nes(pid)) and not nes(pname):
        raise ValueError('"pid" or "pname" must be specified')
    if nes(pid):
        try:
            p = {"action": "kill", "pid": int(pid)}
        except ValueError:
            raise ValueError('"pid" is not a valid number')
        if p["pid"] < 1:
            raise ValueError('"pid" must be an greater than zero')
    elif isinstance(pid, int):
        if pid < 1:
            raise ValueError('"pid" must be an greater than zero')
        p = {"action": "kill", "pid": pid}
    else:
        p = {"action": "kill_name", "name": pname}
    if nes(line):
        p["line"] = line
    return p


def _pkg_pull(url, path="", agent=None, line=None):
    if not nes(url):
        raise ValueError('"url" must be a non-empty string')
    p = {"url": url}
    if nes(path):
        p["path"] = path
    if nes(agent):
        p["agent"] = agent
    if nes(line):
        p["line"] = line
    return p


def _pkg_workhours(days="", start="", end="", line=None):
    p = {"days": days}
    if nes(start):
        if ":" not in start:
            raise ValueError("workhours: invalid start format")
        x = start.split(":")
        if len(x) != 2:
            raise ValueError("workhours: invalid start format")
        try:
            h, j = int(x[0]), int(x[1])
        except ValueError:
            raise ValueError("workhours: invalid start format")
        del x
        if h > 23 or j > 59:
            raise ValueError("workhours: invalid start format")
        p["start_hour"], p["start_min"] = h, j
        del h, j
    if nes(end):
        if ":" not in end:
            raise ValueError("workhours: invalid end format")
        x = end.split(":")
        if len(x) != 2:
            raise ValueError("workhours: invalid end format")
        try:
            n, m = int(x[0]), int(x[1])
        except ValueError:
            raise ValueError("workhours: invalid end format")
        del x
        if n > 23 or m > 59:
            raise ValueError("workhours: invalid end format")
        p["end_hour"], p["end_min"] = n, m
        del n, m
    if nes(line):
        p["line"] = line
    return p


def _pkg_troll(action, enable=False, seconds=None, line=None):
    if not nes(action):
        raise ValueError('"action" must be a non-empty string')
    a = action.lower()
    if a not in ACTIONS_TROLL:
        raise ValueError(f'action "{action}" is not valid')
    p = {"action": a}
    if a == "wtf":
        if nes(seconds):
            try:
                p["seconds"] = int(seconds)
            except ValueError:
                raise ValueError('"seconds" is not a valid number')
            if p["seconds"] < 1:
                raise ValueError('"seconds" must be an greater than zero')
        elif isinstance(seconds, int):
            if seconds < 1:
                raise ValueError('"seconds" must be an greater than zero')
            p["seconds"] = seconds
    else:
        p["enable"] = is_true(enable)
    del a
    if nes(line):
        p["line"] = line
    return p


def _pkg_login(user, domain="", pw="", interactive=False, line=None):
    if not nes(user):
        raise ValueError('"user" must be a non-empty string')
    u, d = split_user_domain(user, domain)
    p = {"user": u, "domain": d, "interactive": is_true(interactive)}
    del u, d
    if nes(pw):
        p["pass"] = pw
    if nes(line):
        p["line"] = line
    return p


def _pkg_funcmap(action, function="", data=None, raw=False, line=None):
    if not nes(action):
        raise ValueError('"action" must be a non-empty string')
    a = action.lower()
    if a not in ACTIONS_FUNCMAP:
        raise ValueError(f'action "{action}" is not valid')
    p = {"action": a}
    if (
        (a == "add" or a.startswith("del") or a.startswith("remove"))
        and not a.endswith("all")
        and not nes(function)
    ):
        raise ValueError('"function" is required')
    p["raw"] = is_true(raw)
    p["function"] = function
    if a[0] != "l" and not a.startswith("del") and not a.startswith("remove"):
        b, _ = bytes_from_src(data, cb64=True, ext=False, empty=False)
        p["data"] = b64encode(b).decode("UTF-8")
        del b
    if nes(line):
        p["line"] = line
    return p


def _pkg_check_patch(dll, function="", data=None, raw=False, line=None):
    if not nes(dll):
        raise ValueError('"dll" must be a non-empty string')
    if raw is True and not nes(function):
        raise ValueError('cannot use "raw" with an empty function')
    p = {"dll": dll, "raw": is_true(raw), "function": function}
    b, r = bytes_from_src(data, cb64=True, ext=True, empty=True, explicit=True)
    if r:
        p["path"] = b
    else:
        p["data"] = b64encode(b).decode("UTF-8")
    del b, r
    if nes(line):
        p["line"] = line
    return p


def _pkg_netcat(host, proto=None, seconds=None, data=None, read=False, line=None):
    if not nes(host):
        raise ValueError('"host" must be a non-empty string')
    p = {"host": host, "read": is_true(read)}
    if proto is None or len(proto) == 0:
        p["protocol"] = "tcp"
    else:
        v = proto.lower()
        if len(v) > 0 and v not in TYPES_NETCAT:
            raise ValueError(f'protocol "{proto}" is not valid')
        p["protocol"] = v
        del v
    if nes(seconds):
        try:
            p["seconds"] = int(seconds)
        except ValueError:
            raise ValueError('"seconds" is not a valid number')
        if p["seconds"] < 1:
            raise ValueError('"seconds" must be an greater than or equal to zero')
    elif isinstance(seconds, int):
        if seconds < 0:
            raise ValueError('"seconds" must be an greater than or equal to zero')
        p["seconds"] = seconds
    b, _ = bytes_from_src(data, empty=True)
    p["data"] = b64encode(b).decode("UTF-8")
    del b
    if nes(line):
        p["line"] = line
    return p


def _pkg_pull_exec(url, agent=None, show=False, detach=False, filter=None, line=None):
    if not nes(url):
        raise ValueError('"url" must be a non-empty string')
    if filter is not None and not isinstance(filter, Filter):
        raise ValueError('"filter" must be a Filter type')
    p = {"url": url, "show": is_true(show), "detach": is_true(detach)}
    if nes(agent):
        p["agent"] = agent
    if isinstance(filter, Filter):
        p["filter"] = filter.json()
    if nes(line):
        p["line"] = line
    return p


def _pkg_power(action, message="", force=False, seconds=None, reason=None, line=None):
    if not nes(action):
        raise ValueError('"action" must be a non-empty string')
    a = action.lower()
    if a not in ACTIONS_POWER:
        raise ValueError(f'action "{action}" is not valid')
    p = {"action": a, "message": message, "force": is_true(force)}
    if nes(reason):
        try:
            p["reason"] = int(reason, base=0)
        except ValueError:
            raise ValueError('"reason" is not a valid number')
        if p["reason"] < 1:
            raise ValueError('"reason" must be an greater than or equal to zero')
    elif isinstance(reason, int):
        if reason < 0:
            raise ValueError('"reason" must be an greater than or equal to zero')
        p["reason"] = reason
    if nes(seconds):
        try:
            p["seconds"] = int(seconds)
        except ValueError:
            raise ValueError('"seconds" is not a valid number')
        if p["seconds"] < 1:
            raise ValueError('"seconds" must be an greater than or equal to zero')
    elif isinstance(seconds, int):
        if seconds < 0:
            raise ValueError('"seconds" must be an greater than or equal to zero')
        p["seconds"] = seconds
    if nes(line):
        p["line"] = line
    del a
    return p


def _pkg_assembly(
    data, show=False, detach=False, filter=None, entry=None, timeout=None, line=None
):
    if filter is not None and not isinstance(filter, Filter):
        raise ValueError('"filter" must be a Filter type')
    b, _ = bytes_from_src(data, cb64=True, empty=False, explicit=True)
    p = {
        "show": is_true(show),
        "detach": is_true(detach),
        "data": b64encode(b).decode("UTF-8"),
    }
    del b
    if nes(entry):
        p["entry"] = entry
    if nes(timeout):
        p["timeout"] = timeout
    elif isinstance(timeout, int):
        p["timeout"] = f"{timeout}s"
    if isinstance(filter, Filter):
        p["filter"] = filter.json()
    if nes(line):
        p["line"] = line
    return p


def _pkg_dll(
    data,
    reflect=True,
    show=False,
    detach=False,
    filter=None,
    entry=None,
    timeout=None,
    line=None,
):
    if filter is not None and not isinstance(filter, Filter):
        raise ValueError('"filter" must be a Filter type')
    p = {"show": is_true(show), "detach": is_true(detach), "reflect": is_true(reflect)}
    b, r = bytes_from_src(data, cb64=True, ext=True, explicit=True, empty=False)
    if r:
        p["path"] = b
    else:
        p["data"] = b64encode(b).decode("UTF-8")
    del b, r
    if nes(entry):
        p["entry"] = entry
    if nes(timeout):
        p["timeout"] = timeout
    elif isinstance(timeout, int):
        p["timeout"] = f"{timeout}s"
    if isinstance(filter, Filter):
        p["filter"] = filter.json()
    if nes(line):
        p["line"] = line
    return p


def _pkg_wts(
    action,
    session=None,
    title="",
    text="",
    flags=None,
    seconds=None,
    wait=False,
    line=None,
):
    if not nes(action):
        raise ValueError('"action" must be a non-empty string')
    a = action.lower()
    if a not in ACTIONS_WTS:
        raise ValueError(f'action "{action}" is not valid')
    p = {"action": a}
    if a != "ls":
        if session is None:
            p["session"] = -1
        elif nes(session):
            if session == "desktop" or session == "cur" or session == "current":
                session = -1
            else:
                try:
                    p["session"] = int(session)
                except ValueError:
                    raise ValueError('"session" is not a valid number')
                if p["session"] < -1:
                    raise ValueError('"session" cannot be less than -1')
        elif isinstance(session, int):
            if session < -1:
                raise ValueError('"session" cannot be less than -1')
            p["session"] = session
    if a == "msg" or a == "message":
        if nes(text):
            v, _ = bytes_from_src(text, path=False)
            text = v.decode("UTF-8")
            del v
        if nes(title):
            v, _ = bytes_from_src(title, path=False)
            title = v.decode("UTF-8")
            del v
        p["text"], p["title"] = text, title
        if nes(flags):
            try:
                p["flags"] = int(flags, base=0)
            except ValueError:
                raise ValueError('"flags" is not a valid number')
            if p["flags"] < 1:
                raise ValueError('"flags" must be an greater than or equal to zero')
        elif isinstance(flags, int):
            if flags < 0:
                raise ValueError('"flags" must be an greater than or equal to zero')
            p["flags"] = flags
        if nes(seconds):
            try:
                p["seconds"] = int(seconds)
            except ValueError:
                raise ValueError('"seconds" is not a valid number')
            if p["seconds"] < 1:
                raise ValueError('"seconds" must be an greater than or equal to zero')
        elif isinstance(seconds, int):
            if seconds < 0:
                raise ValueError('"seconds" must be an greater than or equal to zero')
            p["seconds"] = seconds
        p["wait"] = is_true(wait)
    del a
    if nes(line):
        p["line"] = line
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
                method, e = "exec", {"show": is_true(show), "cmd": exec}
        elif method.lower() == "exec":
            e = {"show": is_true(show), "cmd": exec}
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
    if nes(profile):
        p["profile"] = profile
    if isinstance(filter, Filter):
        p["filter"] = filter.json()
    if nes(line):
        p["line"] = line
    return p


def _pkg_zombie(
    data,
    fake_args,
    show=False,
    detach=False,
    filter=None,
    user="",
    domain="",
    pw="",
    entry=None,
    timeout=None,
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
    b, _ = bytes_from_src(data, cb64=True, raw=True, explicit=True, empty=False)
    u, d = split_user_domain(user, domain)
    if pw is None:
        pw = ""
    p = {
        "show": is_true(show),
        "detach": is_true(detach),
        "data": b64encode(b).decode("UTF-8"),
        "fake": fake_args,
        "user": u,
        "domain": d,
        "pass": pw,
    }
    del u, d, b
    if nes(entry):
        p["entry"] = entry
    if nes(timeout):
        p["timeout"] = timeout
    elif isinstance(timeout, int):
        p["timeout"] = f"{timeout}s"
    if isinstance(filter, Filter):
        p["filter"] = filter.json()
    if nes(line):
        p["line"] = line
    return p


def _pkg_window(
    action,
    handle=None,
    state=None,
    opacity=None,
    pos_x=None,
    pos_y=None,
    width=None,
    height=None,
    title="",
    text="",
    flags=None,
    line=None,
):
    if not nes(action):
        raise ValueError('"action" must be a non-empty string')
    a = action.lower()
    if a not in ACTIONS_WINDOW:
        raise ValueError(f'action "{action}" is not valid')
    if isinstance(handle, int) and handle < 0 and (a == "mv" or a == "move"):
        raise ValueError('"handle" must be and integer greater than or equal to zero')
    elif handle == "desktop" or handle == "wm":
        handle = -1
    elif handle == "all" or handle == "*" or handle == "0":
        handle = 0
    elif nes(handle):
        try:
            handle = int(handle, 16)
        except ValueError:
            raise ValueError(
                '"handle" string value must be a valid base16 positive integer'
            )
    elif not isinstance(handle, int):
        handle = 0
    if handle < -1:
        raise ValueError('"handle" cannot be less than -1')
    p = {"action": a, "handle": handle}
    if nes(text):
        v, _ = bytes_from_src(text, path=False)
        text = v.decode("UTF-8")
        del v
    if nes(title):
        v, _ = bytes_from_src(title, path=False)
        title = v.decode("UTF-8")
        del v
    if a == "sw" or a == "show":
        if nes(state):
            try:
                p["state"] = int(state)
            except ValueError:
                p["state"] = state
            else:
                if p["state"] < 0 or p["state"] > 12:
                    raise ValueError('"state" must be a str or int inside [0, 12]')
        elif isinstance(state, int):
            if state < 0 or state > 12:
                raise ValueError('"state" must be a str or int inside [0, 12]')
            p["state"] = state
        else:
            p["state"] = ""
    elif a == "tr" or a == "trans" or a == "transparent":
        if nes(opacity):
            try:
                if "%" in opacity:
                    p["level"] = min(
                        255, int(round((float(int(opacity[:-1])) / 100.0) * 255))
                    )
                else:
                    p["level"] = int(opacity)
            except ValueError:
                p["level"] = state
            else:
                if p["level"] < 0 or p["level"] > 255:
                    raise ValueError(
                        '"opacity" must be a str or int inside [0, 255] or a percentage'
                    )
        elif isinstance(opacity, int):
            if opacity < 0 or opacity > 12:
                raise ValueError(
                    '"opacity" must be a str or int inside [0, 255] or a percentage'
                )
            p["level"] = opacity
        else:
            raise ValueError('"opacity" must be a value between 0-255 or a percentage')
    elif a == "mv" or a == "pos" or a == "move" or a == "size" or a == "resize":
        if nes(pos_x):
            try:
                p["x"] = int(pos_x)
            except ValueError:
                raise ValueError('"pos_x" must be None, a str or an integer')
        elif isinstance(pos_x, int):
            p["x"] = pos_x
        if nes(pos_y):
            try:
                p["y"] = int(pos_y)
            except ValueError:
                raise ValueError('"pos_y" must be None, a str or an integer')
        elif isinstance(pos_y, int):
            p["y"] = pos_y
        if nes(width):
            try:
                p["width"] = int(width)
            except ValueError:
                raise ValueError('"width" must be None, a str or an integer')
        elif isinstance(width, int):
            p["width"] = width
        if nes(height):
            try:
                p["height"] = int(height)
            except ValueError:
                raise ValueError('"height" must be None, a str or an integer')
        elif isinstance(height, int):
            p["height"] = height
    elif a == "in" or a == "send" or a == "type" or a == "text" or a == "input":
        if nes(text):
            p["text"] = text
        elif nes(title):
            p["text"] = title
    elif a[0] == "m":
        if nes(title):
            p["title"] = title
        if nes(text):
            p["text"] = text
        if nes(flags):
            try:
                p["flags"] = int(flags, base=0)
            except ValueError:
                raise ValueError('"flags" is not a valid number')
            if p["flags"] < 1:
                raise ValueError('"flags" must be an greater than or equal to zero')
        elif isinstance(flags, int):
            if flags < 0:
                raise ValueError('"flags" must be an greater than or equal to zero')
            p["flags"] = flags
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
    timeout=None,
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
        "show": is_true(show),
        "detach": is_true(detach),
        "user": u,
        "domain": d,
        "pass": pw,
    }
    del u, d
    if stdin is not None:
        if isinstance(stdin, str):
            b, _ = bytes_from_src(stdin, empty=True)
            p["stdin"] = b64encode(b).decode("UTF-8")
            del b
        else:
            p["stdin"] = b64encode(stdin).decode("UTF-8")
    if nes(timeout):
        p["timeout"] = timeout
    elif isinstance(timeout, int):
        p["timeout"] = f"{timeout}s"
    if isinstance(filter, Filter):
        p["filter"] = filter.json()
    if nes(line):
        p["line"] = line
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
    p = {"key": key, "force": is_true(force), "action": a}
    if a == "set" or a == "edit" or a == "update":
        if data is not None:
            if isinstance(data, (int, float)):
                p["data"] = str(data)
            elif type in TYPES_REG_NO_DATA:
                p["data"] = str(data)
            else:
                b, _ = bytes_from_src(data, empty=True)
                p["data"] = b64encode(b).decode("UTF-8")
                del b
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
        try:
            self._events.close()
        except OSError:
            pass

    def alive(self):
        return self._events is not None and self._events._sock is not None

    def _detect_open(self, _):
        try:
            self._trigger.set()
        except AttributeError:
            pass

    def server_public_key(self):
        r = self._req("server", 200, "get")
        if not isinstance(r, dict):
            raise ValueError(f'"{self._base}/server" returned an invalid result')
        if "public_key" not in r:
            return None, None
        v, h = r["public_key"], r.get("public_key_hash", 0)
        del r
        if len(v) == 0:
            return None, None
        return v, h

    def start_events(self, on_msg, on_close=None, on_error=None):
        self._ws.on_close = on_close
        self._ws.on_message = on_msg
        if callable(on_error):
            self._ws.on_error = on_error
        else:
            self._ws.on_error = _socket_except
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
        try:
            if json:
                r = f(f"{self._base}/{url}", json=json)
            else:
                r = f(f"{self._base}/{url}", data=data)
        except ConnectionError:
            raise OSError(f'Cannot access "{self._base}/{url}"') from None
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

    def script_import(self, name, data):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(data):
            raise ValueError('"data" must be a non-empty string')
        b, _ = bytes_from_src(data, cb64=True, raw=False, empty=False)
        d = loads(b)
        del b
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

    def script_evade(self, name, line, action):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/evade", 201, "put", json=_pkg_evade(action, line)
        )

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

    def script_wallpaper(self, name, line, data):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/ui", 201, "put", json=_pkg_wallpaper(data, line)
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

    def script_upload(self, name, line, data, dest):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/upload",
            201,
            "put",
            json=_pkg_upload(data, dest, line),
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

    def script_kill(self, name, line, pid=None, pname=None):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/io", 201, "put", json=_pkg_kill(pid, pname, line)
        )

    def script_pull(self, name, line, url, path="", agent=None):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/pull", 201, "put", json=_pkg_pull(url, path, agent, line)
        )

    def script_workhours(self, name, line, days="", start="", end=""):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/sys/workhours",
            201,
            "put",
            json=_pkg_workhours(days, start, end, line),
        )

    def script_troll(self, name, line, action, enable=False, seconds=None):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/ui",
            201,
            "put",
            json=_pkg_troll(action, enable, seconds, line),
        )

    def script_check(self, name, line, dll, function="", data=None, raw=False):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/dll/check",
            201,
            "put",
            json=_pkg_check_patch(dll, function, data, raw, line),
        )

    def script_patch(self, name, line, dll, function="", data=None, raw=False):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/dll/patch",
            201,
            "put",
            json=_pkg_check_patch(dll, function, data, raw, line),
        )

    def script_login(self, name, line, user, domain="", pw="", interactive=False):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/login",
            201,
            "put",
            json=_pkg_login(user, domain, pw, interactive, line),
        )

    def script_funcmap(self, name, line, action, function="", data=None, raw=False):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/funcmap",
            201,
            "put",
            json=_pkg_funcmap(action, function, data, raw, line),
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
        data,
        reflect=True,
        show=False,
        detach=False,
        filter=None,
        entry=None,
        timeout=None,
    ):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/dll",
            201,
            "put",
            json=_pkg_dll(data, reflect, show, detach, filter, entry, timeout, line),
        )

    def script_wts(
        self,
        name,
        line,
        action,
        session=None,
        title="",
        text="",
        flags=None,
        seconds=None,
        wait=False,
    ):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/wts",
            201,
            "put",
            json=_pkg_wts(action, session, title, text, flags, seconds, wait, line),
        )

    def script_power(
        self,
        name,
        line,
        action,
        message="",
        force=False,
        seconds=None,
        reason=None,
    ):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/power",
            201,
            "put",
            json=_pkg_power(action, message, force, seconds, reason, line),
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

    def script_netcat(
        self,
        name,
        line,
        host,
        proto=None,
        seconds=None,
        data=None,
        read=False,
    ):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/net",
            201,
            "put",
            json=_pkg_netcat(host, proto, seconds, data, read, line),
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
        data,
        fake_args,
        show=False,
        detach=False,
        filter=None,
        user="",
        domain="",
        pw="",
        entry=None,
        timeout=None,
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
                data,
                fake_args,
                show,
                detach,
                filter,
                user,
                domain,
                pw,
                entry,
                timeout,
                line,
            ),
        )

    def script_window(
        self,
        name,
        line,
        action,
        handle=None,
        state=None,
        opacity=None,
        pos_x=None,
        pos_y=None,
        width=None,
        height=None,
        title="",
        text="",
        flags=None,
    ):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/ui",
            201,
            "put",
            json=_pkg_window(
                action,
                handle,
                state,
                opacity,
                pos_x,
                pos_y,
                width,
                height,
                title,
                text,
                flags,
                line,
            ),
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
        timeout=None,
    ):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/exec",
            201,
            "put",
            json=_pkg_execute(
                cmd, show, detach, filter, stdin, user, domain, pw, timeout, line
            ),
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
        data,
        show=False,
        detach=False,
        filter=None,
        entry=None,
        timeout=None,
    ):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(line):
            raise ValueError('"line" must be a non-empty string')
        return self._req(
            f"script/{name}/asm",
            201,
            "put",
            json=_pkg_assembly(data, show, detach, filter, entry, timeout, line),
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

    def sessions(self, hw=None):
        v = self._req(f"session{f'/?hw={hw}' if nes(hw) else ''}", 200, "get")
        v.sort(key=lambda x: x["id"], reverse=True)
        return v

    def session(self, id):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        return self._req(f"session/{id}", 200, "get")

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

    def session_rename(self, id, name, map=False):
        v = name
        if not nes(v):
            v = ""
        elif len(v) > 64:
            raise ValueError("name must be less than 64 chars")
        elif len(v) < 4:
            raise ValueError("name must be at least 4 chars")
        return self._req(f"session/{id}/name", 200, "put", json={"name": v, "map": map})

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

    def session_prune(
        self, duration=None, force=True, errors=False, verbose=False, work_hours=True
    ):
        if duration is None or (isinstance(duration, str) and len(duration) == 0):
            duration = "1m"
        elif not isinstance(duration, (str, int)):
            raise ValueError('invalid "duration" value')
        elif nes(duration) and duration[-1] not in Utils.UNITS:
            duration += "m"  # Make it default to mins.
        v = Utils.str_to_dur(duration) / 1000000000
        (r, w) = (list(), 25)
        n = datetime.now()
        for e in self.sessions():
            i = e["session"]
            x = n - datetime.fromisoformat(i["last"].replace("Z", "")).replace(
                tzinfo=None
            )
            if x.total_seconds() > v:
                if work_hours and "work_hours" in i and len(i["work_hours"]) > 0:
                    continue
                if nes(e["name"]) and len(e["name"]) > w:
                    w = len(e["name"])
                r.append((i["id"], i["last"], e["name"]))
            del x
        del v
        if len(r) == 0:
            del r, w
            if errors:
                raise ValueError("There were no Bolts matching the prune limit")
            return False
        if verbose:
            print(f'{"ID":{w}}Last\n{"=" * (w + 15)}')
            for i in r:
                if nes(i[2]):
                    print(f"{i[2]:{w}}{time_str(n, i[1], True)}")
                else:
                    print(f"{i[0]:{w}}{time_str(n, i[1], True)}")
            print()
        del n, w
        if force or not do_ask(f"Prune {len(r)} Bolts", True):
            del r
            if errors:
                raise ValueError("Aborting prune!")
            return False
        for i in r:
            self.session_remove(i[0])
            if verbose:
                print(f"[+] Removed Bolt {i[0]}")
        if verbose:
            print(f"[+] Removed {len(r)} Bolts")
        del r
        return True

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

    def task_evade(self, id, action):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(f"session/{id}/evade", 201, "put", json=_pkg_evade(action))
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/evade" returned an invalid result'
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

    def task_wallpaper(self, id, data):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(f"session/{id}/ui", 201, "put", json=_pkg_wallpaper(data))
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/ui" returned an invalid result'
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

    def task_upload(self, id, data, dest):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(f"session/{id}/upload", 201, "put", json=_pkg_upload(data, dest))
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/upload" returned an invalid result'
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

    def task_kill(self, id, pid=None, pname=None):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(f"session/{id}/io", 201, "put", json=_pkg_kill(pid, pname))
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/io" returned an invalid result'
            )
        return int(r["id"])

    def task_pull(self, id, url, path="", agent=None):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/pull", 201, "put", json=_pkg_pull(url, path, agent)
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/pull" returned an invalid result'
            )
        return int(r["id"])

    def task_workhours(self, id, days="", start="", end=""):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/sys/workhours",
            201,
            "put",
            json=_pkg_workhours(days, start, end),
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/sys/workhours" returned an invalid result'
            )
        return int(r["id"])

    def task_troll(self, id, action, enable=False, seconds=None):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/ui", 201, "put", json=_pkg_troll(action, enable, seconds)
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/ui" returned an invalid result'
            )
        return int(r["id"])

    def task_check(self, id, dll, function="", data=None, raw=False):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/dll/check",
            201,
            "put",
            json=_pkg_check_patch(dll, function, data, raw),
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/dll/check" returned an invalid result'
            )
        return int(r["id"])

    def task_patch(self, id, dll, function="", data=None, raw=False):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/dll/patch",
            201,
            "put",
            json=_pkg_check_patch(dll, function, data, raw),
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/dll/patch" returned an invalid result'
            )
        return int(r["id"])

    def task_login(self, id, user, domain="", pw="", interactive=False):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/login",
            201,
            "put",
            json=_pkg_login(user, domain, pw, interactive),
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/login" returned an invalid result'
            )
        return int(r["id"])

    def task_funcmap(self, id, action, function="", data=None, raw=False):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/funcmap",
            201,
            "put",
            json=_pkg_funcmap(action, function, data, raw),
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/funcmap" returned an invalid result'
            )
        return int(r["id"])

    def task_netcat(self, id, host, proto=None, seconds=None, data=None, read=False):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/net",
            201,
            "put",
            json=_pkg_netcat(host, proto, seconds, data, read),
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/net" returned an invalid result'
            )
        return int(r["id"])

    def task_dll(
        self,
        id,
        data,
        reflect=True,
        show=False,
        detach=False,
        filter=None,
        entry=None,
        timeout=None,
    ):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/dll",
            201,
            "put",
            json=_pkg_dll(data, reflect, show, detach, filter, entry, timeout),
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/dll" returned an invalid result'
            )
        return int(r["id"])

    def task_wts(
        self,
        id,
        action,
        session=None,
        title="",
        text="",
        flags=None,
        seconds=None,
        wait=False,
    ):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/wts",
            201,
            "put",
            json=_pkg_wts(action, session, title, text, flags, seconds, wait),
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/wts" returned an invalid result'
            )
        return int(r["id"])

    def task_power(
        self,
        id,
        action,
        message="",
        force=False,
        seconds=None,
        reason=None,
    ):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/power",
            201,
            "put",
            json=_pkg_power(action, message, force, seconds, reason),
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/power" returned an invalid result'
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
        data,
        fake_args,
        show=False,
        detach=False,
        filter=None,
        user="",
        domain="",
        pw="",
        timeout=None,
        entry=None,
    ):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/zombie",
            201,
            "put",
            json=_pkg_zombie(
                data, fake_args, show, detach, filter, user, domain, pw, entry, timeout
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
        state=None,
        opacity=None,
        pos_x=None,
        pos_y=None,
        width=None,
        height=None,
        title="",
        text="",
        flags=None,
    ):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/ui",
            201,
            "put",
            json=_pkg_window(
                action,
                handle,
                state,
                opacity,
                pos_x,
                pos_y,
                width,
                height,
                title,
                text,
                flags,
            ),
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
        timeout=None,
    ):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/exec",
            201,
            "put",
            json=_pkg_execute(
                cmd, show, detach, filter, stdin, user, domain, pw, timeout
            ),
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

    def task_assembly(
        self,
        id,
        data,
        show=False,
        detach=False,
        filter=None,
        entry=None,
        timeout=None,
    ):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        r = self._req(
            f"session/{id}/asm",
            201,
            "put",
            json=_pkg_assembly(data, show, detach, filter, entry, timeout),
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/asm" returned an invalid result'
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

    abort = 0

    def __init__(self, sock):
        Thread.__init__(self)
        self._sock = sock
        self.daemon = False
        self._handle = None
        self._running = Event()
        self._select = DefaultSelector()
        self.name = "Cirrus Events Thread"
        threading.excepthook = _thread_except

    def run(self):
        try:
            self._sock.run_forever(
                ping_interval=None,
                skip_utf8_validation=True,
                dispatcher=self,
            )
        except Exception as err:
            print(f"[!] Socket error: {err}!")

    def close(self):
        if self._running.is_set():
            return
        self._running.set()
        if self._sock is None:
            return
        self._select.register(stderr, 3)
        try:
            if self._handle is not None:
                try:
                    self._handle.close()
                except Exception:
                    pass
        except AttributeError:
            pass
        try:
            self._select.close()
        except Exception:
            pass
        try:
            if self._sock.sock:
                self._sock.sock.shutdown()
                self._sock.sock.close(timeout=1)
            else:
                self._sock.close(timeout=1)
        except Exception as err:
            print(err)

    def read(self, s, f):
        self._handle = s
        try:
            self._select.register(s, 1)
            while self._select.select(None):
                if self._running.is_set():
                    return
                f()
        finally:
            self._handle = None
            try:
                self._select.close()
            except Exception:
                pass

    def signal(self, a, _):
        if a == 2:
            return
        self.close()


class CirrusError(ValueError):
    def __init__(self, val, sub=None, code=None):
        ValueError.__init__(self, val)
        if nes(sub):
            self.sub = sub[0].upper() + sub[1:]
        else:
            self.sub = None
        self.code = code

    def __str__(self):
        if nes(self.sub):
            return self.sub
        return super(__class__, self).__str__()

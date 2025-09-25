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

from base64 import b64encode
from json import dumps, loads
from os import getcwd, getenv
from queue import Empty, Queue
from traceback import format_exc
from argparse import ArgumentParser
from include.cli.shell import Shell
from threading import Event, Thread
from include.cli.const import MENU_BOLT
from datetime import datetime, timedelta
from include.config import Utils, Config
from sys import argv, exit, stdin, stderr
from include.cirrus import Api, CirrusError
from include.cli.helpers import Exp, parse_exp, print_job_result
from include.util import nes, ip_str, is_true, size_str, time_str
from os.path import join, isfile, basename, expanduser, expandvars

_HELP_TEXT = """ Doppler: ThunderStorm C2 Console Interface
Part of the |||||| ThunderStorm Project (https://dij.sh/ts)
(c) 2019 - 2023 iDigitalFlame

Usage: {proc} -a <cirrus> [-p password] [-A] [-D] [-b] [-B] [-f] [-j] [-l] [-x] [-s] [-i] [-c cmd] [...]

Required Arguments:
  -a          <cirrus_address>   Name/IP and port of the Cirrus server. This
                                  argument is required. Can be set via the
                                  "DOPPLER_HOST" environment variable.

Optional Arguments:
  -p          <password>         Password to use with the specified Cirrus server.
                                  Can be set via the "DOPPLER_PW" environment variable.
  -f          <file>             Specify a config file that can supply arguments to
  --config                        Doppler without using environment variables or
                                  command line arguments. This file defaults to
                                  "doppler.json" in the current directly, but can
                                  also be set using the "DOPPLER_CONFIG" environment
                                  variable. Values set in the config can be overridden
                                  with environment variables or command arguments.

 Shell Helper Arguments:
  -N                             Disable automatic command handeling. If specified,
  --no-empty                      all commands must be ran using a prefix (run|shell|
                                  pwsh). Can be set via the "DOPPLER_NO_EMPTY"
                                  environment variable or the supplied config file.
  -P          <pile_name>        Specify a default pipe name to be used for spawn/migrate
  --pipe                          commands. Can be set via the "DOPPLER_PIPE" environment
                                  variable or the supplied config file.
  -A          <asm_file>         Specify a default ASM file that can be used as
  --asm                           the default file source for spawn/migrate commands
                                  when no file is specified. If supplied, this will
                                  also default empty methods to "asm". Can be set
                                  via the "DOPPLER_ASM" environment variable or
                                  the supplied config file.
  -D          <dll_file>         Specify a default DLL file that can be used as
  --dll                           the default file source for spawn/migrate commands
                                  when no file is specified. If supplied, this will
                                  also default empty methods to "dll" if no ASM file
                                  is specified. Can be set via the "DOPPLER_DLL"
                                  environment variable or the supplied config file.

 Shell Behavior Arguments:
  -z          <file|'-'>         Specify a file (or '-' for stdin) that contains
  --input                         newline seperated commands to be ran as input to
                                  the shell before entering the prompt. Running
                                  commands and history are not allowed. When using
                                  stdin, this will not enter the shell and will
                                  instead exit.
  -i          <Bolt ID>          Directly enter into a shell with the specified
  --interact                      Bolt ID.
  --debug                        Print more error tracing details when a crash
                                  occurs.

 Execution Option Arguments:
  -c          <command>          Run a single shell command and exit. This command
  --cmd                           requires that a Bolt ID be specified.
  -w          <duration[s|m|h]>  Specify a timeout for a "command" operation (above)
  --timeout                       to wait for before a timeout occurs. This value
                                  defaults to seconds, but a duration identifier may
                                  be specified.
  -k          <command>          Specify a comand (or set of commands seperated by
  --oneline                       a semicolon ";") that are executed in the context
                                  of the Doppler shell. Once the command(s) complete
                                  the shell will exit.
  -K          <command>          The argument acts just the like "-k"/"--online"
  --online-ne                     argument, but allows the shell to continue in the
                                  position that it was placed in after running the
                                  specified command(s). If this is used with the
                                  "-k"/"--online" argument, this one will take
                                  precedence.

 List Operations
  -b                             List the current Bolts connected to the supplied
  --bolts                         Cirrus server.
  -B                             List the current Bolts connected to the supplied
  --bolts-adv                     Cirrus server with more information.
  -j                             List all Jobs saved and/or active currently. An
  --jobs                          expression may be used to filter the results.
  -s                             List all the Scripts contained on the supplied
  --scripts                       Cirrus server.
  -n                             List all the Profiles contained on the supplied
  --profiles                      Cirrus server.
  -l                             List all the active Listeners on the supplied
  --listeners                     Cirrus server.
"""
_UPDATE_NAMES = [
    "job_delete",
    "job_new",
    "listener_delete",
    "listener_update",
    "profile_delete",
    "profile_new",
    "profile_update",
    "session_delete",
]


def _trunc(n, s):
    if len(s) < n:
        return s
    return s[:n] + "~"


def _uniq_session_id(x):
    if nes(x["name"]):
        return x["name"]
    return x["session"]["device"]["id"]


def _print_session_info(x):
    s = x["session"]
    a = x.get("name", None)
    if nes(a):
        n = f" ({a})"
    else:
        n = ""
    del a
    print(
        f'{"ID:":<12}{s["id"]}{n}\n{"=" * 64}\n{"Hostname:":<12}{s["device"]["hostname"]}\n'
        f'{"User:":<12}{("*" if s["device"]["elevated"] else "") + s["device"]["user"]}\n'
        f'{"Domain:":<12}{"Yes" if s["device"]["domain"] else "No"}\n'
        f'{"OS:":<12}{s["device"]["os"]}\n{"Version:":<12}{s["device"]["version"]}\n{"Arch:":<12}'
        f'{s["device"]["arch"]}\n{"PID:":<12}{s["device"]["pid"]}\n{"PPID:":<12}'
        f'{s["device"]["ppid"]}\n{"Abilities:":<12}{s["device"]["capabilities"]}\nNetwork:'
    )
    del n
    for i in s["device"]["network"]:
        print(f'  {i["name"] + ":":6} {", ".join(i["ip"])}')
    t = datetime.now()
    print(
        f'{"Sleep:":<12}{int(int(s["sleep"]) // 1000000000)}s\n{"Jitter:":<12}{s["jitter"]}%\n'
        f'{"Channel:":<12}{"Yes" if s["channel"] else "No"}',
    )
    h = s["device"]["id"][: -len(s["id"])]
    print(
        f'{"Last:":<12}{time_str(t, s["last"], True)}\n{"Created:":<12}'
        f'{time_str(t, s["created"], True)}\n{"From:":<12}{s["via"]}'
    )
    k = s.get("kill_date")
    if nes(k):
        print(f'{"Kill Date:":<12}{k}')
    del k
    w = s.get("work_hours")
    if isinstance(w, dict) and len(w) > 0:
        print("Work Hours:")
        d = w.get("days")
        if nes(d):
            print(f'  {"Days":<12}{d}')
        del d
        k, j = w.get("start_hour"), w.get("start_min")
        if isinstance(k, int) and isinstance(j, int):
            print(f'  {"Start:":<12}{k:02}:{j:02}')
        del k, j
        f, g = w.get("end_hour"), w.get("end_min")
        if isinstance(f, int) and isinstance(g, int):
            print(f'  {"End:":<12}{f:02}:{g:02}')
        del f, g
    if "connector" in s:
        print(f'{"Connector:":<12}{s["connector"]}')
    print(f'{"Hardware:":<12}{h}')
    del h, t


def _handle_socket_error(err):
    print(f"websocket error: {err}", file=stderr)
    exit(1)


class Doppler(Api):
    __slots__ = ("watch", "events", "eventer", "last_job")

    def __init__(self, base_url, password=None):
        Api.__init__(self, base_url, password=password)
        self.watch = dict()
        self.eventer = None
        self.last_job = None
        self.events = Queue()

    def close(self):
        if self.eventer is not None and self.eventer.is_alive():
            self.eventer.close()
        super(__class__, self).close()

    def _on_event(self, _, msg):
        try:
            v = loads(msg)
        except (ValueError, UnicodeDecodeError):
            return
        if not isinstance(v, dict) or len(v) == 0:
            return
        if "name" not in v or "action" not in v:
            return
        n = v["name"]
        a = v["action"]
        z = v.get("value")
        if not nes(n) or not nes(a):
            del n, a, z, v
            return
        if a == "packet_new":
            return self.events.put(
                _Event(action=a, msg=f"New Oneshot ({z} ID: {n}) Received!", id=n)
            )
        if a == "session_new":
            return self.events.put(
                _Event(action=a, msg=f"{n}: New Bolt Registered", id=n)
            )
        if a == "listener_new":
            return self.events.put(
                _Event(action=a, msg=f"{n}: New Listener Registered", id=n)
            )
        if a == "session_update":
            return self.events.put(
                _Event(action=a, msg=f"{n}: Bolt Details Updated", id=n)
            )
        if a == "session_update":
            return self.events.put(
                _Event(action=a, msg=f"{n}: Bolt Details Updated", id=n)
            )
        if a == "job_update" and isinstance(z, int) and z > 0 and z < 0xFFFF:
            return self.events.put(
                _Event(action=a, msg=f"{n}: Accepted Job {z}", id=n, job=z)
            )
        if a == "job_complete" and isinstance(z, int) and z > 0 and z < 0xFFFF:
            return self.events.put(_Event(action=a, id=n, job=z))
        if a == "job_receiving" and isinstance(z, int) and z > 0 and z < 0xFFFF:
            return self.events.put(
                _Event(
                    action=a,
                    msg=f'{n}: Receiving Job {z} ({v.get("count", 0) + 1}/{v.get("total", 0)})',
                    id=n,
                    job=z,
                )
            )
        if a in _UPDATE_NAMES:
            self.events.put(_Event(action=a, id=n))
        del a, n, z, v

    def _sessions(self, exp=None):
        r = super(__class__, self).sessions()
        if not isinstance(r, list) or len(r) == 0:
            return list()
        r.sort(key=_uniq_session_id, reverse=False)
        if isinstance(exp, Exp):
            return exp.matches(r)
        return r

    def _watch(self, id, job, args, out=None):
        if job is None:
            return print(f"[+] {id}: Ok")
        if not isinstance(job, int) or job < 1 or job > 0xFFFF:
            raise ValueError('"job" must be a positive number between [1-65535]')
        s = id + ":" + str(job)
        if s in self.watch:
            raise KeyError(f'duplicate "BoltID:JobID": "{s}"')
        self.watch[s] = (out, args)
        del s
        self.last_job = job
        print(f"[+] {id}: Queued Job {job}")

    def _show_jobs(self, id, sz, prefix=False):
        d = super(__class__, self).jobs(id)
        if not isinstance(d, dict) and len(d) > 0:
            return
        if not prefix:
            print(
                f'{"ID":6}{"Type":5}{"Status":11}{"Start":10}{"Complete":10}{"Took":8}Result Error\n{"=" * 65}'
            )
        t = datetime.now()
        e = list(d.values())
        del d
        e.sort(key=lambda x: x["start"], reverse=True)
        for j in e:
            if "id" not in j or "status" not in j or "type" not in j:
                continue
            if prefix:
                print(f"{_trunc(sz - 1, id):{sz}} ", end="")
            print(
                f'{j["id"]:<6}{j["type"]:<5X}{j["status"].title():11}{time_str(t, j["start"]):10}',
                end="",
            )
            if "complete" in j:
                s = datetime.fromisoformat(j["complete"].replace("Z", "")).replace(
                    tzinfo=None
                )
                print(
                    f'{time_str(t, j["complete"]):10}' f'{time_str(s, j["start"]):8}',
                    end="",
                )
                del s
            else:
                print(f'{"":10}{"":10}', end="")
            if "result" in j and isinstance(j["result"], int) and j["result"] > 0:
                print(size_str(j["result"], True), end="")
            if "error" in j and len("error") > 0:
                print(" " + j["error"].replace("\n", " "), end="")
            print()
        del t, e

    def start(self, do_eventer=True, events=None):
        if do_eventer:
            self.eventer = _Thread(self, events)
            self.eventer.start()
        self.start_events(self._on_event, on_error=_handle_socket_error)

    def single(self, timeout=None, init=True, job=None):
        if init:
            self.start(False)
        if job is None:
            job = self.last_job
        w, v = None, None
        if isinstance(timeout, (int, float)):
            w = datetime.now() + timedelta(seconds=timeout)
            v = timeout
        try:
            while True:
                n = self.events.get(block=True, timeout=v)
                if w is not None:
                    v = (w - datetime.now()).seconds
                    if v <= 0:
                        break
                if n is None:
                    break
                if "job_" not in n.action and n.job != job:
                    continue
                if nes(n.msg):
                    print(f"[-] {n.msg}.")
                    continue
                if n.action != "job_complete" and n.job != job:
                    continue
                self.job_display(n.id, n.job)
                del n
                break
        except Empty:
            print("[!] Timeout was reached.")
        except KeyboardInterrupt:
            pass
        del w, v
        self.close()

    def job_display(self, id, job, shell=False, multi=False):
        if not nes(id) or not isinstance(job, int) or job < 1 or job > 0xFFFF:
            return
        v = id + ":" + str(job)
        if v not in self.watch:
            del v
            return
        a = self.watch[v]
        del self.watch[v]
        if shell:
            print()
        print_job_result(
            id, job, super(__class__, self).job_result(id, job), a[1], a[0], multi
        )
        del v, a

    def show_script_info(self, script):
        if not nes(script):
            raise ValueError('"name" must be a non-empty string')
        n = super(__class__, self).script(script)
        if not isinstance(n, dict) or len(n) == 0:
            return
        print(
            f'{script} - {size_str(n["size"])}\n{"=" * 35}\n'
            f'Channel:       {n["channel"]}\n'
            f'Return Output: {n["return_output"]}\n'
            f'Stop On Error: {n["stop_on_error"]}\n'
        )
        if "commands" not in n:
            return
        c = n["commands"]
        if len(c) > 0:
            print(f'#    Command\n{"=" * 35}')
            for x in range(0, len(c)):
                print(f"{x:3}: {c[x]}")
        del c, n

    def show_profiles(self, name=None):
        if nes(name):
            n = {name: super(__class__, self).profile(name)}
        else:
            n = super(__class__, self).profiles()
        if not isinstance(n, dict) or len(n) == 0:
            return
        print(f'{"Name":16}Details\n{"=" * 35}')
        for k, v in n.items():
            print(f"{k:16}{v}")
        del n

    def show_scripts(self, script=None):
        if nes(script):
            n = {script: super(__class__, self).script(script)}
        else:
            n = super(__class__, self).scripts()
        if not isinstance(n, dict) or len(n) == 0:
            return
        print(
            f'{"Name":16}{"Size":9} {"History":7} StopOnError ReturnOutput\n{"=" * 60}'
        )
        for k, v in n.items():
            i = k
            if "marks" in v and "rollbacks" in v and "commands" in v:
                if len(v["marks"]) != v["rollbacks"]:
                    i = k + " !"
                elif len(v["commands"]) != v["rollbacks"]:
                    i = k + " !"
                elif len(v["marks"]) != len(v["commands"]):
                    i = k + " !"
            print(
                f'{i:16}{v["size"] if v["loaded"] else "n/a":<9} {v["rollbacks"]:>7} '
                f'{"X" if v["stop_on_error"] else " ":>11} '
                f'{"X" if v["return_output"] else " ":>12}'
            )
            del i
        del n

    def show_listeners(self, name=None):
        if nes(name):
            n = {name: super(__class__, self).listener(name)}
        else:
            n = super(__class__, self).listeners()
        if not isinstance(n, dict) or len(n) == 0:
            return
        print(
            f'{"Name":16}{"Profile":16}{"Bind Address":24}{"Connect Script":16}# Bolts\n{"=" * 80}'
        )
        for k, v in n.items():
            print(f'{k:16}{v["profile_name"]:16}', end="")
            if "type" in v:
                print(f'{v["listener"]["type"]:24}', end="")
            else:
                print(f'{v["listener"]["address"]:24}', end="")
            print(f'{v["script"]:16}{v["listener"]["count"]}')
        del n

    def show_script_history(self, name):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        n = super(__class__, self).script(name)
        if not isinstance(n, dict) or len(n) == 0:
            return
        if "commands" not in n:
            return
        c = n["commands"]
        print(f'#    Command\n{"=" * 35}')
        for x in range(0, len(c)):
            print(f"{x:3}: {c[x]}")
        del c, n

    def show_result(self, id, job, out=None):
        r = super(__class__, self).job_result(id, job)
        if not isinstance(r, dict):
            return False
        print_job_result(id, job, r, None, out)
        del r
        return True

    def show_profile(self, name, as_bytes=False):
        p = super(__class__, self).profile(name)
        if not isinstance(p, Config) or len(p) == 0:
            return
        if as_bytes:
            print(f"// Profile {name}\nvar profile = cfg.Config{{\n\t", end="")
            n, f = 0, False
            for i in p:
                if n == 0 and f:
                    print("\t", end="")
                print(f"0x{str(hex(i)[2:]).zfill(2).upper()}", end="")
                if n > 10:
                    print(",\n", end="")
                    n = 0
                else:
                    print(", ", end="")
                    n += 1
                f = True
            del p
            if n > 0:
                print()
            del n
            return print("}")
        print(f'{name} ({p})\n{55 * "="}')
        print(f'JSON:\n{dumps(p.json(), sort_keys=False, indent=4)}\n{55 * "="}\nRaw:')
        n = 0
        for i in p:
            if n > 10:
                print()
                n = 0
            print(f"0x{str(hex(i)[2:]).zfill(2).upper()} ", end="")
            n += 1
        print(f'\n{55 * "="}\nBase64: {b64encode(p).decode("UTF-8")}')
        del p, n

    def show_info(self, id=None, all=False, exp=None):
        if not all:
            return _print_session_info(super(__class__, self).session(id))
        r = self._sessions(exp=exp)
        if not isinstance(r, list) or len(r) == 0:
            return
        for s in r:
            _print_session_info(s)
            print()
        del r

    def show_jobs(self, id=None, all=False, exp=None):
        if not all:
            return self._show_jobs(id, 0, False)
        r = self._sessions(exp=exp)
        if not isinstance(r, list) or len(r) == 0:
            return
        w = min(max(max(len(i["name"]) for i in r), 64) + 1, 26)
        print(
            f'{"Host":{w}}{"ID":6}{"Type":5}{"Status":11}{"Start":10}{"Complete":10}{"Took":8}Result Error\n{"=" * 100}'
        )
        for s in r:
            if nes(s["name"]):
                self._show_jobs(s["name"], w, True)
            else:
                self._show_jobs(s["id"], w, True)
        del r, w

    def show_sessions(self, exp=None, advanced=False, hw=False):
        e = self._sessions(exp=exp)
        if not isinstance(e, list) or len(e) == 0:
            return
        t = datetime.now()
        m = 0
        if hw:
            m = 16
        w = 26
        for i in e:
            if len(i["name"]) >= 26:
                w = 64
                break
        if advanced:
            print(
                f'{"ID":{w}}{"Hostname":20}{"IP":17}{"OS":32}{"Arch":8}{"User":32}'
                f'{"From":20}{"PID":9}{" Last":8}\n{"=" * (146 + m + w)}'
            )
        else:
            print(
                f'{"ID":26}{"Hostname":20}{"IP":17}{"OS":10}{"User":32}{"PID":9}{"Last":8}\n{"=" * (126 + m)}'
            )
        del m
        for x in e:
            s = x["session"]
            if advanced:
                # Handle IPv6 encoded IPv4 addresses
                if s["via"].lower().startswith("[::ffff:"):
                    i = s["via"].rfind("]")
                    if i > 8:
                        v = s["via"][8:i]
                    else:
                        v = s["via"]
                    del i
                elif ":" in s["via"]:
                    i = s["via"].rfind(":")
                    if i > 1:
                        v = s["via"][:i]
                    else:
                        v = s["via"]
                    del i
                else:
                    v = s["via"]
                if "connector" in s and len(v) > 0:
                    if len(v) > 15:
                        v = "<IPv6>"
                    if "/" in s["connector"]:
                        v = s["connector"].split("/")[0] + "|" + v
                    else:
                        v = s["connector"] + "|" + v
                if "(" in s["device"]["version"]:
                    n = s["device"]["version"].index("(")
                    if n > 0:
                        o = s["device"]["version"][:n].strip()
                    else:
                        o = s["device"]["version"]
                else:
                    o = s["device"]["version"]
                if o.startswith("Microsoft Windows Server"):
                    o = o[25:]
                elif o.startswith("Microsoft Windows "):
                    o = o[10:]
                if hw:
                    print(f'{s["device"]["id"][:16] + s["id"]:25}', end="")
                else:
                    a = x["name"]
                    if nes(a):
                        print(f"{_trunc(w - 2, a):{w}}", end="")
                    else:
                        print(f'{s["id"]:{w}}', end="")
                    del a
                u = ""
                if s["device"]["elevated"]:
                    u = "*"
                u = u + s["device"]["user"]
                if s["device"]["domain"]:
                    u = u + "@"
                h = s["device"]["hostname"]
                if len(h) > 19 and "." in h:
                    h = h.split(".")[0]
                c = " "
                if s["channel"]:
                    c = "C"
                elif "work_hours" in s and len(s["work_hours"]) > 0:
                    c = "W"
                a = "x" + s["device"]["arch"].replace("bit", "")
                if "[" in a:
                    a = a[: a.find("[")].strip() + "*"
                print(
                    f"{_trunc(18, h):20}{ip_str(s):17}{_trunc(30, o):32}{a:8}{_trunc(30, u):32}"
                    f'{v:20}{s["device"]["pid"]:<9}{c}{time_str(t, s["last"])}'
                )
                del v, o, u, h, c, a, x
                continue
            if hw:
                print(f'{s["device"]["id"][:16] + s["id"]:26}', end="")
            else:
                a = x["name"]
                if nes(a):
                    print(f"{_trunc(24, a):26}", end="")
                else:
                    print(f'{s["id"]:26}', end="")
            u = ""
            if s["device"]["elevated"]:
                u = "*"
            u = u + s["device"]["user"]
            if s["device"]["domain"]:
                u = u + "@"
            h = s["device"]["hostname"]
            if len(h) > 19 and "." in h:
                h = h.split(".")[0]
            c = " "
            if s["channel"]:
                c = "C"
            elif "work_hours" in s and len(s["work_hours"]) > 0:
                c = "W"
            print(
                f'{_trunc(18, h):20}{ip_str(s):17}{s["device"]["os"]:10}{_trunc(30, u):32}{s["device"]["pid"]:<9}'
                f'{c}{time_str(t, s["last"])}'
            )
            del u, h, c
        del t, e, w

    def session_proxy_delete(self, id, name):
        self._watch(
            id,
            super(__class__, self).session_proxy_delete(id, name),
            f"proxy delete {name}",
        )

    def session_proxy_add(self, id, name, address, profile):
        self._watch(
            id,
            super(__class__, self).session_proxy_add(id, name, address, profile),
            f"proxy add {name}",
        )

    def session_proxy_update(self, id, name, address, profile=None):
        self._watch(
            id,
            super(__class__, self).session_proxy_update(id, name, address, profile),
            f"proxy update {name}",
        )

    def sessions_autoname(self, exp, prefix=None, force=False, map=False):
        r = self._sessions(exp=exp)
        if len(r) == 0:
            return None
        v = list()
        for i in r:
            if nes(i["name"]):
                v.append(i["name"])
            else:
                v.append(i["id"])
        del r
        if len(v) == 0:
            raise ValueError("no matches found")
        if len(v) == 1:
            return super(__class__, self).sessions_auto_rename(v, prefix, force, map)
        return super(__class__, self).sessions_auto_rename(v, prefix, force, map)

    def task_touch(self, id, path):
        self._watch(id, super(__class__, self).task_touch(id, path), f"touch {path}")

    def task_evade(self, id, action):
        self._watch(
            id, super(__class__, self).task_evade(id, action), f"evade {action}"
        )

    def task_script(self, id, script):
        self._watch(
            id, super(__class__, self).task_script(id, script), f"script {script}"
        )

    def task_copy(self, id, src, dest):
        self._watch(
            id, super(__class__, self).task_copy(id, src, dest), f"copy {src} {dest}"
        )

    def task_move(self, id, src, dest):
        self._watch(
            id, super(__class__, self).task_move(id, src, dest), f"move {src} {dest}"
        )

    def task_wallpaper(self, id, data):
        self._watch(
            id,
            super(__class__, self).task_wallpaper(id, data),
            "wallpaper",
        )

    def task_profile(self, id, profile):
        self._watch(
            id, super(__class__, self).task_profile(id, profile), f"profile {profile}"
        )

    def task_upload(self, id, data, dest):
        self._watch(
            id,
            super(__class__, self).task_upload(id, data, dest),
            f"upload to {dest}",
        )

    def task_delete(self, id, path, force=False):
        self._watch(
            id, super(__class__, self).task_delete(id, path, force), f"delete {path}"
        )

    def task_kill(self, id, pid=None, pname=None):
        self._watch(
            id,
            super(__class__, self).task_kill(id, pid, pname),
            f"kill {str(pid) if not nes(pname) else pname}",
        )

    def task_download(self, id, target, dest=None):
        self._watch(
            id,
            super(__class__, self).task_download(id, target),
            f"download {target}",
            dest,
        )

    def task_system(self, id, cmd, filter=None, out=None):
        self._watch(id, super(__class__, self).task_system(id, cmd, filter), cmd, out)

    def task_workhours(self, id, days="", start="", end=""):
        self._watch(
            id,
            super(__class__, self).task_workhours(id, days, start, end),
            f'workhours {days if nes(days) else "SMTWRFS"} '
            f'{start if nes(start) else "--:--"} - {end if end else "--:--"}',
        )

    def task_troll(self, id, action, enable=False, seconds=None):
        self._watch(
            id,
            super(__class__, self).task_troll(id, action, enable, seconds),
            f'troll {action} {str(enable).lower() if enable is not None else "true"}',
        )

    def task_pull(self, id, url, path="", agent=None, dest=None):
        self._watch(
            id,
            super(__class__, self).task_pull(id, url, path, agent),
            f"pull {url}",
            dest,
        )

    def task_check(self, id, dll, function="", data=None, raw=False):
        self._watch(
            id,
            super(__class__, self).task_check(id, dll, function, data, raw),
            f"check {dll}{f' {function}' if nes(function) else ''}",
        )

    def task_patch(self, id, dll, function="", data=None, raw=False):
        self._watch(
            id,
            super(__class__, self).task_patch(id, dll, function, data, raw),
            f"patch {dll}{f' {function}' if nes(function) else ''}",
        )

    def task_login(self, id, user, domain="", pw="", interactive=False):
        self._watch(
            id,
            super(__class__, self).task_login(id, user, domain, pw, interactive),
            f'login_user {"interactive" if interactive else "network"} {user}'
            f'{"@" + domain if nes(domain) else ""}',
        )

    def task_funcmap(self, id, action, function="", data=None, raw=False):
        self._watch(
            id,
            super(__class__, self).task_funcmap(id, action, function, data, raw),
            f"funcmap {action}{f' {function}' if nes(function) else ''}",
        )

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
        self._watch(
            id,
            super(__class__, self).task_dll(
                id, data, reflect, show, detach, filter, entry, timeout
            ),
            "dll",
        )

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
        self._watch(
            id,
            super(__class__, self).task_wts(
                id, action, session, title, text, flags, seconds, wait
            ),
            f"wts {action} {session if nes(session) else 'current'}",
        )

    def task_power(
        self,
        id,
        action,
        message="",
        force=False,
        seconds=None,
        reason=None,
    ):
        self._watch(
            id,
            super(__class__, self).task_power(
                id, action, message, force, seconds, reason
            ),
            f"power {action}",
        )

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
        self._watch(
            id,
            super(__class__, self).task_spawn(
                id, pipe, method, profile, exec, show, filter
            ),
            f"spawn{f' {method}' if nes(method) else ''}",
        )

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
        entry=None,
        timeout=None,
    ):
        self._watch(
            id,
            super(__class__, self).task_zombie(
                id,
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
            ),
            "zombie",
        )

    def task_netcat(
        self,
        id,
        host,
        proto,
        seconds=None,
        data=None,
        read=False,
        dest=None,
    ):
        self._watch(
            id,
            super(__class__, self).task_netcat(id, host, proto, seconds, data, read),
            f"netcat {host}/{proto}",
            dest,
        )

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
        self._watch(
            id,
            super(__class__, self).task_window(
                id,
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
            f'window {action}{" " + hex(handle) if isinstance(handle, int) else (f" {handle}" if nes(handle) else "")}',
        )

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
        self._watch(
            id,
            super(__class__, self).task_execute(
                id, cmd, show, detach, filter, stdin, user, domain, pw, timeout
            ),
            cmd,
        )

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
        self._watch(
            id,
            super(__class__, self).task_migrate(
                id, pipe, method, profile, exec, show, filter, wait
            ),
            f"migrate{f' {method}' if nes(method) else ''}",
        )

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
        self._watch(
            id,
            super(__class__, self).task_registry(
                id, action, key, value, type, data, force
            ),
            f"regedit {action} {key}{f':{value}' if nes(value) else ''}",
        )

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
        self._watch(
            id,
            super(__class__, self).task_assembly(
                id, data, show, detach, filter, entry, timeout
            ),
            "asm",
        )

    def task_pull_exec(
        self,
        id,
        url,
        agent=None,
        show=False,
        detach=False,
        filter=None,
    ):
        self._watch(
            id,
            super(__class__, self).task_pull_exec(id, url, agent, show, detach, filter),
            f"pull_ex {url}",
        )


class _Event(object):
    __slots__ = ("id", "msg", "job", "action")

    def __init__(self, action, msg=None, id=None, job=None):
        self.id = id
        self.msg = msg
        self.job = job
        self.action = action


class _Thread(Thread):
    __slots__ = ("_api", "_events", "_running")

    def __init__(self, api, event):
        Thread.__init__(self)
        self._api = api
        self.daemon = False
        self._events = event
        self._running = Event()
        self.name = "_EventProcessor"

    def run(self):
        while not self._running.is_set():
            try:
                n = self._api.events.get(block=True)
                if n is None:
                    break
                if self._events is not None:
                    self._events(n.action, n.id, n.msg, n.job)
                    continue
                if nes(n.msg):
                    print(f"[-] {n.msg}.")
                    continue
                self._api.job_display(n.id, n.job)
                del n
            except Exception as err:
                print(f"Error during event runtime: {err}!")
                print(format_exc(3))

    def close(self):
        if self._running.is_set():
            return
        print("[-] Shutting down..")
        self._running.set()
        self._api.events.put(None)


class _Parser(ArgumentParser):
    def __init__(self):
        ArgumentParser.__init__(
            self,
            prog="doppler",
            add_help=True,
            allow_abbrev=True,
            fromfile_prefix_chars=None,
        )
        self.add_argument(
            "-f", "--config", dest="config", type=str, default=getenv("DOPPLER_CONFIG")
        )
        self._args = dict()
        self._setup()

    def _setup(self):
        self.add("cirrus", "-a", "--api", name="cirrus", env="DOPPLER_HOST")
        self.add(
            "cirrus_password",
            "-p",
            "--password",
            name="cirrus_password",
            env="DOPPLER_PW",
        )
        # List Arguments
        self.add("jobs", "-j", "--jobs", bool=True)
        self.add("scripts", "-s", "--scripts", bool=True)
        self.add("profiles", "-n", "--profiles", bool=True)
        self.add("listeners", "-l", "--listeners", bool=True)
        self.add("bolts", "-b", "--bolts", bool=True)
        self.add("bolts_adv", "-B", "--bolts-adv", bool=True)
        self.add("info", "-I", bool=True)
        # Execution Arguments
        self.add("cmd", "-c", "--cmd")
        self.add("timeout", "-w", "--timeout")
        # CLI Default Arguments
        self.add("asm", "-A", "--asm", name="default_asm", env="DOPPLER_ASM")
        self.add("dll", "-D", "--dll", name="default_dll", env="DOPPLER_DLL")
        self.add("pipe", "-P", "--pipe", name="default_pipe", env="DOPPLER_PIPE")
        self.add(
            "no_empty",
            "-N",
            "--no-empty",
            bool=True,
            name="default_exec",
            env="DOPPLER_NO_EMPTY",
            type=lambda x: not x,  # Flip the config value, to make it less confusing.
        )
        # CLI Modification Arguments
        self.add("input", "-z", "--input")
        self.add("oneline", "-k", "--oneline")
        self.add("oneline_no_exit", "-K", "--oneline-ne")
        self.add("shell", "-i", "--interact", bool=True)
        self.add("debug", "--debug", bool=True)
        # Extra
        self.add_argument(nargs="*", type=str, dest="extra")

    def print_help(self, file=stderr):
        print(_HELP_TEXT.format(proc=basename(argv[0])), file=file)

    def parse_args(self, args=None, namespace=None):
        r, c = super(__class__, self).parse_args(args, namespace), None
        if nes(r.config):
            try:
                with open(expandvars(expanduser(r.config))) as f:
                    c = loads(f.read())
            except ValueError as err:
                raise ValueError(f'reading config "{r.config}": {err}')
        else:
            p = join(getcwd(), "cirrus.json")
            if isfile(p):
                try:
                    with open(p) as f:
                        c = loads(f.read())
                except ValueError as err:
                    raise ValueError(f'reading config "{p}": {err}')
            del p
        if c is not None and not isinstance(c, dict):
            raise ValueError("invalid JSON type for config")
        for k, v in self._args.items():
            try:
                w = getattr(r, k)
                if v[2] is None and w is not None:
                    continue
                if v[2] is not None and v[2] == w:
                    continue
                del w
            except AttributeError:
                pass
            x = None
            if nes(v[1]):
                x = getenv(v[1])
            if x is None and nes(v[0]) and c is not None and v[0] in c:
                x = c[v[0]]
            if x is None:
                continue
            if v[2] is not None:
                setattr(r, k, is_true(x))
            if v[3] is not None and callable(v[3]):
                setattr(r, k, v[3](x))
            else:
                setattr(r, k, x)
            del x
        del c
        if not nes(r.cirrus):
            raise ValueError("empty/missing Cirrus server address")
        if nes(r.input):
            p = r.input.strip()
            if p == "-" and not stdin.isatty():
                if hasattr(stdin, "buffer"):
                    r.input = stdin.buffer.read().decode("UTF-8").split("\n")
                else:
                    r.input = stdin.read().split("\n")
            else:
                with open(expandvars(expanduser(p))) as f:
                    r.input = f.read().split("\n")
            del p
        if isinstance(r.extra, list):
            r.extra = " ".join(r.extra)
        if nes(r.timeout):
            r.timeout = Utils.str_to_dur(r.timeout) / 1000000000
        if nes(r.oneline_no_exit):
            r.oneline = r.oneline_no_exit
            r.oneline_no_exit = True
        return r

    def add(self, dest, *f, type=str, bool=None, default=None, name=None, env=None):
        if bool is True:
            self.add_argument(*f, dest=dest, action="store_true")
        elif bool is False:
            self.add_argument(*f, dest=dest, action="store_false")
        else:
            self.add_argument(*f, dest=dest, type=str, default=default)
        if env is None and name is None:
            return
        if bool is not None and type == str:
            self._args[dest] = (name, env, bool, None)
        else:
            self._args[dest] = (name, env, bool, type)


def _main():
    p = _Parser()
    try:
        r = p.parse_args()
    except (OSError, ValueError) as err:
        print(f"Error: {str(err)}!", file=stderr)
        exit(1)
    del p
    try:
        d = Doppler(r.cirrus, r.cirrus_password)
    except (OSError, ValueError) as err:
        print(f"Error: {str(err)}!\n{format_exc(10 if r.debug else 3)}", file=stderr)
        exit(1)
    try:
        if r.jobs:
            return d.show_jobs(all=True, exp=parse_exp(r.extra))
        if r.scripts:
            return d.show_scripts(r.extra)
        if r.profiles:
            return d.show_profiles(r.extra)
        if r.listeners:
            return d.show_listeners(r.extra)
        if r.bolts or r.bolts_adv:
            return d.show_sessions(advanced=r.bolts_adv, exp=parse_exp(r.extra))
        if r.info:
            if len(r.extra) == 0:
                return d.show_info(all=True)
            return d.show_info(id=r.extra)
        s = Shell(d, r)
        if nes(r.cmd):
            d.session(r.extra)
            s.set_menu(MENU_BOLT, r.extra)
            s.init(True)
            s.onecmd(r.cmd)
            return d.single(init=False, timeout=r.timeout)
        if isinstance(r.input, list) and len(r.input) > 0:
            for i in r.input:
                if len(i) == 0:
                    continue
                s.run_cmd(i, True, True, False, False)
            print()
            if not stdin.isatty():
                return
        if nes(r.oneline):
            if ";" in r.oneline:
                for i in r.oneline.split(";"):
                    v = i.lstrip()
                    if len(v) == 0:
                        continue
                    s.run_cmd(v, True, True, False, False)
                    del v
                if not r.oneline_no_exit:
                    return
            if not r.oneline_no_exit:
                return s.run_cmd(r.oneline, True, True, False, False)
        if r.shell and nes(r.extra):
            d.session(r.extra)
            s.set_menu(MENU_BOLT, r.extra)
        s.enter(debug=r.debug)
    except (OSError, ValueError, CirrusError) as err:
        print(f"Error: {str(err)}!\n{format_exc(10 if r.debug else 3)}", file=stderr)
        exit(1)
    finally:
        d.close()
        del r, d


if __name__ == "__main__":
    _main()

#!/usr/bin/python3
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

from os import getenv
from base64 import b64encode
from json import loads, dumps
from queue import Queue, Empty
from traceback import format_exc
from threading import Thread, Event
from argparse import ArgumentParser
from include.config import Config, Utils
from datetime import datetime, timedelta
from sys import exit, stderr, stdin, argv
from os.path import expanduser, expandvars
from include.cirrus import Api, CirrusError
from include.cli import Shell, Exp, print_job_result, MENU_BOLT
from include.util import nes, size_str, time_str, ip_str, is_true

_HELP_TEXT = """ Doppler: ThunderStorm C2 Console Interface
Part of the |||||| ThunderStorm Project (https://dij.sh/ts)
(c) 2019 - 2022 iDigitalFlame

Usage: {proc} -a <cirrus> [-p password] [-b] [-B] [-j] [-l] [-x] [-s] [-i] [-c cmd] [...]

Required Arguments:
  -a

Optional Arguments:
  -p          <password>         |

 Shell Option Arguments
  -N                             |
  --no-empty
  -z          <file|'-'>         |
  --input
  -i          <Bolt ID>          |
  --interact

 Execution Option Arguments:
  -c          <command>          |
  --cmd
  -w          <duration[s|m|h]>  |
  --timeout
  -k          <cli command>      |
  --oneline

 List Operations
  -b
  --bolts
  -B
  --bolts-adv
  -j
  --jobs
  -s
  --scripts
  -n
  --profiles
  -l
  --listeners

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


def _print_session_info(s):
    print(
        f'{"ID:":<12}{s["id"]}\n{"="*40}\n{"Hostname:":<12}{s["device"]["hostname"]}\n'
        f'{"User:":<12}{("*" if s["device"]["elevated"] else "") + s["device"]["user"]}\n'
        f'{"Domain:":<12}{"Yes" if s["device"]["domain"] else "No"}\n'
        f'{"OS:":<12}{s["device"]["os"]}\n{"Version:":<12}{s["device"]["version"]}\n{"Arch:":<12}'
        f'{s["device"]["arch"]}\n{"PID:":<12}{s["device"]["pid"]}\n{"PPID:":<12}{s["device"]["ppid"]}\nNetwork:'
    )
    for i in s["device"]["network"]:
        print(f'  {i["name"]+":":6} {", ".join(i["ip"])}')
    t = datetime.now()
    print(
        f'{"Sleep:":<12}{int(int(s["sleep"])//1000000000)}s\n{"Jitter:":<12}{s["jitter"]}%\n'
        f'{"Channel:":<12}{"Yes" if s["channel"] else "No"}',
    )
    h = s["device"]["id"][: -len(s["id"])]
    print(
        f'{"Last:":<12}{time_str(t, s["last"], True)}\n{"Created:":<12}'
        f'{time_str(t, s["created"], True)}\n{"From:":<12}{s["via"]}'
    )
    if "connector" in s:
        print(f'{"Connector:":<12}{s["connector"]}')
    print(f'{"Hardware:":<12}{h}')
    del h, t


class Doppler(Api):
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
                    msg=f'{n}: Receiving Job {z} ({v.get("count", 0)+1}/{v.get("total", 0)})',
                    id=n,
                    job=z,
                )
            )
        if a in _UPDATE_NAMES:
            return self.events.put(_Event(action=a, id=n))
        del a, n, z, v

    def _show_jobs(self, id, prefix=False):
        d = super(__class__, self).jobs(id)
        if not isinstance(d, dict) and len(d) > 0:
            return
        if not prefix:
            print(
                f'{"ID":6}{"Type":5}{"Status":11}{"Start":10}{"Complete":10}Result Error\n{"="*55}'
            )
        t = datetime.now()
        e = list(d.values())
        del d
        e.sort(key=lambda x: x["start"], reverse=True)
        for j in e:
            if "id" not in j or "status" not in j or "type" not in j:
                continue
            if prefix:
                print(f'{j["host"]} ', end="")
            print(
                f'{j["id"]:<6}{j["type"]:<5X}{j["status"].title():11}{time_str(t, j["start"]):10}',
                end="",
            )
            if "complete" in j:
                print(f'{time_str(t, j["complete"]):10}', end="")
            else:
                print(f'{"":10}', end="")
            if "result" in j and isinstance(j["result"], int) and j["result"] > 0:
                print(size_str(j["result"], True), end="")
            if "error" in j and len("error") > 0:
                print(" " + j["error"], end="")
            print()
        del t, e

    def _sessions(self, exp=None, hw=False):
        r = super(__class__, self).sessions()
        if not isinstance(r, list) or len(r) == 0:
            return list()
        if hw:
            r.sort(key=lambda x: x["device"]["id"], reverse=True)
        else:
            r.sort(key=lambda x: x["id"], reverse=True)
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

    def start(self, do_eventer=True, events=None):
        if do_eventer:
            self.eventer = _Thread(self, events)
            self.eventer.start()
        self.start_events(self._on_event)

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

    def show_scripts(self, name=None):
        if nes(name):
            n = {name: super(__class__, self).script(name)}
        else:
            n = super(__class__, self).scripts()
        if not isinstance(n, dict) or len(n) == 0:
            return
        print(
            f'{"Name":16}{"Size":>9} {"History":7} StopOnError ReturnOutput\n{"="*60}'
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
                f'{i:16}{v["size"]:>9} {v["rollbacks"]:>7} '
                f'{"X" if v["stop_on_error"] else " ":>11} '
                f'{"X" if v["return_output"] else " ":>12}'
            )
            del i
        del n

    def show_script_info(self, name):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        n = super(__class__, self).script(name)
        if not isinstance(n, dict) or len(n) == 0:
            return
        print(
            f'{name} - {size_str(n["size"])}\n{"="*35}\n'
            f'Channel:       {n["channel"]}\n'
            f'Return Output: {n["return_output"]}\n'
            f'Stop On Error: {n["stop_on_error"]}\n'
        )
        if "commands" not in n:
            return
        c = n["commands"]
        if len(c) > 0:
            print(f'#    Command\n{"="*35}')
            for x in range(0, len(c)):
                print(f"{x:3}: {c[x]}")
        del c, n

    def show_script_history(self, name):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        n = super(__class__, self).script(name)
        if not isinstance(n, dict) or len(n) == 0:
            return
        if "commands" not in n:
            return
        c = n["commands"]
        print(f'#    Command\n{"="*35}')
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
        print(f'{"Name":16}Details\n{"="*35}')
        for k, v in n.items():
            print(f"{k:16}{v}")
        del n

    def show_listeners(self, name=None):
        if nes(name):
            n = {name: super(__class__, self).listener(name)}
        else:
            n = super(__class__, self).listeners()
        if not isinstance(n, dict) or len(n) == 0:
            return
        print(
            f'{"Name":16}{"Profile":16}{"Bind Address":24}{"Connect Script":16}# Bolts\n{"="*80}'
        )
        for k, v in n.items():
            print(f'{k:16}{v["profile_name"]:16}', end="")
            if "type" in v:
                print(f'{v["listener"]["type"]:24}', end="")
            else:
                print(f'{v["listener"]["address"]:24}', end="")
            print(f'{v["script"]:16}{v["listener"]["count"]}')
        del n

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
        print(f'{name} ({p})\n{55*"="}')
        print(f'JSON:\n{dumps(p.json(), sort_keys=False, indent=4)}\n{55*"="}\nRaw:')
        n = 0
        for i in p:
            if n > 10:
                print()
                n = 0
            print(f"0x{str(hex(i)[2:]).zfill(2).upper()} ", end="")
            n += 1
        print(f'\n{55*"="}\nBase64: {b64encode(p).decode("UTF-8")}')
        del p, n

    def show_info(self, id=None, all=False, exp=None, hw=False):
        if not all:
            return _print_session_info(super(__class__, self).session(id))
        r = self._sessions(exp=exp, hw=hw)
        if not isinstance(r, list) or len(r) == 0:
            return
        for s in r:
            _print_session_info(s)
            print()
        del r

    def show_jobs(self, id=None, all=False, exp=None, hw=False):
        if not all:
            return self._show_jobs(id, False)
        r = self._sessions(exp=exp, hw=hw)
        if not isinstance(r, list) or len(r) == 0:
            return
        print(
            f'{"Host":9}{"ID":6}{"Type":5}{"Status":11}{"Start":10}{"Complete":10}Result Error\n{"="*65}'
        )
        for s in r:
            self._show_jobs(s["id"], True)
        del r

    def show_sessions(self, exp=None, advanced=False, hw=False):
        e = self._sessions(exp=exp, hw=hw)
        if not isinstance(e, list) or len(e) == 0:
            return
        t = datetime.now()
        m = 0
        if hw:
            print(f'{"ID":25}', end="")
            m = 16
        else:
            print(f'{"ID":9}', end="")
        if advanced:
            print(
                f'{"Hostname":20}{"IP":17}{"OS":22}{"User":32}{"From":20}{"PID":9}{" Last":8}\n{"="*(140+m)}'
            )
        else:
            print(
                f'{"Hostname":20}{"IP":17}{"OS":10}{"User":32}{"PID":9}{"Last":8}\n{"="*(105+m)}'
            )
        del m
        for s in e:
            if advanced:
                v = s["via"].split(":")
                if "connector" in s and len(v) > 0:
                    if "/" in s["connector"]:
                        v = s["connector"].split("/")[0] + "|" + v[0]
                    else:
                        v = s["connector"] + "|" + v[0]
                if "(" in s["device"]["version"]:
                    n = s["device"]["version"].index("(")
                    if n > 0:
                        o = s["device"]["version"][:n].strip()
                    else:
                        o = s["device"]["version"]
                else:
                    o = s["device"]["version"]
                if len(o) > 20:
                    o = o[:20] + "~"
                if hw:
                    print(f'{s["device"]["id"][:16]+ s["id"]:25}', end="")
                else:
                    print(f'{s["id"]:9}', end="")
                u = ""
                if s["device"]["elevated"]:
                    u = "*"
                u = u + s["device"]["user"]
                if len(u) > 30:
                    u = u[:30] + "~"
                if s["device"]["domain"]:
                    u = u + "@"
                print(
                    f'{s["device"]["hostname"]:20}{ip_str(s):17}{o:22}{u:32}{v:20}'
                    f'{s["device"]["pid"]:<9}{"C" if s["channel"] else " "}{time_str(t, s["last"])}'
                )
                del v, o, u
                continue
            if hw:
                print(f'{s["device"]["id"][:16]+ s["id"]:25}', end="")
            else:
                print(f'{s["id"]:9}', end="")
            u = ""
            if s["device"]["elevated"]:
                u = "*"
            u = u + s["device"]["user"]
            if len(u) > 30:
                u = u[:30] + "~"
            if s["device"]["domain"]:
                u = u + "@"
            print(
                f'{s["device"]["hostname"]:20}{ip_str(s):17}{s["device"]["os"]:10}'
                f'{u:32}{s["device"]["pid"]:<9}'
                f'{"C" if s["channel"] else " "}{time_str(t, s["last"])}'
            )
            del u
        del t, e

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

    def task_touch(self, id, path):
        self._watch(id, super(__class__, self).task_touch(id, path), f"touch {path}")

    def task_script(self, id, name):
        self._watch(id, super(__class__, self).task_script(id, name), f"script {name}")

    def task_copy(self, id, src, dest):
        self._watch(
            id, super(__class__, self).task_copy(id, src, dest), f"copy {src} {dest}"
        )

    def task_move(self, id, src, dest):
        self._watch(
            id, super(__class__, self).task_move(id, src, dest), f"move {src} {dest}"
        )

    def task_profile(self, id, profile):
        self._watch(
            id, super(__class__, self).task_profile(id, profile), f"profile {profile}"
        )

    def task_pull(self, id, url, dest, agent):
        self._watch(
            id, super(__class__, self).task_pull(id, url, dest, agent), f"pull {url}"
        )

    def task_troll(self, id, action, arg1=None):
        self._watch(
            id,
            super(__class__, self).task_troll(id, action, arg1),
            f'troll {action} {str(arg1).lower() if arg1 is not None else "true"}',
        )

    def task_delete(self, id, path, force=False):
        self._watch(
            id, super(__class__, self).task_delete(id, path, force), f"delete {path}"
        )

    def task_kill(self, id, pid=None, proc=None):
        self._watch(
            id,
            super(__class__, self).task_kill(id, pid, proc),
            f"kill {str(pid) if not nes(proc) else proc}",
        )

    def task_wallpaper(self, id, file, raw=None):
        self._watch(
            id,
            super(__class__, self).task_wallpaper(id, file, raw),
            f"wallpaper {file}",
        )

    def task_download(self, id, target, dest=None):
        self._watch(
            id,
            super(__class__, self).task_download(id, target),
            f"download {target}",
            dest,
        )

    def task_login(self, id, user, domain="", pw=""):
        self._watch(
            id,
            super(__class__, self).task_login(id, user, domain, pw),
            f'login_user {user}{"@"+domain if nes(domain) else ""}',
        )

    def task_upload(self, id, target, dest, raw=None):
        self._watch(
            id,
            super(__class__, self).task_upload(id, target, dest, raw),
            f'upload{" "+target if nes(target) else ""}',
        )

    def task_system(self, id, cmd, out=None, filter=None):
        self._watch(id, super(__class__, self).task_system(id, cmd, filter), cmd, out)

    def task_assembly(self, id, file, raw=None, show=False, detach=False, filter=None):
        self._watch(
            id,
            super(__class__, self).task_assembly(id, file, raw, show, detach, filter),
            f"asm {file}",
        )

    def task_pull_exec(
        self, id, url, agent=None, show=False, detach=False, filter=None
    ):
        self._watch(
            id,
            super(__class__, self).task_pull_exec(id, url, agent, show, detach, filter),
            f"pull_ex {url}",
        )

    def task_dll(
        self, id, file, raw=None, reflect=True, show=False, detach=False, filter=None
    ):
        self._watch(
            id,
            super(__class__, self).task_dll(
                id, file, raw, reflect, show, detach, filter
            ),
            f"dll {file}",
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
        self._watch(
            id,
            super(__class__, self).task_zombie(
                id, file, fake_args, raw, show, detach, filter, user, domain, pw
            ),
            f"zombie {file}",
        )

    def task_window(
        self,
        id,
        action,
        handle=0,
        arg1=None,
        arg2=None,
        arg3=None,
        arg4=None,
    ):
        self._watch(
            id,
            super(__class__, self).task_window(
                id, action, handle, arg1, arg2, arg3, arg4
            ),
            f'window {action}{" " + hex(handle) if isinstance(handle, int) else ""}',
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
    ):
        self._watch(
            id,
            super(__class__, self).task_execute(
                id, cmd, show, detach, filter, stdin, user, domain, pw
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


class _Event(object):
    def __init__(self, action, msg=None, id=None, job=None):
        self.id = id
        self.msg = msg
        self.job = job
        self.action = action


class _Thread(Thread):
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
                print(format_exc(4))

    def close(self):
        if self._running.set():
            return
        # print("[-] Shutting down..")
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
        self.add = self.add_argument
        self._setup()

    @staticmethod
    def _verify(a):
        if not nes(a.cirrus):
            raise ValueError("empty/missing Cirrus API target")
        if isinstance(a.extra, list):
            a.extra = " ".join(a.extra)
        if nes(a.timeout):
            a.timeout = Utils.str_to_dur(a.timeout) / 1000000000
        if not a.no_empty:
            if is_true(getenv("DOPPLER_NO_EMPTY")):
                a.no_empty = True
        if nes(a.input):
            p = a.input.strip()
            if p == "-" and not stdin.isatty():
                if hasattr(stdin, "buffer"):
                    a.input = stdin.buffer.read().decode("UTF-8").split("\n")
                else:
                    a.input = stdin.read().split("\n")
                stdin.close()
            else:
                with open(expandvars(expanduser(p))) as f:
                    a.input = f.read().split("\n")
            del p

    def _setup(self):
        self.add("-a", "--api", type=str, dest="cirrus", default=getenv("DOPPLER_HOST"))
        self.add("-p", "--password", type=str, dest="pw", default=getenv("DOPPLER_PW"))
        # List Arguments
        self.add("-j", "--jobs", action="store_true", dest="list_jobs")
        self.add("-s", "--scripts", action="store_true", dest="list_scripts")
        self.add("-n", "--profiles", action="store_true", dest="list_profiles")
        self.add("-l", "--listeners", action="store_true", dest="list_listeners")
        self.add("-b", "--bolts", action="store_true", dest="list_bolts")
        self.add("-B", "--bolts-adv", action="store_true", dest="list_bolts_adv")
        # Execution Arguments
        self.add("-c", "--cmd", type=str, dest="cmd")
        self.add("-w", "--timeout", type=str, dest="timeout")
        # CLI Modification Arguments
        self.add("-z", "--input", type=str, dest="input")
        self.add("-k", "--oneline", type=str, dest="oneline")
        self.add("-i", "--interact", action="store_true", dest="shell")
        self.add("-N", "--no-empty", action="store_true", dest="no_empty")

        self.add(nargs="*", type=str, dest="extra")

    def print_help(self, file=stderr):
        print(_HELP_TEXT.format(proc=argv[0]), file=file)

    def parse_args(self, args=None, namespace=None):
        r = super(__class__, self).parse_args(args, namespace)
        _Parser._verify(r)
        return r


def _main():
    p = _Parser()
    try:
        r = p.parse_args()
    except (OSError, ValueError) as err:
        print(f"Error: {str(err)}!", file=stderr)
        exit(1)
    del p
    try:
        d = Doppler(r.cirrus, r.pw)
    except (OSError, ValueError) as err:
        print(f"Error: {str(err)}!", file=stderr)
        exit(1)
    try:
        if r.list_jobs:
            return d.show_jobs(all=True, exp=Exp.parse(r.extra))
        if r.list_scripts:
            return d.show_scripts(r.extra)
        if r.list_profiles:
            return d.show_profiles(r.extra)
        if r.list_listeners:
            return d.show_listeners(r.extra)
        if r.list_bolts or r.list_bolts_adv:
            return d.show_sessions(advanced=r.list_bolts_adv, exp=Exp.parse(r.extra))
        s = Shell(d, r.no_empty)
        if nes(r.cmd):
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
        if nes(r.oneline):
            if ";" in r.oneline:
                for i in r.oneline.split(";"):
                    if len(i) == 0:
                        continue
                    s.run_cmd(i.lstrip(), True, True, False, False)
                return
            return s.run_cmd(r.oneline, True, True, False, False)
        if r.shell and nes(r.extra):
            s.set_menu(MENU_BOLT, r.extra)
        s.enter()
    except (OSError, ValueError, CirrusError) as err:
        print(f"Error: {str(err)}!")
        exit(1)
    finally:
        d.close()
        del r, d


if __name__ == "__main__":
    _main()

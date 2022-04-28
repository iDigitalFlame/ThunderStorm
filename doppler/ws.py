#!/usr/bin/python3

from base64 import b64encode
from json import loads, dumps
from datetime import datetime
from include.cirrus import Api
from queue import Queue, Empty
from traceback import format_exc
from include.config import Config
from threading import Thread, Event
from argparse import ArgumentParser
from include.cli import Shell, Exp, print_job_result
from include.util import nes, size_str, time_str, ip_str


_UPDATE_NAMES = [
    "job_delete",
    "session_delete",
    "profile_delete",
    "profile_update",
    "listener_update",
    "listener_delete",
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
    del h
    del t


class Doppler(Api):
    def __init__(self, base_url, password=None):
        Api.__init__(self, base_url, password=password)
        self.watch = dict()
        self.eventer = None
        self.events = Queue()

    def close(self):
        if self.eventer.is_alive():
            print("[-] Shutting down..")
        self.eventer.close()
        self.events.put(None, block=False)
        super(__class__, self).close()
        print("[-] Close Complete.")

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
        del v
        if not nes(n) or not nes(a):
            del n
            del a
            del z
            return
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
        if a == "job_new" or a == "profile_new":
            return self.events.put(_Event(action=a, id=n))
        if a == "job_update" and isinstance(z, int) and z > 0 and z < 0xFFFF:
            return self.events.put(_Event(action=a, msg=f"{n}: Accepted Job {z}", id=n))
        if a == "job_complete" and isinstance(z, int) and z > 0 and z < 0xFFFF:
            return self.events.put(_Event(action=a, id=n, job=z))
        if a == "job_receiving" and isinstance(z, int) and z > 0 and z < 0xFFFF:
            return self.events.put(
                _Event(action=a, msg=f"{n}: Receiving Job {z}", id=n)
            )
        if a in _UPDATE_NAMES:
            return self.events.put(_Event(action=a))
        del a
        del n
        del z

    def single(self, timeout=None):
        self._start(False)
        try:
            while True:
                n = self.events.get(block=True, timeout=timeout)
                if n is None:
                    break
                if nes(n.msg):
                    print(f"[-] {n.msg}.")
                    continue
                self.job_display(n.id, n.job)
                del n
                break
        except Empty:
            print("[!] Timeout was reached.")
        except KeyboardInterrupt:
            pass
        self.close()

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
        del t
        del e

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
            raise KeyError()
        self.watch[s] = (out, args)
        del s
        print(f"[+] {id}: Queued Job {job}")

    def job_display(self, id, job, shell=False):
        if not nes(id) or not isinstance(job, int) or job < 1 or job > 0xFFFF:
            return
        v = id + ":" + str(job)
        if v not in self.watch:
            del v
            return
        a = self.watch[v]
        if shell:
            print()
        print_job_result(
            id, job, super(__class__, self).job_result(id, job), a[1], a[0]
        )
        del v
        del a

    def start(self, do_eventer=True, events=None):
        if do_eventer:
            self.eventer = _Thread(self, events)
            self.eventer.start()
        self.start_events(self._on_event)

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
        print(f'{"Name":16}{"Profile":16}{"Bind Address":24}# Bolts\n{"="*65}')
        for k, v in n.items():
            print(f'{k:16}{v["profile_name"]:16}', end="")
            if "type" in v:
                print(f'{v["listener"]["type"]:24}{v["listener"]["count"]}')
            else:
                print(f'{v["listener"]["address"]:24}{v["listener"]["count"]}')
        del n

    def show_result(self, id, job, out=None):
        r = super(__class__, self).job_result(id, job)
        if not isinstance(r, dict):
            return
        print_job_result(id, job, r, None, out)
        del r

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
        del p
        del n

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
                del v
                del o
                del u
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
        del t
        del e

    def task_io_touch(self, id, path):
        self._watch(id, super(__class__, self).task_io_touch(id, path), f"touch {path}")

    def task_pull(self, id, url, dest):
        self._watch(id, super(__class__, self).task_pull(id, url, dest), f"pull {url}")

    def task_profile(self, id, profile):
        self._watch(
            id, super(__class__, self).task_profile(id, profile), f"profile {profile}"
        )

    def task_io_copy(self, id, src, dst):
        self._watch(
            id, super(__class__, self).task_io_copy(id, src, dst), f"copy {src} {dst}"
        )

    def task_io_move(self, id, src, dst):
        self._watch(
            id, super(__class__, self).task_io_move(id, src, dst), f"move {src} {dst}"
        )

    def task_download(self, id, target, dest=None):
        self._watch(
            id,
            super(__class__, self).task_download(id, target),
            f"download {target}",
            dest,
        )

    def task_io_delete(self, id, path, force=False):
        self._watch(
            id, super(__class__, self).task_io_delete(id, path, force), f"delete {path}"
        )

    def task_io_kill(self, id, pid=None, name=None):
        self._watch(
            id,
            super(__class__, self).task_io_kill(id, pid, name),
            f"kill {str(pid) if not nes(name) else name}",
        )

    def task_upload(self, id, target, dest, raw=None):
        self._watch(
            id,
            super(__class__, self).task_upload(id, target, dest, raw),
            f"upload {target}",
        )

    def task_system(self, id, cmd, out=None, filter=None):
        self._watch(id, super(__class__, self).task_system(id, cmd, filter), cmd, out)

    def task_execute(self, id, cmd, show=False, detach=False, filter=None):
        self._watch(
            id, super(__class__, self).task_execute(id, cmd, show, detach, filter), cmd
        )

    def task_pull_exec(self, id, url, show=False, detach=False, filter=None):
        self._watch(
            id,
            super(__class__, self).task_pull_exec(id, url, show, detach, filter),
            f"pull_ex {url}",
        )

    def task_assembly(self, id, file, raw=None, show=False, detach=False, filter=None):
        self._watch(
            id,
            super(__class__, self).task_assembly(id, file, raw, show, detach, filter),
            f"asm {file}",
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
        name,
        method=None,
        profile=None,
        exec=None,
        show=False,
        filter=None,
    ):
        self._watch(
            id,
            super(__class__, self).task_spawn(
                id, name, method, profile, exec, show, filter
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
    ):
        self._watch(
            id,
            super(__class__, self).task_zombie(
                id, file, fake_args, raw, show, detach, filter
            ),
            f"zombie {file}",
        )

    def task_migrate(
        self,
        id,
        name,
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
                id, name, method, profile, exec, show, filter, wait
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
                print(format_exc(3))

    def close(self):
        self._running.set()
        self._api.events.put(None)


class _Parser(ArgumentParser):
    pass


if __name__ == "__main__":
    Shell(Doppler("", "")).enter()

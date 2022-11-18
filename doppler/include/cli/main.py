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

from include.util import nes
from include.cli.helpers import is_valid_name, make_menu, complete_with_all
from include.cli.const import (
    EMPTY,
    MENU_BOLT,
    MENU_BOLTS,
    MENU_SCRIPT,
    MENU_SCRIPTS,
    MENU_PROFILE,
    MENU_PROFILES,
    MENU_BOLT_ALL,
    HELP_MAIN_LS,
    MENU_LISTENER,
    MENU_LISTENERS,
)

_MENU = [
    "bolt",
    "bolts",
    "exit",
    "help",
    "job",
    "jobs",
    "listener",
    "listeners",
    "profile",
    "profiles",
    "script",
    "scripts",
]


class MenuMain(object):
    __slots__ = ("shell",)

    def __init__(self, shell):
        self.shell = shell

    def do_ls(self, _):
        print(HELP_MAIN_LS)

    def do_jobs(self, id):
        if is_valid_name(id, 7):
            return self.shell.cirrus.show_jobs(id, all=False)
        if len(id) > 0:
            return
        return self.shell.cirrus.show_jobs(all=True)

    def do_bolts(self, _):
        self.shell.set_menu(MENU_BOLTS)

    def do_script(self, n):
        if len(n) == 0:
            return self.shell.set_menu(MENU_SCRIPTS)
        if not is_valid_name(n, 1, True):
            return print("script <name>")
        try:
            self.shell.cirrus.script(n)
        except ValueError:
            return print(f'[!] Script "{n}" does not exist!')
        self.shell.set_menu(MENU_SCRIPT, n.lower())

    def do_scripts(self, _):
        self.shell.set_menu(MENU_SCRIPTS)

    def do_profile(self, n):
        if len(n) == 0:
            return self.shell.set_menu(MENU_PROFILES)
        if not is_valid_name(n, 1, True):
            return print("profile <name>")
        try:
            self.shell.cirrus.profile(n)
        except ValueError:
            return print(f'[!] Profile "{n}" does not exist!')
        self.shell.set_menu(MENU_PROFILE, n.lower())

    def do_profiles(self, _):
        self.shell.set_menu(MENU_PROFILES)

    def do_bolt(self, id, f):
        if not nes(id) and not nes(f):
            return self.shell.set_menu(MENU_BOLTS)
        if not nes(id) or (len(id) != 3 and len(id) < 8):
            return print("bolt <id|all>")
        if id == "all":
            return self.shell.set_menu(MENU_BOLT_ALL, f)
        if not is_valid_name(id, 7):
            return print("bolt <id|all>")
        try:
            self.shell.cirrus.session(id)
        except ValueError:
            return print(f'[!] Bolt "{id}" does not exist!')
        self.shell.set_menu(MENU_BOLT, id.upper())

    def do_listener(self, n):
        if len(n) == 0:
            return self.shell.set_menu(MENU_LISTENERS)
        if not is_valid_name(n, 1, True):
            return print("listener <name>")
        try:
            self.shell.cirrus.listener(n)
        except ValueError:
            return print(f'[!] Listener "{n}" does not exist!')
        self.shell.set_menu(MENU_LISTENER, n.lower())

    def do_listeners(self, _):
        self.shell.set_menu(MENU_LISTENERS)

    def do_job(self, id, job):
        if not is_valid_name(id, 7):
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
        return " > "

    def complete_bolt(self, n, *_):
        return complete_with_all(self.shell.cache.bolts(n), n)

    def completenames(self, n, *_):
        return make_menu(n, _MENU)

    def complete_script(self, n, *_):
        return self.shell.cache.scripts(n)

    def complete_profile(self, n, *_):
        return self.shell.cache.profiles(n)

    def complete_listener(self, n, *_):
        return self.shell.cache.listeners(n)

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

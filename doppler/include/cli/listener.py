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

from json import dumps
from base64 import b64decode
from include.config import Config
from include.util import nes, do_ask, print_hash
from include.cli.parser import PARSERS, PARSER_LISTENER
from include.cli.helpers import is_valid_name, complete_with_all, make_menu
from include.cli.const import (
    EMPTY,
    MENU_BOLTS,
    MENU_SCRIPTS,
    MENU_PROFILE,
    MENU_PROFILES,
    MENU_LISTENER,
    MENU_LISTENERS,
)

_MENU_LISTENER = [
    "back",
    "delete",
    "exit",
    "help",
    "info",
    "main",
    "noscript",
    "profile",
    "pubkey",
    "pubkey_full",
    "replace",
    "script",
    "update",
]
_MENU_LISTENERS = [
    "back",
    "bolts",
    "delete",
    "exit",
    "help",
    "info",
    "ls",
    "main",
    "new",
    "profile",
    "profiles",
    "pubkey",
    "pubkey_full",
    "replace",
    "scripts",
    "update",
]


def _print_listener_info(v):
    c = Config(b64decode(v["profile"], validate=True))
    print(
        f'Listener: {v["listener"]["name"]}\n{"="*30}\nProfile : {v["profile_name"]} ({c})'
    )
    print(dumps(c.json(), sort_keys=False, indent=4))
    del c
    print(f'Address : {v["listener"]["address"]}')
    if "type" in v["listener"]:
        print(f'Type    : {v["listener"]["type"]}')
    print(f'Bolts   : {v["listener"]["count"]}')
    print(f'Script  : {v["script"]}')


class MenuListener(object):
    __slots__ = ("name", "shell", "quick_back")

    def __init__(self, shell):
        self.name = None
        self.shell = shell
        self.quick_back = True

    def do_back(self, _):
        self.shell.set_menu(MENU_LISTENERS)

    def do_info(self, _):
        _print_listener_info(self.shell.cirrus.listener(self.name))

    def do_script(self, n):
        if len(n) == 0:
            r = self.shell.cirrus.listener(self.name)
            if "script" not in r or not nes(r["script"]):
                print("No Connect Script is set.")
            else:
                print(f'Connect Script is {r["script"]}')
            del r
            return
        if n == "-c":
            self.shell.cirrus.listener_update_script(self.name, "")
            return print(f'[+] Cleared Connect Script for "{self.name}".')
        self.shell.cirrus.listener_update_script(self.name, n)
        print(f'[+] Set Connect Script for "{self.name}" to "{n}".')

    def do_delete(self, _):
        if not do_ask(f'Confirm deletion of Listener "{self.name}"'):
            return print("[-] Aborting delete!")
        self.shell.cirrus.listener_remove(self.name)
        self.shell.cache._listeners = None
        print(f'[+] Deleted Listener "{self.name}".')
        self.shell.set_menu(MENU_LISTENERS)

    def do_pubkey(self, a):
        try:
            k, h = self.shell.cirrus.server_public_key()
            if k is None:
                return print("The Server has no associated Public Key.")
            if len(a) > 0:
                del h
                return print(k)
            print_hash(k, h)
            del k, h
        except (ValueError, TypeError) as err:
            print(f"[!] {err}!")

    def do_profile(self, _):
        r = self.shell.cirrus.listener(self.name)
        if "profile_name" not in r:
            return print(
                f'[!] Listener "{self.name}" does not have an associated Profile!'
            )
        self.shell.cirrus.profile(r["profile_name"])
        self.shell.set_menu(MENU_PROFILE, r["profile_name"])
        del r

    def do_noscript(self, _):
        try:
            self.shell.cirrus.listener_update_script(self.name, "")
            print(f'[+] Cleared Connect Script for "{self.name}".')
        except ValueError as err:
            print(f"[!] {err}!")

    def do_pubkey_full(self, _):
        self.do_pubkey(".")

    def prompt(self, args=None):
        self.name = args
        return f" > Listener > {args} > "

    def completenames(self, n, *_):
        return make_menu(n, _MENU_LISTENER)

    def do_update(self, a, profile):
        self._upgrade("update", a, profile)

    def do_replace(self, a, profile):
        self._upgrade("replace", a, profile)

    def complete_script(self, n, *_):
        return self.shell.cache.scripts(n)

    def complete_update(self, n, c, *_):
        return self.complete_replace(n, c, _)

    def complete_replace(self, n, c, *_):
        if c.count(" ") == 2:
            return self.shell.cache.profiles(n)
        return EMPTY

    def _upgrade(self, name, address, profile):
        if not nes(address):
            return print(f"{name} <address> [profile]")
        r = self.shell.cirrus.listener_update(self.name, address, profile)
        c = Config(b64decode(r["profile"], validate=True))
        print(f'[+] Listener "{self.name}" @ {r["listener"]["address"]} ({c}) updated!')
        del r, c


class MenuListeners(object):
    __slots__ = ("shell", "quick_back")

    def __init__(self, shell):
        self.shell = shell
        self.quick_back = True

    def do_ls(self, _):
        self.shell.cirrus.show_listeners()

    def do_new(self, *a):
        if len(a) == 0:
            return print("new [-s|--script script] <name> <address> <profile>")
        r = PARSERS[PARSER_LISTENER].parse_args(a)
        if not nes(r.name) or not nes(r.address) or not nes(r.profile):
            return print("new [-s|--script script] <name> <address> <profile>")
        o = self.shell.cirrus.listener_add(r.name, r.address, r.profile, r.script)
        c = Config(b64decode(o["profile"], validate=True))
        print(f'[+] Listener "{r.name}" @ {o["listener"]["address"]} ({c}) created!')
        del r, o, c
        self.shell.cache._listeners = None

    def default(self, n):
        if not is_valid_name(n, 1, True):
            return
        try:
            self.shell.cirrus.listener(n)
        except ValueError:
            return print(f'[!] Listener "{n}" does not exist!')
        self.shell.set_menu(MENU_LISTENER, n.lower())

    def do_info(self, n):
        if len(n) == 0:
            return print("info <name|all>")
        try:
            if n != "all":
                return _print_listener_info(self.shell.cirrus.listener(n))
            for v in self.shell.cirrus.listeners().values():
                _print_listener_info(v)
        except ValueError:
            print(f'[!] Listener "{n}" does not exist!')

    def do_bolts(self, _):
        self.shell.set_menu(MENU_BOLTS)

    def do_pubkey(self, a):
        try:
            k, h = self.shell.cirrus.server_public_key()
            if k is None:
                return print("The Server has no associated Public Key.")
            if len(a) > 0:
                del h
                return print(k)
            print_hash(k, h)
            del k, h
        except (ValueError, TypeError) as err:
            print(f"[!] {err}!")

    def do_delete(self, n):
        if len(n) == 0:
            return print("delete <name|all>")
        if n == "all":
            if not do_ask("Confirm deletion of ALL Listeners"):
                return print("[-] Aborting delete!")
            for e in self.shell.cirrus.listeners():
                self.shell.cirrus.listener_remove(e["name"])
            print("[+] All Listeners deleted.")
        else:
            if not do_ask(f'Confirm deletion of Listener "{n}"'):
                return print("[-] Aborting delete!")
            self.shell.cirrus.listener_remove(n)
            print(f"[+] Deleted Listener {n}.")
        self.shell.cache._listeners = None

    def do_profile(self, n):
        if len(n) == 0:
            return print("profile <name>")
        r = self.shell.cirrus.listener(n)
        if "profile_name" not in r:
            return print(f'[!] Listener "{n}" does not have an associated Profile!')
        self.shell.cirrus.profile(r["profile_name"])
        self.shell.set_menu(MENU_PROFILE, r["profile_name"])
        del r

    def do_update(self, *a):
        self._upgrade("update", a)

    def do_scripts(self, _):
        self.shell.set_menu(MENU_SCRIPTS)

    def do_profiles(self, _):
        self.shell.set_menu(MENU_PROFILES)

    def do_replace(self, *a):
        self._upgrade("replace", a)

    def do_pubkey_full(self, _):
        self.do_pubkey(".")

    def prompt(self, args=None):
        return " > Listeners > "

    def _upgrade(self, name, a):
        if len(a) == 0:
            return print(f"{name} [-s|--script script] <name> <address> [profile]")
        r = PARSERS[PARSER_LISTENER].parse_args(a)
        if not nes(r.name):
            return print(f"{name} [-s|--script script] <name> <address> [profile]")
        if not r.no_script and r.script is None and not nes(r.address):
            return print(f"{name} [-s|--script script] <name> <address> [profile]")
        if r.script is None and r.no_script:
            r.script = ""
        o = self.shell.cirrus.listener_update(r.name, r.address, r.profile, r.script)
        c = Config(b64decode(o["profile"], validate=True))
        print(f'[+] Listener "{r.name}" @ {o["listener"]["address"]} ({c}) updated!')
        del r, o, c

    def completenames(self, n, *_):
        return make_menu(n, _MENU_LISTENERS + self.shell.cache.listeners(n))

    def complete_info(self, n, *_):
        return complete_with_all(self.shell.cache.listeners(n), n)

    def complete_new(self, n, c, *_):
        if len(c) < 3:
            return EMPTY
        if c[-3:] == "-s " or (len(c) > 9 and c[-9:] == "--script "):
            return self.shell.cache.scripts(n)
        if " -s " in c or " --sc" in c:
            if c.count(" ") == 5:
                return self.shell.cache.profiles(n)
            return EMPTY
        if c.count(" ") == 3:
            return self.shell.cache.profiles(n)
        return EMPTY

    def complete_delete(self, n, *_):
        return complete_with_all(self.shell.cache.listeners(n), n)

    def complete_profile(self, n, *_):
        return self.shell.cache.listeners(n)

    def complete_update(self, n, c, *_):
        return self.complete_replace(n, c, _)

    def complete_replace(self, n, c, *_):
        if c.count(" ") == 1:
            return self.shell.cache.listeners(n)
        if len(c) < 3:
            return EMPTY
        if c[-3:] == "-s " or (len(c) > 9 and c[-9:] == "--script "):
            return self.shell.cache.scripts(n)
        if " -s " in c or " --sc" in c:
            if c.count(" ") == 5:
                return self.shell.cache.profiles(n)
            return EMPTY
        if c.count(" ") == 3:
            return self.shell.cache.profiles(n)
        return EMPTY

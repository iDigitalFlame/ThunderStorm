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
from base64 import b64encode
from include.util import nes, do_ask
from os.path import expanduser, expandvars
from include.cli.helpers import is_valid_name, complete_with_all, make_menu
from include.cli.const import (
    EMPTY,
    MENU_BOLTS,
    MENU_SCRIPTS,
    MENU_PROFILE,
    MENU_PROFILES,
    MENU_LISTENERS,
)

_MENU_PROFILE = [
    "back",
    "base64",
    "bin",
    "delete",
    "edit",
    "exit",
    "export",
    "help",
    "info",
    "json",
    "main",
    "replace",
    "update",
]
_MENU_PROFILES = [
    "back",
    "base64",
    "bin",
    "bolts",
    "delete",
    "edit",
    "exit",
    "export",
    "help",
    "import",
    "info",
    "json",
    "listeners",
    "ls",
    "main",
    "new",
    "replace",
    "scripts",
    "update",
]


class MenuProfile(object):
    __slots__ = ("name", "shell", "quick_back")

    def __init__(self, shell):
        self.name = None
        self.shell = shell
        self.quick_back = True

    def do_bin(self, _):
        self.shell.cirrus.show_profile(self.name, as_bytes=True)

    def do_back(self, _):
        self.shell.set_menu(MENU_PROFILES)

    def do_json(self, _):
        print(
            dumps(
                self.shell.cirrus.profile(self.name).json(), sort_keys=False, indent=4
            )
        )

    def do_info(self, _):
        self.shell.cirrus.show_profile(self.name)

    def do_edit(self, _):
        # TODO(dij): Work on
        print("Come back later..")

    def do_delete(self, _):
        self.shell.cirrus.profile_remove(self.name)
        self.shell.cache._profiles = None
        print(f'[+] Deleted Profile "{self.name}".')
        self.shell.set_menu(MENU_PROFILES)

    def do_base64(self, _):
        print(b64encode(self.shell.cirrus.profile(self.name)).decode("UTF-8"))

    def do_update(self, d):
        if len(d) == 0:
            return print("update <file|base64|json>")
        try:
            self.shell.cirrus.profile_build_update(self.name, d)
        except (OSError, ValueError) as err:
            return print(f"[!] {err}!")
        print(f'[+] Updated Profile "{self.name}".')

    def do_replace(self, d):
        self.do_update(d)

    def do_export(self, file):
        try:
            p = self.shell.cirrus.profile(self.name)
            if not nes(file):
                return print(b64encode(p).decode("UTF-8"))
            with open(expanduser(expandvars(file)), "wb") as f:
                f.write(p)
            print(f'[+] Exported Profile "{self.name}" to "{file}".')
            del p
        except (ValueError, OSError) as err:
            print(f"[!] {err}!")

    def prompt(self, args=None):
        self.name = args
        return f" > Profiles > {args} > "

    def completenames(self, n, *_):
        return make_menu(n, _MENU_PROFILE)


class MenuProfiles(object):
    __slots__ = ("shell", "quick_back")

    def __init__(self, shell):
        self.shell = shell
        self.quick_back = True

    def do_ls(self, _):
        self.shell.cirrus.show_profiles()

    def do_bin(self, n):
        if len(n) == 0:
            return print("bin <name>")
        self.shell.cirrus.show_profile(n, as_bytes=True)

    def do_new(self, n):
        # if len(n) == 0:
        #    return print("new <name>")
        # TODO(dij): Work on
        #            Could probably pipe the args into this from cfg-builder?
        print("Come back later..")
        # self.shell.cache._profiles = None

    def default(self, n):
        if not is_valid_name(n, 1):
            return
        try:
            self.shell.cirrus.profile(n)
        except ValueError:
            return print(f'[!] Profile "{n}" does not exist!')
        self.shell.set_menu(MENU_PROFILE, n.lower())

    def do_edit(self, n):
        # if len(n) == 0:
        #    return print("edit <name>")
        # TODO(dij): Work on
        #            Could probally pipe the args into this from cfg-builder?
        print("Come back later..")

    def do_json(self, n):
        if len(n) == 0:
            return print("json <name|all>")
        if n != "all":
            return print(
                dumps(self.shell.cirrus.profile(n).json(), sort_keys=False, indent=4)
            )
        for k, p in self.shell.cirrus.profiles().items():
            print(f"{k}\n{dumps(p.json(), sort_keys=False)}")

    def do_info(self, n):
        if len(n) == 0:
            return print("info <name|all>")
        if n != "all":
            return self.shell.cirrus.show_profile(n)
        e = list(self.shell.cirrus.profiles().keys())
        for x in range(0, len(e)):
            if x > 0:
                print()
            self.shell.cirrus.show_profile(e[x])
        del e

    def do_bolts(self, _):
        self.shell.set_menu(MENU_BOLTS)

    def do_delete(self, n):
        if len(n) == 0:
            return print("delete <name|all>")
        if n == "all":
            if not do_ask("Confirm deletion of ALL Profiles"):
                return print("[-] Aborting delete!")
            for e in self.shell.cirrus.profiles().keys():
                self.shell.cirrus.profile_remove(e)
            print("[+] All Profiles deleted!")
        else:
            self.shell.cirrus.profile_remove(n)
            print(f'[+] Deleted Profile "{n}".')
        self.shell.cache._profiles = None

    def do_base64(self, n):
        if len(n) == 0:
            return print("base64 <name|all>")
        if n != "all":
            return print(b64encode(self.shell.cirrus.profile(n)).decode("UTF-8"))
        for k, p in self.shell.cirrus.profiles().items():
            print(f'{k + ":":<21}{b64encode(p).decode("UTF-8")}')

    def do_scipts(self, _):
        self.shell.set_menu(MENU_SCRIPTS)

    def do_listeners(self, _):
        self.shell.set_menu(MENU_LISTENERS)

    def prompt(self, args=None):
        return " > Profiles > "

    def do_export(self, n, file):
        if not nes(n):
            return print("export <name> [file]")
        try:
            p = self.shell.cirrus.profile(n)
            if not nes(file):
                return print(b64encode(p).decode("UTF-8"))
            with open(expanduser(expandvars(file)), "wb") as f:
                f.write(p)
            print(f'[+] Exported Profile "{n}" to "{file}".')
            del p
        except (ValueError, OSError) as err:
            print(f"[!] {err}!")

    def do_import(self, n, data):
        if not nes(n) or not nes(data):
            return print("import <name> <file|base64|json>")
        try:
            self.shell.cirrus.profile_build_add(n, data)
        except (OSError, ValueError) as err:
            return print(f"[!] {err}!")
        self.shell.cache._profiles = None
        print(f'[+] Imported Profile "{n}"!')

    def do_update(self, n, data):
        if not nes(n) or not nes(data):
            return print("update <name> <file|base64|json>")
        try:
            self.shell.cirrus.profile_build_update(n, data)
        except (OSError, ValueError) as err:
            return print(f"[!] {err}!")
        print(f'[+] Updated Profile "{n}".')

    def do_replace(self, n, data):
        self.do_update(n, data)

    def complete_bin(self, n, *_):
        return self.shell.cache.profiles(n)

    def completenames(self, n, *_):
        return make_menu(n, _MENU_PROFILES + self.shell.cache.profiles(n))

    def complete_edit(self, n, *_):
        return self.shell.cache.profiles(n)

    def complete_json(self, n, *_):
        return complete_with_all(self.shell.cache.profiles(n), n)

    def complete_info(self, n, *_):
        return complete_with_all(self.shell.cache.profiles(n), n)

    def complete_base64(self, n, *_):
        return complete_with_all(self.shell.cache.profiles(n), n)

    def complete_delete(self, n, *_):
        return complete_with_all(self.shell.cache.profiles(n), n)

    def complete_export(self, n, c, *_):
        if c.count(" ") == 1:
            return self.shell.cache.profiles(n)
        return EMPTY

    def complete_update(self, n, c, *_):
        if c.count(" ") == 1:
            return self.shell.cache.profiles(n)
        return EMPTY

    def complete_replace(self, n, c, *_):
        if c.count(" ") == 1:
            return self.shell.cache.profiles(n)
        return EMPTY

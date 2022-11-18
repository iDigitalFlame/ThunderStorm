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

from threading import Lock
from string import whitespace
from include.cli.bolt import _MENU, MenuBolt
from include.util import nes, do_ask, is_true
from include.cli.parser import PARSERS, PARSER_NETCAT
from include.cli.helpers import is_valid_name, complete_with_all, make_menu
from include.cli.const import (
    EMPTY,
    HELP_DATA,
    MENU_BOLTS,
    HELP_STRVAL,
    HELP_SCRIPT,
    MENU_SCRIPT,
    MENU_SCRIPTS,
    MENU_PROFILES,
    MENU_LISTENERS,
)

_MENU_SCRIPT = [
    "history",
    "return_output",
    "rollback",
    "stop_on_error",
    "undo",
    "wait",
] + _MENU
_MENU_SCRIPTS = [
    "back",
    "bolts",
    "copy",
    "delete",
    "export",
    "help",
    "history",
    "import",
    "info",
    "listeners",
    "ls",
    "main",
    "new",
    "profiles",
    "rename",
    "return_output",
    "rollback",
    "stop_on_error",
    "update",
]


class MenuScripts(object):
    __slots__ = ("shell", "quick_back")

    def __init__(self, shell):
        self.shell = shell
        self.quick_back = True

    def do_ls(self, _):
        self.shell.cirrus.show_scripts()

    def do_new(self, n):
        self.shell.cirrus.script_add(n)
        self.shell.cache._scripts = None
        print(f"[+] Script {n} created.")

    def do_info(self, n):
        if len(n) == 0:
            return print("info <script>|all")
        if n != "all":
            return self.shell.cirrus.show_script_info(n)
        for i in self.shell.cirrus.scripts().keys():
            self.shell.cirrus.show_script_info(i)
            print()

    def default(self, n):
        if not is_valid_name(n, 1, True):
            return
        try:
            self.shell.cirrus.script(n)
        except ValueError:
            return print(f'[!] Script "{n}" does not exist!')
        self.shell.set_menu(MENU_SCRIPT, n.lower())

    def do_bolts(self, _):
        self.shell.set_menu(MENU_BOLTS)

    def do_delete(self, n):
        if len(n) == 0:
            return print("delete <name>|all")
        if n == "all" and not do_ask("Confirm delete of ALL Scripts"):
            return print("[-] Aborting delete!")
        if n == "all":
            for e in self.shell.cirrus.scripts().keys():
                self.shell.cirrus.script_remove(e)
            print("[+] Deleted all Scripts.")
        else:
            self.shell.cirrus.script_remove(n)
            print(f'[+] Deleted Script "{n}".')
        self.shell.cache._scripts = None

    def do_history(self, n):
        if len(n) == 0:
            return print("history <script>")
        self.shell.cirrus.show_script_history(n)

    def do_profiles(self, _):
        self.shell.set_menu(MENU_PROFILES)

    def do_copy(self, n, new):
        if not nes(n) or not nes(new):
            return print("copy <script> <new_name>")
        self.shell.cirrus.script_duplicate(n, new)
        self.shell.cache._scripts = None
        print(f'[+] Copied Script "{n}" to "{new}".')

    def do_listeners(self, _):
        self.shell.set_menu(MENU_LISTENERS)

    def prompt(self, args=None):
        return " > Scripts > "

    def do_rename(self, n, new):
        if not nes(n) or not nes(new):
            return print("rename <script> <new_name>")
        self.shell.cirrus.script_rename(n, new)
        self.shell.cache._scripts = None
        print(f'[+] Renamed Script "{n}" to "{new}".')

    def do_import(self, n, file):
        if not nes(n) or not nes(file):
            return print("import <script> <file>")
        try:
            self.shell.cirrus.script_import(n, file)
        except (OSError, ValueError) as err:
            return print(f"[!] {err}")
        self.shell.cache._scripts = None
        print(f'[+] Imported Script "{n}" from "{file}".')

    def do_update(self, n, file):
        if not nes(n) or not nes(file):
            return print("update <script> <file>")
        try:
            self.shell.cirrus.script_replace(n, file)
        except (OSError, ValueError) as err:
            return print(f"[!] {err}")
        print(f'[+] Updated Script "{n}" from "{file}".')

    def do_export(self, n, file):
        if not nes(n):
            return print("export <script> [file]")
        try:
            self.shell.cirrus.script_export(n, file)
        except (OSError, ValueError) as err:
            return print(f"[!] {err}")
        if not nes(file):
            return
        print(f'[+] Exported Script "{n}" to "{file}".')

    def do_rollback(self, n, pos):
        p = None
        if nes(n):
            try:
                p = int(pos)
            except ValueError:
                return print("rollback <script> [number]")
        r = self.shell.cirrus.script_rollback(n, p)
        del p
        print(f'[+] Rolled Script "{n}" to "{r["rollbacks"]}".')
        del r

    def completenames(self, n, *_):
        return make_menu(n, _MENU_SCRIPTS + self.shell.cache.scripts(n))

    def complete_info(self, n, *_):
        return complete_with_all(self.shell.cache.scripts(n), n)

    def complete_delete(self, n, *_):
        return complete_with_all(self.shell.cache.scripts(n), n)

    def complete_update(self, n, *_):
        return self.shell.cache.scripts(n)

    def do_return_output(self, n, v):
        self._get_set_setting(n, "Return Output", "return_output", "output", v)

    def do_stop_on_error(self, n, v):
        self._get_set_setting(n, "Stop on Error", "stop_on_error", "stop_on_error", v)

    def complete_copy(self, n, c, *_):
        if c.count(" ") > 1:
            return EMPTY
        return self.shell.cache.scripts(n)

    def complete_history(self, n, *_):
        return self.shell.cache.scripts(n)

    def complete_export(self, n, c, *_):
        if c.count(" ") > 1:
            return EMPTY
        return self.shell.cache.scripts(n)

    def complete_rename(self, n, c, *_):
        if c.count(" ") > 1:
            return EMPTY
        return self.shell.cache.scripts(n)

    def complete_rollback(self, n, c, *_):
        if c.count(" ") > 1:
            return EMPTY
        return self.shell.cache.scripts(n)

    def _get_set_setting(self, i, n, a, p, v):
        if not nes(v):
            r = self.shell.cirrus.script(i)
            if r is None or a not in r:
                print(f"{i}: {n} == False")
            else:
                print(f"{i}: {n} == {str(r[a]).title()}")
            del r
            return
        b = is_true(v)
        self.shell.cirrus.script_update(i, **{p: b})
        print(f'[+] Updated Script "{i}" set "{n}" to "{str(b).title()}"')
        del n

    def complete_return_output(self, n, c, *_):
        if c.count(" ") > 1:
            return EMPTY
        return self.shell.cache.scripts(n)

    def complete_stop_on_error(self, n, c, *_):
        if c.count(" ") > 1:
            return EMPTY
        return self.shell.cache.scripts(n)


class MenuScript(MenuBolt):
    __slots__ = ("line", "name", "args", "lock", "show_line")

    def __init__(self, shell):
        MenuBolt.__init__(self, shell)
        self.line = None
        self.name = None
        self.args = dict()
        self.lock = Lock()
        self.show_line = True
        self._setup()

    def _setup(self):
        d = vars(self.__class__)
        for i in dir(self):
            if not i.startswith("do_"):
                continue
            if i in d:
                c = getattr(self, i).__code__.co_argcount - 1
                if c == 0:  # Catch varargs functions
                    continue
                self.args[i] = c
                del c
                continue
            try:
                f = getattr(self, i)
            except AttributeError:
                continue
            setattr(self, i, self._wrap_func(f))
        del d

    def default(self, c):
        if self.shell.no_default_run:
            return
        self._do_exec(super(__class__, self).do_run, c, c)

    def do_back(self, _):
        self.shell.set_menu(MENU_SCRIPTS)

    def _exec(self, f, **a):
        if not isinstance(a, dict):
            a = dict()
        k = getattr(self.shell.cirrus, "script" + f.__name__[4:])
        if "out" in a:
            del a["out"]
        if (
            k.__name__ == "script_download" or k.__name__ == "script_netcat"
        ) and "dest" in a:
            del a["dest"]
        try:
            r = k(self.name, self.line, **a)
        except (ValueError, TypeError) as err:
            return print(f"[!] {err}!")
        del a
        self._set_prompt(r)
        del r

    def _wrap_func(self, f):
        self.args[f.__name__] = f.__code__.co_argcount

        def _func(*a, line=None):
            self._do_exec(f, a, line)

        return _func

    def _set_prompt(self, r):
        if r is None or "rollbacks" not in r:
            self.shell.prompt = f" > Scripts > {self.name}#? > "
            return
        self.shell.prompt = f' > Scripts > {self.name}#{r["rollbacks"]} > '

    def arg_count(self, name):
        if name in self.args:
            return self.args[name]
        return None

    def _add_note(self, line):
        self._set_prompt(self.shell.cirrus.script_note(self.name, line))

    def complete_job(self, *_):
        return EMPTY

    def prompt(self, args=None):
        self.name = args
        print(HELP_SCRIPT.format(script=self.name))
        print("Default execution is ", end="")
        if self.shell.no_default_run:
            print(
                'disabled. Execution can only occur with "run", "hup", "shell" or "pwsh".'
            )
        else:
            print("enabled.")
        # NOTE(dij): Not sure if we should catch a ValueError here?
        #            What could we do if it happens? If it does, ugh thats bad.
        #
        # UPDATE:    The built in handler will grab it, and prevent entering this
        #            section, (ie: we'd never leave the previous menu).
        r = self.shell.cirrus.script(self.name)
        if r is None or "rollbacks" not in r:
            return f" > Scripts > {self.name}#? > "
        return f' > Scripts > {self.name}#{r["rollbacks"]} > '

    def do_cat(self, f, line=None):
        self._do_exec(super(__class__, self).do_download, [f, None], line)

    def _do_exec(self, f, a, line):
        self.lock.acquire(True)
        self.line = line
        try:
            if isinstance(a, str):
                return f(a)
            if a is None:
                return f(None)
            if len(a) == 1 and f.__code__.co_argcount <= 2:
                return f(a[0])
            return f(*a)
        finally:
            self.line = None
            self.lock.release()

    def completenames(self, n, *_):
        return make_menu(n, _MENU_SCRIPT)

    def do_nc(self, *a, line=None):
        r = PARSERS[PARSER_NETCAT].parse_args(a, cat=" ")
        if r is not None and nes(r.output):
            print(f'The output value "{r.output}" will be omitted when executed.')
        self._do_exec(super(__class__, self).do_nc, a, line)

    def do_job(self, _, line=None):
        print("Not available inside a Script.")

    def do_wait(self, d, line=None):
        """
        wait <duration>

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Wait will indicate the script to pause for the time period given. This
        allows for adding a "pause" in any scripts.

        The default duration is parsed as seconds, however the "s", "m" or "h"
        suffixes may be specified to suggest seconds, minutes and hours respectively.

        Examples:
            wait 10
            wait 1m
        """
        if not nes(d):
            return print("wait <duration>")
        self._do_exec(super(__class__, self)._system, [f"wait {d}"], line)

    def do_info(self, _, line=None):
        self.shell.cirrus.show_script_info(self.name)

    def do_help(self, n, line=None):
        if len(n) == 0 or n == "help":
            return print("help <command>")
        if n == "data":
            return print(HELP_DATA)
        if n == "strval":
            return print(HELP_STRVAL)
        try:
            d = getattr(self, "do_" + n).__doc__
        except AttributeError:
            return print(f'[!] Help text for "{n}" not found.')
        if d is None:
            try:
                d = getattr(super(__class__, self), "do_" + n).__doc__
            except AttributeError:
                pass
        if d is None:
            return print(f'[!] Help text for "{n}" not found.')
        for i in d.strip().split("\n"):
            print(i.lstrip(whitespace))
        del d

    def do_undo(self, n, line=None):
        """
        undo [steps to undo]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        Undo is used to undo commands entered in the scripting interface. If
        nothing is specific as an argument, undo will undo the last command entered.
        Otherwise undo will attempt to rollback to the specified index.

        Undo is an alias of "rollback".

        Examples:
            undo
            undo 2
            undo 0 # Rollback to the start
        """
        self.do_rollback(n, line)

    def do_jobs(self, _, line=None):
        print("Not available inside a Script.")

    def do_last(self, _, line=None):
        print("Not available inside a Script.")

    def do_sleep(self, v, line=None):
        if len(v) == 0:
            return print("sleep <duration>")
        self._do_exec(super(__class__, self).do_sleep, v, line)

    def do_jitter(self, v, line=None):
        if len(v) == 0:
            return print("jitter <percentage %>")
        self._do_exec(super(__class__, self).do_jitter, v, line)

    def do_script(self, _, line=None):
        print("Cannot call a Script from inside a Script.")

    def do_creds(self, *a, line=None):
        if not super(__class__, self).do_creds(a):
            return
        self._add_note(line)

    def do_history(self, _, line=None):
        """
        history

        History will output the list of commands entered to this script and will
        list the index of each command.
        """
        r = self.shell.cirrus.script(self.name)
        if r is None or "commands" not in r:
            return
        v = r["commands"]
        for x in range(0, len(v)):
            print(f"{x:3}: {v[x]}")
        del v, r

    def do_parent(self, *a, line=None):
        if not super(__class__, self).do_parent(a):
            return
        self._add_note(line)

    def do_loginas(self, *a, line=None):
        self._do_exec(super(__class__, self).do_make_token, a, line)

    def do_mktoken(self, *a, line=None):
        self._do_exec(super(__class__, self).do_make_token, a, line)

    def do_killdate(self, v, line=None):
        if len(v) == 0:
            return print("killdate <date/time>")
        self._do_exec(super(__class__, self).do_killdate, v, line)

    def do_set_hide(self, v, line=None):
        if not super(__class__, self).do_set_hide(v):
            return
        self._add_note(line)

    def do_rollback(self, n, line=None):
        """
        rollback [steps to rollback]

        OS:    Any
        OPsec: n/a
        Admin: n/a

        rollback is used to undo commands entered in the scripting interface. If
        nothing is specific as an argument, undo will undo the last command entered.
        Otherwise undo will attempt to rollback to the specified index.

        Examples:
            rollback
            rollback 2
            rollback 0 # Rollback to the start
        """
        p = None
        if nes(n):
            try:
                p = int(n)
            except ValueError:
                return print("rollback [number]")
        r = self.shell.cirrus.script_rollback(self.name, p)
        del p
        print(f'[+] Rolled Script "{self.name}" to "{r["rollbacks"]}".')
        self._set_prompt(r)
        del r

    def do_zerotrace(self, _, line=None):
        self._do_exec(super(__class__, self).do_evade, "patch_etw", line)

    def do_workhours(self, *a, line=None):
        if len(a) == 0:
            return print("workhours [-d <SMTWRFS>] [-s <HH:MM>] [-e <HH:MM>]")
        self._do_exec(super(__class__, self).do_workhours, a, line)

    def do_parent_pid(self, v, line=None):
        if not super(__class__, self).do_parent_pid(v):
            return
        self._add_note(line)

    def do_parent_name(self, v, line=None):
        if not super(__class__, self).do_parent_name(v):
            return
        self._add_note(line)

    def do_download(self, f, p, line=None):
        if nes(p):
            print(f'The output value "{p}" will be omitted when executed.')
        self._do_exec(super(__class__, self).do_download, [f, None], line)

    def _get_set_setting(self, n, a, p, v):
        if not nes(v):
            r = self.shell.cirrus.script(self.name)
            if r is None or a not in r:
                print(f"{n}: False")
            else:
                print(f"{n}: {str(r[a]).title()}")
            del r
            return
        b = is_true(v)
        self.shell.cirrus.script_update(self.name, **{p: b})
        print(f"[+] Set {n}: {str(b).title()}")
        del b

    def do_parent_clear(self, _, line=None):
        if not super(__class__, self).do_parent_clear(_):
            return
        self._add_note(line)

    def do_return_output(self, v, line=None):
        """
        return_output [boolean]

        The return_output command can be used to get or set the "return_output"
        value of this script, which specifies if command output is returned once
        the script completes.

        To get the current setting, use "return_output" without any arguments.
        To set the setting, any boolean value or boolean-ish value may be used to
        set the value.

        Examples:
            return_output
            return_output false
            return_output yes
        """
        self._get_set_setting("Return Output", "return_output", "output", v)

    def do_stop_on_error(self, v, line=None):
        """
        stop_on_error [boolean]

        The stop_on_error command can be used to get or set the "stop_on_error"
        value of this script, which specifies if the script should continue execution
        if one of it's commands errors out.

        To get the current setting, use "stop_on_error" without any arguments.
        To set the setting, any boolean value or boolean-ish value may be used to
        set the value.

        Examples:
            stop_on_error
            stop_on_error false
            stop_on_error yes
        """
        self._get_set_setting("Stop on Error", "stop_on_error", "stop_on_error", v)

    def do_parent_desktop(self, v, line=None):
        if not super(__class__, self).do_parent_desktop(v):
            return
        self._add_note(line)

    def do_parent_include(self, v, line=None):
        if not super(__class__, self).do_parent_include(v):
            return
        self._add_note(line)

    def do_parent_exclude(self, v, line=None):
        if not super(__class__, self).do_parent_exclude(v):
            return
        self._add_note(line)

    def do_parent_elevated(self, v, line=None):
        if not super(__class__, self).do_parent_elevated(v):
            return
        self._add_note(line)

    def do_parent_fallback(self, v, line=None):
        if not super(__class__, self).do_parent_fallback(v):
            return
        self._add_note(line)

    def _system(self, c, filter=None, out=None):
        if nes(out):
            print(f'The output value "{out}" will be omitted when executed.')
        return super(__class__, self)._system(c, filter, None)

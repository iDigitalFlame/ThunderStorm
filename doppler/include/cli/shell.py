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

from cmd import Cmd
from shlex import shlex
from os import getcwd, getenv
from traceback import format_exc
from importlib import import_module
from include.util import nes, ip_str
from sys import stdin, stdout, stderr
from subprocess import run, SubprocessError
from os.path import expanduser, expandvars, devnull, isdir, join
from include.cli.const import (
    MENU_INTRO,
    EMPTY,
    HELP_TEXT,
    MENU_MAIN,
    MENU_BOLT,
    MENU_BOLT_ALL,
)
from readline import (
    get_begidx,
    get_endidx,
    clear_history,
    get_completer,
    set_completer,
    parse_and_bind,
    get_line_buffer,
    get_history_item,
    read_history_file,
    write_history_file,
    set_history_length,
    remove_history_item,
    replace_history_item,
    set_completer_delims,
    get_completer_delims,
    get_current_history_length,
)

from include.cli.main import MenuMain
from include.cli.bolt import MenuBolt
from include.cli.bolts import MenuBolts, MenuBoltAll
from include.cli.script import MenuScripts, MenuScript
from include.cli.profile import MenuProfiles, MenuProfile
from include.cli.listener import MenuListeners, MenuListener

_MENUS = [
    [None, MenuMain],
    [None, MenuBolts],
    [None, MenuBolt],
    [None, MenuBoltAll],
    [None, MenuProfiles],
    [None, MenuProfile],
    [None, MenuListeners],
    [None, MenuListener],
    [None, MenuScripts],
    [None, MenuScript],
]


def _shell_split(v):
    z = shlex(v, punctuation_chars=True)
    z.commenters = ""
    z.wordchars += ":;|$&!@%^()[]{}\\<>,+"
    v = list(z)
    del z
    if len(v) <= 2:
        return v
    # NOTE(dij): Remove '"' when supplied in the string since 9/10 we are using
    #            a string with a space. However, we won't strip single quotes (')
    #            so users can override this behavior.
    #
    #            Checks for >2 to ignore long commands
    for x in range(0, len(v)):
        if len(v[x]) == 0 or v[x][0] != '"' or v[x][-1] != '"':
            continue
        v[x] = v[x][1:-1]
    return v


def _run_print_stdout(c):
    try:
        v = run(c, text=True, shell=True, check=False, capture_output=True)
    except (SubprocessError, OSError) as err:
        return print(f"[!] {err}!")
    if nes(v.stdout):
        print(v.stdout, end="")
        if v.stdout[-1] != "\n":
            print()
    if nes(v.stderr):
        print(v.stderr, end="")
        if v.stderr[-1] != "\n":
            print()
    del v


class Shell(Cmd):
    __slots__ = (
        "dll",
        "asm",
        "pipe",
        "cache",
        "_init",
        "_state",
        "cirrus",
        "_module",
        "_history",
        "_old_delims",
        "no_default_run",
    )

    def __init__(self, cirrus, config=None):
        Cmd.__init__(self, stdin=stdin, stdout=stdout, completekey="tab")
        self._state = 0
        self._init = False
        self.cirrus = cirrus
        self.asm = config.asm
        self.dll = config.dll
        self.pipe = config.pipe
        self._old_delims = None
        self.cache = _Cache(cirrus)
        self.no_default_run = config.no_empty
        self._module = import_module(__name__)
        self._history = ""
        self.set_menu(0)

    def enter(self):
        self.init()
        try:
            self.cmdloop(MENU_INTRO)
        except KeyboardInterrupt:
            print()
        except Exception as err:
            print(
                f"\n[!] {err.__class__.__name__} {err}\n{format_exc(3)}",
                file=stderr,
            )
        self.close()

    def close(self):
        if self._history != devnull:
            try:
                write_history_file(self._history)
            except OSError:
                pass
        self.cirrus.close()

    def _on_main(self):
        return self._menu is None or isinstance(self._menu, MenuMain)

    def _backable(self):
        return (
            not self._on_main()
            and hasattr(self._menu, "quick_back")
            and self._menu.quick_back
        )

    def onecmd(self, n):
        self.run_cmd(n, True, True, True, True)

    def emptyline(self):
        return None

    def do_exit(self, _):
        raise EOFError()

    def do_help(self, _):
        if self._state > len(HELP_TEXT):
            return
        print(HELP_TEXT[self._state])

    def default(self, cmd):
        return None

    def init(self, single=False):
        if self._init:
            return
        try:
            if single:
                self.cirrus.start(False)
            else:
                self.cirrus.start(True, events=self._on_event)
        except (KeyboardInterrupt, ValueError) as err:
            self.cirrus.close()
            raise err
        except Exception as err:
            self.cirrus.close()
            return print(
                f"\n[!] {err.__class__.__name__} {err}\n{format_exc(3)}",
                file=stderr,
            )
        if single:
            self._init = True
            return
        self._history = getenv("DOPPLER_HISTFILE")
        if not nes(self._history):
            c = getenv("XDG_CACHE_HOME")
            if not nes(c):
                c = expanduser("~/.cache")
            if not isdir(c):
                c = getcwd()
            self._history = join(c, "doppler.history")
            del c
        else:
            self._history = expandvars(expanduser(self._history))
        if self._history != devnull:
            try:
                read_history_file(self._history)
            except (OSError, ValueError):
                pass
        set_history_length(400)
        if not self.cirrus.alive():
            print(
                "[!] WARNING Eventer is not active, Cirrus may be down or not reachable.."
            )
        self._init = True

    def complete(self, text, s):
        if s == 0:
            v = get_line_buffer()
            o = v.lstrip()
            i = len(v) - len(o)
            del v
            x = get_begidx() - i
            e = get_endidx() - i
            del i
            if x <= 0:
                f = self._complete_func(x, "")
            else:
                c, _, _ = self.parseline(o)
                f = self._complete_func(x, c)
                del c
            self.completion_matches = f(text, o, x, e)
            del f, o, x, e
        try:
            return self.completion_matches[s]
        except IndexError:
            return None

    def completedefault(self, *_):
        return EMPTY

    def cmdloop(self, intro=None):
        self.preloop()
        if self.completekey:
            self.old_completer = get_completer()
            set_completer(self.complete)
            parse_and_bind(self.completekey + ": complete")
        self._old_delims = get_completer_delims()
        set_completer_delims(self._old_delims.replace("-", "", 1))
        try:
            if intro is not None:
                self.intro = intro
            if self.intro and self._state == 0:
                self.stdout.write(str(self.intro) + "\n")
            s, o = None, False
            while not s:
                try:
                    if self.cmdqueue:
                        n = self.cmdqueue.pop(0)
                    else:
                        n, o = input(self.prompt), False
                    n = n.strip()
                    s = self.postcmd(self.onecmd(n), self.precmd(n))
                    del n
                except EOFError:
                    print()
                    break
                except KeyboardInterrupt as err:
                    print()
                    if nes(get_line_buffer()):
                        o = False
                        continue
                    if not self._on_main():
                        if not hasattr(self._menu, "do_back"):
                            self.set_menu(MENU_MAIN)
                            continue
                        self._menu.do_back(None)
                        continue
                    if o:
                        raise err
                    o = True
                    print(
                        'Ctrl-C pressed. (Press Ctrl-C again, type "exit" or press Ctrl-D to exit)',
                        file=self.stdout,
                    )
            del s, o
            self.postloop()
        finally:
            if self.completekey:
                set_completer(self.old_completer)
            set_completer_delims(self._old_delims)

    def _complete_func(self, b, cmd):
        if b <= 0:
            if self._menu is None:
                return self.completenames
            try:
                f = getattr(self._menu, "completenames")
                if callable(f):
                    return f
                del f
            except AttributeError:
                pass
            return self.completenames
        if len(cmd) > 0 and self._menu is not None:
            try:
                f = getattr(self._menu, "complete_" + cmd)
                if callable(f):
                    return f
                del f
            except AttributeError:
                pass
            try:
                f = getattr(self._menu, "completedefault")
                if callable(f):
                    return f
                del f
            except AttributeError:
                pass
        elif self._menu is not None:
            try:
                f = getattr(self._menu, "completedefault")
                if callable(f):
                    return f
                del f
            except AttributeError:
                pass
        try:
            f = getattr(self, "complete_" + cmd)
            if callable(f):
                return f
            del f
        except AttributeError:
            pass
        return self.completedefault

    def set_menu(self, index, args=None):
        m = _MENUS[index]
        if m[0] is None:
            m[0] = m[1](self)
        self._menu, self._state = m[0], index
        self.prompt = self._menu.prompt(args)
        del m

    def _on_event(self, a, id, msg, job):
        if a == "job_new" or a == "job_delete":
            if self.cache._jobs is not None and id in self.cache._jobs:
                del self.cache._jobs[id]
            return
        if a == "profile_new" or a == "profile_delete" or a == "profile_update":
            self.cache._profiles = None
            return
        if a == "listener_new" or a == "listener_update" or a == "listener_delete":
            self.cache._listeners = None
            return
        if a == "session_new":
            if self._state != MENU_BOLT:
                try:
                    s = self.cirrus.session(id)
                    print(
                        f"\nNew Bolt Registered: [{id}] "
                        f'{("*" if s["device"]["elevated"] else "") + s["device"]["user"]}'
                        f" @ {ip_str(s)}"
                    )
                    del s
                except ValueError:
                    print(f"\n[*] {msg}", end="")
            self.cache._bolts = None
            if self.cache._jobs is not None and id in self.cache._jobs:
                del self.cache._jobs[id]
            return
        if a == "session_delete":
            if self._state == MENU_BOLT and self._menu.id == id:
                print(f"\n[*] {id}: This Bolt was removed or shutdown.")
            self.cache._bolts, self.cache._jobs = None, None
            return
        if self._state == MENU_BOLT:
            if self._menu.id != id:
                return
            if a == "job_receiving" or a == "job_update" or a == "session_update":
                return print(f"\n[*] {msg}")
            if a == "job_complete":
                self.cirrus.job_display(id, job, True)
            return
        # NOTE(dij): Disabling for now as it can get spammy.
        # if a == "packet_new" and self._state != MENU_BOLT_ALL:
        #     return print(f"\n[*] {msg}")
        if self._state != MENU_BOLT_ALL:
            return
        if a == "job_receiving" or a == "job_update" or a == "session_update":
            return print(f"\n[*] {msg}")
        if a == "job_complete" and self._menu.results:
            return self.cirrus.job_display(id, job, True, True)

    def run_cmd(self, n, can_back, can_main, can_run, can_hist):
        c, a, n = self.parseline(n)
        if not nes(n):
            return self.emptyline()
        if c is None:
            if len(n) > 1 and n[0] == "!":
                if not can_run:
                    return print("[!] Not allowed to run commands!")
                return _run_print_stdout(n[1:])
            if can_back and self._backable():
                if hasattr(self._menu, "do_back"):
                    return self._menu.do_back(None)
                return self.set_menu(MENU_MAIN)
            if not self._on_main():
                try:
                    return self._menu.default(n)
                except AttributeError:
                    pass
            return self.default(n)
        if c == "":
            if len(n) == 1 and n[0] == "@":
                if not can_hist:
                    return print("[!] Not allowed to run history commands!")
                for x in range(1, get_current_history_length()):
                    v = get_history_item(x)
                    if v is None:
                        continue
                    print(f"{x:3}: {v}")
                    del v
                return remove_history_item(get_current_history_length() - 1)
            if len(n) == 6 and n == "@clear":
                if not can_hist:
                    return print("[!] Not allowed to run history commands!")
                return clear_history()
            if len(n) > 1 and n[0] == "@":
                if not can_hist:
                    return print("[!] Not allowed to run history commands!")
                try:
                    v = int(n[1:])
                except ValueError:
                    y = n[1:].lower()
                    for x in range(1, get_current_history_length()):
                        u = get_history_item(x)
                        if u is None or (nes(u) and not u.lower().startswith(y)):
                            continue
                        print(f"{x:3}: {u}")
                    del y
                    return
                try:
                    x = get_history_item(v)
                except IndexError:
                    return print("[!] Non-existent history index!")
                finally:
                    if not nes(x):
                        remove_history_item(get_current_history_length() - 1)
                    else:
                        replace_history_item(get_current_history_length() - 1, x)
                if not nes(x):
                    return print("[!] Invalid history index!")
                if x[0] == "@" or x[0] == "!":
                    return
                del v
                print(f"Running: {x}")
                return self.run_cmd(x, True, True, False, False)
            if a == ".." and can_back and self._backable():
                if not hasattr(self._menu, "do_back"):
                    return self.set_menu(MENU_MAIN)
                return self._menu.do_back(None)
            if a == "\\" and can_main and self._backable():
                return self.set_menu(MENU_MAIN)
            if self._menu is not None:
                try:
                    return self._menu.default(n)
                except AttributeError:
                    pass
                except ValueError as err:
                    return print(f"[!] {err}!")
            try:
                return self.default(n)
            except ValueError as err:
                return print(f"[!] {err}!")
        if (
            c == "main"
            and can_main
            and not self._on_main()
            and not hasattr(self._menu, "do_main")
        ):
            return self.set_menu(MENU_MAIN)
        if (
            c == "back"
            and can_back
            and not self._on_main()
            and not hasattr(self._menu, "do_back")
        ):
            return self.set_menu(MENU_MAIN)
        if c == "exit" and can_main and not hasattr(self._menu, "do_exit"):
            return self.do_exit(None)
        if c == "help" and not hasattr(self._menu, "do_help"):
            return self.do_help(None)
        if n == "EOF":
            self.lastcmd = ""
        else:
            self.lastcmd = n
        try:
            if self._menu is not None:
                f = getattr(self._menu, "do_" + c)
            else:
                f = getattr(self, "do_" + c)
        except AttributeError:
            if self._menu is not None:
                try:
                    return self._menu.default(n)
                except AttributeError:
                    pass
                except ValueError as err:
                    return print(f"[!] {err}!")
            try:
                return self.default(n)
            except ValueError as err:
                return print(f"[!] {err}!")
        y = False
        if self._menu is not None:
            try:
                y = getattr(self._menu, "show_line") is not None
            except AttributeError:
                y = False
        if y and self._menu is not None:
            try:
                u, k = getattr(self._menu, "arg_count"), None
                if callable(u):
                    k = u("do_" + c)
                if k is None:
                    k = f.__code__.co_argcount
                del u
            except AttributeError:
                k = f.__code__.co_argcount
        else:
            k = f.__code__.co_argcount
        del c
        if k == 1:
            try:
                v = _shell_split(a)
            except ValueError:
                try:
                    if y:
                        return f(a, line=n)
                    return f(a)
                except ValueError as err:
                    return print(f"[!] {err}!")
            try:
                if y:
                    return f(*v, line=n)
                return f(*v)
            except ValueError as err:
                return print(f"[!] {err}!")
        if k <= 2:
            try:
                if y:
                    return f(a, line=n)
                return f(a)
            except ValueError as err:
                return print(f"[!] {err}!")
        try:
            v = _shell_split(a)
        except ValueError:
            try:
                if y:
                    return f(a, line=n)
                return f(a)
            except ValueError as err:
                return print(f"[!] {err}!")
        if len(v) == k - 1:
            try:
                if y:
                    return f(*v, line=n)
                return f(*v)
            except ValueError as err:
                return print(f"[!] {err}!")
        i = [None] * (k - 1)
        for x in range(0, len(v)):
            if x >= len(i) or x >= len(v):
                break
            i[x] = v[x]
        if len(v) > len(i):
            i[-1] = " ".join(v[len(i) - 1 :])
        del v
        try:
            if y:
                return f(*i, line=n)
            return f(*i)
        except ValueError as err:
            return print(f"[!] {err}!")


class _Cache(object):
    __slots__ = ("_jobs", "_bolts", "_scripts", "cirrus", "_profiles", "_listeners")

    def __init__(self, cirrus):
        self._jobs = None
        self._bolts = None
        self._scripts = None
        self.cirrus = cirrus
        self._profiles = None
        self._listeners = None

    def bolts(self, n):
        if self._bolts is None:
            self._bolts = [i["id"].upper() for i in self.cirrus.sessions()]
        if nes(n) and len(self._bolts) > 0:
            n, r = n.upper(), list()
            for e in self._bolts:
                if e.startswith(n):
                    r.append(e)
            return r
        return self._bolts

    def scripts(self, n):
        if self._scripts is None:
            self._scripts = [i.lower() for i in self.cirrus.scripts().keys()]
        if nes(n) and len(self._scripts) > 0:
            n, r = n.lower(), list()
            for e in self._scripts:
                if e.startswith(n):
                    r.append(e)
            return r
        return self._scripts

    def profiles(self, n):
        if self._profiles is None:
            self._profiles = [i.lower() for i in self.cirrus.profiles().keys()]
        if nes(n) and len(self._profiles) > 0:
            n, r = n.lower(), list()
            for e in self._profiles:
                if e.startswith(n):
                    r.append(e)
            return r
        return self._profiles

    def listeners(self, n):
        if self._listeners is None:
            self._listeners = [i.lower() for i in self.cirrus.listeners().keys()]
        if nes(n) and len(self._listeners) > 0:
            n, r = n.lower(), list()
            for e in self._listeners:
                if e.startswith(n):
                    r.append(e)
            return r
        return self._listeners

    def jobs(self, s, n, v=True):
        if v:
            if not nes(s):
                return EMPTY
            r = self.bolts(s)
            if s.upper() not in r:
                return r
            del r
        if self._jobs is None:
            self._jobs = dict()
        if s not in self._jobs:
            self._jobs[s] = list(self.cirrus.jobs(s).keys())
        if nes(n) and isinstance(self._jobs[s], list) and len(self._jobs[s]) > 0:
            r = list()
            for e in self._jobs[s]:
                if e.startswith(n):
                    r.append(e)
            return r
        return self._jobs[s]

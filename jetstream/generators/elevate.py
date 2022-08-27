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

from os.path import join
from include.util import nes
from include.builder import random_chars
from argparse import BooleanOptionalAction
from include.manager import Manager, is_str

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

  Behavior Arguments
   -A                 <service_name>  |
   --service-name
   -K
   --critical
"""


class Elevate(object):
    __slots__ = ("_m",)

    def __init__(self):
        self._m = Manager("elevate")

    def args_help(self):
        return _HELP_TEXT

    def check(self, cfg):
        self._m.verify(cfg)

    def config_load(self, cfg):
        self._m.add("pipe", ("-P", "--pipe"), "", is_str(False, min=5), str)
        self._m.add("client", ("-X", "--client"), False, action=BooleanOptionalAction)
        self._m.add("service_name", ("-A", "--service-name"), "", is_str(True), str)
        self._m.add("func", ("-F", "--func"), "", is_str(True, ft=True), str)
        self._m.add("thread", ("-T", "--thread"), "", is_str(True, ft=True), str)
        self._m.add(
            "critical", ("-K", "--critical"), False, action=BooleanOptionalAction
        )
        self._m.init(cfg)

    def args_pre(self, parser):
        self._m.prep(parser)

    def args_post(self, cfg, args):
        self._m.parse(cfg, args)

    def print_options(self, cfg, root, file):
        return

    def run(self, cfg, base, workspace, templates):
        p = join(base, "bolt.go")
        t = "elevate_server.go"
        if cfg["client"]:
            t = "elevate_client.go"
        with open(p, "w") as f:
            f.write(
                templates[t].substitute(
                    pipe=cfg["pipe"],
                    service=cfg["service_name"],
                    critical="true"
                    if cfg["critical"] and not workspace["library"]
                    else "false",
                )
            )
        del t
        return p

    def run_cgo(self, export, cfg, base, workspace, templates):
        t = "bolt.c"
        if workspace["library"]:
            if nes(cfg["service_name"]):
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

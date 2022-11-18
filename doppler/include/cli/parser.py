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


from argparse import REMAINDER
from include.util import Parser
from argparse import BooleanOptionalAction as Boolean

PARSER_RM = 0x0
PARSER_ASM = 0x1
PARSER_DEX = 0x2
PARSER_DLL = 0x3
PARSER_CREDS = 0x4
PARSER_RUNAS = 0x5
PARSER_SPAWN = 0x6
PARSER_PARENT = 0x7
PARSER_ZOMBIE = 0x8
PARSER_PULL = 0x9
PARSER_REGEDIT = 0xA
PARSER_RUN = 0xB
PARSER_PROXY = 0xC
PARSER_LISTENER = 0xD
PARSER_NETCAT = 0xE
PARSER_WTS = 0xF
PARSER_CHECK = 0x10
PARSER_POWER = 0x11
PARSER_FUNCMAP = 0x12
PARSER_WORKHOURS = 0x13


def __parsers():
    # Parsers Generator
    #  Basics
    #  - All Domain args are -d/--domain
    #  - All Username args are -u/--user
    #    - Username MUST parse domain if domain empty/nil
    #  - All Password args are -p/--pass
    #  - All Profile args are -n/--profile
    #  - All Detach args are -x/--detach
    p = [None] * (PARSER_WORKHOURS + 1)
    # rm
    # eq    = True
    p[PARSER_RM] = Parser()
    p[PARSER_RM].add("-f", "--force", dest="force", action="store_true")
    p[PARSER_RM].add(nargs=1, type=str, dest="path")
    # asm
    # eq    = False
    p[PARSER_ASM] = Parser()
    p[PARSER_ASM].add("-e", "--entry", type=str, dest="entry")
    p[PARSER_ASM].add("-x", "--detach", dest="detach", action="store_true")
    p[PARSER_ASM].add(nargs=1, type=str, dest="data")
    # dex
    # eq    = True
    p[PARSER_DEX] = Parser()
    p[PARSER_DEX].add("-a", "--agent", type=str, dest="agent")
    p[PARSER_DEX].add("-x", "--detach", dest="detach", action="store_true")
    p[PARSER_DEX].add(nargs=1, type=str, dest="url")
    # dll
    p[PARSER_DLL] = Parser()
    p[PARSER_DLL].add("-e", "--entry", type=str, dest="entry")
    p[PARSER_DLL].add("-x", "--detach", dest="detach", action="store_true")
    p[PARSER_DLL].add("-r", "--reflect", dest="reflect", action="store_true")
    p[PARSER_DLL].add(nargs=1, type=str, dest="data")
    # creds, make_token, loginas
    # nones = True (False for make_token)
    p[PARSER_CREDS] = Parser()
    p[PARSER_CREDS].add("-d", "--domain", type=str, dest="domain")
    p[PARSER_CREDS].add("-c", "--clear", dest="clear", action="store_true")
    p[PARSER_CREDS].add("-i", "--interactive", dest="interactive", action="store_true")
    p[PARSER_CREDS].add(nargs=1, type=str, dest="user")
    p[PARSER_CREDS].add(nargs=1, type=str, dest="pw")
    # runas
    # cat   = " "
    # nones = False
    p[PARSER_RUNAS] = Parser()
    p[PARSER_RUNAS].add("-d", "--domain", type=str, dest="domain")
    p[PARSER_RUNAS].add("-x", "--detach", dest="detach", action="store_true")
    p[PARSER_RUNAS].add(nargs=1, type=str, dest="user")
    p[PARSER_RUNAS].add(nargs=1, type=str, dest="pw")
    p[PARSER_RUNAS].add(nargs=REMAINDER, type=str, dest="cmd")
    # migrate, spawn
    p[PARSER_SPAWN] = Parser()
    p[PARSER_SPAWN].add("-f", "--args", type=str, dest="args")
    p[PARSER_SPAWN].add("-u", "--user", type=str, dest="user")
    p[PARSER_SPAWN].add("-p", "--password", type=str, dest="pw")
    p[PARSER_SPAWN].add("-a", "--agent", type=str, dest="agent")
    p[PARSER_SPAWN].add("-e", "--entry", type=str, dest="entry")
    p[PARSER_SPAWN].add("-d", "--domain", type=str, dest="domain")
    p[PARSER_SPAWN].add("-t", "--target", type=str, dest="target")
    p[PARSER_SPAWN].add("-m", "--method", type=str, dest="method")
    p[PARSER_SPAWN].add("-n", "--profile", type=str, dest="profile")
    p[PARSER_SPAWN].add("-z", "--no-auto", dest="no_auto", action="store_true")
    p[PARSER_SPAWN].add("-R", "--no-reflect", dest="reflect", action="store_false")
    p[PARSER_SPAWN].add(nargs=1, type=str, dest="pipe")
    p[PARSER_SPAWN].add(nargs=1, type=str, dest="data")
    # parent
    p[PARSER_PARENT] = Parser()
    p[PARSER_PARENT].add("-p", "--pid", type=int, dest="pid")
    p[PARSER_PARENT].add("-D", dest="no_desktop", action="store_false")
    p[PARSER_PARENT].add("-F", dest="no_fallback", action="store_false")
    p[PARSER_PARENT].add("-A", "-E", dest="no_admin", action="store_false")
    p[PARSER_PARENT].add("-d", "--desktop", dest="desktop", action=Boolean)
    p[PARSER_PARENT].add("-c", "--clear", dest="clear", action="store_true")
    p[PARSER_PARENT].add("-x", "--exclude", dest="exclude", action="append")
    p[PARSER_PARENT].add("-f", "--fallback", dest="fallback", action=Boolean)
    p[PARSER_PARENT].add(
        "-a", "-e", "--admin", "--elevated", dest="admin", action=Boolean
    )
    p[PARSER_PARENT].add(nargs=REMAINDER, type=str, dest="include")
    # zombie
    # cat   = " "
    p[PARSER_ZOMBIE] = Parser()
    p[PARSER_ZOMBIE].add("-u", "--user", type=str, dest="user")
    p[PARSER_ZOMBIE].add("-e", "--entry", type=str, dest="entry")
    p[PARSER_ZOMBIE].add("-p", "--password", type=str, dest="pw")
    p[PARSER_ZOMBIE].add("-d", "--domain", type=str, dest="domain")
    p[PARSER_ZOMBIE].add("-x", "--detach", dest="detach", action="store_true")
    p[PARSER_ZOMBIE].add(nargs=1, type=str, dest="data")
    p[PARSER_ZOMBIE].add(nargs=REMAINDER, type=str, dest="args")
    # pull
    # eq    = True
    p[PARSER_PULL] = Parser()
    p[PARSER_PULL].add("-a", "--agent", type=str, dest="agent")
    p[PARSER_PULL].add(nargs=1, type=str, dest="url")
    p[PARSER_PULL].add(nargs=1, type=str, dest="file")
    # regedit
    # eq    = True
    p[PARSER_REGEDIT] = Parser()
    p[PARSER_REGEDIT].add("-f", "--force", dest="force", action="store_true")
    p[PARSER_REGEDIT].add(nargs=1, type=str, dest="action")
    p[PARSER_REGEDIT].add(nargs=1, type=str, dest="key")
    p[PARSER_REGEDIT].add(nargs=1, type=str, dest="value")
    p[PARSER_REGEDIT].add(nargs=1, type=str, dest="exp")
    p[PARSER_REGEDIT].add(nargs=1, type=str, dest="data")
    # run, shell, pwsh, hup, pwsh_file
    # cat   = " "
    p[PARSER_RUN] = Parser()
    p[PARSER_RUN].add("-u", "--user", type=str, dest="user")
    p[PARSER_RUN].add("-p", "--password", type=str, dest="pw")
    p[PARSER_RUN].add("-d", "--domain", type=str, dest="domain")
    p[PARSER_RUN].add("-f", "--file", dest="file", action="store_true")
    p[PARSER_RUN].add("-x", "--detach", dest="detach", action="store_true")
    p[PARSER_RUN].add(nargs=REMAINDER, type=str, dest="command")
    # proxy
    # eq    = False
    p[PARSER_PROXY] = Parser()
    p[PARSER_PROXY].add("-r", "--remove", dest="remove", action="store_true")
    p[PARSER_PROXY].add("-u", "--update", dest="update", action="store_true")
    p[PARSER_PROXY].add(nargs=1, type=str, dest="name")
    p[PARSER_PROXY].add(nargs=1, type=str, dest="bind")
    p[PARSER_PROXY].add(nargs=1, type=str, dest="profile")
    # listeners/new
    p[PARSER_LISTENER] = Parser()
    p[PARSER_LISTENER].add("-s", "--script", type=str, dest="script")
    p[PARSER_LISTENER].add("-S", "--no-script", dest="no_script", action="store_true")
    p[PARSER_LISTENER].add(nargs=1, type=str, dest="name")
    p[PARSER_LISTENER].add(nargs=1, type=str, dest="address")
    p[PARSER_LISTENER].add(nargs=1, type=str, dest="profile")
    # nc
    # cat   = " "
    p[PARSER_NETCAT] = Parser()
    p[PARSER_NETCAT].add("-o", "--output", type=str, dest="output")
    p[PARSER_NETCAT].add("-t", "--timeout", type=int, dest="timeout")
    p[PARSER_NETCAT].add("-T", "--tcp", dest="tcp", action="store_true")
    p[PARSER_NETCAT].add("-U", "--udp", dest="udp", action="store_true")
    p[PARSER_NETCAT].add("-S", "--tls", dest="tls", action="store_true")
    p[PARSER_NETCAT].add("-I", "--icmp", dest="icmp", action="store_true")
    p[PARSER_NETCAT].add("-r", "--read", dest="read", action="store_true")
    p[PARSER_NETCAT].add(
        "-X", "--tls-insecure", dest="tls_insecure", action="store_true"
    )
    p[PARSER_NETCAT].add(nargs=1, type=str, dest="host")
    p[PARSER_NETCAT].add(nargs=REMAINDER, type=str, dest="data")
    # wts
    # cat   = " "
    # nones = False
    p[PARSER_WTS] = Parser()
    p[PARSER_WTS].add("-f", "--flags", type=str, dest="flags")
    p[PARSER_WTS].add("-t", "--seconds", type=int, dest="seconds")
    p[PARSER_WTS].add("-w", "--wait", dest="wait", action="store_true")
    p[PARSER_WTS].add(nargs=1, type=str, dest="cmd")
    p[PARSER_WTS].add(nargs=1, type=str, dest="session")
    p[PARSER_WTS].add(nargs=1, type=str, dest="title")
    p[PARSER_WTS].add(nargs=REMAINDER, type=str, dest="text")
    # check/patch
    # nones = False
    p[PARSER_CHECK] = Parser()
    p[PARSER_CHECK].add("-f", "--function", type=str, dest="function")
    p[PARSER_CHECK].add("-r", "--raw", dest="raw", action="store_true")
    p[PARSER_CHECK].add(nargs=1, type=str, dest="dll")
    p[PARSER_CHECK].add(nargs=1, type=str, dest="data")
    # poweroff/reboot
    # cat   = " "
    p[PARSER_POWER] = Parser()
    p[PARSER_POWER].add("-r", "--reason", type=str, dest="reason")
    p[PARSER_POWER].add("-t", "--seconds", type=int, dest="seconds")
    p[PARSER_POWER].add("-f", "--force", dest="force", action="store_true")
    p[PARSER_POWER].add(nargs=REMAINDER, type=str, dest="message")
    # funcmap
    # nones = False
    p[PARSER_FUNCMAP] = Parser()
    p[PARSER_FUNCMAP].add("-r", "--raw", dest="raw", action="store_true")
    p[PARSER_FUNCMAP].add(nargs=1, type=str, dest="action")
    p[PARSER_FUNCMAP].add(nargs=1, type=str, dest="function")
    p[PARSER_FUNCMAP].add(nargs=REMAINDER, type=str, dest="data")
    # workhours
    # nones = False
    p[PARSER_WORKHOURS] = Parser()
    p[PARSER_WORKHOURS].add("-e", "--end", type=str, dest="end")
    p[PARSER_WORKHOURS].add("-d", "--days", type=str, dest="days")
    p[PARSER_WORKHOURS].add("-s", "--start", type=str, dest="start")
    p[PARSER_WORKHOURS].add("-c", "--clear", dest="clear", action="store_true")
    return p


PARSERS = __parsers()

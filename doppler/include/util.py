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

from math import floor
from io import StringIO
from datetime import datetime
from argparse import ArgumentParser

_BOOLEANS = ["1", "on", "t", "true", "y", "yes", "en", "enable"]


def nes(v):
    return isinstance(v, str) and len(v) > 0


def split(v):
    if not nes(v):
        return None
    e = list()
    n = 0
    for x in range(0, len(v)):
        if v[x] == " " or v[x] == ",":
            if x - n == 0:
                n = x + 1
                continue
            e.append(v[n:x].strip())
            n = x + 1
    if len(e) == 0:
        e.append(v.strip())
    elif n < len(v):
        e.append(v[n:].strip())
    del n
    return e


def xor(k, d):
    if len(d) == 0 or len(k) == 0:
        return bytearray()
    r = bytearray(len(d))
    for i in range(0, len(r)):
        r[i] = d[i] ^ k[i % len(k)]
    return r


def do_ask(m):
    try:
        v = input(f"[?] {m}? [Y/n] ")
        if not nes(v) or v.lower() != "y":
            return False
        return True
    except EOFError:
        print()
    except KeyboardInterrupt:
        pass
    return False


def ip_str(s):
    if "network" not in s["device"]:
        return ""
    for i in s["device"]["network"]:
        if "ip" not in i:
            continue
        for n in i["ip"]:
            if n.startswith("127.0.0") or ":" in n:
                continue
            # TODO(dij): We're going to have to address IPv6 addresses here.
            #            they will overflow the Bolt list space, just an annoying
            #            view issue we can fix later.
            # NOTE(dij): Maybe we can compact the IP if it's IPv6? There might
            #            be a python library for it.
            return n
    return ""


def is_true(v):
    if not nes(v):
        return False
    return v.strip().lower() in _BOOLEANS


def perm_str(v):
    if v == 0:
        return "---------"
    b = StringIO()
    if v & (2**31) != 0:
        b.write("d")
    elif v & (2**27) != 0:
        b.write("l")
    elif v & (2**26) != 0:
        b.write("b")
    elif v & (2**25) != 0:
        b.write("p")
    elif v & (2**24) != 0:
        b.write("s")
    elif v & (2**21) != 0:
        b.write("c")
    elif v & (2**19) != 0:
        b.write("I")
    else:
        b.write("-")
    for x in range(8, -1, -1):
        if x % 3 == 2:
            if v & (2**x) == 0:
                b.write("-")
            else:
                b.write("r")
            continue
        if x % 3 == 1:
            if v & (2**x) == 0:
                b.write("-")
            else:
                b.write("w")
            continue
        if v & (2**x) == 0:
            if x == 6 and v & (2**23) != 0:
                if v & (2**31) != 0:
                    b.write("S")
                else:
                    b.write("s")
            elif x == 3 and v & (2**22) != 0:
                if v & (2**31) != 0:
                    b.write("S")
                else:
                    b.write("s")
            elif x == 0 and v & (2**20) != 0:
                b.write("t")
            else:
                b.write("-")
            continue
        if x == 6 and v & (2**23) != 0:
            b.write("S")
        elif x == 3 and v & (2**22) != 0:
            b.write("S")
        elif x == 0 and v & (2**20) != 0:
            b.write("t")
        else:
            b.write("x")
    r = b.getvalue()
    b.close()
    del b
    return r


def split_user_domain(u, d):
    if not nes(u):
        if nes(d):
            raise ValueError("empty user with non-empty domain")
        return "", ""
    if nes(d):
        return u, d
    if "\\" in u:
        i = u.find("\\")
        return u[i + 1 :], u[:i]
    if "/" in u:
        i = u.find("/")
        return u[i + 1 :], u[:i]
    if "@" in u:
        i = u.find("@")
        return u[:i], u[i + 1 :]
    return u, ""


def size_str(v, align=False):
    if v < 1024.0:
        if align:
            return f"{int(v):>5d}b"
        return f"{int(v):d}b"
    v /= 1024.0
    for n in "KMGTPEZ":
        if abs(v) < 1024.0:
            if float(v) == floor(v):
                if align:
                    return f"{int(v):>5d}{n}"
                return f"{int(v):d}{n}"
            if align:
                return f"{float(v):>5.1f}{n}"
            return f"{float(v):.1f}{n}"
        v /= 1024.0
    return f"{float(v):.1f}Y"


def time_str(n, s, exact=False):
    if len(s) == 0:
        return ""
    v = datetime.fromisoformat(s.replace("Z", "")).replace(tzinfo=None)
    if (n - v).days > 0:
        if exact:
            return v.strftime("%H:%M %m/%d/%y")
        return f"~{(n - v).days}d"
    m, n = divmod((n - v).seconds, 60)
    h, m = divmod(m, 60)
    if h > 12:
        return v.strftime("%H:%M")
    del v
    if h > 0:
        return f"{h}h {m}m"
    if m > 0:
        return f"{m}m {n}s"
    return f"{n}s"


class Parser(ArgumentParser):
    def __init__(self):
        ArgumentParser.__init__(
            self,
            prog="",
            usage="",
            epilog="",
            add_help=False,
            description="",
            allow_abbrev=True,
            fromfile_prefix_chars=None,
        )
        self.add = self.add_argument

    def error(self, _):
        pass

    def print_help(Self, _):
        pass

    def print_usage(self, _):
        pass

    def exit(self, _=0, m=None):
        pass

    def parse_args(self, args=None, namespace=None, nones=True, cat=None):
        r = super(__class__, self).parse_args(args, namespace)
        if r is None:
            return r
        for i in r.__dict__.keys():
            try:
                v = getattr(r, i)
                if not isinstance(v, list):
                    continue
                if len(v) == 1:
                    if not nones and v[0] is None:
                        setattr(r, i, "")
                    else:
                        setattr(r, i, v[0])
                    continue
                if len(v) > 0:
                    if nes(cat):
                        setattr(r, i, cat.join(v))
                    continue
                if not nones:
                    setattr(r, i, "")
                else:
                    setattr(r, i, None)
            except AttributeError:
                pass
        return r

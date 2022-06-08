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

from json import loads
from io import BytesIO
from random import choice
from include.util import xor
from secrets import token_bytes
from string import ascii_letters
from base64 import urlsafe_b64encode

CRUMB = b"\x00\x00\x00\x00\x06crypto\x00"
CRUMBS = [
    b"\x00\x00\x00\x00\x0Ecompress",
    b"\x00\x00'github.com",
    b"\x00\x00\x00\x00+github.com",
    b"\x00\x00\x00\x003github.com",
    b"\x00\x00sync/a",
    b"\x00\x00\x00\x00\x00#github.com",
    b"\x00\x00\x00\x00_cgo_",
    b"\x00\x00internal/",
    b"\x2E\x08\x00'github",
    b"\x0D\x00internal/",
]


def _is_abc(c):
    if c >= ord("A") and c <= ord("Z"):
        return True
    return c >= ord("a") and c <= ord("z")


def _use_tag(tags, values):
    if not isinstance(tags, list) or not isinstance(values, list):
        return True
    if len(values) == 0:
        return True
    r = False
    for t in tags:
        for v in values:
            if t.lower() == v.lower():
                r = True
                break
            if v[0] == "!" and v[1:].lower() == t.lower():
                return False
    return r


def generate_crypt(tags, file):
    b = _CryptBuilder(tags, file)
    return b.key(), b.out()


def strip_binary(file, log=None):
    with open(file, "rb") as f:
        b = bytearray(f.read())
    x = b.find(CRUMB)
    if x <= 0:
        raise RuntimeError()
    v, n = dict(), dict()
    x = _next_block(b, x + 4, v, n, log)
    for _ in range(0, 5):
        for i in CRUMBS:
            _find_next_push(b, x, i, v, n, log)
    with open(file, "wb") as f:
        f.write(b)


def _next_block(b, start, v, n, log):
    s, e, c = start, start, 0
    while e < len(b):
        if b[e] == 0:
            c += 1
        else:
            if e + 2 < len(b) and b[e + 1] == 0:
                c += 1
            else:
                c = 0
        if c > 5:
            break
        e += 1
    _map_swap(b, s, e, v, n)
    if callable(log):
        log(f"Strip remapped {s:X} => {e:X}")
    return e


def _find_next_push(b, x, c, v, n, log):
    i = b.find(c, x)
    if i > 0 and i < x:
        raise IOError(f"invalid next offset {x:X} => {i:X}")
    if i == -1:
        return
    _next_block(b, i + 2, v, n, log)


def _map_swap(b, start, end, vars, names):
    n = start
    while n < len(b) and n < end:
        while not _is_abc(b[n]):
            n += 1
            if n > end:
                return
        e = n + 1
        while _is_abc(b[e]):
            e += 1
            if e >= end:
                break
        if e - n >= 2:
            v = b[n:e].decode("UTF-8")
            if v not in vars:
                d = ""
                while True:
                    d = "".join(choice(ascii_letters) for _ in range(e - n))
                    if d not in names:
                        names[d] = True
                        break
                vars[v] = d
            h = vars[v]
            i = 0
            for x in range(n, e):
                b[x] = ord(h[i])
                i += 1
        n = e + 1


class _CryptBuilder(BytesIO):
    def __init__(self, tags, file):
        BytesIO.__init__(self)
        self._key = token_bytes(64)
        self.read_file(file, tags)

    def out(self):
        return urlsafe_b64encode(xor(self._key, self.getvalue())).decode("UTF-8")

    def key(self):
        return urlsafe_b64encode(self._key).decode("UTF-8")

    def add(self, v):
        self.write(v.encode("UTF-8"))
        self.write(bytearray(1))

    def read_file(self, f, tags):
        with open(f, "r") as b:
            d = loads(b.read())
        if not isinstance(d, dict) or len(d) == 0:
            return
        c = [None] * len(d)
        for k, v in d.items():
            if not isinstance(v, dict) or "value" not in v:
                c[int(k)] = ""
                continue
            if not _use_tag(tags, v.get("tags")):
                c[int(k)] = ""
            else:
                c[int(k)] = v["value"]
        for x in range(0, len(c)):
            self.add(c[x])

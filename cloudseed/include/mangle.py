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
from string import punctuation
from collections import namedtuple
from random import choice, randint

VOWELS = "aeiouAEIOU"
VOWELS_LOWER = "aeiou"
VOWELS_UPPER = "AEIOU"
CHARS = "abcdefghijklmnopqrstuvwxABCDEFGHIJKLMNOPQRSTUVWX"
LOWER = "abcdefghijklmnopqrstuvwx"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWX"
NUMBERS = "0123456789"
PUNCTUATION = "-_"

CLASSES = [
    VOWELS_LOWER,
    LOWER,
    VOWELS_UPPER,
    UPPER,
    NUMBERS,
    PUNCTUATION,
    CHARS,
]

Path = namedtuple("Path", ["path", "dir", "name"])


def mangle_name(s):
    while True:
        b, w, r = StringIO(), 0, None
        for x in range(0, len(s)):
            if randint(0, 20 + w) != 0:
                r = s[x]
                b.write(s[x])
                continue
            while True:
                n = _mangle_char(s[x], x == 0, r)
                if n != s[x]:
                    r = n
                    b.write(n)
                    break
            w += 1
        o = b.getvalue()
        b.close
        del b
        if o.lower() != s.lower():
            return o


def _mangle_char(c, first, last):
    if c in VOWELS_LOWER:
        return _mangle_class(c, 0, first, last)
    if c in LOWER:
        return _mangle_class(c, 1, first, last)
    if c in VOWELS_UPPER:
        return _mangle_class(c, 2, first, last)
    if c in UPPER:
        return _mangle_class(c, 3, first, last)
    if c in NUMBERS:
        return _mangle_class(c, 4, first, last)
    if c in punctuation and not first:
        return _mangle_class(c, 5, first, last)
    return _mangle_class(c, 6, first, last)


def _mangle_class(c, ci, first, last):
    p = randint(0, len(CLASSES[ci]) + len(CLASSES))
    if p < len(CLASSES[ci]):
        r = CLASSES[ci][p]
        if last is None:
            return r
        if last in VOWELS and r in VOWELS or r == last:
            return _mangle_class(c, ci, first, last)
        return r
    if first or randint(0, 3) == 0:  # Try again (same class)
        return _mangle_class(c, ci, first, last)
    v = p - (len(CLASSES[ci]) + 1)
    if v >= len(CLASSES[ci]):
        v = len(CLASSES[ci]) - v
    if c not in NUMBERS and v == 4:
        return _mangle_class(c, 3 if c in UPPER else 1, first, last)
    return _mangle_class(c, v, first, last)


class Mangler(object):
    __slots__ = ("_entries", "_past", "_cache")

    def __init__(self, entries):
        if not isinstance(entries, list) or len(entries) == 0:
            raise ValueError("mangle: entries list is invalid or empty")
        self._past = dict()
        self._cache = dict()
        self._entries = entries

    def _pick(self, sel, ext, exe, x86, sep):
        if exe and not sel.get("exec", False):
            return None
        if x86 and not sel.get("x86", True):
            return None
        c = sel["path"].count(sep)
        if c > 3 and exe and randint(0, c) != 0:
            return None
        del c
        n = mangle_name(choice(sel["names"]))
        while n in sel["names"]:
            n = mangle_name(choice(sel["names"]))
        if not isinstance(ext, str):
            n += f'.{choice(sel["exts"])}'
        elif len(ext) > 0:
            if ext[0] != ".":
                n += f".{ext}"
            else:
                n += ext
        p = sel["path"] + sep + n
        if p in self._past:
            return None
        self._past[p] = True
        return Path(p, sel["path"], n)

    def _pick_only(self, only, ext, exe, x86, n, sep):
        s, f = None, only.lower()
        if f not in self._cache:
            for i in self._entries:
                if i["path"].lower() == f:
                    s = i
                    break
            if not isinstance(s, dict) or len(s) == 0:
                raise ValueError(f'pick: could not find valid "only" value "{only}"')
            if "path" not in s or "names" not in s or "exts" not in s:
                raise ValueError(f'pick: could not find valid "only" value "{only}"')
            if s is None:
                raise ValueError(f'pick: could not find "only" value "{only}"')
            self._cache[f] = s
        else:
            s = self._cache[f]
        del f
        for _ in range(0, n):
            r = self._pick(s, ext, exe, x86, sep)
            if r is None:
                continue
            return r
        raise ValueError(f"pick: max attempts {n} failed to find a match")

    def pick(self, ext, exe=False, x86=False, n=256, sep="\\", base=None, only=None):
        if isinstance(only, str) and len(only) > 0:
            return self._pick_only(only, ext, exe, x86, n, sep)
        v = None
        if isinstance(base, str) and len(base) > 0:
            v = base.lower()
        for _ in range(0, n):
            s = choice(self._entries)
            if not isinstance(s, dict) or len(s) == 0:
                continue
            if "path" not in s or "names" not in s or "exts" not in s:
                continue
            if v is not None and v not in s["path"].lower():
                continue
            r = self._pick(s, ext, exe, x86, sep)
            if r is None:
                continue
            return r
        raise ValueError(f"pick: max attempts {n} failed to find a match")

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

from io import StringIO
from collections import namedtuple
from random import choice, randint


Path = namedtuple("Path", ["path", "dir", "name"])
_Class = namedtuple("Class", ["members", "replacable"])

_CLASSES = {
    "uni_a": _Class("aа", ["lower"]),  # äàáạąą
    "uni_c": _Class("cс", ["lower"]),  # ċ
    "uni_d": _Class("dԁɗ", ["lower"]),
    "uni_e": _Class("eе", ["lower"]),  # ėẹ
    "uni_g": _Class("gġ", ["lower"]),
    "uni_h": _Class("hһ", ["lower"]),
    "uni_i": _Class("iіíï", ["lower", "lookalike_i"]),
    "uni_j": _Class("jјʝ", ["lower", "lookalike_j"]),
    "uni_l": _Class("lӏ", ["lower"]),
    "uni_n": _Class("nո", ["lower"]),
    "uni_o": _Class("oоοօ", ["lower"]),  # ỏọơ
    "uni_p": _Class("pр", ["lower"]),
    "uni_q": _Class("qզ", ["lower"]),
    "uni_u": _Class("uυս", ["lower"]),  # úù
    "uni_v": _Class("vνѵ", ["lower"]),
    "uni_x": _Class("xхҳ", ["lower"]),
    "uni_y": _Class("yуý", ["lower"]),
    "uni_z": _Class("zʐż", ["lower"]),
    "uni_A": _Class("AА", ["lower"]),
    "uni_B": _Class("BВ", ["lower"]),
    "uni_C": _Class("CС", ["lower"]),
    "uni_E": _Class("EЕ", ["lower"]),
    "uni_G": _Class("GԌ", ["lower"]),
    "uni_H": _Class("HН", ["lower"]),
    "uni_I": _Class("IІ", ["lower"]),
    "uni_J": _Class("JЈ", ["lower"]),
    "uni_K": _Class("KКK", ["lower"]),
    "uni_M": _Class("MМ", ["lower"]),
    "uni_O": _Class("O0О", ["lower"]),
    "uni_P": _Class("PР", ["lower"]),
    "uni_Q": _Class("QԚ", ["lower"]),
    "uni_S": _Class("SЅ", ["lower"]),
    "uni_T": _Class("TТ", ["lower"]),
    "uni_V": _Class("VѴ", ["lower"]),
    "uni_W": _Class("WԜ", ["lower"]),
    "uni_X": _Class("XХ", ["lower"]),
    "lookalike_i": _Class("ilI", None),
    "lookalike_j": _Class("ijlI", None),
    "vowels_lower": _Class("aeiou", ["lower"]),
    "vowels_upper": _Class("AEIOU", ["upper"]),
    "lookalike_O": _Class("O0", None),
    "lookalike_m": _Class("mn", None),
    "lookalike_M": _Class("MN", None),
    "lower": _Class("abcdefghijklmnopqrstuvwx", ["upper", "chars"]),
    "upper": _Class("ABCDEFGHIJKLMNOPQRSTUVWX", ["lower", "chars"]),
    "numbers": _Class("0123456789", None),
    "chars": _Class("abcdefghijklmnopqrstuvwxABCDEFGHIJKLMNOPQRSTUVWX", None),
}
_UNTOUCHABLE = ["microsoft", "windows"]


def mangle_name(v):
    u = list()
    s = v.lower()
    for i in _UNTOUCHABLE:
        if len(i) > len(s):
            continue
        x = s.find(i)
        if x < 0 or x + len(i) > len(s):
            continue
        u.append((x, x + len(i)))
    o = None
    while True:
        b, p, t, r = StringIO(), None, len(v), 0
        for x in range(0, t):
            if _not_touch_range(x, u):
                b.write(v[x])
                continue
            if v[x] == "." and t - x <= 4:
                p = x
                break
            n = _try_mangle_char(x, t, r, v[x], v[x - 1] if x > 0 else None)
            if n is not None:
                b.write(n)
                r += 1
            else:
                b.write(v[x])
            if r > 0 and randint(0, 3) == 0:
                break
            del n
        if isinstance(p, int) and p > 0:
            b.write(v[p:])
        if r > 0:
            o = b.getvalue()
            if len(o) != t or o.lower() == s:
                o = None
        b.close()
        del b, p, t, r
        if o is not None:
            break
    del u, s
    return o


def _match_lower(v, e):
    for i in e:
        if v.lower() == i.lower():
            return True
    return False


def _find_mangle_class(c):
    for v in _CLASSES.values():
        if c in v.members:
            return v
    return None


def _not_touch_range(x, u):
    if len(u) == 0:
        return False
    for i in u:
        if x >= i[0] and x <= i[1]:
            return True
    return False


def _try_mangle_char(x, t, r, c, p):
    if randint(0, 20 + r + (t - x)) != 0:
        return None
    m = _find_mangle_class(c)
    if m is None:
        return None
    if m.replacable is not None and randint(0, 60 + r) == 0:
        m = _CLASSES[choice(m.replacable)]
    while True:
        s = choice(m.members)
        if p is not None and p == s:
            continue
        del m
        return s


class Mangler(object):
    __slots__ = ("_entries", "_past", "_cache", "_extras")

    def __init__(self, entries, names):
        if not isinstance(entries, list) or len(entries) == 0:
            raise ValueError("mangle: entries list is invalid or empty")
        self._past = dict()
        self._cache = dict()
        self._extras = names
        self._entries = entries

    def _pick(self, sel, ext, exe, x86, sep, sz):
        if exe and not sel.get("exec", False):
            return None
        if x86 and not sel.get("x86", True):
            return None
        c = sel["path"].count(sep)
        if c > 3 and exe and randint(0, c) != 0:
            return None
        del c
        if (
            len(sel["names"]) == 0
            or (len(sel["names"]) == 1 and randint(0, 2) == 0)
            or randint(0, 6) == 0
        ):
            n = choice(self._extras)
            if _match_lower(n, sel["names"]):
                n = mangle_name(n)
        else:
            n = mangle_name(choice(sel["names"]))
        while _match_lower(n, sel["names"]):
            if randint(0, 8) == 0:
                n = choice(self._extras)
                if _match_lower(n, sel["names"]):
                    n = mangle_name(n)
                # else:
                #    break
            else:
                n = mangle_name(choice(sel["names"]))
        if isinstance(sz, int) and sz > 0 and len(n) > sz:
            return None
        i = n.rfind(".")
        if i > 0 and len(n) - i == 4:
            n = n[:i]
        if n.upper() == n:
            n = n.lower()
        if _match_lower(n, sel["names"]):
            return None
        # Sanity check
        if _match_lower(n, sel["names"]):
            raise RuntimeError(f'name {n} found in {sel["names"]}')
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

    def _pick_only(self, only, ext, exe, x86, n, sep, sz):
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
            r = self._pick(s, ext, exe, x86, sep, sz)
            if r is None:
                continue
            return r
        raise ValueError(f"pick: max attempts {n} failed to find a match")

    def pick(self, ext, exe=False, x86=False, n=300, sep="\\", sz=0, base="", only=""):
        if isinstance(only, str) and len(only) > 0:
            return self._pick_only(only, ext, exe, x86, n, sep, sz)
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
            if exe and ext[1:].lower() not in s["exts"]:
                # NOTE(dij): Limit to only put DLLs in dirs that contain DLLs
                #            Disable if not needed or if it breaks stuff.
                continue
            r = self._pick(s, ext, exe, x86, sep, sz)
            if r is None:
                continue
            return r
        raise ValueError(f"pick: max attempts {n} failed to find a match")

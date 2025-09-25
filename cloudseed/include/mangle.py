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
    "unicode_a": _Class("aа", ["lower"]),
    "unicode_b": _Class("bḅ", ["lower"]),
    "unicode_c": _Class("cϲᴄс", ["lower"]),
    # "unicode_d": _Class("dɗď", ["lower"]),
    "unicode_e": _Class("eeҽе", ["lower"]),
    "unicode_f": _Class("fḟ", ["lower"]),
    # "unicode_g": _Class("gģǥ", ["lower"]),
    "unicode_h": _Class("hhհ", ["lower"]),
    "unicode_i": _Class("iіiі", ["lower", "lookalike_i"]),
    "unicode_j": _Class("jϳј", ["lower", "lookalike_j"]),
    "unicode_k": _Class("kk", ["lower"]),
    "unicode_l": _Class("llł", ["lower"]),
    "unicode_m": _Class("mm", ["lower"]),
    "unicode_n": _Class("nnո", ["lower"]),
    "unicode_o": _Class("oօᴏоѻoоοօ", ["lower"]),
    "unicode_p": _Class("ppƿрρ", ["lower"]),
    "unicode_q": _Class("qզ", ["lower"]),
    # "unicode_r": _Class("rṛŕ", ["lower"]),
    "unicode_s": _Class("sѕ", ["lower"]),
    "unicode_t": _Class("tț", ["lower"]),
    "unicode_u": _Class("uᴜυυս", ["lower"]),
    "unicode_v": _Class("vνᴠ", ["lower"]),
    "unicode_w": _Class("wᴡ", ["lower"]),
    "unicode_x": _Class("xх", ["lower"]),
    "unicode_y": _Class("yу", ["lower"]),
    "unicode_z": _Class("zzzᴢ", ["lower"]),
    "unicode_A": _Class("AAА", ["upper"]),
    "unicode_B": _Class("BВ", ["upper"]),
    "unicode_C": _Class("CС", ["upper"]),
    "unicode_D": _Class("DDD", ["upper"]),
    "unicode_E": _Class("EЕE", ["upper"]),
    "unicode_F": _Class("FF", ["upper"]),
    "unicode_G": _Class("GԌ", ["upper"]),
    "unicode_H": _Class("HНΗ", ["upper"]),
    "unicode_I": _Class("IІIӀӏ", ["upper"]),
    "unicode_J": _Class("JЈ", ["upper"]),
    "unicode_K": _Class("KKКƘKҚ", ["upper"]),
    "unicode_L": _Class("LԼ", ["upper"]),
    "unicode_M": _Class("MMМΜ", ["upper"]),
    "unicode_N": _Class("NN", ["upper"]),
    "unicode_O": _Class("OО0", ["upper"]),
    "unicode_P": _Class("PPРƤ", ["lower"]),
    "unicode_Q": _Class("QԚQ", ["upper"]),
    "unicode_R": _Class("RŔ", ["upper"]),
    "unicode_S": _Class("SЅՏЅ", ["upper"]),
    "unicode_T": _Class("TТT", ["upper"]),
    "unicode_U": _Class("UUṲ", ["upper"]),
    "unicode_V": _Class("VѴ", ["upper"]),
    "unicode_W": _Class("WԜ", ["upper"]),
    "unicode_X": _Class("ҲҲӼХ", ["upper"]),
    "unicode_Y": _Class("YYƳ", ["upper"]),
    "unicode_Z": _Class("ZŹ", ["upper"]),
    "spacer": _Class(" _-.", None),
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


def _match_lower(v, e):
    for i in e:
        if v.lower() == i.lower():
            return True
    return False


def _not_touch_range(x, u):
    if len(u) == 0:
        return False
    for i in u:
        if x >= i[0] and x <= i[1]:
            return True
    return False


def _find_mangle_class(c, u):
    for n, v in _CLASSES.items():
        if not u and n.startswith("unicode_"):
            continue
        if c in v.members:
            return v
    return None


def mangle_name(v, unicode=True):
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
            # x - index
            # t - name length
            # r - number of replacements made
            n = _try_mangle_char(x, t, r, v[x], v[x - 1] if x > 0 else None, unicode)
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


def _try_mangle_char(x, t, r, c, p, u):
    # x - index
    # t - name length
    # r - number of replacements made
    # c - character
    # p - previous character, None if the first
    # u - unicode support
    if randint(0, 20 + r + (t - x)) != 0:
        return None
    m = _find_mangle_class(c, u)
    if m is None:
        return None
    if m.replacable is not None and randint(0, 60 + r) == 0:
        v = _find_mangle_class(choice(m.replacable), u)
        if v is not None:
            m = v
        del v
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

    def _pick(self, sel, ext, exe, x86, sep, sz, lib):
        if exe and not sel.get("exec", False):
            return None
        if x86 and not sel.get("x86", True):
            return None
        c = sel["path"].count(sep)
        # Lesson the chance of long paths, each seperator makes it less likely
        # to be picked.
        if c > 4 and exe and randint(0, c + 4) == 0:
            return None
        del c
        # If the "names" list is empty, OR it contains a single entry and an
        # executable is requested OR randomally, chose the global names list
        # instead.
        if (
            len(sel["names"]) == 0
            or (len(sel["names"]) == 1 and exe)  # and randint(0, 2) == 0)
            or randint(0, 6) == 0
        ):
            n = choice(self._extras)
            # If there's names in that entry, make sure we don't have a collision
            if _match_lower(n, sel["names"]):
                n = mangle_name(n, not lib)
        else:
            # Pick from the dir names list.
            n = mangle_name(choice(sel["names"]), not lib)
        # Check to see if there's a bunch of caps or non-alpha-nums, random chance
        # to switch it with a global name.
        i = sum(1 for c in n if c.isupper() or not c.isalnum())
        if exe and i > 4 and randint(0, i + 2) == 0:
            n = choice(self._extras)
        del i
        # Check to see if we have any collisions and mangle if we do.
        while _match_lower(n, sel["names"]):
            if randint(0, 8) == 0:
                # If mangling keeps looping, change out the name from the global
                # names list.
                n = choice(self._extras)
                if _match_lower(n, sel["names"]):
                    n = mangle_name(n, not lib)
                # else:
                #    break
            else:
                n = mangle_name(choice(sel["names"]), not lib)
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

    def _pick_only(self, only, ext, exe, x86, n, sep, sz, lib):
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
            r = self._pick(s, ext, exe, x86, sep, sz, lib)
            if r is None:
                continue
            return r
        raise ValueError(f"pick: max attempts {n} failed to find a match")

    def pick(self, ext, exe=False, x86=False, n=300, sep="\\", sz=0, base="", only=""):
        if isinstance(only, str) and len(only) > 0:
            # The caller has a specific dir they want to use.
            return self._pick_only(
                only, ext, exe, x86, n, sep, sz, ext == ".dll" or ext == ".so"
            )
        v = None
        if isinstance(base, str) and len(base) > 0:
            v = base.lower()
        for _ in range(0, n):
            s = choice(self._entries)
            if not isinstance(s, dict) or len(s) == 0:
                continue
            # Skip invalid entries.
            if "path" not in s or "names" not in s or "exts" not in s:
                continue
            # If we have a base path, check if it matches.
            if v is not None and v not in s["path"].lower():
                continue
            if exe and ext[1:].lower() not in s["exts"]:
                # NOTE(dij): Limit to only put DLLs in dirs that contain DLLs
                #            Disable if not needed or if it breaks stuff.
                continue
            r = self._pick(s, ext, exe, x86, sep, sz, ext == ".dll" or ext == ".so")
            if r is None:
                continue
            return r
        raise ValueError(f"pick: max attempts {n} failed to find a match")

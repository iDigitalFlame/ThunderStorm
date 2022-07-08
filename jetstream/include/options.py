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

from shutil import which
from string import Template
from base64 import b64decode
from include.util import nes
from datetime import datetime
from json import loads, dumps
from include.builder import RC
from traceback import format_exc
from random import choice, randint
from os import listdir, makedirs, chmod
from include.generators import load_generators
from logging import getLogger, Formatter, StreamHandler, FileHandler
from os.path import expanduser, expandvars, isfile, isdir, isabs, join, dirname


LEVELS = {
    "0": "DEBUG",
    "1": "INFO",
    "2": "WARNING",
    "3": "ERROR",
    "debug": "DEBUG",
    "info": "INFO",
    "warning": "WARNING",
    "error": "ERROR",
}

_DEFAULT_TAGS = ["implant", "noproxy", "nojson"]


def try_find_bin(v):
    if not nes(v):
        return v
    if isabs(v) or isfile(v):
        return v
    o = which(v)
    if nes(o):
        return o
    return v


def _cfg_rc(cfg, b):
    cfg["icon_multi"] = dict()
    cfg["title_multi"] = dict()
    cfg["version_multi"] = dict()
    cfg["product_multi"] = dict()
    cfg["company_multi"] = dict()
    cfg["filename_multi"] = dict()
    cfg["copyright_multi"] = dict()
    if not isinstance(b, dict):
        cfg["enabled"] = False
        cfg["file"] = ""
        cfg["json"] = ""
        cfg["icon"] = ""
        cfg["title"] = ""
        cfg["version"] = ""
        cfg["product"] = ""
        cfg["company"] = ""
        cfg["filename"] = ""
        cfg["copyright"] = ""
        _cfg_multi("icon", cfg["icon_multi"], None)
        _cfg_multi("title", cfg["title_multi"], None)
        _cfg_multi("version", cfg["version_multi"], None)
        _cfg_multi("product", cfg["product_multi"], None)
        _cfg_multi("company", cfg["company_multi"], None)
        _cfg_multi("filename", cfg["filename_multi"], None)
        _cfg_multi("copyright", cfg["copyright_multi"], None)
        return
    cfg["enabled"] = b.get("enabled", False)
    cfg["file"] = b.get("file", "")
    cfg["json"] = b.get("json", "")
    cfg["icon"] = b.get("icon", "")
    cfg["title"] = b.get("title", "")
    cfg["version"] = b.get("version", "")
    cfg["product"] = b.get("product", "")
    cfg["company"] = b.get("company", "")
    cfg["filename"] = b.get("filename", "")
    cfg["copyright"] = b.get("copyright", "")
    vet_bool("build.support.rc.enabled", cfg["enabled"])
    vet_str_exists("build.support.rc.file", cfg["file"])
    vet_str_exists("build.support.rc.json", cfg["json"])
    vet_str_exists("build.support.rc.icon", cfg["icon"])
    vet_str("build.support.rc.title", cfg["title"])
    vet_str("build.support.rc.version", cfg["version"])
    vet_str("build.support.rc.product", cfg["product"])
    vet_str("build.support.rc.company", cfg["company"])
    vet_str("build.support.rc.filename", cfg["filename"])
    vet_str("build.support.rc.copyright", cfg["copyright"])
    _cfg_multi("icon", cfg["icon_multi"], b.get("icon_multi"))
    _cfg_multi("title", cfg["title_multi"], b.get("title_multi"))
    _cfg_multi("version", cfg["version_multi"], b.get("version_multi"))
    _cfg_multi("product", cfg["product_multi"], b.get("product_multi"))
    _cfg_multi("company", cfg["company_multi"], b.get("company_multi"))
    _cfg_multi("filename", cfg["filename_multi"], b.get("filename_multi"))
    _cfg_multi("copyright", cfg["copyright_multi"], b.get("copyright_multi"))


def _cfg_log(cfg, b):
    if not isinstance(b, dict):
        cfg["file"] = ""
        cfg["level"] = "INFO"
        return
    cfg["file"] = b.get("file", "")
    cfg["level"] = b.get("level", "INFO")
    vet_str("config.log.file", cfg["file"], null=True)
    vet_str("config.log.level", cfg["level"])
    if cfg["level"].lower() in LEVELS:
        return
    raise ValueError(f'"config.log.level" value "{cfg["level"]}" is invalid')


def _cfg_base(cfg, b):
    if not isinstance(b, dict):
        _cfg_log(cfg["log"], None)
        cfg["template_dir"] = ""
        cfg["generator_dir"] = ""
        return
    _cfg_log(cfg["log"], b.get("log"))
    cfg["template_dir"] = b.get("template_dir", "")
    cfg["generator_dir"] = b.get("generator_dir", "")
    vet_str_exists("config.template_dir", cfg["template_dir"], f=isdir)
    vet_str_exists("config.generator_dir", cfg["generator_dir"], f=isdir)


def _cfg_sign(cfg, b):
    if not isinstance(b, dict):
        cfg["enabled"] = False
        cfg["generate_name"] = ""
        cfg["generate_target"] = ""
        cfg["date"] = ""
        cfg["date_range"] = 0
        cfg["pfx"] = ""
        cfg["pfx_raw"] = ""
        cfg["pfx_password"] = ""
        cfg["cert"] = ""
        cfg["cert_raw"] = ""
        cfg["pem"] = ""
        cfg["pem_raw"] = ""
        return
    cfg["enabled"] = b.get("enabled", False)
    cfg["generate_name"] = b.get("generate_name", "")
    cfg["generate_target"] = b.get("generate_target", "")
    cfg["date"] = b.get("date", "")
    cfg["date_range"] = b.get("date_range", 0)
    cfg["pfx"] = b.get("pfx", "")
    cfg["pfx_raw"] = b.get("pfx_raw", "")
    cfg["pfx_password"] = b.get("pfx_password", "")
    cfg["cert"] = b.get("cert", "")
    cfg["cert_raw"] = b.get("cert_raw", "")
    cfg["pem"] = b.get("pem", "")
    cfg["pem_raw"] = b.get("pem_raw", "")
    vet_bool("build.support.sign.enabled", cfg["enabled"])
    vet_str("build.support.sign.generate_name", cfg["generate_name"])
    vet_str("build.support.sign.generate_target", cfg["generate_target"])
    vet_str("build.support.sign.date", cfg["date"])
    vet_int("build.support.sign.date_range", cfg["date_range"], min=0)
    if nes(cfg["date"]):
        datetime.fromisoformat(cfg["date"])
    vet_str_exists("build.support.sign.pfx", cfg["pfx"])
    vet_str("build.support.sign.pfx_raw", cfg["pfx_raw"], b64=True)
    vet_str("build.support.sign.pfx_password", cfg["pfx_password"])
    vet_str_exists("build.support.sign.cert", cfg["cert"])
    vet_str("build.support.sign.cert_raw", cfg["cert_raw"], b64=True)
    vet_str_exists("build.support.sign.pem", cfg["pem"])
    vet_str("build.support.sign.pem_raw", cfg["pem_raw"], b64=True)


def _cfg_bins(cfg, b):
    if not isinstance(b, dict):
        cfg["go"] = ""
        cfg["gcc"] = ""
        cfg["upx"] = ""
        cfg["wgcc32"] = ""
        cfg["wgcc64"] = ""
        cfg["wres32"] = ""
        cfg["wres64"] = ""
        cfg["garble"] = ""
        cfg["openssl"] = ""
        cfg["osslsigncode"] = ""
        return
    cfg["go"] = try_find_bin(b.get("go", ""))
    cfg["gcc"] = try_find_bin(b.get("gcc", ""))
    cfg["upx"] = try_find_bin(b.get("upx", ""))
    cfg["wgcc32"] = try_find_bin(b.get("wgcc32", ""))
    cfg["wgcc64"] = try_find_bin(b.get("wgcc64", ""))
    cfg["wres32"] = try_find_bin(b.get("wres32", ""))
    cfg["wres64"] = try_find_bin(b.get("wres64", ""))
    cfg["garble"] = try_find_bin(b.get("garble", ""))
    cfg["openssl"] = try_find_bin(b.get("openssl", ""))
    cfg["osslsigncode"] = try_find_bin(b.get("osslsigncode", ""))
    vet_str_exists("build.bins.go", cfg["go"])
    vet_str_exists("build.bins.gcc", cfg["gcc"])
    vet_str_exists("build.bins.upx", cfg["upx"])
    vet_str_exists("build.bins.wgcc32", cfg["wgcc32"])
    vet_str_exists("build.bins.wgcc64", cfg["wgcc64"])
    vet_str_exists("build.bins.wres32", cfg["wres32"])
    vet_str_exists("build.bins.wres64", cfg["wres64"])
    vet_str_exists("build.bins.garble", cfg["garble"])
    vet_str_exists("build.bins.openssl", cfg["openssl"])
    vet_str_exists("build.bins.osslsigncode", cfg["osslsigncode"])


def _cfg_build(cfg, b):
    if not isinstance(b, dict):
        cfg["dir"] = ""
        cfg["dir_link"] = ""
        _cfg_bins(cfg["bins"], None)
        _cfg_options(cfg["options"], None)
        _cfg_support(cfg["support"], None)
        return
    cfg["dir"] = b.get("dir", "")
    cfg["dir_link"] = b.get("dir_link", "")
    _cfg_bins(cfg["bins"], b.get("bins"))
    _cfg_options(cfg["options"], b.get("options"))
    _cfg_support(cfg["support"], b.get("support"))
    vet_str("build.dir", cfg["dir"], null=True)
    vet_str("build.dir_link", cfg["dir_link"], null=True)
    if "generators" not in b or not isinstance(b["generators"], dict):
        return
    for k, v in b["generators"].items():
        if not isinstance(k, str) or len(k) == 0:
            raise ValueError(
                '"build.options.generators" key values can only be non-empty strings'
            )
        if not isinstance(v, dict):
            raise ValueError(f'"build.options.generators.{k}" value must be a dict')
        cfg["generators"][k] = v


def _cfg_options(cfg, b):
    if not isinstance(b, dict):
        cfg["upx"] = False
        cfg["cgo"] = False
        cfg["tags"] = _DEFAULT_TAGS
        cfg["crypt"] = True
        cfg["strip"] = True
        cfg["goroot"] = ""
        cfg["garble"] = True
        cfg["compact"] = True
        return
    cfg["upx"] = b.get("upx", False)
    cfg["cgo"] = b.get("cgo", False)
    cfg["crypt"] = b.get("crypt", True)
    cfg["strip"] = b.get("strip", True)
    cfg["goroot"] = b.get("goroot", "")
    cfg["garble"] = b.get("garble", True)
    cfg["compact"] = b.get("compact", True)
    cfg["tags"] = b.get("tags", _DEFAULT_TAGS)
    vet_bool("build.options.upx", cfg["upx"])
    vet_bool("build.options.cgo", cfg["cgo"])
    vet_bool("build.options.crypt", cfg["crypt"])
    vet_bool("build.options.strip", cfg["strip"])
    vet_bool("build.options.garble", cfg["garble"])
    vet_bool("build.options.compact", cfg["compact"])
    vet_list_strs("build.options.tags", cfg["tags"], null=True)
    vet_str_exists("build.options.goroot", cfg["goroot"], f=isdir)


def _cfg_support(cfg, b):
    if not isinstance(b, dict):
        cfg["manifest"] = True
        cfg["cgo_export"] = ""
        _cfg_rc(cfg["rc"], None)
        _cfg_sign(cfg["sign"], None)
        return
    cfg["manifest"] = b.get("manifest", True)
    cfg["cgo_export"] = b.get("cgo_export", "")
    vet_bool("build.support.manifest", cfg["manifest"])
    vet_str("build.support.cgo_export", cfg["cgo_export"])
    _cfg_rc(cfg["rc"], b.get("rc"))
    _cfg_sign(cfg["sign"], b.get("sign"))


def _cfg_multi(n, cfg, b):
    if not isinstance(b, dict):
        cfg["file"] = ""
        cfg["chance"] = 0
        cfg["default"] = ""
        cfg["enabled"] = False
        cfg["choices"] = list()
        return
    cfg["file"] = b.get("file", "")
    cfg["chance"] = b.get("chance", 0)
    cfg["default"] = b.get("default", "")
    cfg["enabled"] = b.get("enabled", False)
    cfg["choices"] = b.get("choices", list())
    vet_str(f"build.support.rc.{n}_multi.default", cfg["default"])
    vet_bool(f"build.support.rc.{n}_multi.enabled", cfg["enabled"])
    vet_str_exists(f"build.support.rc.{n}_multi.file", cfg["file"])
    vet_int(f"build.support.rc.{n}_multi.chance", cfg["chance"], min=0)
    vet_list_strs(f"build.support.rc.{n}_multi.choices", cfg["choices"])


def vet_bool(name, v, null=False):
    if v is None and null:
        return
    if isinstance(v, bool):
        return
    if null:
        raise ValueError(f'"{name}" must be null or a boolean')
    raise ValueError(f'"{name}" must be a boolean')


def vet_str(name, v, null=False, b64=False):
    if v is None and null:
        return
    if not isinstance(v, str):
        if null:
            raise ValueError(f'"{name}" must be null or a string')
        raise ValueError(f'"{name}" must be a string')
    if not b64:
        return
    try:
        b64decode(v, validate=True)
        return
    except ValueError:
        pass
    raise ValueError(f'"{name}" must be a valid base64 string')


def vet_int(name, v, min=0, max=0, null=False):
    if v is None and null:
        return
    if not isinstance(v, (int, float)):
        if null:
            raise ValueError(f'"{name}" must be null or a number')
        raise ValueError(f'"{name}" must be a number')
    if min == 0 and max == 0:
        return
    if min > 0 and v < min:
        raise ValueError(f'"{name}" value must be greater than or equal to "{min}"')
    if max == 0 or v < max:
        return
    raise ValueError(f'"{name}" value must be less than "{max}"')


def vet_str_exists(name, v, f=isfile, null=False):
    if v is None and null:
        return
    if not isinstance(v, str):
        if null:
            raise ValueError(f'"{name}" must be null or a string')
        raise ValueError(f'"{name}" must be a string')
    if len(v) == 0:
        return
    p = expanduser(expandvars(v))
    if not f(p):
        raise ValueError(f'"{name}" path "{v}" does not exist')
    del p


def vet_list_strs(name, v, null=False, empty=True):
    if v is None and null:
        return
    if not isinstance(v, list):
        if null:
            raise ValueError(f'"{name}" must be null or a string list')
        raise ValueError(f'"{name}" must be a string list')
    if len(v) == 0:
        if not empty:
            raise ValueError(f'"{name}" cannot be empty')
        return
    for i in v:
        if isinstance(i, str) and len(i) > 0:
            continue
        raise ValueError(f'"{name}" can only contain non-empty strings')


class Rc(object):
    __slots__ = (
        "file",
        "json",
        "icon",
        "title",
        "enabled",
        "version",
        "company",
        "product",
        "filename",
        "copyright",
        "icon_multi",
        "title_multi",
        "version_multi",
        "product_multi",
        "company_multi",
        "filename_multi",
        "copyright_multi",
    )

    def __init__(self, v):
        self.file = v.get("file")
        self.json = v.get("json")
        self.enabled = v.get("enabled", True)
        if isinstance(self.json, str) and len(self.json) > 0:
            return self._file(self.json)
        self._dict(v, False)

    def _file(self, p):
        p = expanduser(expandvars(self.json))
        if not isfile(p):
            raise ValueError(f'"build.support.rc.json" path "{p}" does not exist')
        with open(p) as f:
            d = loads(f.read())
        if d is not None and not isinstance(d, dict):
            raise ValueError(
                f'"build.support.rc.json" path "{p}" did not parse to a dict'
            )
        self._dict(d, True)
        vet_str_exists("build.support.rc.json|icon", self.icon)
        vet_str("build.support.rc.json|title", self.title)
        vet_str("build.support.rc.json|version", self.version)
        vet_str("build.support.rc.json|product", self.product)
        vet_str("build.support.rc.json|company", self.company)
        vet_str("build.support.rc.json|filename", self.filename)
        vet_str("build.support.rc.json|copyright", self.copyright)
        del p, d

    def _dict(self, d, ex):
        self.icon = d.get("icon")
        self.title = d.get("title")
        self.version = d.get("version")
        self.product = d.get("product")
        self.company = d.get("company")
        self.filename = d.get("filename")
        self.copyright = d.get("copyright")
        self.icon_multi = _Multi(d.get("icon_multi"), "icon", ex)
        self.title_multi = _Multi(d.get("title_multi"), "title", ex)
        self.version_multi = _Multi(d.get("version_multi"), "version", ex)
        self.product_multi = _Multi(d.get("product_multi"), "product", ex)
        self.company_multi = _Multi(d.get("company_multi"), "company", ex)
        self.filename_multi = _Multi(d.get("filename_multi"), "filename", ex)
        self.copyright_multi = _Multi(d.get("copyright_multi"), "copyright", ex)

    def generate(self, n, library):
        if not library:
            if self.icon_multi.enabled:
                i = self.icon_multi.pick()
            else:
                i = self.icon
            if nes(i) and not isfile(i):
                raise ValueError(f'icon path "{i}" is not a file')
        else:
            i = ""
        if self.title_multi.enabled:
            t = self.title_multi.pick()
        else:
            t = self.title
        if self.version_multi.enabled:
            v = self.version_multi.pick()
        else:
            v = self.version
        if self.product_multi.enabled:
            p = self.product_multi.pick()
        else:
            p = self.product
        if self.company_multi.enabled:
            c = self.company_multi.pick()
        else:
            c = self.company
        if self.filename_multi.enabled:
            f = self.filename_multi.pick()
        else:
            f = self.filename
        if self.copyright_multi.enabled:
            r = self.copyright_multi.pick()
        else:
            r = self.copyright
        if len(f) == 0:
            f = n
        if len(v) == 0:
            v = "0.0.0.0"
        if not library and len(i) > 0:
            i = f'IDI_ICON_128 ICON "{i}"\n'
        d = RC.format(
            file=f,
            icon=i,
            title=t,
            company=c,
            product=p,
            copyright=r,
            version_string=v,
            version=v.replace(".", ","),
        )
        del i, t, v, p, c, f, r
        return d


class _Multi(object):
    __slots__ = ("_cache", "file", "chance", "default", "choices", "enabled")

    def __init__(self, v, n, ex=True):
        if v is None:
            return
        if not isinstance(v, dict):
            raise ValueError('"build.support.rc.*_multi": constructor was not a dict')
        self._cache = None
        self.file = v.get("file", "")
        self.chance = v.get("chance", 0)
        self.default = v.get("default", "")
        self.choices = v.get("choices", list())
        self.enabled = v.get("enabled", False)
        if n == "icon":
            vet_str_exists(f"build.support.rc.{n}_multi.default", self.default)
        if not ex:
            return
        vet_str(f"build.support.rc.{n}_multi.default", self.default)
        vet_bool(f"build.support.rc.{n}_multi.enabled", self.enabled)
        vet_str_exists(f"build.support.rc.{n}_multi.file", self.file)
        vet_int(f"build.support.rc.{n}_multi.chance", self.chance, min=0)
        vet_list_strs(f"build.support.rc.{n}_multi.choices", self.choices)

    def pick(self):
        if self._cache is None:
            if isinstance(self.file, str) and len(self.file) > 0:
                self._cache = list()
                with open(expandvars(expanduser(self.file))) as f:
                    for i in f.read().split("\n"):
                        v = i.strip()
                        if len(v) == 0:
                            continue
                        self._cache.append(v)
                        del v
            elif isinstance(self.choices, list) and len(self.choices) > 0:
                self._cache = self.choices.copy()
            else:
                self._cache = list()
        if self.chance > 0 and randint(0, self.chance) != 0:
            return self.default
        if len(self._cache) > 0:
            return choice(self._cache)
        return self.default


class Logger(object):
    __slots__ = ("_log", "_prefix")

    def __init__(self, name, level, file=None):
        if not isinstance(level, str) or len(level) == 0:
            raise ValueError('"level" must be a non-empty String!')
        self._prefix = None
        self._log = getLogger(name)
        self._log.setLevel(level.upper())
        f = Formatter(
            "%(asctime)s [%(levelname)s] %(name)s|%(threadName)s: %(message)s",
            "%m-%d-%H:%M;%S",
        )
        if isinstance(file, str) and file:
            d = dirname(file)
            if not isdir(d):
                try:
                    makedirs(d, exist_ok=True)
                except OSError as err:
                    raise OSError(f'error creating log directory "{d}": {err}')
            del d
            try:
                h = FileHandler(file)
                h.setFormatter(f)
                h.setLevel(level.upper())
                self._log.addHandler(h)
                chmod(file, 0o644, follow_symlinks=True)
            except OSError as err:
                raise OSError(f'error creating log file "{file}": {err}')
            del h
        else:
            s = StreamHandler()
            s.setFormatter(f)
            self._log.addHandler(s)
            del s
        del f

    def prefix(self, v):
        self._prefix = v

    def info(self, message, err=None):
        if self._prefix is None:
            if err is not None:
                return self._log.info(f"{message} ({str(err)})\n{format_exc(limit=3)}")
            self._log.info(message)
        else:
            if err is not None:
                return self._log.info(
                    f"{self._prefix}: {message} ({str(err)})\n{format_exc(limit=3)}"
                )
            self._log.info(f"{self._prefix}: {message}")

    def debug(self, message, err=None):
        if self._prefix is None:
            if err is not None:
                return self._log.debug(f"{message} ({str(err)})\n{format_exc(limit=3)}")
            self._log.debug(message)
        else:
            if err is not None:
                return self._log.debug(
                    f"{self._prefix}: {message} ({str(err)})\n{format_exc(limit=3)}"
                )
            self._log.debug(f"{self._prefix}: {message}")

    def error(self, message, err=None):
        if self._prefix is None:
            if err is not None:
                return self._log.error(f"{message} ({str(err)})\n{format_exc(limit=3)}")
            self._log.error(message)
        else:
            if err is not None:
                return self._log.error(
                    f"{self._prefix}: {message} ({str(err)})\n{format_exc(limit=3)}"
                )
            self._log.error(f"{self._prefix}: {message}")

    def warning(self, message, err=None):
        if self._prefix is None:
            if err is not None:
                return self._log.warning(
                    f"{message} ({str(err)})\n{format_exc(limit=3)}"
                )
            self._log.warning(message)
        else:
            if err is not None:
                return self._log.warning(
                    f"{self._prefix}: {message} ({str(err)})\n{format_exc(limit=3)}"
                )
            self._log.warning(f"{self._prefix}: {message}")


class Options(object):
    __slots__ = ("lock", "_gens", "_temps", "_config")

    def __init__(self, d=None):
        self.lock = False
        self._gens = None
        self._temps = None
        self._config = None
        if isinstance(d, dict):
            self.load_from(d)

    def vet(self):
        d = {
            "build": {
                "bins": dict(),
                "options": dict(),
                "generators": dict(),
                "support": {"rc": dict(), "sign": dict()},
            },
            "config": {"log": dict()},
        }
        _cfg_build(d["build"], self._config["build"])
        _cfg_base(d["config"], self._config["config"])
        del d

    def logger(self):
        if self._config is None:
            raise ValueError("save: options was not loaded")
        return Logger(
            "JetStream",
            self._config["config"]["log"]["level"],
            self._config["config"]["log"]["file"],
        )

    def save(self, p):
        if self._config is None:
            raise ValueError("save: options was not loaded")
        if isinstance(p, str) and len(p) > 0:
            v = expanduser(expandvars(p))
        else:
            v = "jetstream.conf"
        with open(v, "w") as f:
            f.write(dumps(self._config, indent=4, sort_keys=True))
        del v

    def load(self, p):
        if nes(p):
            v = expanduser(expandvars(p))
            if not isfile(v):
                raise ValueError(f'load: options file "{v}" was not found')
        else:
            v = "jetstream.conf"
        if isfile(v):
            with open(v) as f:
                d = loads(f.read())
            if not isinstance(d, dict):
                raise ValueError(f'load: options file "{v}" is invalid')
        else:
            d = dict()
        del v
        self.load_from(d)
        del d

    def set(self, n, d):
        if self._config is None:
            raise ValueError("set: options was not loaded")
        if not nes(n):
            raise KeyError("set: key was not a non-empty string")
        if "." not in n:
            self._config[n.lower()] = d
            return d
        v = n.lower().split(".")
        if len(v) == 0 or v[0] not in self._config:
            raise KeyError(n)
        if len(v) == 1:
            return self._config[v[0]]
        p = self._config[v[0]]
        for x in range(1, len(v) - 1):
            if v[x] not in p:
                if not n.startswith("build.generators"):
                    raise KeyError(n)
                p[v[x]] = dict()
            p = p[v[x]]
            if not isinstance(p, dict):
                raise KeyError(n)
        if not isinstance(p, dict):
            raise KeyError(n)
        p[v[-1]] = d
        del p, v
        return d

    def templates(self):
        if self._temps is not None:
            return self._temps
        if self._config is None:
            raise ValueError("templates: options was not loaded")
        d = self._config["config"]["template_dir"]
        if not isinstance(d, str) or len(d) == 0:
            d = join(dirname(dirname(__file__)), "templates")
        else:
            d = expanduser(expandvars(d))
        v = listdir(d)
        self._temps = dict()
        if isinstance(v, list) and len(v) > 0:
            for i in v:
                with open(join(d, i)) as f:
                    self._temps[i] = Template(f.read())
        return self._temps

    def load_from(self, d):
        if not isinstance(d, dict):
            raise ValueError("load_from: parameter must be a dict")
        if "_" in d:
            self.lock = True
        self._config = {
            "build": {
                "bins": dict(),
                "options": dict(),
                "generators": dict(),
                "support": {"rc": dict(), "sign": dict()},
            },
            "config": {"log": dict()},
        }
        _cfg_build(self._config["build"], d.get("build"))
        _cfg_base(self._config["config"], d.get("config"))

    def get(self, n, default=None):
        if self._config is None:
            raise ValueError("get: options was not loaded")
        if not nes(n):
            raise KeyError("get: key was not a non-empty string")
        if "." not in n:
            return self._config.get(n.lower(), default)
        v = n.lower().split(".")
        if len(v) == 0 or v[0] not in self._config:
            raise KeyError(n)
        if len(v) == 1:
            return self._config[v[0]]
        p = self._config[v[0]]
        for x in range(1, len(v) - 1):
            if v[x] not in p:
                raise KeyError(n)
            p = p[v[x]]
            if not isinstance(p, dict):
                raise KeyError(n)
        if not isinstance(p, dict):
            raise KeyError(n)
        return p.get(v[-1], default)

    def get_rc(self, n, default=None):
        return self._get("build", "support", "rc", n, default)

    def generators(self, sel, d=None):
        if self._gens is not None:
            return self._gens
        if self._config is None:
            raise ValueError("generators: options was not loaded")
        if isinstance(d, str) and d:
            self._gens = load_generators(d)
        else:
            self._gens = load_generators(self._config["config"]["generator_dir"])
        for k, v in self._gens.items():
            if sel is None or k == sel:
                if k not in self._config["build"]["generators"]:
                    self._config["build"]["generators"][k] = dict()
                v.config_load(self._config["build"]["generators"][k])
        return self._gens

    def get_bin(self, n, default=None):
        return self._get("build", "bins", n, None, default)

    def get_sign(self, n, default=None):
        return self._get("build", "support", "sign", n, default)

    def _get(self, m, c, e, n, default):
        if self._config is None:
            raise ValueError("get: options was not loaded")
        if c is None:
            return self._config.get(m, default)
        if m not in self._config or not isinstance(self._config[m], dict):
            raise KeyError(f"{m}")
        if e is None:
            return self._config[m].get(c, default)
        if c not in self._config[m] or not isinstance(self._config[m][c], dict):
            raise KeyError(f"{m}.{c}")
        if n is None:
            return self._config[m][c].get(e, default)
        if e not in self._config[m][c] or not isinstance(self._config[m][c][e], dict):
            raise KeyError(f"{m}.{c}.{e}")
        return self._config[m][c][e].get(n, default)

    def get_build(self, n, default=None):
        return self._get("build", n, None, None, default)

    def get_option(self, n, default=None):
        return self._get("build", "options", n, None, default)

    def get_support(self, n, default=None):
        return self._get("build", "support", n, None, default)

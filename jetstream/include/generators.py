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

from glob import glob
from sys import stderr
from importlib.util import spec_from_file_location, module_from_spec
from os.path import dirname, expanduser, expandvars, isdir, join, basename


def _callable(m, n):
    try:
        f = getattr(m, n)
        if callable(f):
            return f
    except AttributeError:
        pass
    try:
        f = getattr(m, n.title())
        if callable(f):
            return f
    except AttributeError:
        pass
    try:
        f = getattr(m, n.upper())
        if callable(f):
            return f
    except AttributeError:
        pass
    if "_" in n:
        try:
            f = getattr(m, n.title().replace("_", ""))
            if callable(f):
                return f
        except AttributeError:
            pass
    return None


def load_generators(base_dir):
    if not isinstance(base_dir, str) or len(base_dir) == 0:
        d = join(dirname(dirname(__file__)), "generators")
    else:
        d = expanduser(expandvars(base_dir))
    if not isdir(d):
        raise ValueError(f'load_generators: generator path "{d}" is not a directory')
    g = dict()
    for i in glob(join(d, "*.py"), recursive=False):
        if not i.endswith(".py"):
            continue
        n = basename(i)[:-3].lower()
        if n[0] == "_":
            n = n[1:]
        if n in g:
            raise ValueError(f'load_generators: duplicate generator entry "{n}" found')
        try:
            k = spec_from_file_location(n, i)
            m = module_from_spec(k)
            k.loader.exec_module(m)
            del k
            f = _callable(m, n)
            del m
            if not callable(f):
                continue
            try:
                c = f()
            except TypeError:
                continue
            del f
            try:
                v = getattr(c, "config_name")
                if callable(v):
                    v = v()
                if not isinstance(v, str) or len(v) == 0:
                    v = None
            except (TypeError, AttributeError):
                v = None
            g[n] = Generator(n, c, v)
            del v
        except (SyntaxError, ImportError) as err:
            print(f'Loading Generator "{i}" failed: {err}!', file=stderr)
    del d
    return g


class Generator(object):
    __slots__ = ("_obj", "_name", "_base")

    def __init__(self, name, obj, base):
        self._obj = obj
        self._base = base
        self._name = name.lower()

    def name(self):
        if self._base is not None:
            return f"{self._name} [{self._base}]"
        return self._name

    def check(self, cfg):
        f = self._try_callable("check")
        if not callable(f):
            return
        try:
            f(self._get_config(cfg))
        except Exception as err:
            raise ValueError(
                f'generator "{self.name()}" function "check": {err}'
            ) from err
        del f

    def args_help(self):
        f = self._try_callable("args_help")
        if not callable(f):
            return None
        try:
            return f()
        except Exception as err:
            raise ValueError(
                f'generator "{self.name()}" function "args_help": {err}'
            ) from err

    def config_load(self, cfg):
        f = self._try_callable("config_load")
        if not callable(f):
            return
        try:
            f(self._get_config(cfg, True))
        except Exception as err:
            raise ValueError(
                f'generator "{self.name()}" function "config_load": {err}'
            ) from err
        del f

    def _try_callable(self, n):
        try:
            f = getattr(self._obj, n)
            if not callable(f):
                return
            return f
        except AttributeError:
            pass
        return None

    def args_pre(self, parser):
        f = self._try_callable("args_pre")
        if not callable(f):
            return
        try:
            f(parser)
        except Exception as err:
            raise ValueError(
                f'generator "{self.name()}" function "args_pre": {err}'
            ) from err
        del f

    def args_post(self, cfg, args):
        f = self._try_callable("args_post")
        if not callable(f):
            return
        try:
            f(self._get_config(cfg), args)
        except Exception as err:
            raise ValueError(
                f'generator "{self.name()}" function "args_post": {err}'
            ) from err
        del f

    def print_options(self, cfg, file):
        f = self._try_callable("print_options")
        if not callable(f):
            return
        try:
            f(self._get_config(cfg), cfg, file)
        except TypeError:
            pass
        del f

    def _get_config(self, cfg, make=False):
        if self._base is not None:
            if make and self._base not in cfg.get("build.generators"):
                cfg.set(f"build.generators.{self._base}", dict())
            return cfg.get(f"build.generators.{self._base}")
        if make and self._name not in cfg.get("build.generators"):
            cfg.set(f"build.generators.{self._name}", dict())
        return cfg.get(f"build.generators.{self._name}")

    def run(self, cfg, base, workspace, templates):
        f = self._try_callable("run")
        if not callable(f):
            return None
        try:
            return f(self._get_config(cfg), base, workspace, templates)
        except Exception as err:
            raise ValueError(
                f'generator "{self.name()}" function "run": {err}'
            ) from err

    def run_cgo(self, export, cfg, base, workspace, templates):
        f = self._try_callable("run_cgo")
        if not callable(f):
            raise ValueError(f'generator "{self.name()}" does not support CGO')
        try:
            return f(export, self._get_config(cfg), base, workspace, templates)
        except Exception as err:
            raise ValueError(
                f'generator "{self.name()}" function "run_cgo": {err}'
            ) from err

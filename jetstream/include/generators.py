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
            g[n] = Generator(n, c)
        except (SyntaxError, ImportError) as err:
            print(f'Loading Generator "{i}" failed: {err}!', file=stderr)
    del d
    return g


class Generator(object):
    __slots__ = ("_obj", "name")

    def __init__(self, name, obj):
        self._obj = obj
        self.name = name.lower()

    def check(self, cfg):
        f = self._try_callable("check")
        if not callable(f):
            return
        try:
            f(cfg.get(f"build.generators.{self.name}"))
        except Exception as err:
            raise ValueError(
                f'generator "{self.name}" function "check": {err}'
            ) from err

    def args_help(self):
        f = self._try_callable("args_help")
        if not callable(f):
            return None
        try:
            return f()
        except Exception as err:
            raise ValueError(
                f'generator "{self.name}" function "args_help": {err}'
            ) from err

    def config_load(self, cfg):
        f = self._try_callable("config_load")
        if not callable(f):
            return
        try:
            f(cfg)
        except Exception as err:
            raise ValueError(
                f'generator "{self.name}" function "config_load": {err}'
            ) from err

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
                f'generator "{self.name}" function "args_pre": {err}'
            ) from err

    def args_post(self, cfg, args):
        f = self._try_callable("args_post")
        if not callable(f):
            return
        try:
            f(cfg.get(f"build.generators.{self.name}"), args)
        except Exception as err:
            raise ValueError(
                f'generator "{self.name}" function "args_post": {err}'
            ) from err

    def print_options(self, cfg, file):
        f = self._try_callable("print_options")
        if not callable(f):
            return
        try:
            f(cfg.get(f"build.generators.{self.name}"), cfg, file)
        except TypeError:
            pass

    def run(self, cfg, base, workspace, templates):
        f = self._try_callable("run")
        if not callable(f):
            return None
        try:
            return f(
                cfg.get(f"build.generators.{self.name}"), base, workspace, templates
            )
        except Exception as err:
            raise ValueError(f'generator "{self.name}" function "run": {err}') from err

    def run_cgo(self, export, cfg, base, workspace, templates):
        f = self._try_callable("run_cgo")
        if not callable(f):
            raise ValueError(f'generator "{self.name}" does not support CGO')
        try:
            return f(
                export,
                cfg.get(f"build.generators.{self.name}"),
                base,
                workspace,
                templates,
            )
        except Exception as err:
            raise ValueError(
                f'generator "{self.name}" function "run_cgo": {err}'
            ) from err

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

from string import digits
from base64 import b64decode
from datetime import datetime
from argparse import BooleanOptionalAction
from os.path import isfile, expanduser, expandvars


def str_lower(v):
    return str(v).lower()


def is_date(empty=False):
    def _check_func(v):
        if not isinstance(v, str):
            raise ValueError("value is not a string")
        if not empty and len(v) == 0:
            raise ValueError("value cannot be empty")
        if empty:
            return
        datetime.fromisoformat(v)

    return _check_func


def is_int(min=None, max=None):
    def _check_func(v):
        if not isinstance(v, int):
            raise ValueError("value is not a integer")
        if min is not None and v < min:
            raise ValueError(f'value "{v}" cannot be less than "{min}"')
        if max is None or v < max:
            return
        raise ValueError(f'value "{v}" cannot be greater than "{max}"')

    return _check_func


def is_file(empty=False, f=isfile):
    def _check_func(v):
        if not isinstance(v, str):
            raise ValueError("value is not a string")
        if not empty and len(v) == 0:
            raise ValueError("string value cannot be empty")
        if len(v) == 0:
            return
        if f(expanduser(expandvars(v))):
            return
        raise ValueError(f'file "{v}" does not exist')

    return _check_func


def is_str_list(empty_list=False, empty=False, min=0, max=None):
    def _check_func(v):
        if not isinstance(v, list):
            raise ValueError("value is not a list")
        if not empty_list and len(v) == 0:
            raise ValueError("list cannot be empty")
        for i in v:
            if not isinstance(i, str):
                raise ValueError("list can only contain strings")
            if not empty and len(i) == 0:
                raise ValueError("list entry value cannot be empty")
            if not empty and len(i) < min:
                raise ValueError(f"list entry length cannot be less than {min}")
            if max is not None and len(i) > max:
                raise ValueError(f"list entry length cannot be greater than {max}")

    return _check_func


def is_str(empty=False, min=0, max=None, b64=False, choices=None, ft=False):
    def _check_func(v):
        if not isinstance(v, str):
            raise ValueError("value is not a string")
        if not empty and len(v) == 0:
            raise ValueError("value cannot be empty")
        if not empty and len(v) < min:
            raise ValueError(f"length cannot be less than {min}")
        if max is not None and len(v) > max:
            raise ValueError(f"length cannot be greater than {max}")
        if isinstance(choices, (str, list, tuple, dict)) and v not in choices:
            raise ValueError(f'value "{v}" is not valid')
        if ft and len(v) > 0 and v[0] in digits:
            raise ValueError(f'value "{v}" cannot start with a number')
        if not b64:
            return
        b64decode(v, validate=True)

    return _check_func


class Manager(object):
    __slots__ = ("_items", "_name")

    def __init__(self, name):
        self._name = name
        self._items = list()

    def init(self, config):
        for i in self._items:
            i._init(config)

    def prep(self, parser):
        for i in self._items:
            i._prep(self._name, parser)

    def verify(self, config):
        for i in self._items:
            i._verify(config)

    def parse(self, config, results):
        for i in self._items:
            i._parse(self._name, config, results)

    def add(self, name, args, default, check=None, type=None, nargs=None, action=None):
        self._items.append(_Option(name, args, check, default, type, nargs, action))


class _Option(object):
    def __init__(self, name, args, check, default, type, nargs, action):
        if not isinstance(name, str) or len(name) == 0:
            raise ValueError("name must be a non empty string")
        if args is not None:
            if not isinstance(args, (list, tuple)):
                raise ValueError("args can only be a list or tuple type")
            for i in args:
                if not isinstance(i, str) or len(i) == 0:
                    raise ValueError("args values must be non empty strings")
        if type is not None and not callable(type):
            raise ValueError("type must be a function type")
        if check is not None and not callable(check):
            raise ValueError("checker must be a function type")
        self._name = name
        self._args = args
        self._type = type
        self._nargs = nargs
        self._check = check
        self._action = action
        self._default = default

    def _init(self, config):
        if self._name in config:
            return
        config[self._name] = self._default

    def _verify(self, config):
        if self._name not in config:
            raise KeyError(f'missing "{self._name}" config value')
        v = config[self._name]
        try:
            if v is not None and callable(self._type):
                v = self._type(v)
            if callable(self._check):
                self._check(v)
        except Exception as err:
            raise ValueError(f"{self._name}: {err}") from err
        config[self._name] = v
        del v

    def _prep(self, name, parser):
        if self._action is not None and isinstance(self._action, str):
            return parser.add_argument(
                *self._args,
                type=self._type,
                nargs=self._nargs,
                action=self._action,
                default=self._default,
                dest=f"{name}_{self._name}",
            )
        parser.add_argument(
            *self._args,
            type=self._type,
            action=self._action,
            dest=f"{name}_{self._name}",
            default=None if self._action == BooleanOptionalAction else self._default,
        )

    def _parse(self, name, config, results):
        try:
            v = getattr(results, f"{name}_{self._name}")
        except AttributeError:
            return
        if self._action == BooleanOptionalAction:
            if v is None:
                return
        elif v == self._default:
            return
        try:
            if v is not None and callable(self._type):
                v = self._type(v)
        except Exception as err:
            raise ValueError(f"{self._name}: {err}") from err
        config[self._name] = v
        del v

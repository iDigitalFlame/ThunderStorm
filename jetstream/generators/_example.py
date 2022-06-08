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


class _Example(object):
    def check(self, cfg):
        pass

    def argparse_help(self):
        return "helptext"

    def config_load(self, cfg):
        pass

    def argparse_pre(self, parser):
        pass

    def argparse_post(self, cfg, args):
        pass

    def print_options(self, cfg, root, file):
        pass

    def run(self, cfg, base, workspace, templates):
        return ".go source file path"

    def run_cgo(self, export, cfg, base, workspace, templates):
        return (".c CGO source file path", "cgo import name")

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

from os import getcwd
from os.path import join
from include.util import nes
from include.options import Options, try_find_bin, LEVELS
from argparse import ArgumentParser, BooleanOptionalAction


def _split_tags(v):
    r = list()
    for i in v:
        if isinstance(i, str) and i:
            _split_tags_str(r, i)
            continue
        if isinstance(i, list) and len(i) > 0:
            for x in i:
                if not isinstance(x, str) or not x:
                    continue
                _split_tags_str(r, x)
    return r


def _split_tags_str(r, v):
    if "," not in v:
        return r.append(v.strip())
    for i in v.split(","):
        r.append(i.strip())


def _insert_args_opts(a, o):
    if a.log_file:
        o.set("config.log.file", a.log_file)
    if a.log_level:
        o.set("config.log.level", LEVELS[a.log_level.lower()])
    if a.dir_templates:
        o.set("config.template_dir", a.dir_templates)
    if a.dir_generators:
        o.set("config.generator_dir", a.dir_generators)
    if a.dir_work:
        o.set("build.dir", a.dir_work)
    if a.dir_link:
        o.set("build.dir_link", a.dir_link)
    if a.bin_garble:
        o.set("build.bins.garble", try_find_bin(a.bin_garble))
    if a.bin_gcc:
        o.set("build.bins.gcc", try_find_bin(a.bin_gcc))
    if a.bin_go:
        o.set("build.bins.go", try_find_bin(a.bin_go))
    if a.bin_openssl:
        o.set("build.bins.openssl", try_find_bin(a.bin_openssl))
    if a.bin_osslsigncode:
        o.set("build.bins.osslsigncode", try_find_bin(a.bin_osslsigncode))
    if a.bin_upx:
        o.set("build.bins.upx", try_find_bin(a.bin_upx))
    if a.bin_wgcc32:
        o.set("build.bins.wgcc32", try_find_bin(a.bin_wgcc32))
    if a.bin_wgcc64:
        o.set("build.bins.wgcc64", try_find_bin(a.bin_wgcc64))
    if a.bin_wres32:
        o.set("build.bins.wres32", try_find_bin(a.bin_wres32))
    if a.bin_wres64:
        o.set("build.bins.wres64", try_find_bin(a.bin_wres64))
    if a.opt_goroot:
        o.set("build.options.goroot", a.opt_goroot)
    if isinstance(a.opt_upx, bool):
        o.set("build.options.upx", a.opt_upx)
    if isinstance(a.opt_cgo, bool):
        o.set("build.options.cgo", a.opt_cgo)
    if isinstance(a.opt_crypt, bool):
        o.set("build.options.crypt", a.opt_crypt)
    if isinstance(a.opt_strip, bool):
        o.set("build.options.strip", a.opt_strip)
    if isinstance(a.opt_garble, bool):
        o.set("build.options.garble", a.opt_garble)
    if isinstance(a.opt_compact, bool):
        o.set("build.options.compact", a.opt_compact)
    if isinstance(a.opt_tags, list) and len(a.opt_tags) > 0:
        o.set("build.options.tags", _split_tags(a.opt_tags))
    if a.sup_entry:
        o.set("build.support.cgo_export", a.sup_entry)
    if isinstance(a.sup_manifest, bool):
        o.set("build.support.manifest", a.sup_manifest)
    if isinstance(a.sign_enabled, bool):
        o.set("build.support.sign.enabled", a.sign_enabled)
    if a.sign_pfx:
        o.set("build.support.sign.pfx", a.sign_pfx)
    if a.sign_pfx_pw:
        o.set("build.support.sign.pfx_password", a.sign_pfx_pw)
    if a.sign_cert:
        o.set("build.support.sign.cert", a.sign_cert)
    if a.sign_pem:
        o.set("build.support.sign.pem", a.sign_pem)
    if a.sign_gen_target:
        o.set("build.support.sign.generate_target", a.sign_gen_target)
    if a.sign_gen_name:
        o.set("build.support.sign.generate_name", a.sign_gen_name)
    if a.sign_date:
        o.set("build.support.sign.date", a.sign_date)
    if isinstance(a.sign_date_range, (int, float)) and a.sign_date_range >= 0:
        o.set("build.support.sign.date_range", a.sign_date_range)
    if isinstance(a.rc_enabled, bool):
        o.set("build.support.rc.enabled", a.rc_enabled)
    if a.rc_file:
        o.set("build.support.rc.file", a.rc_file)
    if a.rc_json:
        o.set("build.support.rc.json", a.rc_json)
    if a.rc_icon:
        o.set("build.support.rc.icon", a.rc_icon)
    if a.rc_title:
        o.set("build.support.rc.title", a.rc_title)
    if a.rc_version:
        o.set("build.support.rc.version", a.rc_version)
    if a.rc_company:
        o.set("build.support.rc.company", a.rc_company)
    if a.rc_product:
        o.set("build.support.rc.product", a.rc_product)
    if a.rc_filename:
        o.set("build.support.rc.filename", a.rc_filename)
    if a.rc_copyright:
        o.set("build.support.rc.copyright", a.rc_copyright)


class Parser(ArgumentParser):
    def __init__(self):
        ArgumentParser.__init__(
            self,
            prog="jetstream",
            add_help=False,
            allow_abbrev=True,
            fromfile_prefix_chars=None,
        )
        self._err = None
        self.add = self.add_argument

    def _pre_setup(self):
        self.add("-C", "--clone", dest="clone", type=str)
        self.add("-c", "--config", dest="config", type=str)
        self.add("-o", "--output", dest="output", type=str)
        self.add("-G", "--generators", dest="dir_generators", type=str)
        self.add("-g", "--generator", dest="generator", type=str, default="bolt")
        self.add("-q", "--quiet", dest="quiet", action="store_true")
        # Logging Arguments
        self.add("-f", "--log-file", dest="log_file", type=str)
        self.add("-i", "--log-level", dest="log_level", type=str, choices=LEVELS.keys())
        # Directory Arguments
        self.add("-d", "--dir", dest="dir_work", type=str)
        self.add("-l", "--link", dest="dir_link", type=str)
        self.add("-t", "--templates", dest="dir_templates", type=str)
        # Build Args Arguments
        self.add("-s", "--save", dest="save", action="store_true")
        self.add("-k", "--check", dest="check", action="store_true")
        self.add("-D", "--library", dest="library", action="store_true")
        self.add("-z", "--no-clean", dest="no_clean", action="store_true")
        self.add("-r", "--read-only", dest="read_only", action="store_true")

    def error(self, message):
        self._err = message

    def parse_with_load(self):
        self._pre_setup()
        # Parse the args initially. We need the config to load the generators
        # to add their args
        a, _ = super(__class__, self).parse_known_args()
        o = Options()
        # We /should/ have a config or at least a default one.
        if isinstance(a.clone, str) and a.clone:
            o.load(a.clone)
        elif isinstance(a.config, str) and a.config:
            o.load(a.config)
        else:
            o.load(None)
        n = a.generator.lower()
        e = o.generators(n, a.dir_generators)
        if e is None or n not in e:
            raise ValueError(f'check: generator "{n}" was not found')
        g = e[n]
        del e
        self._post_setup(n, g)
        del a, n
        try:
            r = super(__class__, self).parse_args()
        except Exception as err:
            raise ValueError(err) from err
        if r.help:
            return None, g, None, True
        if nes(self._err):
            raise ValueError(self._err)
        if not r.read_only and r.config and not o.lock:
            o.save(r.config)
        _insert_args_opts(r, o)
        o.vet()
        if not nes(r.output):
            r.output = join(getcwd(), "result")
        g.argparse_post(o, r)
        if r.save and r.config:
            o.save(r.config)
        r.target = r.target[0].lower()
        return o, g, r, False

    def _post_setup(self, name, gen):
        self.add("-h", "--help", dest="help", action="store_true")
        # Config [build.bin] Arguments
        self.add("--bin-garble", dest="bin_garble", type=str)
        self.add("--bin-gcc", dest="bin_gcc", type=str)
        self.add("--bin-go", dest="bin_go", type=str)
        self.add("--bin-openssl", dest="bin_openssl", type=str)
        self.add("--bin-osslsigncode", dest="bin_osslsigncode", type=str)
        self.add("--bin-upx", dest="bin_upx", type=str)
        self.add("--bin-wgcc32", dest="bin_wgcc32", type=str)
        self.add("--bin-wgcc64", dest="bin_wgcc64", type=str)
        self.add("--bin-wres32", dest="bin_wres32", type=str)
        self.add("--bin-wres64", dest="bin_wres64", type=str)
        # Config [build.options] Arguments
        self.add("--goroot", dest="opt_goroot", type=str)
        self.add("--upx", dest="opt_upx", action=BooleanOptionalAction)
        self.add("--cgo", dest="opt_cgo", action=BooleanOptionalAction)
        self.add("--crypt", dest="opt_crypt", action=BooleanOptionalAction)
        self.add("--strip", dest="opt_strip", action=BooleanOptionalAction)
        self.add("--garble", dest="opt_garble", action=BooleanOptionalAction)
        self.add("--compact", dest="opt_compact", action=BooleanOptionalAction)
        self.add("--tags", dest="opt_tags", action="append", nargs="*", type=str)
        # Config [build.support] Arguments
        self.add("-e", "--entry", dest="sup_entry", type=str)
        self.add("--manifest", dest="sup_manifest", action=BooleanOptionalAction)
        # Config [build.support.sign] Arguments
        self.add("--sign", dest="sign_enabled", action=BooleanOptionalAction)
        self.add("--pfx", dest="sign_pfx", type=str)
        self.add("--pfx-pw", dest="sign_pfx_pw", type=str)
        self.add("--cert", dest="sign_cert", type=str)
        self.add("--pem", dest="sign_pem", type=str)
        self.add("--spoof", dest="sign_gen_target", type=str)
        self.add("--spoof-name", dest="sign_gen_name", type=str)
        self.add("--date", dest="sign_date", type=str)
        self.add("--date-range", dest="sign_date_range", type=int)
        # Config [build.support.rc] Arguments
        self.add("--rc", dest="rc_enabled", action=BooleanOptionalAction)
        self.add("--rc-file", dest="rc_file", type=str)
        self.add("--rc-json", dest="rc_json", type=str)
        self.add("--rc-icon", dest="rc_icon", type=str)
        self.add("--rc-title", dest="rc_title", type=str)
        self.add("--rc-version", dest="rc_version", type=str)
        self.add("--rc-company", dest="rc_company", type=str)
        self.add("--rc-product", dest="rc_product", type=str)
        self.add("--rc-filename", dest="rc_filename", type=str)
        self.add("--rc-copright", dest="rc_copyright", type=str)
        g = self.add_argument_group(name)
        g.add = g.add_argument
        gen.argparse_pre(g)
        del g
        self.add(nargs=1, dest="target", type=str)

    def print_help(self, file=None, gen=None):
        if gen is not None:
            gen.argparse_help()
        print("helptext")

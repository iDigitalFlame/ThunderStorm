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

from os import getcwd
from include.util import nes
from sys import argv, stderr
from os.path import join, basename
from include.options import Options, try_find_bin, LEVELS
from argparse import ArgumentParser, BooleanOptionalAction

_HELP_TEXT = """ JetStream: ThunderStorm Builder
Part of the |||||| ThunderStorm Project (https://dij.sh/ts)
(c) 2019 - 2023 iDigitalFlame

{proc} [-c config] [-C clone] [-g generator] [-o output] [various options] target

Required Arguments
  target                               The Operating System and Architecture to
                                         build for. This value matches the "GOOS/GOARCH"
                                         string connotation. (ex: windows/amd64, linux/ppc).

Basic Arguments
  -h                                   Show this help text and exit.
  --help
  -c                  <config_file>    Path to the configuration file to use.
  --config                               Defaults to "jetstream.conf".
  -C                  <template_file>  Load the initial configuration from this
  --clone                                file and save the modified results to
                                         the config file path (if supplied). This
                                         file is not modified.
  -r                                   Do not re-lint/format the configuration
  --read-only                            file supplied. This will also overrite
                                         the "save" argument. If a "_" exists in
                                         the JSON as a top-level key, this argument
                                         is inferred.
  -s                                   Save the changes made by arguments to the
  --save                                 supplied configuration file (if it exists).
  -g                  <generator_name> Specify the Generator to load and use. This
  --generator                            defaults to "bolt" (The Bolt Generator)
                                         if omitted.
  -G                  <generator_dir>  Specify/Override the directory to load
  --generators                           Generator files from.
  -o                  <output_file>    Specify the path to output the built binary
  --output                               to. This will default to "result.<ext>"
                                         when omitted (<ext> being dependent on
                                         the target type).
  -k                                   Do not run and only check/print the configuration
  --check                                then exit.
  -t                  <templates_dir>  Specify/Override the directory to load
  --templates                            Template files from.

Output Arguments
  -q                                   Do not print out the configuration. Can be
  --quiet                                used with '-k' to do a silent check based
                                         on the exit code.
  -f                  <log_file>       Specify/Override an output file to log messages
  --log-file                             to. If empty/omitted and not set, standard out
                                         is used.
  -i                  <log_level>      Specify/Override the logging level used. Takes
  --log-level                            a string name of the level. If omitted and not
                                         set, the "INFO" level is used.

Build Arguments
  -d                  <work_dir>       Specify/Override the build directory to use.
  --dir                                  If empty/omitted and not set, a temporary
                                         directory is used.
  -l                  <link_dir>       Specify/Override the link directory to use.
  --link                                 The linked dir will have a symlink of the
                                         build directory (above) placed in it. This
                                         is used during Go build operations and will
                                         be changed into when building. Useful for
                                         building packages in a specific workspace.
  -z                                   Do not remove the build directory or it's
  --no-clean                             contents when finished.
  -D                                   Build in library (DLL on Windows .so on nix)
  --library                              mode. Currently only supports CGO builds.

Options Override Arguments
 These options can change the way the build occurs. This will NOT be saved to the
 configuration file unless the "-s/--save" argument is supplied.

 Binary Options
   --bin-go           <binary_path>    Specify/Override the Golang binary path.
   --bin-gcc          <binary_path>    Specify/Override the *nix GCC binary path.
   --bin-upx          <binary_path>    Specify/Override the UPX binary path.
   --bin-garble       <binary_path>    Specify/Override the Golang Garble binary path.
   --bin-wgcc32       <binary_path>    Specify/Override the Windows GCC x86 (MinGW)
                                         binary path.
   --bin-wgcc64       <binary_path>    Specify/Override the Windows GCC x64 (MinGW)
                                         binary path.
   --bin-wres32       <binary_path>    Specify/Override the Windows Resource x86
                                         (MinGW) binary path.
   --bin-wres64       <binary_path>    Specify/Override the Windows Resource x64
                                         (MinGW) binary path.
   --bin-openssl      <binary_path>    Specify/Override the Openssl binary path.
   --bin-osslsigncode <binary_path>    Specify/Override the OsslSignCode (Code Sign)
                                         binary path.

 Build Settings Options
   --tags             <build_tags>     Specify/Override the Go build tags used.
                                         These values may be changed by the Generator
                                         used. The first tag may be prefixed with
                                         a "+" to indicate that the new tags should
                                         be appended to the current ones instead of
                                         the default action of replacing them.
   --goroot           <goroot_dir>     Specify/Override the GOROOT directory. The
                                         default or empty value will be taken from
                                         the current environment. This directory will
                                         be the one copied if "compact" is enabled.
   --upx                               Enable the UPX packer.
   --no-upx                            Disable the UPX packer.
   --cgo                               Enable CGO for building.
   --no-cgo                            Disable CGO for building.
   --crypt                             Enable the Crypt generator to obscure strings
                                         inside the resulting binary.
   --no-crypt                          Disable the Crypt generator.
   --strip                             Enable the Strip packer/generator.
   --no-strip                          Disable the Strip packer/generator.
   --grable                            Enable using Garble for building.
   --no-garble                         Disable using Garble for building.
   --compact                           Enable the "compact" GOROOT. This will
                                         strip and remove un-needed functions
                                         and packages in the runtime and disables
                                         some functionality. See dij.sh/tinyroot
                                         for more information.
   --no-compact                        Disable the "compact" GOROOT.

 Support Options
   -e                 <entry_name>     Specify/Override the function name for the
   --entry                               CGO entry point function. If empty/omitted,
                                         the function name is randomized.
   --manifest                          Enable generating a Windows version manifest
                                         for Windows binaries. This has NO effect
                                         if CGO is disabled.
   --no-manifest                       Disable generating a Windows version manifest.

  Signing Arguments
   --sign                              Enable signing binaries. Requires a PFX,
                                         certificate pair (CERT+PEM) or a Spoof target.
   --no-sign                           Disable signing binaries.
   --pfx              <pfx_file>       Specify/Override the PFX file to be used for
                                         signing. PFX certificates take precedence
                                         over any other signing methods.
   --pfx-pw           <pfx_password>   Specify/Override the PFX password to be used for
                                         the supplied PFX file or encoded data. Ignored
                                         if no PFX file/data is supplied.
   --cert             <cert_file>      Specify/Override the Certificate file to be used
                                         for signing. This will only work if a paired
                                         PEM file/data is also supplied. CERT+PEM takes
                                         precedence over Spoofing.
   --pem              <pem_file>       Specify/Override the Private Key file to be used
                                         for signing. This will only work if a paired
                                         Certificate file/data is also specified. CERT+PEM
                                         takes precedence over Spoofing.
   --spoof            <spoof_url>      Specify/Override an Internet hostname to be used
                                         for Certificate grabbing and spoofing. The
                                         name of the Certificate will not be changed unless
                                         the "spoof-name" is specified or in the config.
                                         Will not be used if another valid signing
                                         mechanism exists.
   --spoof-name       <spoof_name>     Specify/Override the name of the spoofed Certificate.
                                         defaults to leaving the name unchanged if
                                         empty/omitted. Only takes effect if spoofing is
                                         enabled and used.
   --date             <iso_datetime>   Specify/Override a signing date to be used in an ISO
                                         string format. This will change the signing date
                                         used. If empty/omitted, the current date will be
                                         used. Only takes effect if spoofing is enabled and
                                         used.
   --date-range       <days>           Specify/Override a signing date that will be random
                                         (+ [only if date < current + days]/-) days from the
                                         supplied date. If empty/omitted, the current date
                                         will be used. Only takes effect if spoofing is
                                         enabled and used.

  Resource Arguments
   --rc                                Enable generating binary resource manifests.
                                         Only takes effect if CGO is enabled.
   --no-rc                             Disable generating binary resource manifests.
   --rc-file          <raw rc_file>    Specify a path to a raw resource (.rc) file to
                                         be used. This will take precedence over any
                                         other resource arguments and will not be parsed.
   --rc-json          <json rc_file>   Specify a path to a JSON-formatted file that contains
                                         the resource configuration. (Similar to the JetStream
                                         config file).  This will take precedence over any
                                          non-raw resource arguments and will fail if the syntax
                                          or values are invalid.
   --rc-icon          <icon_file>      Specify/Override the path to the icon file to be used.
                                         If empty/omitted, it will default to no icon.
   --rc-title         <title>          Specify/Override the RC Title value to be used.
                                         This will take precedence over any value set in the
                                         JetStream config.
   --rc-version       <version>        Specify/Override the RC Version value to be used.
                                         This will take precedence over any value set in the
                                         JetStream config.
   --rc-company       <company>        Specify/Override the RC Company value to be used.
                                         This will take precedence over any value set in the
                                         JetStream config.
   --rc-product       <product>        Specify/Override the RC Product value to be used.
                                         This will take precedence over any value set in the
                                         JetStream config.
   --rc-filename      <filename>       Specify/Override the RC Filename value to be used.
                                         This will take precedence over any value set in the
                                         JetStream config. If no value is set or omitted, it
                                         will default to the output file name.
   --rc-copyright     <copyright>      Specify/Override the RC Copyright value to be used.
                                         This will take precedence over any value set in the
                                         JetStream config.
"""


def _split_tags(v):
    r = list()
    for i in v:
        if isinstance(i, str) and i:
            _split_tags_str(r, i)
            continue
        if not isinstance(i, list) or len(i) == 0:
            continue
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


def insert_args_opts(a, o):
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
        # If the first tag starts with a "+", add the tags instead of replacing
        # them.
        t = _split_tags(a.opt_tags)
        if nes(t[0]) and t[0][0] == "+":
            v, t[0] = o.get("build.options.tags"), t[0][1:]
            if v is None or len(v) == 0:
                o.set("build.options.tags", t)
            else:
                v.extend(t)
                o.set("build.options.tags", v)
            del v
        else:
            o.set("build.options.tags", t)
        del t
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

    @staticmethod
    def with_load():
        return Parser().parse_with_load()

    def _pre_setup(self):
        self.add("-C", "--clone", dest="clone", type=str)
        self.add("-c", "--config", dest="config", type=str)
        self.add("-o", "--output", dest="output", type=str)
        self.add("-h", "--help", dest="help", action="store_true")
        self.add("-q", "--quiet", dest="quiet", action="store_true")
        self.add("-g", "--generator", dest="generator", type=str, default="bolt")
        # Logging Arguments
        self.add("-f", "--log-file", dest="log_file", type=str)
        self.add("-i", "--log-level", dest="log_level", type=str, choices=LEVELS.keys())
        # Directory Arguments
        self.add("-d", "--dir", dest="dir_work", type=str)
        self.add("-l", "--link", dest="dir_link", type=str)
        self.add("-t", "--templates", dest="dir_templates", type=str)
        self.add("-G", "--generators", dest="dir_generators", type=str)
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
            try:
                o.load(a.clone)
            except ValueError as err:
                raise ValueError(f'Clone file "{a.clone}" parse error: {err}') from err
        elif isinstance(a.config, str) and a.config:
            try:
                o.load(a.config)
            except ValueError as err:
                raise ValueError(
                    f'Config file "{a.config}" parse error: {err}'
                ) from err
        else:
            try:
                o.load(None)
            except ValueError as err:
                raise ValueError(f"Config file parse error: {err}") from err
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
        elif not r.config and not r.clone:
            o.save(join(getcwd(), "jetstream.conf"))
        insert_args_opts(r, o)
        o.vet()
        if not nes(r.output):
            r.output = join(getcwd(), "result")
        g.args_post(o, r)
        if r.save and r.config:
            o.save(r.config)
        r.target = r.target[0].lower()
        return o, g, r, False

    def _post_setup(self, name, gen):
        # Config [build.bin] Arguments
        self.add("--bin-go", dest="bin_go", type=str)
        self.add("--bin-gcc", dest="bin_gcc", type=str)
        self.add("--bin-upx", dest="bin_upx", type=str)
        self.add("--bin-wgcc32", dest="bin_wgcc32", type=str)
        self.add("--bin-wgcc64", dest="bin_wgcc64", type=str)
        self.add("--bin-wres32", dest="bin_wres32", type=str)
        self.add("--bin-wres64", dest="bin_wres64", type=str)
        self.add("--bin-garble", dest="bin_garble", type=str)
        self.add("--bin-openssl", dest="bin_openssl", type=str)
        self.add("--bin-osslsigncode", dest="bin_osslsigncode", type=str)
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
        self.add("--rc-copyright", dest="rc_copyright", type=str)
        g = self.add_argument_group(name)
        g.add = g.add_argument
        gen.args_pre(g)
        del g
        self.add(nargs=1, dest="target", type=str)

    @staticmethod
    def print_help(gen=None, file=stderr):
        print(_HELP_TEXT.format(proc=basename(argv[0])), file=file)
        if gen is not None:
            print(f'Current Generator "{gen.name()}":')
            try:
                print(gen.args_help(), file=stderr)
            except Exception:
                pass
        else:
            print(file=stderr)
        exit(2)

#!/usr/bin/python3
# Copyright (C) 2020 - 2022 iDigitalFlame
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
from re import compile
from copy import deepcopy
from shutil import rmtree
from sys import stderr, argv
from include.util import nes
from json import loads, dumps
from secrets import token_bytes
from include.sign import make_pki
from collections import namedtuple
from random import randint, sample
from include.sentinel import Sentinel
from base64 import b64decode, b64encode
from tempfile import mkdtemp, gettempdir
from include.mangle import Mangler, Path
from include.args import insert_args_opts
from os import environ, makedirs, listdir, getcwd
from datetime import datetime, timedelta, timezone
from include.jetstream import JetStream, which_empty
from include.builder import tiny_root, make_cert_target
from argparse import ArgumentParser, BooleanOptionalAction, Namespace
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_EXCEPTION
from os.path import isdir, join, isfile, expanduser, expandvars, basename
from include.values import Pki, Build, Override, Generator, WINDOWS, UNIX
from include.options import LEVELS, Logger, Options, vet_list_strs, vet_str_exists

_HELP_TEXT = """ CloudSeed: ThunderStorm Deployment Pipeline
Part of the |||||| ThunderStorm Project (https://dij.sh/ts)
(c) 2019 - 2022 iDigitalFlame

{proc} [-c config] [-g generator] [-o output] [various options] target

Required Arguments
  target                               The Operating System and Architecture to
                                         build for. This value matches the "GOOS/GOARCH"
                                         string connatation. (ex: windows/amd64, linux/ppc).

Basic Arguments
  -h                                   Show this help text and exit.
  --help
  -c                  <config_file>    Path to the configuration file to use.
  --config                               Defaults to "cloudseed.conf".
  -G                  <generator_dir>  Specify/Overrite the directory to load
  --generators                           Generator files from.
  -o                  <output_file>    Specify the path to output the generated
  --json                                 JSON file to.
  -O                  <output_dir>     Specify the path to output the generated
  --dir                                  binary file results to.
  -t                  <templates_dir>  Specify/Overrite the directory to load
  --templates                            Template files from.

CloudSeed Specific Arguments
  -x                  <config_file>
  --jetstream
  -n                  <paths_json>
  --paths
  -I                  <icons_dir>
  --icons

Output Arguments
  -f                  <log_file>       Specify/Overrite an output file to log messages
  --log-file                             to. If empty/omitted and not set, standard out
                                         is used.
  -i                  <log_level>      Specify/Overrite the logging level used. Takes
  --log-level                            a string name of the level. If omitted and not
                                         set, the "INFO" level is used.

Build Arguments
  --debug                              Do not cleanup the building directories.
                                         This can be used to diagnose a build failure
                                         as the files will NOT be removed upon
                                         completion.
  -l                  <link_dir>       Specify/Overrite the link dirrectory to use.
  --link                                 The linked dir will have a symlink of the
                                         build directory (above) placed in it. This
                                         is used during Go build operations and will
                                         be changed into when building. Useful for
                                         building packages in a specific workspace.

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
                                         used.
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
   --rc-title         <title>
   --rc-version       <version>
   --rc-company       <company>
   --rc-product       <product>
   --rc-filename      <filename>
   --rc-copyright     <copyright>
"""

_GARBLE = compile("garble-shared([0-9]+)")
_GO_BUILD = compile("go-build([0-9]+)")

_BUILD_TYPES = ["bolt", "flurry", "extra"]
_BUILD_TYPE_BOLT = 0
_BUILD_TYPE_EXTRA = 2
_BUILD_TYPE_FLURRY = 1

_Bolt = namedtuple("Bolt", ["builder", "file"])
_Sentinel = namedtuple("Sentinel", ["base", "file"])
_Flurry = namedtuple("Flurry", ["file", "sentinels"])
_Build = namedtuple("Build", ["builder", "paths", "build"])


def _cleanup_temp():
    d = gettempdir()
    for i in listdir(d):
        if len(i) < 4 or i[0] != "g":
            continue
        if _GARBLE.match(i) or _GO_BUILD.match(i):
            rmtree(join(d, i), ignore_errors=True)
            continue
    del d


def _parse_date(gen, opts):
    d = None
    if nes(gen):
        d = datetime.fromisoformat(gen)
        if nes(opts.get_sign("date")):
            v = datetime.fromisoformat(opts.get_sign("date"))
            if v < d:
                raise ValueError(
                    f'sign: date "{opts.get_sign("date")}" is before cert date "{gen}"'
                )
            del v
    r = opts.get_sign("date_range")
    if isinstance(r, int) and r > 0:
        x = timedelta(days=r)
        if d is None or (datetime.now() - x).days < r:
            d = datetime.now() - x
        del x
    del r
    if d is None:
        return d
    return d.replace(tzinfo=timezone.utc).isoformat()


class CloudSeed(object):
    __slots__ = (
        "_x",
        "log",
        "_pki",
        "_tmp",
        "_gen",
        "_opts",
        "_paths",
        "_icons",
        "_bolts",
        "_extra",
        "_titles",
        "_builds",
        "_output",
        "_mangle",
        "_process",
        "_versions",
        "_flurries",
        "_overrides",
        "_sentinels",
    )

    def __init__(self, config=None):
        self._tmp = None
        self._opts = None
        self._output = dict()
        self._builds = dict()
        self._process = list()
        self._sentinels = list()
        self._overrides = dict()
        if nes(config):
            self.load(config)

    def _build_prep(self):
        self._tmp = mkdtemp(prefix="cloudseed-")
        self.log.info(f'Setting up temp dir "{self._tmp}".')
        if nes(self._icons):
            self._opts.set("build.support.rc.icon", "")
            self._opts.set("build.support.rc.icon_multi.file", "")
            self._opts.set("build.support.rc.icon_multi.enabled", True)
            # NOTE(dij): I shouldn't have to verify this list tbh.
            self._opts.set(
                "build.support.rc.icon_multi.choices",
                glob(join(expanduser(expandvars(self._icons)), "*"), recursive=False),
            )
            if not isinstance(
                self._opts.get("build.support.rc.icon_multi.chance"), int
            ):
                self._opts.set("build.support.rc.icon_multi.chance", 2)
        if isinstance(self._titles, list) and len(self._titles) > 0:
            self._opts.set("build.support.rc.title", "")
            self._opts.set("build.support.rc.title_multi.file", "")
            self._opts.set("build.support.rc.title_multi.chance", 0)
            self._opts.set("build.support.rc.title_multi.enabled", True)
            self._opts.set("build.support.rc.title_multi.choices", self._titles)
        if isinstance(self._versions, list) and len(self._versions) > 0:
            self._opts.set("build.support.rc.version", "")
            self._opts.set("build.support.rc.version_multi.file", "")
            self._opts.set("build.support.rc.version_multi.chance", 0)
            self._opts.set("build.support.rc.version_multi.enabled", True)
            self._opts.set("build.support.rc.version_multi.choices", self._versions)
        self._output["overrides"] = dict()
        if len(self._overrides) > 0:
            for k, v in self._overrides.items():
                d = v.get()
                if nes(v.output):
                    self._output["overrides"][v.output] = d
                self.log.debug(f'Added override "{k}" with value "{d}".')
                self._opts.set(k, d)
                del d
        if self._opts.get_option("compact"):
            r = self._opts.get_option("goroot")
            if not nes(r):
                r = environ["GOROOT"]
            if not isdir(r):
                raise ValueError(f'build: GOROOT directory "{r}" is not valid')
            d = join(self._tmp, "root")
            self.log.debug(f'Building compact GOROOT from "{r}" to "{d}"..')
            tiny_root(r, d)
            self._opts.set("build.options.goroot", d)
            self._opts.set("build.options.compact", False)
            del d
        self._opts.vet()
        self._opts.generators(None)
        which_empty(self._opts)
        self._build_prep_sign()

    def _cleanup(self, debug):
        if self._builds is None:
            return
        self.log.info("Performing cleanup..")
        self._builds.clear()
        self._builds = None
        # del self._builds
        if isdir(self._tmp) and not debug:
            self.log.debug(f'Deleting working directory "{self._tmp}"..')
            try:
                rmtree(self._tmp, ignore_errors=True)
            except Exception as err:
                self.log.error(
                    f'Error deleting working directory "{self._tmp}": {err}!', err=err
                )
        self.log.debug("Deleting any existing Golang cache directories.")
        try:
            _cleanup_temp()
        except Exception as err:
            self.log.error(f"Error deleting Golang cache directories: {err}!", err=err)

    def _build_prep_sign(self):
        if self._pki.generate:
            return self._build_prep_sign_generate()
        if nes(self._pki.spoof):
            return self._build_prep_sign_spoof(self._pki.spoof, self._pki.name)
        if not nes(self._opts.get_sign("generate_target")):
            return
        self._build_prep_sign_spoof(
            self._opts.get_sign("generate_target"), self._opts.get_sign("generate_name")
        )

    def load_from_args(self, a):
        n, o = self.load_from_file(a.config, False)
        if a.jetstream:
            self._opts.load(a.jetstream)
        if a.file_icons:
            self._icons = a.file_icons
        if a.file_paths:
            self._paths = a.file_paths
        vet_str_exists("resources.paths", self._paths, null=False)
        vet_str_exists("resources.icons", self._icons, null=True, f=isdir)
        if a.log_level is not None:
            n = a.log_level
        if a.log_file is not None:
            o = a.log_file
        self.log = Logger("CloudSeed", n, o)
        del n, o

    def _check_paths(self, pathval):
        for v in self._builds.values():
            if nes(v.dir) and not pathval.valid(v.dir):
                raise ValueError(f'check: path "{v.dir}" is not valid')
            if nes(v.base) and not pathval.valid(v.base):
                raise ValueError(f'check: path "{v.base}" is not valid')

    def _build(self, osv, arch, out):
        k = None
        if nes(self._gen.key_file):
            with open(expanduser(expandvars(self._gen.key_file)), "rb") as f:
                k = f.read()
            self._opts.set("build.generators.flurry.key", "")
            self._opts.set("build.generators.flurry.key_file", "")
            self._opts.set(
                "build.generators.flurry.key_base64", b64encode(k).decode("UTF-8")
            )
        else:
            if nes(self._gen.key_b64):
                k = b64decode(self._gen.key_b64, validate=True)
            elif nes(self._gen.key):
                k = self._gen.key.encode("UTF-8")
            elif self._gen.sentinel.encrypt:
                self.log.info(
                    "No keys found, but encryption is enabled, generating new key.."
                )
                k = token_bytes(64)
            if k is not None:
                self._opts.set("build.generators.flurry.key", "")
                self._opts.set("build.generators.flurry.key_file", "")
                self._opts.set(
                    "build.generators.flurry.key_base64", b64encode(k).decode("UTF-8")
                )
        if k is None:
            self.log.info("Not encrypting Sentinel contents.")
            self._opts.set("build.generators.flurry.key", "")
            self._opts.set("build.generators.flurry.key_path", "")
            self._opts.set("build.generators.flurry.key_base64", "")
            self._output["sentinel_key"] = ""
        else:
            self._output["sentinel_key"] = b64encode(k).decode("UTF-8")
        # NOTE(dij): We do the Sentinel/Event overrides here so we can allow for
        #            overriding them if we want to later.
        self._opts.set("build.generators.flurry.linker", self._gen.linker)
        self._opts.set("build.generators.bolt.guardian", self._gen.guardian)
        self._opts.set("build.generators.flurry.guardian", self._gen.guardian)
        self._output["sentinels"] = list()
        for i in self._sentinels:
            self._output["sentinels"].append(
                {
                    "dir": i.file.dir,
                    "path": i.file.path,
                    "name": i.file.name,
                    "data": b64encode(i.base.save(None, key=k)).decode("UTF-8"),
                }
            )
        if not isdir(out):
            makedirs(out, mode=0o755, exist_ok=True)
        self._build_prep()
        self._output["results"] = list()
        self._output["builders"] = dict()
        del k
        self.log.debug("Shedding extra info that is no longer needed..")
        if isinstance(self._bolts, list):
            self._bolts.clear()
        if isinstance(self._extra, list):
            self._extra.clear()
        if isinstance(self._flurries, list):
            self._flurries.clear()
        self._sentinels.clear()
        self._overrides.clear()
        del self._sentinels, self._overrides
        del self._bolts, self._extra, self._flurries
        self.log.info("Starting builder thread pool..")
        self._x = ThreadPoolExecutor(max_workers=12, thread_name_prefix="Builder")
        w = list()
        try:
            for i in range(0, len(self._process)):
                self._build_thread(w, out, i, osv, arch, self._process[i])
            self.log.info(f"All {len(w)} thread jobs created, waiting on completion..")
            r, _ = wait(w, return_when=FIRST_EXCEPTION)
            for v in r:
                e = v.exception()
                if e is not None:
                    raise e
                del e
                x, b = v.result()
                if x is None or b is None:
                    raise RuntimeError()
                if len(self._output["overrides"]) > 0:
                    for k, v in self._output["overrides"].items():
                        x["overrides"][k] = v
                if len(self._output["builders"][b]["overrides"]) > 0:
                    for k, v in self._output["builders"][b]["overrides"].items():
                        x["overrides"][k] = v
                self._output["results"].append(x)
                self._output["builders"][b]["results"].append(x)
                del x, b
            del r
        except BaseException as err:
            self.log.error(f"Error building/waiting for threads: {err}!", err=err)
            raise err
        finally:
            del w
            self.log.info("Shutting down builder thread pool.")
            self._x.shutdown(wait=True, **{"cancel_futures": True})
            self.log.debug("Thread pool shutdown down complete!")
            del self._x

    def _generate(self, x86, pathval):
        self._check_paths(pathval)
        self._generate_sentinels(x86, pathval)
        self._generate_flurries(x86, pathval)
        self._generate_extra(x86, pathval)

    def load_from(self, d, verify=True):
        if not isinstance(d, dict):
            raise ValueError("load_from: parameter must be a dict")
        self._pki = Pki(d.get("pki"))
        self._opts = Options(d.get("jetstream"))
        if (
            "jetstream" in d
            and isinstance(d["jetstream"], dict)
            and nes(d["jetstream"].get("file"))
        ):
            self._opts.load(d["jetstream"]["file"])
        self._gen = Generator(d.get("generate"))
        if "builds" in d and isinstance(d["builds"], dict):
            for k, v in d["builds"].items():
                self._builds[k] = Build(v, k)
        if "targets" in d and isinstance(d["targets"], dict):
            self._bolts = d["targets"].get("bolts")
            self._extra = d["targets"].get("extra")
            self._flurries = d["targets"].get("flurries")
        if "overrides" in d and isinstance(d["overrides"], dict):
            for k, v in d["overrides"].items():
                self._overrides[k] = Override(v, k)
        if "resources" in d and isinstance(d["resources"], dict):
            self._icons = d["resources"].get("icons")
            self._paths = d["resources"].get("paths")
        n, m = None, None
        if len(self._builds) == 0:
            raise ValueError('"builds" is empty')
        if verify:
            if not nes(self._paths):
                raise ValueError('"resources.paths" value must be a non-empty string')
            vet_str_exists("resources.paths", self._paths, null=False)
            vet_str_exists("resources.icons", self._icons, null=True, f=isdir)
        c = 0
        if isinstance(self._bolts, list):
            vet_list_strs("targets.bolts", self._bolts, False, False)
            self._bolts = list(set(self._bolts))
            for i in self._bolts:
                if isinstance(self._extra, list) and i in self._extra:
                    raise ValueError(
                        f'"targets.bolts" build "{i}" is in "targets.extra"'
                    )
                if isinstance(self._flurries, list) and i in self._flurries:
                    raise ValueError(
                        f'"targets.bolts" build "{i}" is in "targets.flurries"'
                    )
                if i in self._builds:
                    continue
                raise ValueError(f'"targets.bolts" build "{i}" is not in "builds"')
            c += len(self._bolts)
        if isinstance(self._extra, list):
            vet_list_strs("targets.extra", self._extra, False, False)
            self._extra = list(set(self._extra))
            for i in self._extra:
                if isinstance(self._bolts, list) and i in self._bolts:
                    raise ValueError(
                        f'"targets.extra" build "{i}" is in "targets.bolts"'
                    )
                if isinstance(self._flurries, list) and i in self._flurries:
                    raise ValueError(
                        f'"targets.extra" build "{i}" is in "targets.flurries"'
                    )
                if i in self._builds:
                    continue
                raise ValueError(f'"targets.extra" build "{i}" is not in "builds"')
            c += len(self._extra)
        if isinstance(self._flurries, list):
            vet_list_strs("targets.flurries", self._flurries, False, False)
            self._flurries = list(set(self._flurries))
            for i in self._flurries:
                if isinstance(self._bolts, list) and i in self._bolts:
                    raise ValueError(
                        f'"targets.flurries" build "{i}" is in "targets.bolts"'
                    )
                if isinstance(self._extra, list) and i in self._extra:
                    raise ValueError(
                        f'"targets.flurries" build "{i}" is in "targets.extra"'
                    )
                if i in self._builds:
                    continue
                raise ValueError(f'"targets.flurries" build "{i}" is not in "builds"')
            c += len(self._flurries)
        if c == 0:
            raise ValueError('load_from: no "targets" are avaliable to be built')
        del c
        if "log" in d and isinstance(d["log"], dict):
            m = d["log"].get("file")
            n = d["log"].get("level", "INFO")
        del d
        return n, m

    def _build_prep_sign_generate(self):
        if not nes(self._pki.name):
            self._pki.name = "Microsoft Windows"
        if not nes(self._pki.ca):
            self._pki.ca = "Microsoft Root CA"
        self.log.info(
            f'Generating a CA pair with Signer "{self._pki.name}" and CA "{self._pki.ca}"..'
        )
        j = JetStream(self._opts, self.log)
        c = make_pki(
            j,
            self._tmp,
            self._pki.ca,
            self._pki.name,
            start=_parse_date(self._pki.date, self._opts),
        )
        del j
        self._output["certs"] = dict()
        self._opts.set("build.support.sign.cert", c.signer)
        self._opts.set("build.support.sign.pem", c.signer_key)
        with open(c.ca, "rb") as f:
            self._output["certs"]["ca_pem"] = b64encode(f.read()).decode("UTF-8")
        with open(c.ca_key, "rb") as f:
            self._output["certs"]["ca_key"] = b64encode(f.read()).decode("UTF-8")
        with open(c.signer, "rb") as f:
            self._output["certs"]["signer_pem"] = b64encode(f.read()).decode("UTF-8")
        with open(c.signer_key, "rb") as f:
            self._output["certs"]["signer_key"] = b64encode(f.read()).decode("UTF-8")
        del c
        self.log.debug("CA pair generation complete!")

    def _generate_bolts(self, x86, pathval):
        if not isinstance(self._bolts, list):
            return list()
        r = list()
        for i in self._bolts:
            v, e = self._builds[i], list()
            for _ in range(0, v.count):
                x = self._mangle.pick(
                    v.ext,
                    True,
                    x86,
                    only=v.dir,
                    base=v.base,
                    sz=v.name_size,
                    sep=pathval.sep,
                )
                if not pathval.valid(x.path):
                    raise ValueError(f'check: path "{x.path}" is not valid')
                e.append(x)
                r.append(_Bolt(v, x))
                del x
            if isinstance(v.raw, list) and len(v.raw) > 0:
                for i in v.raw:
                    if not pathval.valid(i):
                        raise ValueError(f'check: path "{i}" is not valid')
                    e.append(Path(i, pathval.parent(i), pathval.base(i)))
            self._process.append(_Build(v, e, _BUILD_TYPE_BOLT))
            del v, e
        self.log.info(f"Generated {len(r)} Bolts.")
        return r

    def _generate_extra(self, x86, pathval):
        if not isinstance(self._extra, list):
            return
        for i in self._extra:
            v, e = self._builds[i], list()
            for _ in range(0, v.count):
                x = self._mangle.pick(
                    v.ext,
                    True,
                    x86,
                    only=v.dir,
                    base=v.base,
                    sz=v.name_size,
                    sep=pathval.sep,
                )
                if not pathval.valid(x.path):
                    raise ValueError(f'check: path "{x.path}" is not valid')
                e.append(x)
                del x
            if isinstance(v.raw, list) and len(v.raw) > 0:
                for i in v.raw:
                    if not pathval.valid(i):
                        raise ValueError(f'check: path "{i}" is not valid')
                    e.append(Path(i, pathval.parent(i), pathval.base(i)))
            self._process.append(_Build(v, e, _BUILD_TYPE_EXTRA))
            del v, e
        self.log.info(f"Generated {len(self._extra)} Extra Builds.")

    def load_from_file(self, p, verify=True):
        if nes(p):
            v = expanduser(expandvars(p))
            if not isfile(v):
                raise ValueError(f'load: options file "{v}" was not found')
        else:
            v = "cloudseed.conf"
        if isfile(v):
            with open(v) as f:
                d = loads(f.read())
            if not isinstance(d, dict):
                raise ValueError(f'load: options file "{v}" is invalid')
        else:
            raise ValueError("load: no config file could be found")
        del v
        n, o = self.load_from(d, verify)
        del d
        if not nes(n):
            n = "info"
        return n, o

    def _generate_flurries(self, x86, pathval):
        if not isinstance(self._flurries, list):
            return
        if len(self._sentinels) == 0:
            raise ValueError("generate: no Sentinels to choose from")
        for i in self._flurries:
            v, e = self._builds[i], list()
            n = v.sentinels
            if not isinstance(n, int) or n < 1:
                n = self._gen.sentinel.size
            for _ in range(0, v.count):
                x = self._mangle.pick(
                    v.ext,
                    True,
                    x86,
                    only=v.dir,
                    base=v.base,
                    sz=v.name_size,
                    sep=pathval.sep,
                )
                if not pathval.valid(x.path):
                    raise ValueError(f'check: path "{x.path}" is not valid')
                e.append(_Flurry(x, sample(self._sentinels, k=n)))
                self.log.debug(f'Picked {n} Sentinels for Flurry "{x.path}".')
                del x
            if isinstance(v.raw, list) and len(v.raw) > 0:
                for i in v.raw:
                    if not pathval.valid(i):
                        raise ValueError(f'check: path "{i}" is not valid')
                    e.append(
                        _Flurry(
                            Path(i, pathval.parent(i), pathval.base(i)),
                            sample(self._sentinels, k=n),
                        )
                    )
                    self.log.debug(f'Picked {n} Sentinels for Flurry "{i}".')
            self._process.append(_Build(v, e, _BUILD_TYPE_FLURRY))
            del v, e, n
        self.log.info(f"Generated {len(self._flurries)} Flurry Builds.")

    def _generate_sentinels(self, x86, pathval):
        b = self._generate_bolts(x86, pathval)
        if len(b) == 0:
            return self.log.warning(
                "No Bolts were returned from Generator, skipping Sentinel generation!"
            )
        for i in self._generate_sentinel_files(x86, pathval):
            self.log.debug(
                f'Starting pick for "{i.path}" ({self._gen.sentinel.size} entries)..'
            )
            s = Sentinel()
            if self._gen.sentinel.filter is not None:
                s.filter = self._gen.sentinel.filter
            for v in sample(b, k=self._gen.sentinel.size):
                if not v.builder.lib:
                    s.add_execute(v.file.path)
                    continue
                m = 1
                if isinstance(v.builder.zombies, list) and len(v.builder.zombies) > 0:
                    m += 1
                c = randint(0, m)
                del m
                if c == 2:
                    s.add_zombie(v.file.path, v.builder.zombies)
                elif c == 1:
                    s.add_asm(v.file.path)
                else:
                    s.add_dll(v.file.path)
                del c
            if isinstance(self._gen.sentinel.urls, list):
                for u in self._gen.sentinel.urls:
                    s.add_download(u["url"], u.get("agent"))
            self._sentinels.append(_Sentinel(s, i))
            del s
        self.log.info(f"Generated {len(self._sentinels)} Sentinels.")
        del b

    def _build_prep_sign_spoof(self, target, name):
        self.log.info(
            f'Generating a spoofed Signing cert from "{target}" as "{name}"..'
        )
        j = JetStream(self._opts, self.log)
        c, p = make_cert_target(j, self._tmp, target, name)
        del j
        self._output["certs"] = dict()
        self._opts.set("build.support.sign.cert", c)
        self._opts.set("build.support.sign.pem", p)
        with open(c, "rb") as f:
            self._output["certs"]["signer_pem"] = b64encode(f.read()).decode("UTF-8")
        with open(p, "rb") as f:
            self._output["certs"]["signer_key"] = b64encode(f.read()).decode("UTF-8")
        del c, p
        self.log.debug("Spoof generation complete!")

    def _generate_sentinel_files(self, x86, pathval):
        r = list()
        for _ in range(0, self._gen.sentinel.count):
            x = self._mangle.pick(
                None,
                False,
                x86,
                sep=pathval.sep,
                only=self._gen.sentinel.dir,
                base=self._gen.sentinel.base,
            )
            if not pathval.valid(x.path):
                raise ValueError(f'check: path "{x.path}" is not valid')
            r.append(x)
            del x
        if isinstance(self._gen.sentinel.raw, list) and len(self._gen.sentinel.raw) > 0:
            for i in self._gen.sentinel.raw:
                if not pathval.valid(i):
                    raise ValueError(f'check: path "{i}" is not valid')
                r.append(Path(i, pathval.parent(i), pathval.base(i)))
        return r

    def run(self, out_dir, out_file, target, debug=False):
        # NOTE(dij): Call this to init ALL the Generators with their default values.
        self._opts.generators(None)
        # NOTE(dij): We're gonna do a thing here to allow for empty/invalid
        #            options in our config. The reason for this is /most/ options
        #            that we supply can be omitted, but JetStream does not like
        #            that.
        v = deepcopy(self._opts)
        if self._pki and not nes(v.get_sign("generate_target")):
            v.set("build.support.sign.generate_target", "<>")
        if nes(self._gen.linker):
            if not nes(v.get("build.generators.bolt.linker")):
                v.set("build.generators.bolt.linker", self._gen.linker)
            if not nes(v.get("build.generators.flurry.linker")):
                v.set("build.generators.flurry.linker", self._gen.linker)
        if nes(self._gen.guardian):
            if not nes(v.get("build.generators.bolt.guardian")):
                v.set("build.generators.bolt.guardian", self._gen.guardian)
            if not nes(v.get("build.generators.flurry.guardian")):
                v.set("build.generators.flurry.guardian", self._gen.guardian)
        if not nes(v.get("build.generators.flurry.key")):
            v.set("build.generators.flurry.key", "<>")
        if not isinstance(v.get("build.generators.flurry.paths"), list):
            v.set("build.generators.flurry.paths", ["<>"])
        if len(v.get("build.generators.flurry.paths")) == 0:
            v.set("build.generators.flurry.paths", ["<>"])
        g = self._opts.generators(None)
        for x in self._builds.values():
            g[x.generator].check(v)
        del g
        j = JetStream(v, self.log, False)
        o, a = j.check(target, None, None, False, False)
        del j, v
        self._opts.vet()
        with open(expanduser(expandvars(self._paths))) as f:
            d = loads(f.read())
            self._mangle = Mangler(d["paths"], d.get("names"))
            self._titles = d.get("titles")
            self._versions = d.get("versions")
            del d
        self._generate("64" not in a, WINDOWS if o.lower() == "windows" else UNIX)
        d = expandvars(expanduser(out_dir))
        u = expandvars(expanduser(out_file))
        try:
            self._build(o, a, d)
            self.log.info(f'Saved {len(self._output["results"])} files to "{d}".')
        except BaseException as err:
            self.log.error(f"Build error: {err}!")
            raise err
        else:
            self._cleanup(False)
        finally:
            del o, a, d
            self._cleanup(debug)
            with open(u, "w") as f:
                f.write(dumps(self._output))
            self.log.info(f'Saved the JSON output to "{u}".')
            del u

    def _build_thread(self, work, out, idx, osv, arch, x):
        self.log.info(
            f'Starting thread stub builder "{x.builder.name}" for {len(x.paths)} items.'
        )
        self._output["builders"][x.builder.name] = {
            "overrides": dict(),
            "results": list(),
        }
        o = deepcopy(self._opts)
        for k, v in x.builder.overrides.items():
            d = v.get()
            if nes(v.output):
                self._output["builders"][x.builder.name]["overrides"][v.output] = d
            self.log.debug(
                f'Builder "{x.builder.name}" added override "{k}" with value "{d}".'
            )
            o.set(k, d)
            del d
        o.vet()
        g = o.generators(None)
        if x.builder.generator not in g:
            raise ValueError(
                f'builder "{x.builder.name}" requested non-existent generator "{x.builder.generator}"'
            )
        s = g[x.builder.generator]
        del g
        if not nes(o.get("build.generators.flurry.paths")):
            o.set("build.generators.flurry.paths", ["<>"])
        s.check(o)
        for i in range(0, len(x.paths)):
            self._build_thread_start(
                work, out, deepcopy(o), idx, i, osv, arch, s, x, x.paths[i]
            )
        del o

    def _build_thread_start(self, work, out, opts, idx, sdx, osv, arch, gen, x, val):
        b = join(self._tmp, f"builder-{idx}-{sdx}")
        if not nes(opts.get_build("dir")):
            opts.set("build.dir", b)
        n, p = None, None
        if x.build == _BUILD_TYPE_FLURRY:
            opts.set(
                "build.generators.flurry.paths", [i.file.path for i in val.sentinels]
            )
            n, p = val.file.name, val.file
        else:
            n, p = val.name, val
        opts.set("build.support.rc.filename", n)
        work.append(
            self._x.submit(
                self._build_thread_enter,
                opts,
                osv,
                arch,
                gen,
                x.builder,
                out,
                p,
                x.build,
                b,
                n,
            )
        )

    def _build_thread_enter(self, opts, osv, arch, gen, builder, out, path, t, base, n):
        e = JetStream(opts, self.log, False)
        n = f"{randint(0, 100)}-{n}"
        try:
            e.run(osv, arch, gen, builder.lib, join(out, n), False)
        except BaseException as err:
            # NOTE(dij): Don't delete files on failure.
            raise err
        else:
            if isdir(base):
                rmtree(base, ignore_errors=True)
        finally:
            del e
        r = path._asdict()
        r["name"] = n
        r["type"] = _BUILD_TYPES[t]
        r["library"] = builder.lib
        r["builder"] = builder.name
        r["overrides"] = dict()
        r["generator"] = builder.generator
        del n
        return (r, builder.name)


class Parser(ArgumentParser):
    def __init__(self):
        ArgumentParser.__init__(
            self,
            prog="cloudseed",
            add_help=False,
            allow_abbrev=True,
            fromfile_prefix_chars=None,
        )
        self._err = None
        self.add = self.add_argument
        self._setup()

    @staticmethod
    def with_load():
        return Parser().parse_with_load()

    def _setup(self):
        self.add("-c", "--config", dest="config", type=str)
        self.add("-O", "--dir", dest="output", type=str)
        self.add("-o", "--json", dest="output_file", type=str)
        self.add("-h", "--help", dest="help", action="store_true")
        # Logging Arguments
        self.add("-f", "--log-file", dest="log_file", type=str)
        self.add("-i", "--log-level", dest="log_level", type=str, choices=LEVELS.keys())
        # Directory Arguments
        self.add("-l", "--link", dest="dir_link", type=str)
        self.add("-t", "--templates", dest="dir_templates", type=str)
        self.add("-G", "--generators", dest="dir_generators", type=str)
        # CloudSeed Arguments
        self.add("-x", "--jetstream", dest="jetstream", type=str)
        self.add("-n", "--paths", dest="file_paths", type=str)
        self.add("-I", "--icons", dest="file_icons", type=str)
        self.add("--debug", dest="debug", action="store_true")
        # self.add("-T", "--titles", dest="file_titles", type=str)
        # self.add("-V", "--versions", dest="file_versions", type=str)
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
        self.add("--rc-copyright", dest="rc_copyright", type=str)
        self.add(nargs=1, dest="target", type=str)

    def error(self, message):
        self._err = message

    def parse_with_load(self):
        n = Namespace()
        n.dir_work = None
        n.rc_filename = None
        try:
            r = super(__class__, self).parse_args(namespace=n)
        except Exception as err:
            raise ValueError(err) from err
        del n
        if r.help:
            return None, None, True
        if nes(self._err):
            raise ValueError(self._err)
        r.target = r.target[0].lower()
        c = CloudSeed()
        c.load_from_args(r)
        insert_args_opts(r, c._opts)
        return c, r, False


if __name__ == "__main__":
    try:
        c, r, h = Parser.with_load()
    except ValueError as err:
        print(f"Error: {err}!", file=stderr)
        exit(1)
    if h:
        print(_HELP_TEXT.format(proc=basename(argv[0])), file=stderr)
        exit(2)
    del h
    o, d = join(getcwd(), "seeds.json"), join(getcwd(), "seed_files")
    if r.output:
        d = expandvars(expanduser(r.output))
    if r.output_file:
        o = expandvars(expanduser(r.output_file))
    try:
        c.run(d, o, r.target, r.debug)
    except KeyboardInterrupt:
        print("Interrupted!", file=stderr)
        exit(1)
    except Exception as err:
        print(f"Error: {err}!", file=stderr)
        exit(1)
    del o, d, c, r

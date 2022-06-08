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
from json import dumps
from re import compile
from requests import get
from tempfile import mkdtemp
from include.util import nes
from include.options import Rc
from include.args import Parser
from sys import exit, stderr, argv
from subprocess import run, CalledProcessError
from shutil import copy, which, copytree, rmtree
from include.crypt import generate_crypt, strip_binary
from os import getcwd, makedirs, symlink, remove, environ
from include.builder import OS, ARCH, MANIFEST, upx, sign, random_chars
from os.path import (
    join,
    isabs,
    isdir,
    isfile,
    relpath,
    dirname,
    basename,
    expanduser,
    expandvars,
)

_REPO_URL = "https://raw.githubusercontent.com/iDigitalFlame/TinyPatchedGo/main"

_DEFAULT_GO = "go"
_DEFAULT_GCC = "gcc"
_DEFAULT_UPX = "upx"
_DEFAULT_WRES32 = "i686-w64-mingw32-windres"
_DEFAULT_WRES64 = "x86_64-w64-mingw32-windres"
_DEFAULT_WGCC32 = "i686-w64-mingw32-gcc"
_DEFAULT_WGCC64 = "x86_64-w64-mingw32-gcc"
_DEFAULT_GARBLE = "garble"
_DEFAULT_OPENSSL = "openssl"
_DEFAULT_OSSLSIGNCODE = "osslsigncode"

_CGO_MAIN_STD = "\nfunc main() {\n"
_CGO_MAIN_REPLACE = "\nfunc main() {{}}\n\n//export {export}\nfunc {export}() {{\n"

_CGO_IMPORT_STD = "package main\n\n"
_CGO_IMPORT_REPLACE = 'package main\n\nimport "C"\n\n'

_HELP_TEXT = """ JetStream: ThunderStorm Builder
Part of the |||||| ThunderStorm Project (https://dij.sh/ts)
(c) 2019 - 2022 iDigitalFlame

{proc}

Basic Arguments
  -h
  --help
  -c
  --config
  -C
  --clone
  -g
  --generator
  -G
  --generators
  -o
  --output
  -s
  --save
  -k
  --check
  -r
  --read-only
  -t
  --templates

Output Arguments
  -q
  --quiet
  -f
  --log-file
  -i
  --log-level

Build Arguments
  -d
  --dir
  -l
  --link
  -z
  --no-clean
  -D
  --library

Options Overrides
 Binary Options
   --bin-go
   --bin-gcc
   --bin-upx
   --bin-garble
   --bin-wgcc32
   --bin-wgcc64
   --bin-wres32
   --bin-wres64
   --bin-openssl
   --bin-osslsigncode

 Build Settings Options
   --tags
   --goroot
   --upx
   --cgo
   --crypt
   --strip
   --grable
   --compact
   --no-upx
   --no-cgo
   --no-crypt
   --no-strip
   --no-garble
   --no-compact

 Support Options
   -e
   --entry
   --manifest

  Signing Arguments
   --sign
   --pfx
   --pfx-pw
   --cert
   --pem
   --spoof
   --spoof-name
   --date
   --date-range

  Resource Arguments
   --rc
   --rc-file
   --rc-json
   --rc-icon
   --rc-title
   --rc-version
   --rc-company
   --rc-product
   --rc-filename
   --rc-copyright
"""

_THROW = compile(r"throw\(")
_PANIC = compile(r"panic\(")


def _get_stdout(r):
    if r is None:
        return ""
    o, e = "", ""
    if nes(r.stdout) and len(r.stdout) > 1 and r.stdout != "\n":
        o = r.stdout.replace("\n", "; ").strip()
        if o[-1] == ";":
            o = o[:-1]
    if nes(r.stderr) and len(r.stderr) > 1 and r.stderr != "\n":
        e = r.stderr.replace("\n", "; ").strip()
        if e[-1] == ";":
            e = e[:-1]
    if len(o) > 0 and len(e) > 0:
        return o + "|" + e
    if len(o) > 0:
        return o
    return e


def _sign_check(o):
    if nes(o.get_sign("pfx")) or nes(o.get_sign("pfx_raw")):
        return True
    if nes(o.get_sign("generate_target")):
        return True
    return (nes(o.get_sign("cert")) or nes(o.get_sign("cert_raw"))) and (
        nes(o.get_sign("pem")) or nes(o.get_sign("pem_raw"))
    )


def _wget(url, path):
    r = get(url, timeout=5, allow_redirects=True)
    r.raise_for_status()
    with open(path, "wb") as f:
        f.write(r.content)
    r.close()
    del r


def _set_empty(o, v, d):
    r = o.get(v)
    if nes(r):
        return
    w = which(d)
    if w is not None:
        o.set(v, w)
    del w, r


def tiny_root(old, new):
    try:
        copytree(old, new)
    except OSError as err:
        raise OSError(f'Copytree from "{old}" to "{new}"') from err
    for i in glob(join(new, "src", "fmt", "*.go"), recursive=False):
        remove(i)
    for i in glob(join(new, "src", "unicode", "*.go"), recursive=False):
        remove(i)
    _wget(f"{_REPO_URL}/fmt/scan.go", join(new, "src", "fmt", "scan.go"))
    _wget(f"{_REPO_URL}/fmt/print.go", join(new, "src", "fmt", "print.go"))
    _wget(f"{_REPO_URL}/fmt/quick.go", join(new, "src", "fmt", "quick.go"))
    _wget(f"{_REPO_URL}/runtime/print.go", join(new, "src", "runtime", "print.go"))
    _wget(f"{_REPO_URL}/unicode/unicode.go", join(new, "src", "unicode", "unicode.go"))
    _sed(
        join(new, "src", "net", "http", "transport.go"),
        [
            "return envProxyFunc()(req.URL)",
            "envProxyFuncValue = httpproxy.FromEnvironment().ProxyFunc()",
            '"golang.org/x/net/http/httpproxy"',
        ],
        [
            "return req.URL, nil",
            "envProxyFuncValue = nil",
            "",
        ],
    )
    _sed(
        join(new, "src", "net", "http", "h2_bundle.go"),
        [
            "if a, err := idna.ToASCII(host); err == nil {",
            '"golang.org/x/net/idna"',
        ],
        [
            'if a := ""; len(a) > 0 {',
            "",
        ],
    )
    _sed(
        join(new, "src", "net", "http", "request.go"),
        [
            "return idna.Lookup.ToASCII(v)",
            '"golang.org/x/net/idna"',
        ],
        [
            "return v, nil",
            "",
        ],
    )
    _sed(
        join(
            new,
            "src",
            "vendor",
            "golang.org",
            "x",
            "net",
            "http",
            "httpguts",
            "httplex.go",
        ),
        [
            "host, err = idna.ToASCII(host)",
            '"golang.org/x/net/idna"',
        ],
        [
            "host, err = host, nil",
            "",
        ],
    )
    _sed(
        join(new, "src", "runtime", "proc.go"),
        ['if n, ok := atoi32(gogetenv("GOMAXPROCS")); ok && n > 0 {'],
        ["if n, ok := int32(0), false; ok && n > 0 {"],
    )
    _sed(
        join(new, "src", "runtime", "runtime1.go"),
        [
            'for p := gogetenv("GODEBUG"); p != ""; {',
            'setTraceback(gogetenv("GOTRACEBACK"))',
        ],
        ['for p := gogetenv(""); p != ""; {', 'setTraceback("none")'],
    )
    _sed(
        join(new, "src", "runtime", "mgcpacer.go"),
        ['p := gogetenv("GOGC")'],
        ['p := ""'],
    )
    _sed(
        join(new, "src", "runtime", "extern.go"),
        ['s := gogetenv("GOROOT")'],
        ['s := "null"'],
    )
    _sed(
        join(new, "src", "time", "zoneinfo_windows.go"),
        [
            "stdName := syscall.UTF16ToString(z.StandardName[:])",
            "a, ok := abbrs[stdName]",
            "a, ok = abbrs[englishName]",
            "return a.std, a.dst",
            "return extractCAPS(stdName), extractCAPS(dstName)",
            "englishName, err := toEnglishName(stdName, dstName)",
            "dstName := syscall.UTF16ToString(z.DaylightName[:])",
        ],
        [
            'return "GMT", "GMT"',
            "ok := true",
            "ok = true",
            'return "GMT", "GMT"',
            'return "GMT", "GMT"',
            "var err error",
            "",
        ],
    )
    remove(join(new, "src", "time", "zoneinfo_abbrs_windows.go"))
    for i in glob(join(new, "src", "**", "**.go"), recursive=True):
        if new not in i or not isfile(i):
            continue
        _remap_file(i, _PANIC, True, 'panic("")')
        _remap_file(i, _THROW, False, 'throw("")')
    for i in glob(join(new, "src", "time", "zoneinfo_*.go"), recursive=False):
        if not isfile(i):
            continue
        _sed(i, ['runtime.GOROOT() + "/lib/time/zoneinfo.zip",'], ["runtime.GOROOT(),"])


def _sed(path, old, new):
    with open(path, "r") as f:
        d = f.read()
    with open(path, "w") as f:
        for x in range(0, len(old)):
            d = d.replace(old[x], new[x])
        f.write(d)
    del d


def _find_next_token(s, i):
    e, c = i, 0
    while True:
        if e >= len(s):
            print(i, e, len(s), s[e:i])
        if s[e] == ")":
            if c == 0:
                if e < 3 or s[e - 3 : e + 1] != "no )":
                    break
            else:
                c -= 1
        if s[e] == "(" and not s[i : i + 15].startswith('"panicwrap: no '):
            c += 1
        e += 1
    del c
    return e + 1


def _print_rc_config(o, file):
    if nes(o.get_rc("file")):
        print(f'- | = {"Raw File:":20}:{o.get_rc("file")}', file=file)
        return
    if o.get_rc("icon_multi").get("enabled"):
        print(f'- | = {"Icon:":20}[multi]', file=file)
    else:
        print(f'- | = {"Icon:":20}{o.get_rc("icon")}', file=file)
    if o.get_rc("title_multi").get("enabled"):
        print(f'- | = {"Title:":20}[multi]', file=file)
    else:
        print(f'- | = {"Title:":20}{o.get_rc("title")}', file=file)
    if o.get_rc("product_multi").get("enabled"):
        print(f'- | = {"Product:":20}[multi]', file=file)
    else:
        print(f'- | = {"Product:":20}{o.get_rc("product")}', file=file)
    if o.get_rc("version_multi").get("enabled"):
        print(f'- | = {"Version:":20}[multi]', file=file)
    else:
        print(f'- | = {"Version:":20}{o.get_rc("version")}', file=file)
    if o.get_rc("company_multi").get("enabled"):
        print(f'- | = {"Company:":20}[multi]', file=file)
    else:
        print(f'- | = {"Company:":20}{o.get_rc("company")}', file=file)
    if o.get_rc("filename_multi").get("enabled"):
        print(f'- | = {"Filename:":20}[multi]', file=file)
    else:
        if not nes(o.get_rc("filename")):
            print(f'- | = {"Filename:":20}[output filename]', file=file)
        else:
            print(f'- | = {"Filename:":20}{o.get_rc("filename")}', file=file)
    if o.get_rc("copyright_multi").get("enabled"):
        print(f'- | = {"Copyright:":20}[multi]', file=file)
    else:
        print(f'- | = {"Copyright:":20}{o.get_rc("copyright")}', file=file)


def _print_sign_config(o, file):
    if nes(o.get_sign("date")):
        print(f'- | = {"Sign Date:":20}{o.get_sign("date")}', file=file)
    else:
        print(f'- | = {"Sign Date:":20}Today', file=file)
    if o.get_sign("date_range"):
        print(f'- | = {"Sign Variation:":20}{o.get_sign("date_range")} days', file=file)
    if nes(o.get_sign("pfx_raw")):
        print(f'- | = {"PFX (Raw):":20}True', file=file)
        if nes(o.get_sign("pfx_password")):
            print(f'- | = {"PFX Password:":20}{o.get_sign("pfx_password")}', file=file)
        return
    if nes(o.get_sign("pfx")):
        print(f'- | = {"PFX:":20}{o.get_sign("pfx")}', file=file)
        if nes(o.get_sign("pfx_password")):
            print(f'- | = {"PFX Password:":20}{o.get_sign("pfx_password")}', file=file)
        return
    if nes(o.get_sign("cert_raw")):
        print(f'- | = {"Cert (Raw):":20}True', file=file)
        if nes(o.get_sign("pem_raw")):
            print(f'- | = {"PEM (Raw):":20}True', file=file)
        elif nes(o.get_sign("pem")):
            print(f'- | = {"PEM:":20}{o.get_sign("pem")}', file=file)
        return
    elif nes(o.get_sign("cert")):
        print(f'- | = {"Cert:":20}{o.get_sign("cert")}', file=file)
        if nes(o.get_sign("pem_raw")):
            print(f'- | = {"PEM (Raw):":20}True', file=file)
        elif nes(o.get_sign("pem")):
            print(f'- | = {"PEM:":20}{o.get_sign("pem")}', file=file)
        return
    if not nes(o.get_sign("generate_target")):
        return
    print(f'- | = {"Spoof:":20}{o.get_sign("generate_target")}', file=file)
    if not nes(o.get_sign("generate_name")):
        return
    print(f'- | = {"Spoof Name":20}{o.get_sign("generate_name")}', file=file)


def _print_cmd(v, trunc, ns=False):
    if not trunc:
        return " ".join(v)
    o = v.copy()
    for x in range(0, len(v)):
        if len(v[x]) > 200:
            o.remove(v[x])
            o.insert(x, "[trunc]")
    if ns:
        return o
    return " ".join(o)


def _remap_file(p, regexp, no_concat, repl):
    with open(p) as f:
        b = f.read()
    if len(b) == 0 or "package" not in b:
        return
    r = regexp.finditer(b)
    if r is None:
        return
    c = b
    for m in r:
        if m.start() == 0 or not b[m.start() - 1].isspace():
            continue
        e = _find_next_token(b, m.end())
        v = b[m.start() : e]
        if v.endswith("string)"):
            continue
        if no_concat and (v[6] != '"' or "+" in v):
            continue
        if v not in c:
            raise KeyError(v)
        c = c.replace(v, repl, 1)
        del e, v
    with open(p, "w") as f:
        f.write(c)
    del r, c, b


class JetStream(object):
    def __init__(self, options, gen, logger=None):
        self.log = logger
        self.opts = options
        self.generator = gen
        self.templates = self.opts.templates()
        if self.log is not None:
            return
        self.log = self.opts.logger()

    @staticmethod
    def cmdline():
        try:
            o, g, r, h = Parser().parse_with_load()
        except ValueError as err:
            print(f"Error: {err}!", file=stderr)
            exit(1)
        if h:
            print(_HELP_TEXT.format(proc=argv[0]), file=stderr)
            if g is not None:
                print(f'Current Generator "{g.name()}":')
                try:
                    print(g.argparse_help(), file=stderr)
                except Exception:
                    pass
            else:
                print(file=stderr)
            exit(2)
        try:
            v = JetStream(o, g)
            osv, arch = v.check(r.target, r.config, r.save, r.library)
        except Exception as err:
            print(f"Error: {err}!", file=stderr)
            exit(1)
        del g, o
        if not r.quiet:
            v.print_options(osv, arch)
        if r.check:
            return v
        try:
            v.start(osv, arch, r.library, r.output, r.no_clean)
        except Exception as err:
            print(f"Error: {err}!", file=stderr)
            exit(1)
        del r
        return v

    def __enter__(self):
        # Syntax sugar to use the "with" statement.
        pass

    def __exit__(self, *_):
        # Syntax sugar to use the "with" statement, but does clear the logging
        # prefix.
        self.log.prefix(None)

    def __call__(self, prefix):
        # Syntax sugar to use the "with" statement, but does set the logging
        # prefix.
        self.log.prefix(prefix)
        return self

    def _fill(self, config, save):
        _set_empty(self.opts, "build.bins.go", _DEFAULT_GO)
        _set_empty(self.opts, "build.bins.gcc", _DEFAULT_GCC)
        _set_empty(self.opts, "build.bins.upx", _DEFAULT_UPX)
        _set_empty(self.opts, "build.bins.wres32", _DEFAULT_WRES32)
        _set_empty(self.opts, "build.bins.wres64", _DEFAULT_WRES64)
        _set_empty(self.opts, "build.bins.wgcc32", _DEFAULT_WGCC32)
        _set_empty(self.opts, "build.bins.wgcc64", _DEFAULT_WGCC64)
        _set_empty(self.opts, "build.bins.garble", _DEFAULT_GARBLE)
        _set_empty(self.opts, "build.bins.openssl", _DEFAULT_OPENSSL)
        _set_empty(self.opts, "build.bins.osslsigncode", _DEFAULT_OSSLSIGNCODE)
        if config and save:
            self.debug(f'Saving configuration at "{config}".')
            self.opts.save(config)

    def _step_protect(self, base, file):
        if self.opts.get_option("strip"):
            self.log.debug("Sanitizing and stripping binary..")
            strip_binary(file, self.log.debug)
        if self.opts.get_option("upx"):
            upx(self, file)
        if self.opts.get_sign("enabled"):
            sign(
                self,
                self.opts,
                self.opts.get_sign("date"),
                self.opts.get_sign("date_range"),
                base,
                file,
            )

    def _step_generate(self, base, workspace):
        self.log.debug(f'Using Generator "{self.generator.name()}".')
        o = self.generator.run(self.opts, base, workspace, self.templates)
        if not nes(o):
            raise ValueError('generator "run" result is invalid')
        if not isfile(o):
            raise ValueError(f'generator "run" result "{o}" is not a file')
        workspace["main"] = o
        self.log.debug(f'Generator "{self.generator.name()}" "run" returned "{o}".')
        if not workspace["cgo"]:
            return o
        self.log.debug("Preparing CGO entry files..")
        if not workspace["export"]:
            workspace["export"] = random_chars(12)
        self.log.debug(f'CGO entry point is "{workspace["export"]}".')
        c, i = self.generator.run_cgo(
            workspace["export"], self.opts, base, workspace, self.templates
        )
        if not nes(c) or not nes(i):
            raise ValueError('generator "run_cgo" result is invalid')
        if not isfile(c):
            raise ValueError(f'generator "run_cgo" result "{c}" is not a file')
        workspace["cgo_main"], workspace["cgo_out"] = c, i
        self.log.debug(
            f'Generator "{self.generator.name()}" "run_cgo" returned "{c}" and "{i}".'
        )
        with open(o) as f:
            d = f.read()
        if _CGO_MAIN_STD not in d:
            raise ValueError(f'file "{o}" does not have a valid "main"')
        if _CGO_IMPORT_STD not in d:
            raise ValueError(f'file "{o}" does not have a valid "package main"')
        self.log.debug(f'Performing CGO entrypoint replacements on "{o}".')
        with open(o, "w") as f:
            f.write(
                d.replace(_CGO_IMPORT_STD, _CGO_IMPORT_REPLACE, 1).replace(
                    _CGO_MAIN_STD, _CGO_MAIN_REPLACE.format(export=workspace["export"])
                )
            )
        del d, c
        return o

    def print_options(self, osv, arch, file=None):
        print(f'JetSteam Load complete!\n- | Configured Options\n{"="*60}', file=file)
        print(f'- | {"Target:":22}{osv}/{arch}', file=file)
        print(f'- | {"Generator:":22}{self.generator.name()}\n- |', file=file)
        print("- | Binary Configuration", file=file)
        print(f'- | = {"go:":20}{self.opts.get_bin("go")}', file=file)
        print(f'- | = {"gcc:":20}{self.opts.get_bin("gcc")}', file=file)
        print(f'- | = {"upx:":20}{self.opts.get_bin("upx")}', file=file)
        print(f'- | = {"garble:":20}{self.opts.get_bin("garble")}', file=file)
        print(f'- | = {"wgcc32:":20}{self.opts.get_bin("wgcc32")}', file=file)
        print(f'- | = {"wgcc64:":20}{self.opts.get_bin("wgcc64")}', file=file)
        print(f'- | = {"wres32:":20}{self.opts.get_bin("wres32")}', file=file)
        print(f'- | = {"wres64:":20}{self.opts.get_bin("wres64")}', file=file)
        print(f'- | = {"openssl:":20}{self.opts.get_bin("openssl")}', file=file)
        print(
            f'- | = {"osslsigncode:":20}{self.opts.get_bin("osslsigncode")}', file=file
        )
        print("- | Build Configuration", file=file)
        if self.opts.get_build("dir"):
            print(f'- | = {"Working Dir:":20}{self.opts.get_build("dir")}', file=file)
        else:
            print(f'- | = {"Working Dir:":20}[temp directory]', file=file)
        print(f'- | = {"Linked Dir:":20}{self.opts.get_build("dir_link")}', file=file)
        print("- | Build Modifications", file=file)
        print(f'- | = {"CGO:":20}{self.opts.get_option("cgo")}', file=file)
        print(f'- | = {"UPX:":20}{self.opts.get_option("upx")}', file=file)
        print(f'- | = {"Crypt:":20}{self.opts.get_option("crypt")}', file=file)
        print(f'- | = {"Strip:":20}{self.opts.get_option("strip")}', file=file)
        print(f'- | = {"Garble:":20}{self.opts.get_option("garble")}', file=file)
        print(f'- | = {"Compact:":20}{self.opts.get_option("compact")}', file=file)
        print(f'- | = {"GOROOT:":20}{self.opts.get_option("goroot")}', file=file)
        print(
            f'- | = {"Build Tags:":20}{",".join(self.opts.get_option("tags"))}',
            file=file,
        )
        if osv != "windows":
            return
        print("- | Support Configuration", file=file)
        print(f'- | = {"Minifest:":20}{self.opts.get_support("manifest")}', file=file)
        if self.opts.get_option("cgo"):
            if self.opts.get_support("cgo_export"):
                print(
                    f'- | = {"CGO Export:":20}{self.opts.get_support("cgo_export")}',
                    file=file,
                )
            else:
                print(f'- | = {"CGO Export:":20}[randomized]', file=file)
        print("- | Signing Configuration", file=file)
        print(f'- | = {"Enabled:":20}{self.opts.get_sign("enabled")}', file=file)
        if self.opts.get_sign("enabled"):
            _print_sign_config(self.opts, file)
        print("- | Resource Configuration", file=file)
        print(f'- | = {"Enabled:":20}{self.opts.get_rc("enabled")}', file=file)
        if self.opts.get_rc("enabled"):
            _print_rc_config(self.opts, file)
        self.generator.print_options(self.opts, file)

    def check(self, target, config, save, library):
        if not nes(target) or "/" not in target:
            raise ValueError(f'invalid target "{target}"')
        n = target.find("/")
        if n is None or n < 3:
            raise ValueError(f'invalid target "{target}"')
        o = target[:n].lower().strip()
        if o not in OS:
            raise ValueError(f'invalid os "{o}"')
        a = target[n + 1 :].lower().strip()
        del n
        if a not in ARCH:
            raise ValueError(f'invalid arch "{a}"')
        if o not in ARCH[a]:
            raise ValueError("invalid arch/os combo")
        self._fill(config, save)
        if not nes(self.opts.get_bin("go")):
            raise ValueError('binary target "go" missing')
        if o == "windows":
            if a.endswith("64"):
                r, g = self.opts.get_bin("wres64"), self.opts.get_bin("wgcc64")
            else:
                r, g = self.opts.get_bin("wres32"), self.opts.get_bin("wgcc32")
            if not nes(r):
                raise ValueError(f'binary target "wres" missing for "{target}"')
            if not nes(g):
                raise ValueError(f'binary target "wgcc" missing for "{target}"')
        else:
            if library:
                raise ValueError(
                    "cannot use '-D' / '--library' for a non-Windows target"
                )
            if self.opts.get_option("cgo"):
                raise ValueError("can only use CGO with Windows")
        if self.opts.get_option("upx") and not nes(self.opts.get_bin("upx")):
            raise ValueError('"upx" is enabled but "upx" binary is missing')
        if self.opts.get_option("garble") and not nes(self.opts.get_bin("garble")):
            raise ValueError('"garble" is enabled but "garble" binary is missing')
        if self.opts.get("build.support.sign.enabled"):
            if not nes(self.opts.get_bin("openssl")):
                raise ValueError('"sign" is enabled but "openssl" binary is missing')
            if not nes(self.opts.get_bin("osslsigncode")):
                raise ValueError(
                    '"sign" is enabled but "osslsigncode" binary is missing'
                )
            if not _sign_check(self.opts):
                raise ValueError(
                    '"sign" is enabled but certificate configuration is invalid'
                )
        self.generator.check(self.opts)
        return o, a

    def _step_build(self, base, workspace, rc, file, out):
        e = environ.copy()
        e["GOOS"] = workspace["os"]
        e["GOARCH"] = workspace["arch"]
        r = self.opts.get_option("goroot")
        if "GOROOT" not in e and not nes(r):
            raise ValueError("GOROOT is not in current ENV and not in build")
        if nes(r):
            r = expandvars(expanduser(r))
            e["GOROOT"] = r
        else:
            r = e["GOROOT"]
        if not isdir(r):
            raise ValueError(f'GOROOT path "{r}" is not a directory')
        self.log.debug(f'Using GOROOT path "{r}".')
        if self.opts.get_option("compact"):
            c = join(base, "root")
            if not isdir(c):
                self.log.info(f'Building Compact GOROOT at "{c}"..')
                tiny_root(r, c)
            e["GOROOT"] = c
            del c
        del r
        self.log.debug(
            f'GOOS="{e["GOOS"]}", GOARCH="{e["GOARCH"]}", GOROOT="{e["GOROOT"]}"..'
        )
        n = basename(out)
        if self.opts.get_option("cgo"):
            self.log.debug("Starting CGO build..")
            o = self._step_build_cgo(
                base,
                workspace,
                e,
                rc,
                workspace["arch"].endswith("64"),
                workspace["library"],
                workspace["cgo_main"],
                file,
                n,
            )
        else:
            self.log.debug("Starting standard build..")
            if rc is not None:
                self.log.warning("CGO is NOT enabled, but RC is, RC will be skipped!")
            o = self._step_build_go(workspace, e, None, None, file, join(base, n))
        del n
        if not nes(o):
            raise ValueError("build result is invalid")
        if not isfile(o):
            raise ValueError(f'built result "{o}" is not a file')
        self.log.info(f'Build step returned "{o}".')
        workspace["bin"] = o
        del e
        return o

    def start(self, osv, arch, library, output, no_clean):
        if not nes(output):
            raise ValueError('"output" is not valid')
        if isabs(output):
            output = join(getcwd(), output)
        self.log.prefix("PRE")
        d, m = self.opts.get_build("dir"), False
        if not nes(d):
            d, m = mkdtemp(prefix="jetstream-build-"), True
            self.opts.set("build.dir", d)
            self.log.debug(f'Made temp working directory "{d}".')
        else:
            d = expanduser(expandvars(d))
            if not isdir(d):
                makedirs(d, exist_ok=True)
            self.log.info(f'Using the non-temp working diretory "{d}".')
        v, k = self.opts.get_build("dir_link"), None
        if nes(v):
            v, n = expanduser(expandvars(v)), basename(d)
            k = join(v, n)
            symlink(d, k)
            self.log.info(
                f'Linking the working directory "{d}" into the target directory "{v}" as "{n}".'
            )
        workspace = {
            "os": osv,
            "cgo": self.opts.get_option("cgo"),
            "dir": d,
            "out": output,
            "main": "",
            "arch": arch,
            "link": v,
            "flags": "",
            "export": self.opts.get_support("cgo_export"),
            "library": library,
            "main_cgo": "",
            "work_dir": d,
        }
        del v
        if nes(k):
            workspace["work_dir"] = k
        rc = None
        if self.opts.get_rc("enabled"):
            rc = Rc(self.opts.get_support("rc"))
        self.log.debug(f"Workspace built: {dumps(workspace)}")
        try:
            with self("SP1"):
                self.log.info("Starting the Generate step..")
                f = self._step_generate(d, workspace)
                self.log.debug("Completed the Generate step!")
            with self("SP2"):
                self.log.info("Starting the Build step..")
                o = self._step_build(d, workspace, rc, f, output)
                self.log.debug("Completed the Build step!")
            with self("SP3"):
                self.log.info("Starting the Protect step..")
                self._step_protect(d, o)
                self.log.debug("Completed the Protect step!")
            copy(o, output)
            del o, f
        except Exception as err:
            self.log.error(f"Error during operation: {err}", err=err)
            raise err
        finally:
            self.log.prefix(None)
            del rc, workspace
            if nes(k):
                self.log.debug(f'Removing link directory "{k}".')
                remove(k)
            if not no_clean and m:
                self.log.debug(f'Removing working directory "{d}".')
                rmtree(d)

    def _step_build_go(self, workspace, env, ld, extra, file, out):
        b, x = self.opts.get_bin("go"), list()
        if self.opts.get_option("garble"):
            b = self.opts.get_bin("garble")
            x += ["-tiny", "-seed=random"]
            x.append("-literals")  # I think this makes the file bigger
        x.insert(0, b)
        del b
        x += ["build", "-o", out, "-buildvcs=false", "-trimpath"]
        t = self.opts.get_option("tags")
        if not isinstance(t, list):
            t = list()
        f = "-w -s"
        if nes(ld):
            v = ld.split(" ")
            if len(v) > 0:
                if "-w" in v:
                    v.remove("-w")
                if "-s" in v:
                    v.remove("-s")
                f += " " + " ".join(v)
            del v
        g = self.opts.get_option("crypt")
        if g:
            e = [workspace["os"], workspace["arch"]]
            if len(t) > 0:
                e += t
            self.log.debug("Starting crypt build..")
            k, v = generate_crypt(e, join(dirname(__file__), "include", "strs.json"))
            del e
            if len(f) > 0:
                f += " "
            f += (
                f"-X 'github.com/iDigitalFlame/xmt/util/crypt.key={k}' "
                f"-X 'github.com/iDigitalFlame/xmt/util/crypt.payload={v}'"
            )
            if "crypt" not in t:
                t.append("crypt")
            del k, v
        if len(t) > 0:
            x += ["-tags", ",".join(t)]
        del t
        x += ["-ldflags", f.strip()]
        del f
        if isinstance(extra, list) and len(extra) > 0:
            x += extra
        w = workspace["work_dir"]
        if nes(workspace["link"]):
            x.append(
                relpath(join(workspace["work_dir"], basename(file)), workspace["link"])
            )
            w = workspace["link"]
        else:
            x.append(file)
        self._exec(x, env=env, trunc=g, wd=w)
        del x, w, g
        return out

    def _exec(self, cmd, env=None, trunc=False, out=True, wd=None):
        self.log.debug(f'Running "{_print_cmd(cmd, trunc)}"..')
        e = env
        if env is None:
            e = environ
        try:
            r = run(
                cmd,
                env=e,
                cwd=wd,
                text=True,
                check=True,
                shell=False,
                capture_output=out,
            )
        except CalledProcessError as err:
            self.log.error(
                f'Error running command (exit {err.returncode}) "{_print_cmd(cmd, trunc)}": {_get_stdout(err)}'
            )
            if trunc:
                err.cmd = _print_cmd(cmd, trunc, True)
            raise err
        finally:
            del e
        if out:
            o = _get_stdout(r)
            if nes(o):
                self.log.debug(f"Command output: {o}")
            del o
        del r

    def _step_build_cgo(self, base, workspace, env, rc, x64, lib, src, file, out):
        if workspace["os"] != "windows":
            raise ValueError("can only use CGO with Windows")
        c = self.opts.get_bin("wgcc" + "64" if x64 else "32")
        env["CC"] = c
        env["CGO_ENABLED"] = "1"
        i = join(base, workspace["cgo_out"]) + ".a"
        self._step_build_go(
            workspace,
            env,
            "-H=windowsgui",
            ["-buildmode=c-archive", "-gcflags", "-G=0"],
            file,
            i,
        )
        n, m = out.lower(), out
        if lib and not n.endswith(".dll"):
            m += ".dll"
        elif not lib and not n.endswith(".exe"):
            m += ".exe"
        del n
        self.log.debug(f'File target name is "{m}".')
        z = list()
        q = self.opts.get_bin("wres" + "64" if x64 else "32")
        if self.opts.get_rc("enabled"):
            self.log.debug("Adding Resource file..")
            r, o = join(base, "res.rc"), join(base, "res.o")
            with open(r, "w") as f:
                f.write(rc.generate(m))
            self._exec([q, "-i", r, "-o", o])
            z.append(o)
            self.log.debug(f'Resource file "{o}" generated.')
            remove(r)
            del r, o
        if self.opts.get_support("manifest"):
            self.log.debug("Adding Manifest file..")
            with open(join(base, f"{m}.manifest"), "w") as f:
                f.write(MANIFEST)
            r, o = join(base, "manifest.rc"), join(base, "manifest.o")
            with open(r, "w") as f:
                f.write(
                    f'#include "winuser.h"\n{"2" if lib else "1"} RT_MANIFEST {m}.manifest\n'
                )
            self._exec([q, "--output-format=coff", "-i", r, "-o", o])
            z.append(o)
            self.log.debug(f'Manifest file "{o}" generated.')
            remove(r)
            del r, o
        del q
        o = join(base, m)
        del m
        if not lib:
            self.log.info(f'Building CGO Binary "{o}".')
            self._exec(
                [
                    c,
                    "-mwindows",
                    "-o",
                    o,
                    "-fPIC",
                    "-pthread",
                    "-lwinmm",
                    "-lkernel32",
                    "-lntdll",
                    "-lws2_32",
                    "-Wl,-x,-s,-nostdlib",
                    src,
                    i,
                ]
                + z,
                env=env,
                wd=base,
            )
        else:
            self.log.info(f'Building CGO DLL "{o}".')
            self._exec(
                [
                    c,
                    "-c",
                    "-o",
                    f"{o}.o",
                    "-mwindows",
                    "-fPIC",
                    "-pthread",
                    "-lwinmm",
                    "-lkernel32",
                    "-lntdll",
                    "-lws2_32",
                    "-Wl,-x,-s,-nostdlib",
                    src,
                ],
                env=env,
                wd=base,
            )
            self._exec(
                [
                    c,
                    "-shared",
                    "-o",
                    o,
                    "-mwindows",
                    "-fPIC",
                    "-pthread",
                    "-lwinmm",
                    "-lkernel32",
                    "-lntdll",
                    "-lws2_32",
                    "-Wl,-x,-s,-nostdlib",
                    f"{o}.o",
                    i,
                ]
                + z,
                env=env,
                wd=base,
            )
        del c, i, z
        return o


if __name__ == "__main__":
    JetStream.cmdline()

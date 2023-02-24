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

from json import dumps
from string import digits
from tempfile import mkdtemp
from include.util import nes
from sys import exit, stderr
from include.options import Rc
from include.args import Parser
from shutil import copy, which, rmtree
from include.crypt import generate_crypt, strip_binary
from os import getcwd, makedirs, symlink, remove, environ, readlink, chmod, walk
from include.builder import (
    OS,
    ARCH,
    MANIFEST,
    upx,
    sign,
    execute,
    tiny_root,
    random_chars,
    pull_in_deps,
)
from os.path import (
    join,
    isabs,
    isdir,
    islink,
    isfile,
    relpath,
    dirname,
    normpath,
    basename,
    splitext,
    expanduser,
    expandvars,
)

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

_CGO_SECONDARY_STD = "\nfunc secondary() {\n"
_CGO_SECONDARY_REPLACE = "\n//export {export}\nfunc {export}() {{\n"

_CGO_IMPORT_STD = "package main\n\n"
_CGO_IMPORT_REPLACE = 'package main\n\nimport "C"\n\n'


def _sign_check(o):
    if nes(o.get_sign("pfx")) or nes(o.get_sign("pfx_raw")):
        return True
    if nes(o.get_sign("generate_target")):
        return True
    return (nes(o.get_sign("cert")) or nes(o.get_sign("cert_raw"))) and (
        nes(o.get_sign("pem")) or nes(o.get_sign("pem_raw"))
    )


def which_empty(opts):
    _which_empty(opts, "build.bins.go", _DEFAULT_GO)
    _which_empty(opts, "build.bins.gcc", _DEFAULT_GCC)
    _which_empty(opts, "build.bins.upx", _DEFAULT_UPX)
    _which_empty(opts, "build.bins.wres32", _DEFAULT_WRES32)
    _which_empty(opts, "build.bins.wres64", _DEFAULT_WRES64)
    _which_empty(opts, "build.bins.wgcc32", _DEFAULT_WGCC32)
    _which_empty(opts, "build.bins.wgcc64", _DEFAULT_WGCC64)
    _which_empty(opts, "build.bins.garble", _DEFAULT_GARBLE)
    _which_empty(opts, "build.bins.openssl", _DEFAULT_OPENSSL)
    _which_empty(opts, "build.bins.osslsigncode", _DEFAULT_OSSLSIGNCODE)


def _which_empty(o, v, d):
    r = o.get(v)
    if nes(r):
        return
    w = which(d)
    if w is not None:
        o.set(v, w)
    del w, r


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


class JetStream(object):
    __slots__ = ("log", "opts", "templates", "prefix")

    def __init__(self, options, logger=None, prefix=True):
        self.log = logger
        self.opts = options
        self.prefix = prefix
        self.templates = self.opts.templates()
        if self.log is not None:
            return
        self.log = self.opts.logger()

    def __enter__(self):
        # Syntax sugar to use the "with" statement.
        pass

    def __exit__(self, *_):
        # Syntax sugar to use the "with" statement, but does clear the logging
        # prefix.
        if not self.prefix:
            return
        self.log.prefix(None)

    def __call__(self, prefix):
        # Syntax sugar to use the "with" statement, but does set the logging
        # prefix.
        if not self.prefix:
            return self
        self.log.prefix(prefix)
        return self

    def _fill(self, config, save):
        which_empty(self.opts)
        if not config or not save:
            return
        self.log.debug(f'Saving configuration at "{config}".')
        self.opts.save(config)

    def protect(self, workspace, base, file):
        if self.opts.get_option("strip") and workspace.get("strip", True):
            self.log.debug("Sanitizing and stripping binary..")
            strip_binary(
                file, self.log.debug, workspace.get("goroot"), workspace.get("gopath")
            )
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

    def generate(self, gen, base, workspace):
        self.log.debug(f'Using Generator "{gen.name()}".')
        o = gen.run(self.opts, base, workspace, self.templates)
        if not nes(o):
            raise ValueError('generate: generator "run" result is invalid')
        if not isfile(o):
            raise ValueError(f'generate: generator "run" result "{o}" is not a file')
        workspace["main"] = o
        self.log.debug(f'Generator "{gen.name()}" "run" returned "{o}".')
        if not workspace["cgo"]:
            return o
        self.log.debug("Preparing CGO entry files..")
        if not nes(workspace["export"]):
            workspace["export"] = random_chars(12)
        elif workspace["export"][0] in digits:
            raise ValueError(
                f'export name "{workspace["export"]}" cannot start with a number'
            )
        self.log.debug(f'CGO entry point is "{workspace["export"]}".')
        v = workspace.get("secondary")
        if not nes(v):
            v = random_chars(12)
        elif v[0] in digits:
            raise ValueError(f'export secondary name "{v}" cannot start with a number')
        k = False
        with open(o) as f:
            d = f.read()
        if _CGO_MAIN_STD not in d:
            raise ValueError(f'generate: file "{o}" does not have a valid "main"')
        if _CGO_IMPORT_STD not in d:
            raise ValueError(
                f'generate: file "{o}" does not have a valid "package main"'
            )
        if _CGO_SECONDARY_STD in d:
            self.log.debug("Secondary CGO entrypoint found!")
            workspace["secondary"], k = v, True
            self.log.debug(f'CGO secondary entry point is "{v}".')
        else:
            workspace["secondary"] = workspace["export"]
        self.log.debug(f'Performing CGO entrypoint replacements on "{o}".')
        with open(o, "w") as f:
            g = d.replace(_CGO_IMPORT_STD, _CGO_IMPORT_REPLACE, 1).replace(
                _CGO_MAIN_STD, _CGO_MAIN_REPLACE.format(export=workspace["export"])
            )
            if k:
                g = g.replace(
                    _CGO_SECONDARY_STD, _CGO_SECONDARY_REPLACE.format(export=v)
                )
            f.write(g)
            del g
        del d, v, k
        c, i = gen.run_cgo(
            workspace["export"], self.opts, base, workspace, self.templates
        )
        if not nes(c) or not nes(i):
            raise ValueError('generate: generator "run_cgo" result is invalid')
        if not isfile(c):
            raise ValueError(
                f'generate: generator "run_cgo" result "{c}" is not a file'
            )
        workspace["cgo_main"], workspace["cgo_out"] = c, i
        self.log.debug(f'Generator "{gen.name()}" "run_cgo" returned "{c}" and "{i}".')
        del c, i
        return o

    def build(self, base, workspace, rc, file, out):
        e = environ.copy()
        e["GOOS"] = workspace["os"]
        e["GOARCH"] = workspace["arch"]
        r = self.opts.get_option("goroot")
        if "GOROOT" not in e and not nes(r):
            raise ValueError("build: GOROOT is not in current ENV and not in build")
        v = self.opts.get_option("gopath")
        if "GOPATH" not in e and not nes(v):
            raise ValueError("build: GOPATH is not in current ENV and not in build")
        if nes(r):
            r = expandvars(expanduser(r))
            e["GOROOT"] = r
        else:
            r = e["GOROOT"]
        if nes(v):
            v = expandvars(expanduser(v))
            e["GOPATH"] = v
        else:
            v = e["GOPATH"]
        if not isdir(r):
            raise ValueError(f'build: GOROOT path "{r}" is not a directory')
        if not isdir(v):
            raise ValueError(f'build: GOPATH path "{v}" is not a directory')
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
            f'GOOS="{e["GOOS"]}", GOARCH="{e["GOARCH"]}", GOROOT="{e["GOROOT"]}" GOPATH="{e["GOPATH"]}"..'
        )
        n, workspace["goroot"], workspace["gopath"] = (
            basename(out),
            e["GOROOT"],
            e["GOPATH"],
        )
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
            raise ValueError("build: result is invalid")
        if not isfile(o):
            raise ValueError(f'built: result "{o}" is not a file')
        self.log.info(f'Build step returned "{o}".')
        workspace["bin"] = o
        del e
        return o

    def print_options(self, osv, arch, gen, file=None):
        print(f'JetSteam Load complete!\n- | Configured Options\n{"="*60}', file=file)
        print(f'- | {"Target:":22}{osv}/{arch}', file=file)
        print(f'- | {"Generator:":22}{gen.name()}\n- |', file=file)
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
        print(f'- | = {"GOPATH:":20}{self.opts.get_option("gopath")}', file=file)
        print(
            f'- | = {"Build Tags:":20}{",".join(self.opts.get_option("tags"))}',
            file=file,
        )
        if osv != "windows":
            return
        print("- | Support Configuration", file=file)
        print(f'- | = {"Manifest:":20}{self.opts.get_support("manifest")}', file=file)
        if self.opts.get_option("cgo"):
            if self.opts.get_support("cgo_export"):
                print(
                    f'- | = {"CGO Export:":20}{self.opts.get_support("cgo_export")}',
                    file=file,
                )
            else:
                print(f'- | = {"CGO Export:":20}[randomized]', file=file)
            if self.opts.get_support("cgo_secondary"):
                print(
                    f'- | = {"CGO Secondary:":20}{self.opts.get_support("cgo_secondary")}',
                    file=file,
                )
            else:
                print(f'- | = {"CGO Secondary:":20}[randomized]', file=file)
        print("- | Signing Configuration", file=file)
        print(f'- | = {"Enabled:":20}{self.opts.get_sign("enabled")}', file=file)
        if self.opts.get_sign("enabled"):
            _print_sign_config(self.opts, file)
        print("- | Resource Configuration", file=file)
        print(f'- | = {"Enabled:":20}{self.opts.get_rc("enabled")}', file=file)
        if self.opts.get_rc("enabled"):
            _print_rc_config(self.opts, file)
        gen.print_options(self.opts, file)

    def check(self, target, gen, config, save, library):
        if not nes(target) or "/" not in target:
            raise ValueError(f'check: invalid target "{target}"')
        n = target.find("/")
        if n is None or n < 3:
            raise ValueError(f'check: invalid target "{target}"')
        o = target[:n].lower().strip()
        if o not in OS:
            raise ValueError(f'check: invalid os "{o}"')
        a = target[n + 1 :].lower().strip()
        del n
        if a not in ARCH:
            raise ValueError(f'check: invalid arch "{a}"')
        if o not in ARCH[a]:
            raise ValueError("check: invalid arch/os combo")
        self._fill(config, save)
        if not nes(self.opts.get_bin("go")):
            raise ValueError('check: binary target "go" missing')
        if o == "windows":
            if a.endswith("64"):
                r, g = self.opts.get_bin("wres64"), self.opts.get_bin("wgcc64")
            else:
                r, g = self.opts.get_bin("wres32"), self.opts.get_bin("wgcc32")
            if not nes(r):
                raise ValueError(f'check: binary target "wres" missing for "{target}"')
            if not nes(g):
                raise ValueError(f'check: binary target "wgcc" missing for "{target}"')
        else:
            if library:
                raise ValueError(
                    "check: cannot use -D/--library for a non-Windows target"
                )
            if self.opts.get_option("cgo"):
                raise ValueError("check: can only use CGO with Windows")
        if library and not self.opts.get_option("cgo"):
            raise ValueError("check: cannot use -D/--library without CGO")
        if self.opts.get_option("upx") and not nes(self.opts.get_bin("upx")):
            raise ValueError('check: "upx" is enabled but "upx" binary is missing')
        if self.opts.get_option("garble") and not nes(self.opts.get_bin("garble")):
            raise ValueError(
                'check: "garble" is enabled but "garble" binary is missing'
            )
        if self.opts.get("build.support.sign.enabled"):
            if not nes(self.opts.get_bin("openssl")):
                raise ValueError(
                    'check: "sign" is enabled but "openssl" binary is missing'
                )
            if not nes(self.opts.get_bin("osslsigncode")):
                raise ValueError(
                    'check: "sign" is enabled but "osslsigncode" binary is missing'
                )
            if not _sign_check(self.opts):
                raise ValueError(
                    'check: "sign" is enabled but certificate configuration is invalid'
                )
        if gen is not None:
            gen.check(self.opts)
        self.opts.vet(check_go=True)
        return o, a

    def _step_build_go(self, workspace, env, ld, extra, file, out):
        b, x = self.opts.get_bin("go"), list()
        if not self.opts._trim and self.opts.get_option("garble"):
            self.log.warning(
                "Disabling Garble as is does not support this Golang version!"
            )
            self.opts.set("build.options.garble", False)
        if self.opts.get_option("garble"):
            b = self.opts.get_bin("garble")
            x += ["-tiny", "-seed=random"]
        else:
            t = which("go")
            if t != b:
                self.log.debug(f'Adding alternate Go binary "{b}" to $PATH..')
                env["PATH"] = b + ":" + env["PATH"]
            del t
        x.insert(0, b)
        del b
        x += ["build", "-o", out]
        if self.opts._vcs:
            x.append("-buildvcs=false")
        if self.opts._trim:
            x.append("-trimpath")
        t = self.opts.get_option("tags")
        if not isinstance(t, list):
            t = list()
        a = workspace.get("tags")
        if isinstance(a, list) and len(a) > 0:
            t.extend(a)
        del a
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
        if len(t) > 0:
            t = list(set(t))
        g = self.opts.get_option("crypt")
        if g:
            e = [workspace["os"], workspace["arch"]]
            if len(t) > 0:
                e += t
            self.log.debug("Starting crypt build..")
            if islink(__file__):
                p = join(
                    dirname(
                        normpath(join(dirname(__file__), normpath(readlink(__file__))))
                    ),
                    "include",
                    "strs.json",
                )
            else:
                p = join(dirname(__file__), "include", "strs.json")
            if not isfile(p):
                raise ValueError(f'crypt: could not find "strs.json" at "{p}"')
            k, v = generate_crypt(e, p)
            del e, p
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
            x.append("-tags")
            if self.opts._trim:
                x.append(",".join(t))
            else:
                x.append(" ".join(t))
        del t
        x += ["-ldflags", f.strip()]
        del f
        if isinstance(extra, list) and len(extra) > 0:
            x += extra
        if "go_args" in workspace and isinstance(workspace["go_args"], list):
            x += workspace["go_args"]
        w = workspace["work_dir"]
        if nes(workspace["link"]):
            x.append(
                relpath(join(workspace["work_dir"], basename(file)), workspace["link"])
            )
            w = workspace["link"]
        else:
            x.append(file)
        if not nes(workspace["link"]):
            b = self.opts.get_bin("go")
            self._exec(
                [b, "mod", "init", "jetstream"],
                env=env,
                trunc=g,
                wd=w,
                dout=False,
            )
            self._exec([b, "mod", "tidy"], env=env, trunc=g, wd=w, dout=False)
            del b
        self._exec(x, env=env, trunc=g, wd=w)
        del x, w, g
        return out

    def _exec(self, cmd, env=None, trunc=False, out=True, wd=None, dout=True):
        return execute(self.log, cmd, env, trunc, out, wd, dout)

    def _step_build_cgo(self, base, workspace, env, rc, x64, lib, src, file, out):
        if workspace["os"] != "windows":
            raise ValueError("build: can only use CGO with Windows")
        c = self.opts.get_bin("wgcc" + ("64" if x64 else "32"))
        env["CC"] = c
        env["CGO_ENABLED"] = "1"
        i = join(base, workspace["cgo_out"]) + ".a"
        self._step_build_go(
            workspace,
            env,
            "-H=windowsgui",
            ["-buildmode=c-archive"],
            file,
            i,
        )
        _, n = splitext(out)
        m = out
        if len(n) == 0 and workspace["os"] == "windows":
            if lib:
                m += ".dll"
            else:
                m += ".exe"
        del n
        self.log.debug(f'File target name is "{m}".')
        z = list()
        q = self.opts.get_bin("wres" + ("64" if x64 else "32"))
        if self.opts.get_rc("enabled"):
            self.log.debug("Adding Resource file..")
            r, o = join(base, "res.rc"), join(base, "res.o")
            with open(r, "w") as f:
                f.write(rc.generate(m, lib))
            self._exec(
                [
                    q,
                    "--codepage=0xFDE9",  # UTF-8
                    "--language=0x409",  # EN-US
                    "--output-format=coff",
                    "-i",
                    r,
                    "-o",
                    o,
                ]
            )
            z.append(o)
            self.log.debug(f'Resource file "{o}" generated.')
            if not workspace.get("no_clean", False):
                remove(r)
            del r, o
        if self.opts.get_support("manifest"):
            self.log.debug("Adding Manifest file..")
            with open(join(base, "file.manifest"), "w") as f:
                f.write(MANIFEST)
            r, o = join(base, "manifest.rc"), join(base, "manifest.o")
            with open(r, "w") as f:
                f.write(
                    f'#include "winuser.h"\n{"2" if lib else "1"} RT_MANIFEST file.manifest\n'
                )
            self._exec(
                [
                    q,
                    "--codepage=0xFDE9",
                    "--language=0x409",
                    "--output-format=coff",
                    "-i",
                    r,
                    "-o",
                    o,
                ]
            )
            z.append(o)
            self.log.debug(f'Manifest file "{o}" generated.')
            if not workspace.get("no_clean", False):
                remove(r)
            del r, o
        del q
        o = join(base, m)
        del m
        if "gcc_args" in workspace and isinstance(workspace["gcc_args"], list):
            z += workspace["gcc_args"]
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
                    "-O2",
                    "-Wa,--strip-local-absolute",
                    "-Wp,-femit-struct-debug-reduced,-O2",
                    "-Wl,-x,-s,-nostdlib,--no-insert-timestamp",
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
                    "-O2",
                    "-Wa,--strip-local-absolute",
                    "-Wp,-femit-struct-debug-reduced,-O2",
                    "-Wl,-x,-s,-nostdlib,--no-insert-timestamp",
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
                    "-O2",
                    "-Wa,--strip-local-absolute",
                    "-Wp,-femit-struct-debug-reduced,-O2",
                    "-Wl,-x,-s,-nostdlib,--no-insert-timestamp",
                    f"{o}.o",
                    i,
                ]
                + z,
                env=env,
                wd=base,
            )
        del c, i, z
        return o

    def run(self, osv, arch, gen, library, output, no_clean, dest=None, auto=False):
        if not nes(output):
            raise ValueError('run: "output" is not valid')
        if isabs(output):
            output = join(getcwd(), output)
        if self.prefix:
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
            "tags": [],
            "main": "",
            "arch": arch,
            "link": v,
            "flags": "",
            "export": self.opts.get_support("cgo_export"),
            "go_args": list(),
            "gcc_args": list(),
            "no_clean": no_clean,
            "library": library,
            "main_cgo": "",
            "work_dir": d,
            "secondary": self.opts.get_support("cgo_secondary"),
        }
        del v
        if nes(k):
            workspace["work_dir"] = k
        if library:
            workspace["tags"].append("svcdll")
        r = None
        if self.opts.get_rc("enabled"):
            r = Rc(self.opts.get_support("rc"))
        self.log.debug(f"Workspace built: {dumps(workspace)}")
        workspace["log"] = self.log
        if not auto and not self.opts._mod:
            p = self.opts.get_option("gopath")
            if not isinstance(p, str) or len(p) == 0:
                p = join(d, "deps")
                pull_in_deps(self.log, p)
                self.opts.set("build.options.gopath", p)
                self.log.debug(f'Setting generated GOPATH to "{p}".')
            else:
                self.log.warning(
                    "Ensure the the Golang modules used are in a localized directory "
                    "as this version does NOT support Go Modules!"
                )
            del p
        try:
            with self("SP1"):
                self.log.info("Starting the Generate step..")
                f = self.generate(gen, d, workspace)
                self.log.debug("Completed the Generate step!")
            with self("SP2"):
                self.log.info("Starting the Build step..")
                o = self.build(d, workspace, r, f, output)
                self.log.debug("Completed the Build step!")
            with self("SP3"):
                self.log.info("Starting the Protect step..")
                self.protect(workspace, d, o)
                self.log.debug("Completed the Protect step!")
            if nes(dest):
                b = dirname(dest)
                if len(b) > 0:
                    makedirs(b, exist_ok=True)
                del b
                copy(o, dest)
            else:
                b = dirname(output)
                if len(b) > 0:
                    makedirs(b, exist_ok=True)
                del b
                copy(o, output)
            del o, f
        except KeyboardInterrupt as err:
            self.log.error("Interrupted!")
            raise err
        except Exception as err:
            self.log.error(f"Error during operation: {err}", err=err)
            raise err
        finally:
            if self.prefix:
                self.log.prefix(None)
            del r, workspace
            if nes(k):
                self.log.debug(f'Removing link directory "{k}".')
                remove(k)
            if not no_clean and m:
                self.log.debug(f'Removing working directory "{d}".')
                # NOTE(dij): Fix for when download deps have weirdly set permissions.
                for x, y, z in walk(d):
                    for k in y:
                        chmod(join(x, k), 0o777)
                    for k in z:
                        chmod(join(x, k), 0o777)
                rmtree(d)
        try:
            chmod(output, 0o755, follow_symlinks=False)
        except OSError:
            pass
        self.log.info(f'Output result file "{output}".')
        return output


if __name__ == "__main__":
    try:
        o, g, r, h = Parser.with_load()
    except ValueError as err:
        print(f"Error: {err}!", file=stderr)
        exit(1)
    if h:
        Parser.print_help(g)
    del h
    try:
        v = JetStream(o)
        t, a = v.check(r.target, g, r.config, r.save, r.library)
    except Exception as err:
        print(f"Error: {err}!", file=stderr)
        exit(1)
    del o
    if not r.quiet:
        v.print_options(t, a, g)
    if r.check:
        exit(0)
    try:
        v.run(t, a, g, r.library, r.output, r.no_clean)
    except KeyboardInterrupt:
        print("Interrupted!", file=stderr)
        exit(1)
    except Exception as err:
        print(f"Error: {err}!", file=stderr)
        exit(1)
    del r, t, a, g

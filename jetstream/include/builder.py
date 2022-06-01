#!/usr/bin/python3

from glob import glob
from requests import get
from shutil import which
from shutil import copytree
from include.util import nes
from os import remove, rename
from json import dumps, loads
from os.path import join, dirname
from include.crypt import generate_crypt
from include.files import Rc, Binary, Dll, DllService, MANIFEST


OS = [
    "aix",
    "android",
    "darwin",
    "dragonfly",
    "freebsd",
    "illumos",
    "ios",
    "js",
    "linux",
    "netbsd",
    "openbsd",
    "plan9",
    "solaris",
    "windows",
]
ARCH = {
    "386": ["android", "freebsd", "linux", "netbsd", "openbsd", "plan9", "windows"],
    "amd64": [
        "android",
        "darwin",
        "dragonfly",
        "freebsd",
        "illumos",
        "ios",
        "linux",
        "netbsd",
        "openbsd",
        "plan9",
        "solaris",
        "windows",
    ],
    "arm": ["android", "freebsd", "linux", "netbsd", "openbsd", "plan9", "windows"],
    "arm64": [
        "android",
        "darwin",
        "freebsd",
        "ios",
        "linux",
        "netbsd",
        "openbsd",
        "windows",
    ],
    "mips": ["linux"],
    "mips64": ["linux", "openbsd"],
    "mips64le": ["linux"],
    "mipsle": ["linux"],
    "ppc64": ["aix", "linux"],
    "ppc64le": ["linux"],
    "riscv64": ["linux"],
    "s390x": ["linux"],
    "wasm": ["js"],
}
_VALIDS = {
    "build": [
        "tags",
        "root",
        "tiny",
        "crypt",
        "garble",
    ],
    "config": [
        "key",
        "pipe",
        "load",
        "guard",
        "linker",
        "ignore",
        "critical",
    ],
    "binary": [
        "go",
        "gcc",
        "wgcc32",
        "wgcc64",
        "wres32",
        "wres64",
        "openssl",
        "osslsigncode",
        "garble",
    ],
}


def upx(build, file):
    build.log(f'UPX Packing file "{file}"..')
    build.run(
        [
            build.get("binary", "upx"),
            "--compress-exports=0",
            "--strip-relocs=1",
            "--compress-icons=2",
            "--best",
            "--no-backup",
            "-9",
            "--no-progress",
            "--no-color",
            "-q",
            file,
        ],
        out=False,
    )


def tiny_root(old, new):
    try:
        copytree(old, new)
    except OSError:
        raise OSError(f'copytree from "{old}" to "{new}" failed')
    for i in glob(join(new, "src", "fmt", "*.go"), recursive=False):
        remove(i)
    for i in glob(join(new, "src", "unicode", "*.go"), recursive=False):
        remove(i)
    b = join(new, "src", "fmt")
    _download_to(
        "https://raw.githubusercontent.com/iDigitalFlame/TinyPatchedGo/main/fmt/print.go",
        join(b, "print.go"),
    )
    _download_to(
        "https://raw.githubusercontent.com/iDigitalFlame/TinyPatchedGo/main/fmt/quick.go",
        join(b, "quick.go"),
    )
    _download_to(
        "https://raw.githubusercontent.com/iDigitalFlame/TinyPatchedGo/main/fmt/scan.go",
        join(b, "scan.go"),
    )
    del b
    _download_to(
        "https://raw.githubusercontent.com/iDigitalFlame/TinyPatchedGo/main/unicode/unicode.go",
        join(new, "src", "unicode", "unicode.go"),
    )
    _sed_file(
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
    _sed_file(
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
    _sed_file(
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
    _sed_file(
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
    return new


def _download_to(url, path):
    r = get(url)
    r.raise_for_status()
    with open(path, "wb") as f:
        f.write(r.content)
    r.close()
    del r


def _sed_file(path, old, new):
    with open(path, "r") as f:
        d = f.read()
    with open(path, "w") as f:
        for x in range(0, len(old)):
            d = d.replace(old[x], new[x])
        f.write(d)
    del d


def sign(build, pfx, pw, file):
    build.log(f'Signing file "{file}"..')
    build.run(
        [
            build.get("binary", "osslsigncode"),
            "sign",
            "-pkcs12",
            pfx,
            "-h",
            "sha2",
            "-in",
            file,
            "-out",
            f"{file}.sig",
            "-pass",
            pw,
        ],
        out=False,
    )
    remove(file)
    rename(f"{file}.sig", file)


def build_go(build, env, go, os, arch):
    v = join(build.dir, "main.go")
    with open(v, "w") as f:
        f.write(go)
    r = join(build.dir, "out")
    _go_build(
        build,
        v,
        env,
        os,
        arch,
        "-s -w",
        r,
        ["-gcflags", "-G=0"],
    )
    return r


def build_cgo(build, env, go, x64, rec, **kw):
    if "//export " not in go:
        raise ValueError("build: CGO file does not have an export")
    x = go.find("//export ")
    if not isinstance(x, int) or x < 10:
        raise ValueError("build: could not find CGO export")
    e = go.find("\n", x + 10)
    n = go[x + 9 : e]
    del x
    del e
    if f"//export {n}\nfunc {n}() {{\n" not in go:
        raise ValueError("build: could not find CGO export")
    v = join(build.dir, "main.go")
    with open(v, "w") as f:
        f.write(go)
    gc = build.get("binary", "wgcc64")
    if not x64:
        gc = build.get("binary", "wgcc32")
    env["CC"] = gc
    env["CGO_ENABLED"] = "1"
    _go_build(
        build,
        v,
        env,
        "windows",
        "amd64" if x64 else "386",
        "-s -w -H=windowsgui",
        join(build.dir, "stub.a"),
        ["-buildmode=c-archive", "-gcflags", "-G=0"],
    )
    del v
    e = list()
    if isinstance(rec, dict):
        build.log("Building resource file..")
        r = join(build.dir, "res.rc")
        with open(r, "w") as f:
            f.write(Rc(rec))
        o = join(build.dir, "res.o")
        x = build.get("binary", "wres64")
        if not x64:
            x = build.get("binary", "wres32")
        build.run([x, "-i", r, "-o", o])
        del x
        del r
        e.append(o)
        del o
    dll = kw.get("dll", False)
    h = join(build.dir, "man.rc")
    m = join(build.dir, "man.o")
    v = None
    if rec is not None:
        v = rec.get("file")
    if not nes(v):
        v = "result"
    if dll and not v.endswith(".dll"):
        v += ".dll"
    if not dll and not v.endswith(".exe"):
        v += ".exe"
    build.log(f'Building manifest file "{v}.manifest"..')
    with open(join(build.dir, f"{v}.manifest"), "w") as f:
        f.write(MANIFEST)
    with open(h, "w") as f:
        f.write('#include "winuser.h"\n')
        if dll:
            f.write("2 ")
        else:
            f.write("1 ")
        f.write(f"RT_MANIFEST {v}.manifest\n")
    x = build.get("binary", "wres64")
    if not x64:
        x = build.get("binary", "wres32")
    build.run([x, "--output-format=coff", "-i", h, "-o", m])
    e.append(m)
    del m
    del h
    del x
    c = join(build.dir, "base.c")
    if not dll:
        build.log("Building CGO Binary..")
        with open(c, "w") as f:
            f.write(Binary(n))
        r = join(build.dir, v)
        del v
        x = [
            gc,
            "-mwindows",
            "-o",
            r,
            "-fPIC",
            "-pthread",
            "-lwinmm",
            "-lntdll",
            "-lws2_32",
            "-Wl,-x,-s,-nostdlib",
            c,
            join(build.dir, "stub.a"),
        ] + e
        build.run(x, env=env, wd=build.dir)
        del x
        del e
        del c
        del n
        return r
    build.log("Building CGO DLL..")
    with open(c, "w") as f:
        if nes(kw.get("dll_svc")):
            f.write(
                DllService(
                    n,
                    kw.get("dll_thread"),
                    kw.get("dll_func"),
                    kw.get("dll_svc"),
                    kw.get("dll_timeout"),
                )
            )
        else:
            f.write(Dll(n, kw.get("dll_thread"), kw.get("dll_func")))
    r = join(build.dir, v)
    del v
    x = [
        gc,
        "-c",
        "-o",
        f"{r}.o",
        "-mwindows",
        "-fPIC",
        "-pthread",
        "-lwinmm",
        "-lntdll",
        "-lws2_32",
        "-Wl,-x,-s,-nostdlib",
        c,
    ]
    build.run(x, env=env, wd=build.dir)
    del x
    x = [
        gc,
        "-shared",
        "-o",
        r,
        "-mwindows",
        "-fPIC",
        "-pthread",
        "-lwinmm",
        "-lntdll",
        "-lws2_32",
        "-Wl,-x,-s,-nostdlib",
        f"{r}.o",
        join(build.dir, "stub.a"),
    ] + e
    build.run(x, env=env, wd=build.dir)
    del x
    del e
    del c
    del n
    return r


def _go_build(build, f, env, os, arch, ld, out, extra):
    b = build.get("binary", "go")
    a = []
    if build.get("build", "garble"):
        b = build.get("binary", "garble")
        if not nes(b):
            raise ValueError('build: Garble is enabled but "garble" is not in PATH')
        a += ["-tiny", "-seed=random"]
        a.append("-literals")  # I think this makes the file bigger
    a.insert(0, b)
    del b
    a += ["build", "-o", out, "-buildvcs=false", "-trimpath"]
    t = build.get("build", "tags")
    if not isinstance(t, list):
        t = list()
    if not nes(ld):
        ld = ""
    if build.get("build", "crypt"):
        q = [os, arch]
        if len(t) > 0:
            q += t
        build.log("Starting crypt build..")
        k, v = generate_crypt(q, join(dirname(__file__), "strs.json"))
        if len(ld) > 0:
            ld += " "
        ld += (
            f"-X 'github.com/iDigitalFlame/xmt/util/crypt.key={k}' "
            f"-X 'github.com/iDigitalFlame/xmt/util/crypt.payload={v}'"
        )
        if "crypt" not in t:
            t.append("crypt")
        del k
        del v
        del q
    if len(t) > 0:
        a += ["-tags", ",".join(t)]
    del t
    if len(ld) > 0:
        a += ["-ldflags", ld]
    del ld
    if isinstance(extra, list) and len(extra) > 0:
        a += extra
    a.append(f)
    build.run(a, env=env, trunc=build.get("build", "crypt"))
    del a


class Options(dict):
    def __init__(self, p=None):
        dict.__init__(self)
        self.load(p)

    def __str__(self):
        return dumps(self, indent=4, sort_keys=True)

    def load(self, p):
        if not nes(p):
            return
        with open(p) as f:
            d = loads(f.read())
        if not isinstance(d, dict):
            raise ValueError(f'load: file "{p}" is not valid')
        if len(d) == 0:
            return
        for k, v in _VALIDS.items():
            if k not in d:
                continue
            if not isinstance(d[k], dict) or len(d[k]) == 0:
                continue
            self[k] = dict()
            for i in v:
                if i not in d[k]:
                    continue
                self[k][i] = d[k][i]
        del d

    def save(self, p):
        if not nes(p):
            return
        with open(p, "w") as f:
            f.write(dumps(self, indent=4, sort_keys=True))

    def validate(self):
        self.get("binary", "upx", which("upx"))
        self.get("binary", "garble", which("garble"))
        if not nes(self.get("binary", "go", which("go"))):
            raise ValueError('binary: "go" was not found')
        if not nes(self.get("binary", "gcc", which("gcc"))):
            raise ValueError('binary: "gcc" was not found')
        if not nes(self.get("binary", "openssl", which("openssl"))):
            raise ValueError('binary: "openssl" was not found')
        if not nes(self.get("binary", "osslsigncode", which("osslsigncode"))):
            raise ValueError('binary: "osslsigncode" was not found')
        if not nes(self.get("binary", "wgcc32", which("i686-w64-mingw32-gcc"))):
            raise ValueError('binary: "i686-w64-mingw32-gcc" was not found')
        if not nes(self.get("binary", "wgcc64", which("x86_64-w64-mingw32-gcc"))):
            raise ValueError('binary: "x86_64-w64-mingw32-gcc" was not found')
        if not nes(self.get("binary", "wres32", which("i686-w64-mingw32-windres"))):
            raise ValueError('binary: "i686-w64-mingw32-windres" was not found')
        if not nes(self.get("binary", "wres64", which("x86_64-w64-mingw32-windres"))):
            raise ValueError('binary: "x86_64-w64-mingw32-windres" was not found')
        if self.get("config", "load", True) and not nes(self.get("config", "pipe")):
            raise ValueError('config: "pipe" is missing/empty')
        if not self.get("config", "ignore", False):
            if not nes(self.get("config", "guard")):
                raise ValueError('config: "guard" is missing/empty')
        v = self.get("config", "key")
        if isinstance(v, (bytes, bytearray)) and len(v) > 0:
            self.set("config", "key", v.encode("UTF-8"))
        del v
        self.get("config", "critical", True)
        # self.get("build", "root")
        self.get("build", "tags", ["implant", "nojson", "noproxy"])
        self.get("build", "tiny", False)
        self.get("build", "crypt", False)
        self.get("build", "garble", True)

    def set(self, b, n, v):
        if b not in self:
            self[b] = dict()
        self[b][n] = v

    def get(self, b, n, d=None):
        if not nes(b) or not nes(n):
            return d
        if b not in self:
            self[b] = dict()
        # if d is None:
        #    return None
        if n not in self[b]:
            self[b][n] = d
            return d
        return self[b][n]

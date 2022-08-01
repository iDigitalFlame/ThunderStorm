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
from io import StringIO
from requests import get
from random import choice
from random import randint
from shutil import copytree
from base64 import b64decode
from include.util import nes
from os import remove, rename
from os.path import isfile, join
from datetime import datetime, timedelta
from string import ascii_letters, Template, ascii_lowercase

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
RC = """#include <windows.h>
{icon}
VS_VERSION_INFO  VERSIONINFO
FILEVERSION      {version}
PRODUCTVERSION   {version}
FILEFLAGSMASK    VS_FFI_FILEFLAGSMASK
FILEFLAGS        0
FILEOS           VOS__WINDOWS32
FILETYPE         VFT_DLL
FILESUBTYPE      VFT2_UNKNOWN

BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"
        BEGIN
            VALUE "Comments", ""
            VALUE "CompanyName", "{company}"
            VALUE "FileDescription", "{title}"
            VALUE "FileVersion", "{version_string}"
            VALUE "InternalName", "{title}"
            VALUE "LegalCopyright", "{copyright}"
            VALUE "OriginalFilename", "{file}"
            VALUE "ProductName", "{product}"
            VALUE "ProductVersion", "{version_string}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
"""
MANIFEST = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
    <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
        <application>
            <supportedOS Id="{e2011457-1546-43c5-a5fe-008deee3d3f0}" />
            <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}" />
            <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}" />
            <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}" />
            <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}" />
        </application>
    </compatibility>
</assembly>
"""
CERT_GEN = """package main

import (
    "bytes"
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "errors"
    "io"
    "net"
    "os"
    "time"
)

func main() {
    if len(os.Args) != 2 {
        os.Stderr.WriteString(os.Args[0] + " <target_name>\\n")
        os.Exit(2)
    }
    if err := generate(os.Args[1]); err != nil {
        os.Exit(1)
    }
}
func certs() ([]byte, error) {
    c, err := tls.DialWithDialer(
        &net.Dialer{Timeout: time.Second * 10, KeepAlive: time.Second * 10, DualStack: true},
        "tcp", "$target:443", &tls.Config{InsecureSkipVerify: true},
    )
    if err != nil {
        return nil, err
    }
    var b bytes.Buffer
    for _, x := range c.ConnectionState().PeerCertificates {
        if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: x.Raw}); err == nil {
            break
        }
    }
    if c.Close(); b.Len() == 0 {
        return nil, io.EOF
    }
    return b.Bytes(), nil
}
func generate(p string) error {
    d, err := certs()
    if err != nil {
        return err
    }
    var (
        v, _ = pem.Decode(d)
        c, _ = x509.ParseCertificate(v.Bytes)
        t    = x509.Certificate{
            IsCA:                  true,
            Subject:               pkix.Name{CommonName: $rename},
            NotAfter:              c.NotAfter,
            KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
            NotBefore:             c.NotBefore,
            ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
            SerialNumber:          c.SerialNumber,
            PublicKeyAlgorithm:    x509.RSA,
            SignatureAlgorithm:    x509.SHA256WithRSA,
            BasicConstraintsValid: true,
        }
        i = x509.Certificate{
            Subject:            pkix.Name{CommonName: c.Issuer.CommonName},
            NotAfter:           c.NotAfter,
            NotBefore:          c.NotBefore,
            SerialNumber:       c.SerialNumber,
            SignatureAlgorithm: x509.SHA256WithRSA,
        }
    )
    k, err := rsa.GenerateKey(rand.Reader, 4096)
    if err != nil {
        return errors.New("cannot generate RSA key: " + err.Error())
    }
    b, err := x509.CreateCertificate(rand.Reader, &t, &i, &k.PublicKey, k)
    if err != nil {
        return errors.New("cannot generate certificate: " + err.Error())
    }
    f, err := os.Create(p + ".pem")
    if err != nil {
        return errors.New(`cannot create file "` + p + `.pem": ` + err.Error())
    }
    var o []byte
    if o, err = x509.MarshalPKCS8PrivateKey(k); err == nil {
        err = pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: o})
    }
    if f.Close(); err != nil {
        return errors.New("cannot marshal RSA key: " + err.Error())
    }
    if f, err = os.Create(p + ".crt"); err != nil {
        return errors.New(`cannot create file "` + p + `.crt": ` + err.Error())
    }
    err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: b})
    if f.Close(); err != nil {
        return errors.New("cannot marshal certificate: " + err.Error())
    }
    return nil
}
"""

_THROW = compile(r"throw\(")
_PANIC = compile(r"panic\(")

_REPO_URL = "https://raw.githubusercontent.com/iDigitalFlame/TinyPatchedGo/main"


def upx(js, file):
    js.log.debug(f'UPX Packing file "{file}"..')
    js._exec(
        [
            js.opts.get_bin("upx"),
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


def _sign_range(d, exp):
    if nes(d):
        t = datetime.fromisoformat(d)
    else:
        t = datetime.now()
    if not isinstance(exp, int) or exp <= 0:
        return str(t.timestamp())
    n, v = datetime.now(), t + timedelta(days=exp)
    if v < n and randint(0, 1) == 1:
        return str((t - timedelta(days=randint(0, exp) * -1)).timestamp())
    return str((t - timedelta(days=randint(0, exp))).timestamp())


def _sed(path, old, new):
    with open(path, "r") as f:
        d = f.read()
    with open(path, "w") as f:
        for x in range(0, len(old)):
            d = d.replace(old[x], new[x])
        f.write(d)
    del d


def go_bytes(v, limit=20):
    if len(v) == 0:
        return ""
    b = StringIO()
    c = 0
    for x in v:
        if limit > 0 and c > 0 and c % limit == 0:
            b.write("\n\t")
        b.write(f"0x{hex(x)[2:].upper().zfill(2)}, ")
        c += 1
    r = b.getvalue()
    b.close()
    if limit == 0 and len(r) > 2:
        r = r[:-2]
    del b
    del c
    return r


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


def _wget(url, path, timeout=5):
    r = get(url, timeout=timeout, allow_redirects=True)
    r.raise_for_status()
    with open(path, "wb") as f:
        f.write(r.content)
    r.close()
    del r


def tiny_root(old, new, timeout=5):
    try:
        copytree(old, new)
    except OSError as err:
        raise OSError(f'tiny_root: copytree from "{old}" to "{new}"') from err
    for i in glob(join(new, "src", "fmt", "*.go"), recursive=False):
        remove(i)
    for i in glob(join(new, "src", "unicode", "*.go"), recursive=False):
        remove(i)
    _wget(f"{_REPO_URL}/fmt/scan.go", join(new, "src", "fmt", "scan.go"), timeout)
    _wget(f"{_REPO_URL}/fmt/print.go", join(new, "src", "fmt", "print.go"), timeout)
    _wget(f"{_REPO_URL}/fmt/quick.go", join(new, "src", "fmt", "quick.go"), timeout)
    _wget(
        f"{_REPO_URL}/runtime/print.go",
        join(new, "src", "runtime", "print.go"),
        timeout,
    )
    _wget(
        f"{_REPO_URL}/unicode/unicode.go",
        join(new, "src", "unicode", "unicode.go"),
        timeout,
    )
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
            'var http2errReadEmpty = errors.New("read from empty dataBuffer")',
            'var http2DebugGoroutines = os.Getenv("DEBUG_HTTP2_GOROUTINES") == "1"',
            'panic(fmt.Sprintf("unexpected buffer len=%v", len(p)))',
            'return fmt.Sprintf("unknown error code 0x%x", uint32(e))',
            'return fmt.Sprintf("ERR_UNKNOWN_%d", uint32(e))',
            'return fmt.Sprintf("connection error: %s", http2ErrCode(e))',
            'return fmt.Sprintf("stream error: stream ID %d; %v; %v", e.StreamID, e.Code, e.Cause)',
            'return fmt.Sprintf("stream error: stream ID %d; %v", e.StreamID, e.Code)',
            'return "connection exceeded flow control window size"',
            'return fmt.Sprintf("http2: connection error: %v: %v", e.Code, e.Reason)',
            'return fmt.Sprintf("invalid pseudo-header %q", string(e))',
            'return fmt.Sprintf("duplicate pseudo-header %q", string(e))',
            'return fmt.Sprintf("invalid header field name %q", string(e))',
            'return fmt.Sprintf("invalid header field value %q", string(e))',
            'http2errMixPseudoHeaderTypes = errors.New("mix of request and response pseudo headers")',
            'http2errPseudoAfterRegular   = errors.New("pseudo header field after regular")',
            'return fmt.Sprintf("UNKNOWN_FRAME_TYPE_%d", uint8(t))',
            'var http2ErrFrameTooLarge = errors.New("http2: frame too large")',
            "\nfunc init() {\n",
            "\n\t\thttp2logFrameReads = true\n\t}\n}",
            "\nvar (\n\thttp2VerboseLogs    bool\n\thttp2logFrameWrites bool\n\t"
            "http2logFrameReads  bool\n\thttp2inTests        bool\n)\n",
        ],
        [
            'if a := ""; len(a) > 0 {',
            "",
            'var http2errReadEmpty = errors.New("empty")',
            "const http2DebugGoroutines = false",
            'panic("")',
            'return "unknown error code"',
            'return "ERR_UNKNOWN"',
            'return "connection error"',
            'return "stream error"',
            'return "stream error"',
            'return "window size"',
            'return "connection error"',
            'return "invalid"',
            'return "duplicate"',
            'return "invalid"',
            'return "invalid"',
            'http2errMixPseudoHeaderTypes = errors.New("headers")',
            'http2errPseudoAfterRegular   = errors.New("after regular")',
            'return "UNKNOWN_FRAME_TYPE"',
            'var http2ErrFrameTooLarge = errors.New("too large")',
            "/*\nfunc init() {\n",
            "\n\t\thttp2logFrameReads = true\n\t}\n}\n*/",
            "\nconst (\n\thttp2VerboseLogs    = false\n\thttp2logFrameWrites = false\n\t"
            "http2logFrameReads  = false\n\thttp2inTests        = false\n)\n",
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
        [
            "if n, ok := int32(1), true; ok && n > 0 {"
        ],  # NOTE(dij): Set GOMAXPROCS to '1' here
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
    _sed(
        join(new, "src", "runtime", "os_plan9.go"),
        [
            'var _badsignal = []byte("runtime: signal received on thread not created by Go.\\n")'
        ],
        ['var _badsignal = []byte("bad\\n")'],
    )
    _sed(
        join(new, "src", "runtime", "signal_windows.go"),
        [
            'print("signal arrived during external code execution\\n")',
            'const msg = "runtime: signal received on thread not created by Go.\\n"',
        ],
        ["", 'const msg = "bad\\n"'],
    )
    _sed(
        join(new, "src", "cmd", "link", "internal", "ld", "data.go"),
        ['const prefix = "\\xff Go buildinf:"'],
        ['const prefix = "\\xff __ _________"'],
    )
    _sed(
        join(new, "src", "debug", "buildinfo", "buildinfo.go"),
        ['buildInfoMagic = []byte("\\xff Go buildinf:")'],
        ['buildInfoMagic = []byte("\\xff __ _________")'],
    )
    _sed(
        join(new, "src", "runtime", "cgo", "libcgo_windows.h"),
        ["__declspec(dllexport) int _cgo_dummy_export;"],
        [f"__declspec(dllexport) int _{random_chars(12, True)};"],
    )
    _sed(
        join(new, "src", "runtime", "proc.go"),
        [
            'var earlycgocallback = []byte("fatal error: cgo callback before cgo call\\n")'
        ],
        ['var earlycgocallback = []byte("bad\\n")'],
    )
    _sed(
        join(new, "src", "runtime", "cgo", "gcc_util.c"),
        ['fprintf(stderr, "runtime/cgo: out of memory in thread_start\\n");'],
        ['fprintf(stderr, "bad\\n");'],
    )
    _sed(
        join(new, "src", "vendor", "golang.org", "x", "sys", "cpu", "cpu.go"),
        ["\tprocessOptions()\n"],
        ["\t// processOptions()\n"],
    )
    _sed(
        join(new, "src", "internal", "cpu", "cpu.go"),
        ["\tprocessOptions(env)\n"],
        ["\t// processOptions(env)\n"],
    )
    _sed(
        join(new, "src", "internal", "godebug", "godebug.go"),
        ['return get(os.Getenv("GODEBUG"), key)'],
        ['return get(os.Getenv(""), key)'],
    )
    _sed(
        join(new, "src", "crypto", "x509", "x509.go"),
        ['override = " (temporarily override with GODEBUG=x509sha1=1)"'],
        ['override = ""'],
    )
    _sed(
        join(new, "src", "runtime", "stubs.go"),
        [
            'var badsystemstackMsg = "fatal: systemstack called from unexpected goroutine"'
        ],
        ['var badsystemstackMsg = "bad"'],
    )
    _sed(
        join(new, "src", "encoding", "asn1", "asn1.go"),
        [
            'err = StructuralError{"unknown Go type for slice"}',
            'err = StructuralError{fmt.Sprintf("unknown Go type: %v", fieldType)}',
        ],
        [
            'err = StructuralError{"unknown type"}',
            'err = StructuralError{"unknown type"}',
        ],
    )
    _sed(
        join(new, "src", "encoding", "asn1", "marshal.go"),
        [
            'return nil, StructuralError{fmt.Sprintf("unknown Go type: %v", v.Type())}',
            'return nil, StructuralError{"unknown Go type"}',
        ],
        [
            'return nil, StructuralError{"unknown type"}',
            'return nil, StructuralError{"unknown type"}',
        ],
    )
    _sed(
        join(new, "src", "runtime", "runtime2.go"),
        [
            "\nvar waitReasonStrings = [...]string{\n",
            "\nfunc (w waitReason) String() string {\n",
            "\n\treturn waitReasonStrings[w]\n}",
        ],
        [
            "/*var waitReasonStrings = [...]string{\n",
            '\n*/\nfunc (waitReason) String() string {\n\treturn "wait"\n}\n/*\n',
            "\n\treturn waitReasonStrings[w]\n}*/",
        ],
    )
    _sed(
        join(new, "src", "runtime", "debug.go"),
        ['stopTheWorldGC("GOMAXPROCS")'],
        ['stopTheWorldGC("GMP")'],
    )
    # NOTE(dij): I have this commented out since I don't necessarily want to break
    #            support for long paths and cause os.fixPath to allocate.
    #            Basically the "runtime.initLongPathSupport" function causes the
    #            Process to attempt to access a super-long ~500 char string path
    #            which is SUPER fingerprintable. I'm debating if I'm gonna turn
    #            this off rn. I have it here just in case.
    # _sed(
    #    join(new, "src", "runtime", "os_windows.go"),
    #    ["getRandomData(longFileName[len(longFileName)-33 : len(longFileName)-1])"],
    #    [
    #        "_ = originalBitField\n\treturn // getRandomData(longFileName[len(longFileName)-33 : len(longFileName)-1])"
    #    ],
    # )
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


def random_chars(size, lower=False):
    if lower:
        return "".join(choice(ascii_lowercase) for _ in range(size))
    return "".join(choice(ascii_letters) for _ in range(size))


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


def make_cert_target(js, base, target, name):
    r = join(base, "grab.go")
    n = f'"{name}"'
    if not nes(name):
        n = "c.Issuer.CommonName"
    v = target
    if v.startswith("http://"):
        v = v[7:]
    elif v.startswith("https://"):
        v = v[8:]
    if "/" in v:
        v = v[: v.find("/")]
    if len(v) == 0:
        raise ValueError(f'sign: spoof target "{v}" (initial "{target}") is invalid')
    with open(r, "w") as f:
        f.write(Template(CERT_GEN).substitute(target=v, rename=n))
    del n, v
    js.log.debug(f'Wrote cert grabbing script to "{r}".')
    t = join(base, "gens")
    js._exec([js.opts.get_bin("go"), "run", r, t])
    remove(r)
    del r
    c, p = t + ".crt", t + ".pem"
    del t
    if not isfile(p) or not isfile(c):
        raise ValueError("sign: certificate script did not result in any valid output")
    return c, p


def sign(js, o, date, date_range, base, file):
    if nes(o.get_sign("pfx")):
        return sign_with_pfx(
            js,
            _sign_range(date, date_range),
            file,
            o.get_sign("pfx"),
            o.get_sign("pfx_password"),
        )
    if nes(o.get_sign("pfx_raw")):
        c = join(base, "sign.pfx")
        with open(c, "wb") as f:
            f.write(b64decode(o.get_sign("pfx_raw"), validate=True))
        sign_with_pfx(
            js,
            _sign_range(date, date_range),
            file,
            c,
            o.get_sign("pfx_password"),
        )
        return remove(c)
    if nes(o.get_sign("cert")):
        if nes(o.get_sign("pem")):
            return sign_with_certs(
                js,
                _sign_range(date, date_range),
                file,
                o.get_sign("cert"),
                o.get_sign("pem"),
            )
        if nes(o.get_sign("pem_raw")):
            c = join(base, "sign-pem.pem")
            with open(c, "wb") as f:
                f.write(b64decode(o.get_sign("pem_raw"), validate=True))
            sign_with_certs(
                js, _sign_range(date, date_range), file, o.get_sign("cert"), c
            )
            return remove(c)
    if nes(o.get_sign("pem")) and nes(o.get_sign("cert_raw")):
        c = join(base, "sign-cert.crt")
        with open(c, "wb") as f:
            f.write(b64decode(o.get_sign("cert_raw"), validate=True))
        sign_with_certs(js, _sign_range(date, date_range), file, c, o.get_sign("pem"))
        return remove(c)
    if nes(o.get_sign("cert_raw")) and nes(o.get_sign("pem_raw")):
        c, p = join(base, "sign-cert.crt"), join(base, "sign-pem.pem")
        with open(c, "wb") as f:
            f.write(b64decode(o.get_sign("cert_raw"), validate=True))
        with open(p, "wb") as f:
            f.write(b64decode(o.get_sign("pem_raw"), validate=True))
        sign_with_certs(js, _sign_range(date, date_range), file, c, p)
        remove(c)
        return remove(p)
    if nes(o.get_sign("generate_target")):
        return sign_with_target(
            js,
            _sign_range(date, date_range),
            file,
            base,
            o.get_sign("generate_target"),
            o.get_sign("generate_name"),
        )


def sign_with_pfx(js, when, file, pfx, pfx_pw):
    x = [
        js.opts.get_bin("osslsigncode"),
        "sign",
        "-h",
        "sha2",
        "-pkcs12",
        pfx,
        "-in",
        file,
        "-out",
        f"{file}.sig",
        "-st",
        when,
    ]
    if nes(pfx_pw):
        x += ["-pass", pfx_pw]
    js._exec(x)
    del x
    js.log.debug(f'Signed "{file}" with "{pfx}".')
    remove(file)
    rename(f"{file}.sig", file)


def sign_with_certs(js, when, file, cert, pem):
    js._exec(
        [
            js.opts.get_bin("osslsigncode"),
            "sign",
            "-h",
            "sha2",
            "-certs",
            cert,
            "-key",
            pem,
            "-in",
            file,
            "-out",
            f"{file}.sig",
            "-st",
            when,
        ]
    )
    js.log.debug(f'Signed "{file}" with "{cert}" and "{pem}".')
    remove(file)
    rename(f"{file}.sig", file)


def sign_with_target(js, when, file, base, target, name):
    c, p = make_cert_target(js, base, target, name)
    sign_with_certs(js, when, file, c, p)
    remove(c)
    remove(p)
    del c, p

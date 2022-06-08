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

from io import StringIO
from random import choice
from random import randint
from base64 import b64decode
from include.util import nes
from os import remove, rename
from os.path import isfile, join
from datetime import datetime, timedelta
from string import ascii_letters, Template

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


def random_chars(size):
    return "".join(choice(ascii_letters) for _ in range(size))


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


def go_bytes(v, limit=20):
    if len(v) == 0:
        return ""
    b = StringIO()
    c = 0
    for x in v:
        if c > 0 and c % limit == 0:
            b.write("\n\t")
        b.write(f"0x{hex(x)[2:].upper().zfill(2)}, ")
        c += 1
    r = b.getvalue()
    b.close()
    del b
    del c
    return r


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
    r = join(base, "grab.go")
    n = f'"{name}"'
    if not nes(name):
        n = "c.Issuer.CommonName"
    with open(r, "w") as f:
        f.write(Template(CERT_GEN).substitute(target=target, rename=n))
    del n
    js.log.debug(f'Wrote cert grabbing script to "{r}".')
    t = join(base, "gens")
    js._exec([js.opts.get_bin("go"), "run", r, t])
    remove(r)
    del r
    c, p = t + ".crt", t + ".pem"
    if not isfile(p) or not isfile(c):
        raise ValueError("certificate script did not result in any valid output")
    sign_with_certs(js, when, file, c, p)
    remove(c)
    remove(p)
    del c, p, t

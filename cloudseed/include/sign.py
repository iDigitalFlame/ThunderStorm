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

from os import remove
from string import Template
from os.path import join, relpath
from collections import namedtuple


Certs = namedtuple("Certs", ["ca", "ca_key", "signer", "signer_key"])

_SIGNER = (
    """package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "math/big"
    "os"
    "time"
)

func main() {
    c, x, err := newCert(nil, nil, "$start", "$ca", $ca_length)
    if err != nil {
        panic(err)
    }
    k, p, err := newCert(c, x, "$start", "$cert", $cert_length)
    if err != nil {
        panic(err)
    }
    if err = writeCert(c, "ca.crt"); err != nil {
        panic(err)
    }
    if err = writeKey(x, "ca.pem"); err != nil {
        panic(err)
    }
    if err = writeCert(k, "sign.crt"); err != nil {
        panic(err)
    }
    if err = writeKey(p, "sign.pem"); err != nil {
        panic(err)
    }
}
func random() *big.Int {
    var (
        n = new(big.Int)
        b [8]byte
    )
    rand.Read(b[:])
    n.SetBytes(b[:])
    return n
}
func writeKey(k *rsa.PrivateKey, p string) error {
    f, err := os.OpenFile(p, 0x242, 0o644)
    if err != nil {
        return err
    }
    err = pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
    f.Close()
    return err
}
func writeCert(c *x509.Certificate, p string) error {
    f, err := os.OpenFile(p, 0x242, 0o644)
    if err != nil {
        return err
    }
    err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
    f.Close()
    return err
}
func newCert(ca *x509.Certificate, k *rsa.PrivateKey, start, """
    + """name string, days uint64) (*x509.Certificate, *rsa.PrivateKey, error) {
    var (
        t   = time.Now()
        err error
    )
    if len(start) > 0 {
        if t, err = time.Parse(time.RFC3339Nano, start); err != nil {
            return nil, nil, err
        }
    }
    var (
        p *rsa.PrivateKey
        c = &x509.Certificate{
            IsCA: ca == nil,
            Subject: pkix.Name{
                Country:      []string{"US"},
                Locality:     []string{"Redmond"},
                Province:     []string{"Washington"},
                CommonName:   name,
                Organization: []string{"Microsoft Corporation"},
            },
            Version:               0,
            KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
            NotAfter:              time.Now().AddDate(0, 0, int(days)),
            NotBefore:             t,
            SerialNumber:          random(),
            PublicKeyAlgorithm:    x509.ECDSA,
            SignatureAlgorithm:    x509.SHA256WithRSA,
            BasicConstraintsValid: true,
        }
    )
    c.DNSNames = []string{c.Subject.CommonName}
    if p, err = rsa.GenerateKey(rand.Reader, 4096); err != nil {
        return nil, nil, err
    }
    if c.PublicKey = p.Public(); ca == nil {
        c.Raw, err = x509.CreateCertificate(rand.Reader, c, c, c.PublicKey, p)
    } else {
        c.Raw, err = x509.CreateCertificate(rand.Reader, c, ca, c.PublicKey, k)
    }
    return c, p, err
}
"""
)


def make_pki(js, base, ca_name, cert_name, ca_days=3650, cert_days=1440, start=None):
    p = join(base, "signer.go")
    with open(p, "w") as f:
        f.write(
            Template(_SIGNER).substitute(
                ca=ca_name,
                cert=cert_name,
                start=start,
                ca_length=str(ca_days),
                cert_length=str(cert_days),
            )
        )
    try:
        js._exec([js.opts.get_bin("go"), "run", relpath(p, base)], out=True, wd=base)
    finally:
        remove(p)
        del p
    return Certs(
        join(base, "ca.crt"),
        join(base, "ca.pem"),
        join(base, "sign.crt"),
        join(base, "sign.pem"),
    )

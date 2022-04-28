// Copyright (C) 2021 iDigitalFlame
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

package main

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

// BUG(dij): I've gotten reports that this is broken, will fix.

const target = "windows.com:443"

func main() {
	if len(os.Args) != 2 {
		os.Stderr.WriteString(os.Args[0] + " <target_name>\n")
		os.Exit(2)
	}
	if err := generate(os.Args[1]); err != nil {
		os.Exit(1)
	}
}
func certs() ([]byte, error) {
	c, err := tls.DialWithDialer(
		&net.Dialer{Timeout: time.Second * 10, KeepAlive: time.Second * 10, DualStack: true},
		"tcp", target, &tls.Config{InsecureSkipVerify: true},
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
			Subject:               pkix.Name{CommonName: "Microsoft Windows"},
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
	/*
		Try to enable Microsoft Tcb signing extensions.
		i.Extensions = append(i.Extensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 22},
			Critical: false,
		})
		i.Extensions = append(i.Extensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 23},
			Critical: false,
		})
		i.ExtraExtensions = append(i.ExtraExtensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 22},
			Critical: false,
		})
		i.ExtraExtensions = append(i.ExtraExtensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 23},
			Critical: false,
		})*/
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

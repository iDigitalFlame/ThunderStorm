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

const target = "microsoft.com:443"

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
	if b.Len() == 0 {
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

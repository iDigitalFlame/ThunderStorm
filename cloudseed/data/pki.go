package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"math/big"
	"os"
	"time"
)

type timeStr struct {
	time.Time
}

func main() {
	var (
		f                = flag.NewFlagSet("pki generate", flag.ExitOnError)
		certStart        timeStr
		caName, certName string
		caDays, certDays uint64
	)
	f.Var(&certStart, "start", "Cert Fake Sign Date in RFC3339Nano format.")
	f.StringVar(&caName, "ca-name", "", "CA Authority Common Name.")
	f.StringVar(&certName, "ca-name", "", "Signing Authority Common Name.")
	f.Uint64Var(&caDays, "ca-days", 3650, "CA Authority Valid Length in Days.")
	f.Uint64Var(&certDays, "cert-days", 1440, "Signing Authority Valid Length in Days.")

	if err := f.Parse(os.Args); err != nil {
		f.PrintDefaults()
		os.Exit(2)
	}
	if len(caName) == 0 || len(certName) == 0 {
		f.PrintDefaults()
		os.Exit(2)
	}

	c, x, err := newCert(nil, nil, certStart.Time, caName, caDays)
	if err != nil {
		os.Stderr.WriteString(os.Args[0] + " error: " + err.Error() + "\n")
		os.Exit(1)
	}
	k, p, err := newCert(c, x, certStart.Time, certName, certDays)
	if err != nil {
		os.Stderr.WriteString(os.Args[0] + " error: " + err.Error() + "\n")
		os.Exit(1)
	}
	if err = writeCert(c, "ca.crt"); err != nil {
		os.Stderr.WriteString(os.Args[0] + " error: " + err.Error() + "\n")
		os.Exit(1)
	}
	if err = writeKey(x, "ca.pem"); err != nil {
		os.Stderr.WriteString(os.Args[0] + " error: " + err.Error() + "\n")
		os.Exit(1)
	}
	if err = writeCert(k, "sign.crt"); err != nil {
		os.Stderr.WriteString(os.Args[0] + " error: " + err.Error() + "\n")
		os.Exit(1)
	}
	if err = writeKey(p, "sign.pem"); err != nil {
		os.Stderr.WriteString(os.Args[0] + " error: " + err.Error() + "\n")
		os.Exit(1)
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
func (t *timeStr) String() string {
	return t.Format(time.RFC3339Nano)
}
func (t *timeStr) Set(s string) error {
	if len(s) == 0 {
		t.Time = time.Now()
	}
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return err
	}
	t.Time = v
	return nil
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
func newCert(ca *x509.Certificate, k *rsa.PrivateKey, start time.Time, name string, days uint64) (*x509.Certificate, *rsa.PrivateKey, error) {
	var (
		err error
		p   *rsa.PrivateKey
		c   = &x509.Certificate{
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
			NotBefore:             start,
			SerialNumber:          random(),
			PublicKeyAlgorithm:    x509.RSA,
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

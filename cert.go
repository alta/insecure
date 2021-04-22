package insecure

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// Pool returns a certifiate pool that trusts cert.
// To use, assign to the RootCAs field of a tls.Config.
// Will panic if cert is nil or contains no certificates.
func Pool(cert tls.Certificate) (*x509.CertPool, error) {
	xcert := cert.Leaf
	if xcert == nil {
		var err error
		xcert, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, err
		}
	}
	pool := x509.NewCertPool()
	pool.AddCert(xcert)
	return pool, nil
}

// Cert returns a deterministic self-signed certificate and private key for the
// specified organization and list of SANs. If the organiation name is
// unspecified, a default value will be used. If SANs are not specified, a
// default set of local SANs will be used.
func Cert(sans ...string) (tls.Certificate, error) {
	cert, key, err := PEM(sans...)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(cert, key)
}

// PEM returns a self-signed certificate and private key in PEM format for the
// specified organization and list of SANs. If the organiation name is
// unspecified, a default value will be used. If SANs are not specified, a
// default set of local SANs will be used.
func PEM(sans ...string) (cert []byte, key []byte, err error) {
	priv, err := Key()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %s", err)
	}

	notBefore, notAfter := notBeforeOrAfter(time.Now())

	template := x509.Certificate{
		SerialNumber: big.NewInt(SerialNumber),
		Subject: pkix.Name{
			Organization: []string{Organization},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if len(sans) == 0 {
		sans = LocalSANs()
	}
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, s)
		}
	}

	// For deterministic output. Do NOT do this for any real server.
	b, err := x509.CreateCertificate(zeroes{}, &template, &template, priv.Public(), priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %s", err)
	}
	cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})

	b, err = x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to marshal private key: %v", err)
	}
	key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})

	return
}

const (
	// SerialNumber is a constant magic number used in generated certificates.
	SerialNumber = 42

	// Organization is used in the x509 subject.
	Organization = "Insecure; DO NOT USE IN PRODUCTION"
)

// LocalSANs is a default list of local SANs (Subject Alternative Names) used for
// generating an insecure local certificate. The return value may be mutated.
func LocalSANs() []string {
	return localSANs[:]
}

var localSANs = []string{"127.0.0.1", "::1", "localhost"}

// notBeforeOrAfter returns a deterministic start and end date for a TLS
// certificate. Given that certificates are accepted by browsers with a max
// duration of 398 days, we start with midnight Jan 1 of the current year in UTC
// and add 398 days to get the end date. The current time (now) should always
// fall between the two dates.
func notBeforeOrAfter(now time.Time) (time.Time, time.Time) {
	notBefore := time.Date(time.Now().UTC().Year(), 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(398 * 24 * time.Hour)
	return notBefore, notAfter
}

// Key returns a P-256 ECDSA private key generated WITHOUT randomess.
func Key() (priv *ecdsa.PrivateKey, err error) {
	curve := elliptic.P256()
	return ecdsa.GenerateKey(curve, zeroes{})
}

// For deterministic output. Do NOT do this for any real server.
type zeroes struct{}

func (z zeroes) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

package insecure

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPEM(t *testing.T) {
	tests := []struct {
		name      string
		sans      []string
		wantNames []string
		wantSHA   string
		wantErr   bool
	}{
		{"computer.local", []string{"computer.local"}, []string{"computer.local"}, "9221e5433fcef4cfa917a793f1112465d9344402784230b3459d64ea13a83222", false},
		{"local SANs + computer.local", append(LocalSANs(), "computer.local"), append(LocalSANs(), "computer.local"), "c770a0201f509803b12e19383a814a3ba0c578c8b38bc6575ae2216c63414dc4", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certPEM, _, err := PEM(tt.sans...)
			if (err != nil) != tt.wantErr {
				t.Errorf("PEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			sha := fmt.Sprintf("%x", sha256.Sum256(certPEM))
			if sha != tt.wantSHA {
				t.Errorf("PEM() sha: got %v, want %v", sha, tt.wantSHA)
			}

			// Certificate acts as its own signing authority.
			roots := x509.NewCertPool()
			ok := roots.AppendCertsFromPEM(certPEM)
			if !ok {
				panic("failed to parse root certificate")
			}

			block, _ := pem.Decode(certPEM)
			if block == nil {
				t.Fatal("failed to parse certificate PEM")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("failed to parse certificate: " + err.Error())
			}

			// Verify certificate is valid for all expected names
			for _, name := range tt.wantNames {
				opts := x509.VerifyOptions{
					DNSName: name,
					Roots:   roots,
				}

				if _, err := cert.Verify(opts); err != nil {
					t.Errorf("failed to verify certificate: " + err.Error())
				}
			}
		})
	}
}

func TestServeCert(t *testing.T) {
	// Configure server
	cert, err := Cert()
	if err != nil {
		t.Fatalf("Cert returned error: %v", err)
	}
	h := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte("OK"))
	})
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{
		NextProtos:   []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{cert},
	}
	s.StartTLS()
	defer s.Close()

	// Configure client
	roots, err := Pool(cert)
	if err != nil {
		t.Fatalf("Pool returned error: %v", err)
	}
	cfg := &tls.Config{RootCAs: roots}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: cfg,
		},
	}

	// Make request
	req, err := http.NewRequest(http.MethodGet, s.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); s != "OK" {
		t.Fatal(err)
	}
}

func TestNotBeforeOrAfter(t *testing.T) {
	// https://en.wikipedia.org/wiki/UTC%E2%88%9212:00
	idlw := time.FixedZone("UTC-12", -12*60*60)
	nz := time.FixedZone("UTC+12", 12*60*60)
	to := time.FixedZone("UTC+13", 13*60*60)
	hi := time.FixedZone("UTC-10", -10*60*60)
	tests := []time.Time{
		time.Now(),
		time.Now().UTC(),
		time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2020, 12, 31, 0, 0, 0, 0, time.UTC),
		time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2021, 12, 31, 0, 0, 0, 0, time.UTC),
		time.Date(2020, 1, 1, 0, 0, 0, 0, idlw),
		time.Date(2020, 12, 31, 0, 0, 0, 0, idlw),
		time.Date(2021, 1, 1, 0, 0, 0, 0, idlw),
		time.Date(2021, 12, 31, 0, 0, 0, 0, idlw),
		time.Date(2020, 1, 1, 0, 0, 0, 0, nz),
		time.Date(2020, 12, 31, 0, 0, 0, 0, nz),
		time.Date(2021, 1, 1, 0, 0, 0, 0, nz),
		time.Date(2021, 12, 31, 0, 0, 0, 0, nz),
		time.Date(2020, 1, 1, 0, 0, 0, 0, to),
		time.Date(2020, 12, 31, 0, 0, 0, 0, to),
		time.Date(2021, 1, 1, 0, 0, 0, 0, to),
		time.Date(2021, 12, 31, 0, 0, 0, 0, to),
		time.Date(2020, 1, 1, 0, 0, 0, 0, hi),
		time.Date(2020, 12, 31, 0, 0, 0, 0, hi),
		time.Date(2021, 1, 1, 0, 0, 0, 0, hi),
		time.Date(2021, 12, 31, 0, 0, 0, 0, hi),
	}
	for _, tt := range tests {
		t.Run(tt.Format(time.RFC3339), func(t *testing.T) {
			notBefore, notAfter := notBeforeOrAfter(tt)
			if tt.Before(notBefore) {
				t.Errorf("time is before notBefore (%v)", notBefore.Format(time.RFC3339))
			}
			if tt.After(notAfter) {
				t.Errorf("time is after notAfter (%v)", notAfter.Format(time.RFC3339))
			}
		})
	}
}

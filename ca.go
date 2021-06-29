package insecure

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
)

// This file borrows heavily from the mkcert project:
// https://github.com/FiloSottile/mkcert
//
// This package will attempt to sign generated certs with your local mkcert CA, if present.

const (
	rootName    = "rootCA.pem"
	rootKeyName = "rootCA-key.pem"
)

// CA returns the mkcert CA certificate and key if found.
// Returns an error if either fail to load or parse.
func CA() (cert *x509.Certificate, key crypto.PrivateKey, err error) {
	certPEMBlock, keyPEMBlock, err := CAPEM()
	if err != nil {
		return nil, nil, err
	}

	certDERBlock, _ := pem.Decode(certPEMBlock)
	if certDERBlock == nil || certDERBlock.Type != "CERTIFICATE" {
		return nil, nil, errors.New("failed to read the CA certificate: unexpected content")
	}
	cert, err = x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyDERBlock, _ := pem.Decode(keyPEMBlock)
	if keyDERBlock == nil || keyDERBlock.Type != "PRIVATE KEY" {
		return nil, nil, errors.New("failed to read the CA key: unexpected content")
	}
	key, err = x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return
}

// CAPEM returns the raw PEM mkcert CA certificate and key if found.
// Returns an error if either doesn’t exist or fails to load.
func CAPEM() (cert []byte, key []byte, err error) {
	caRoot := getCARoot()

	caPath := filepath.Join(caRoot, rootName)
	if !pathExists(caPath) {
		return nil, nil, fmt.Errorf("no CA certificate located at: %s", caPath)
	}
	cert, err = ioutil.ReadFile(caPath)
	if err != nil {
		return nil, nil, err
	}

	keyPath := filepath.Join(caRoot, rootKeyName)
	if !pathExists(keyPath) {
		return nil, nil, fmt.Errorf("no CA key located at: %s", keyPath)
	}
	key, err = ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}

	return
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func getCARoot() string {
	if env := os.Getenv("CAROOT"); env != "" {
		return env
	}

	var dir string
	switch {
	case runtime.GOOS == "windows":
		dir = os.Getenv("LocalAppData")
	case os.Getenv("XDG_DATA_HOME") != "":
		dir = os.Getenv("XDG_DATA_HOME")
	case runtime.GOOS == "darwin":
		dir = os.Getenv("HOME")
		if dir == "" {
			return ""
		}
		dir = filepath.Join(dir, "Library", "Application Support")
	default: // Unix
		dir = os.Getenv("HOME")
		if dir == "" {
			return ""
		}
		dir = filepath.Join(dir, ".local", "share")
	}
	return filepath.Join(dir, "mkcert")
}

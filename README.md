# Insecure

[![go.dev reference](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white)](https://pkg.go.dev/github.com/alta/insecure) [![build status](https://img.shields.io/github/workflow/status/alta/insecure/Go.svg)](https://github.com/alta/insecure/actions)

Generate deterministic [TLS certificates](https://golang.org/pkg/crypto/tls/) for local [Go](https://golang.org/) development servers. The certificates use a [P-256 ECDSA private key](https://csrc.nist.gov/csrc/media/events/workshop-on-elliptic-curve-cryptography-standards/documents/papers/session6-adalier-mehmet.pdf) generated with a total lack of randomness.

## Why?

So your browser can trust a single certificate from your development servers, and dev/test with TLS. **Do not use in production.**

## Install

`go get github.com/alta/insecure`

## Usage

Get a TLS certificate suitable for `localhost`, `127.0.0.1`, etc:

```go
cert, err := insecure.Cert()
```

## Note

Seriously, do not use this in production.

## Author

Originally developed by [@cee-dub](https://github.com/cee-dub) for Alta Software LLC.

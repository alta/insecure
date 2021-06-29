// +build tools

package tools

import (
	// Blank imports for tool binaries
	_ "filippo.io/mkcert"
	_ "honnef.co/go/tools/cmd/staticcheck"
)

//go:generate go install filippo.io/mkcert
//go:generate go install honnef.co/go/tools/cmd/staticcheck

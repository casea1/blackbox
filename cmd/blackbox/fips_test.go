package main

import (
	"runtime/debug"
	"strings"
	"testing"
)

// COMP3: blackbox version says which FIPS 140-3 module the build links and
// whether FIPS mode is on.
func TestFIPSText(t *testing.T) {
	release := []debug.BuildSetting{{Key: "GOOS", Value: "linux"}, {Key: "GOFIPS140", Value: "v1.0.0"}, {Key: "DefaultGODEBUG", Value: "fips140=on"}}
	if got := fipsText(release, true); got != "FIPS 140-3: Go Cryptographic Module v1.0.0 (built with GOFIPS140=v1.0.0); FIPS mode on" {
		t.Errorf("release build: %q", got)
	}
	if got := fipsText(nil, false); !strings.Contains(got, "not built with GOFIPS140") || !strings.HasSuffix(got, "FIPS mode off") {
		t.Errorf("plain build: %q", got)
	}
	if got := fipsText([]debug.BuildSetting{{Key: "GOFIPS140", Value: "off"}}, true); !strings.Contains(got, "not built with GOFIPS140") || !strings.HasSuffix(got, "FIPS mode on") {
		t.Errorf("GODEBUG=fips140=on on a plain build: %q", got)
	}
	if !strings.HasPrefix(fipsState(), "FIPS 140-3: ") {
		t.Error(fipsState())
	}
}

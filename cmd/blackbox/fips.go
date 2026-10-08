package main

import (
	"crypto/fips140"
	"runtime/debug"
)

// fipsState says which FIPS 140-3 module this program was built with and
// whether FIPS 140-3 mode is on (COMP3). Releases are built with
// GOFIPS140=v1.0.0, which links the Go Cryptographic Module v1.0.0 (CMVP
// certificate #5247) and turns FIPS mode on by default; GODEBUG=fips140=on
// turns it on for any build.
func fipsState() string {
	var settings []debug.BuildSetting
	if bi, ok := debug.ReadBuildInfo(); ok {
		settings = bi.Settings
	}
	return fipsText(settings, fips140.Enabled())
}

func fipsText(settings []debug.BuildSetting, enabled bool) string {
	module := "not built with GOFIPS140 (the standard library's own crypto code)"
	for _, s := range settings {
		if s.Key == "GOFIPS140" && s.Value != "" && s.Value != "off" {
			module = "Go Cryptographic Module " + s.Value + " (built with GOFIPS140=" + s.Value + ")"
		}
	}
	mode := "off"
	if enabled {
		mode = "on"
	}
	return "FIPS 140-3: " + module + "; FIPS mode " + mode
}

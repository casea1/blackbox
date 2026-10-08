#!/bin/sh
# Builds release packages into dist/:
#   Blackbox-Setup-VERSION.exe           Windows: the one file to carry over (blackbox.exe marked windowed)
#   blackbox-VERSION-linux-amd64.tar.gz  blackbox + install.sh + uninstall.sh
#   blackbox-VERSION-linux-arm64.tar.gz
#   SHA256SUMS
# Pure Go with no cgo and no third-party modules, so it builds fully offline.
#   VERSION=0.1.0 scripts/build.sh
set -eu
cd "$(dirname "$0")/.."
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
VERSION="${VERSION#v}"
LDFLAGS="-s -w -buildid= -X main.version=${VERSION}"
# Go's FIPS 140-3 module (COMP3): GOFIPS140=v1.0.0 links the Go
# Cryptographic Module v1.0.0 (CMVP certificate #5247) and turns FIPS
# 140-3 mode on by default. "blackbox version" prints both. Needs Go 1.24
# or later; GOFIPS140=off builds without it.
GOFIPS140="${GOFIPS140:-v1.0.0}"
export GOFIPS140
rm -rf dist && mkdir -p dist/stage

# Authenticode signing, when a certificate is given (CI secrets):
#   SIGN_PFX       path to the code-signing certificate (.pfx)
#   SIGN_PASSWORD  its password
#   SIGN_TIMESTAMP timestamp server (optional)
# Without them the programs are built unsigned, as before.
sign() {
	if [ -z "${SIGN_PFX:-}" ]; then
		echo "not signed (no certificate given): $1"
		return 0
	fi
	command -v osslsigncode >/dev/null || { echo "osslsigncode is needed to sign" >&2; exit 1; }
	ts=""
	[ -n "${SIGN_TIMESTAMP:-}" ] && ts="-ts ${SIGN_TIMESTAMP}"
	# shellcheck disable=SC2086
	osslsigncode sign -pkcs12 "$SIGN_PFX" -pass "${SIGN_PASSWORD:-}" -n "Blackbox" \
		-i "https://github.com/casea1/blackbox" -h sha256 $ts -in "$1" -out "$1.signed"
	mv "$1.signed" "$1"
	osslsigncode verify -in "$1" >/dev/null 2>&1 || osslsigncode verify -in "$1" | tail -3
	echo "signed: $1"
}

package() { # os arch
	name="blackbox-${VERSION}-$1-$2"
	dir="dist/stage/$name"
	mkdir -p "$dir"
	exe=blackbox
	if [ "$1" = windows ]; then
		exe=blackbox.exe
		# Program icon and version details (Properties > Details, Settings > Apps).
		syso="cmd/blackbox/rsrc_windows_$2.syso"
		go run ./scripts/winres -version "$VERSION" -arch "$2" -o "$syso"
	fi
	echo "building $name"
	CGO_ENABLED=0 GOOS="$1" GOARCH="$2" go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$dir/$exe" ./cmd/blackbox
	if [ "$1" = windows ]; then
		# The console blackbox.exe, signed, travels inside the setup file,
		# which setup installs unchanged; the setup file itself is the same
		# program marked windowed, then signed (A10).
		sign "$dir/$exe"
		go run ./scripts/winres -version "$VERSION" -arch "$2" -payload "$dir/$exe" -o "$syso"
		CGO_ENABLED=0 GOOS="$1" GOARCH="$2" go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$dir/setup.exe" ./cmd/blackbox
		rm -f "$syso"
		# Double-clicking it opens the setup window without a console;
		# setup installs blackbox.exe (console) and blackboxw.exe from it.
		go run ./scripts/winres -windowed "$dir/setup.exe" -o "dist/Blackbox-Setup-${VERSION}.exe"
		sign "dist/Blackbox-Setup-${VERSION}.exe"
	else
		cp packaging/linux/* "$dir/"
		cp LICENSE NOTICE "$dir/"
		chmod +x "$dir/blackbox" "$dir"/*.sh
		tar -C dist/stage -czf "dist/$name.tar.gz" "$name"
	fi
}
package windows amd64
package linux amd64
package linux arm64
# The Linux amd64 program must report the module it was built with.
if [ "$GOFIPS140" != off ] && [ "$(uname -s)-$(uname -m)" = Linux-x86_64 ]; then
	fips=$("dist/stage/blackbox-${VERSION}-linux-amd64/blackbox" version | tail -1)
	echo "$fips"
	case "$fips" in
	# Newer Go names the snapshot in full: v1.0.0-c2097c7c.
	*"Go Cryptographic Module ${GOFIPS140}"[\ -]*"FIPS mode on") ;;
	*) echo "the build does not report the FIPS 140-3 module ${GOFIPS140}" >&2; exit 1 ;;
	esac
fi
rm -rf dist/stage
# A software bill of materials (SPDX), from the module and the Go
# toolchain that built it: no third-party modules to list.
go run ./scripts/sbom -version "$VERSION" > "dist/blackbox-${VERSION}.spdx.json"
(cd dist && sha256sum -- *.exe *.tar.gz *.spdx.json > SHA256SUMS)
cat dist/SHA256SUMS

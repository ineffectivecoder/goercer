#!/usr/bin/env bash
set -euo pipefail

# Build goercer for multiple platforms.
# Run `go mod tidy` first if this is a fresh checkout (generates go.sum).
if [[ ! -f go.sum ]]; then
    echo "[*] go.sum missing - running 'go mod tidy' to resolve dependencies..."
    go mod tidy
fi

VERSION="${1:-}"
LDFLAGS="-s -w"
if [[ -n "${VERSION}" ]]; then
    LDFLAGS="-s -w -X main.version=${VERSION}"
fi

OUT="${OUT_DIR:-bin}"

build() {
    local os="$1" arch="$2" ext="$3"
    local name="goercer-${os}-${arch}"
    echo "[*] Building ${name}..."
    GOOS="${os}" GOARCH="${arch}" CGO_ENABLED=0 \
        go build -trimpath -ldflags "${LDFLAGS}" -o "${OUT}/${name}${ext}" ./cmd/goercer
}

mkdir -p "${OUT}"

# Native host build first (fastest feedback).
build "$(go env GOOS)" "$(go env GOARCH)" ".exe" || true

# Cross-compiles for common lab platforms.
build linux amd64 ""
build linux arm64 ""
# Windows builds already covered by host; add explicit if needed.
build windows amd64 ".exe"

echo "[+] Done. Binaries in ${OUT}/"

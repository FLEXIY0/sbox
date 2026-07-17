#!/bin/sh
# Кросс-компиляция sbox под все поддерживаемые платформы (включая ARM).
# Результат — статические бинарники в ./dist, готовые к загрузке в GitHub Releases.
set -eu

OUT=dist
mkdir -p "$OUT"
LDFLAGS="-s -w"

build() {
    goos=$1; goarch=$2; suffix=$3; goarm=${4:-}
    name="sbox-${goos}-${suffix}"
    [ "$goos" = "windows" ] && name="${name}.exe"
    echo "-> $name"
    CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch GOARM=$goarm \
        go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/$name" .
}

build linux   amd64 amd64
build linux   arm64 arm64          # ARM 64-bit (Raspberry Pi 4/5, серверы Ampere)
build linux   arm   arm     7      # ARM 32-bit v7 (роутеры, Raspberry Pi 2/3)
build linux   mips  mips
build linux   mipsle mipsle        # роутеры MIPS little-endian
build linux   386   386
build windows amd64 amd64          # Windows x86_64
build windows 386   386            # Windows 32-bit (старые машины)
build windows arm64 arm64          # Windows on ARM (Surface Pro X и т.п.)
build darwin  amd64 amd64
build darwin  arm64 arm64          # Apple Silicon

echo ""
ls -lh "$OUT"

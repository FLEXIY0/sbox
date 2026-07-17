#!/bin/sh
# sbox installer — Linux / macOS.
# Скачивает бинарник под текущую архитектуру (в т.ч. ARM), кладёт его в
# /usr/local/bin/sbox и прописывает альяс `s` в .bashrc / .zshrc.
#
# Использование:  curl -fsSL https://raw.githubusercontent.com/flexiy0/sbox/main/install.sh | sh
#            или: wget -qO- https://raw.githubusercontent.com/flexiy0/sbox/main/install.sh | sh
set -eu

REPO="flexiy0/sbox"
BIN_DIR="/usr/local/bin"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in
    x86_64|amd64)   arch="amd64" ;;
    aarch64|arm64)  arch="arm64" ;;
    armv7l|armv6l|arm*) arch="arm" ;;
    mips)           arch="mips" ;;
    mipsel|mipsle)  arch="mipsle" ;;
    i386|i686)      arch="386" ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

asset="sbox-${os}-${arch}"
url="https://github.com/${REPO}/releases/latest/download/${asset}"

echo "-> downloading ${asset} ..."
tmp=$(mktemp)
if command -v curl >/dev/null 2>&1; then
    curl -fL -o "$tmp" "$url"
else
    wget -qO "$tmp" "$url"
fi
chmod 755 "$tmp"

if [ -w "$BIN_DIR" ]; then
    mv "$tmp" "$BIN_DIR/sbox"
else
    echo "-> need sudo to install into $BIN_DIR"
    sudo mv "$tmp" "$BIN_DIR/sbox"
fi
echo "-> installed $BIN_DIR/sbox"

# Глобальный альяс `s`
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [ -f "$rc" ] || continue
    if ! grep -q 'alias s="sbox"' "$rc"; then
        printf '\nalias s="sbox"\n' >> "$rc"
        echo "-> alias 's' added to $rc"
    fi
done

echo ""
echo "Done. Open a new shell and press: s"

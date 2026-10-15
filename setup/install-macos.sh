#!/usr/bin/env bash
set -euo pipefail

echo "╔══════════════════════════════════════╗"
echo "║  Malvex Tool Setup — macOS           ║"
echo "╚══════════════════════════════════════╝"
echo

command -v brew >/dev/null 2>&1 || {
    echo "[!] Homebrew not found. Installing..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
}

command -v python3 >/dev/null 2>&1 || {
    echo "[!] Python3 not found. Installing..."
    brew install python@3.12
}

command -v cargo >/dev/null 2>&1 || {
    echo "[!] Rust not found. Installing..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
}

command -v npm >/dev/null 2>&1 || {
    echo "[!] Node.js not found. Installing..."
    brew install node
}

# ── Brew packages ────────────────────────────────────────────────────────────
echo
echo "[1/6] Installing brew packages..."
BREW_PKGS=(
    radare2 rizin yara capa
    binwalk foremost exiftool
    ssdeep hashdeep upx
    gdb ngrep zeek suricata termshark
    apktool jadx
    osslsigncode checksec patchelf
    bulk_extractor innoextract
    podman qemu mitmproxy
    tshark wireshark
    floss
    capstone unicorn keystone
    ropper
    msitools p7zip cabextract
    sqlite jq yq xxd
    jsbeautifier
    radamsa
)
for pkg in "${BREW_PKGS[@]}"; do
    if brew list "$pkg" &>/dev/null; then
        echo "  ✓ $pkg (already installed)"
    else
        echo "  ↓ $pkg"
        brew install "$pkg" 2>/dev/null || echo "  ✗ $pkg failed (non-critical)"
    fi
done

# ── pip packages ─────────────────────────────────────────────────────────────
echo
echo "[2/6] Installing pip packages..."
pip3 install --upgrade pip 2>/dev/null || true

PIP_PKGS=(
    pefile lief capstone-engine keystone-engine unicorn-engine
    angr ropper
    yara-python
    oletools msoffcrypto-tool
    pdf-parser pdfid
    oledump zipdump
    XLMMacroDeobfuscator
    volatility3
    frida-tools
    androguard objection
    droidlysis quark-engine
    pyinstxtractor uncompyle6
    speakeasy-emulator qiling
    sigma-cli pySigma
    pySigma-backend-splunk pySigma-backend-elasticsearch
    stix2-validator stix-shifter taxii2-client
    pymisp pyeti
    py-tlsh rich-header-hash
    vt-cli
    iocextract cymru-whois
    macholib hachoir balbuzard
    unblob
    jsbeautifier
)
pip3 install "${PIP_PKGS[@]}" 2>/dev/null || {
    echo "  [!] Batch install had errors, trying individually..."
    for pkg in "${PIP_PKGS[@]}"; do
        pip3 install "$pkg" 2>/dev/null && echo "  ✓ $pkg" || echo "  ✗ $pkg failed"
    done
}

# ── npm packages ─────────────────────────────────────────────────────────────
echo
echo "[3/6] Installing npm packages..."
NPM_PKGS=(
    js-beautify
)
for pkg in "${NPM_PKGS[@]}"; do
    npm install -g "$pkg" 2>/dev/null && echo "  ✓ $pkg" || echo "  ✗ $pkg failed"
done

# ── Cargo packages ───────────────────────────────────────────────────────────
echo
echo "[4/6] Installing cargo packages..."
CARGO_PKGS=(
    ripgrep fd-find bat
)
for pkg in "${CARGO_PKGS[@]}"; do
    cargo install "$pkg" 2>/dev/null && echo "  ✓ $pkg" || echo "  ✗ $pkg failed"
done

# ── GitHub releases ──────────────────────────────────────────────────────────
echo
echo "[5/6] Installing from GitHub releases..."

TOOLS_DIR="${MALVEX_TOOLS_DIR:-$HOME/.malvex/tools}"
mkdir -p "$TOOLS_DIR/bin"

install_github_release() {
    local name="$1" repo="$2" pattern="$3"
    if command -v "$name" &>/dev/null; then
        echo "  ✓ $name (already installed)"
        return
    fi
    echo "  ↓ $name from $repo"
    local url
    url=$(curl -sL "https://api.github.com/repos/$repo/releases/latest" \
        | grep "browser_download_url.*$pattern" | head -1 | cut -d'"' -f4)
    if [ -n "$url" ]; then
        local tmp="/tmp/malvex-install-$name"
        curl -sL "$url" -o "$tmp"
        if [[ "$url" == *.zip ]]; then
            unzip -qo "$tmp" -d "$TOOLS_DIR/bin/" 2>/dev/null
        elif [[ "$url" == *.tar.gz || "$url" == *.tgz ]]; then
            tar xzf "$tmp" -C "$TOOLS_DIR/bin/" 2>/dev/null
        else
            cp "$tmp" "$TOOLS_DIR/bin/$name"
            chmod +x "$TOOLS_DIR/bin/$name"
        fi
        rm -f "$tmp"
        echo "  ✓ $name installed to $TOOLS_DIR/bin/"
    else
        echo "  ✗ $name — no release found for this platform"
    fi
}

install_github_release "capa" "mandiant/capa" "macos.zip"
install_github_release "floss" "mandiant/flare-floss" "macos.zip"
install_github_release "retdec" "avast/retdec" "macOS"
install_github_release "dex2jar" "pxb1988/dex2jar" ".zip"
install_github_release "apktool" "iBotPeaches/Apktool" "apktool_"

# ── Build Malvex ─────────────────────────────────────────────────────────────
echo
echo "[6/6] Building Malvex..."
cd "$(dirname "$0")/.."
cargo build --release 2>/dev/null && echo "  ✓ malvex built" || echo "  ✗ build failed"

# ── PATH setup ───────────────────────────────────────────────────────────────
echo
if [[ ":$PATH:" != *":$TOOLS_DIR/bin:"* ]]; then
    echo "Add to your shell profile:"
    echo "  export PATH=\"$TOOLS_DIR/bin:\$PATH\""
fi

# ── Verify ───────────────────────────────────────────────────────────────────
echo
echo "Running malvex doctor..."
./target/release/malvex doctor 2>/dev/null || echo "(doctor not available yet)"

echo
echo "Done! Run 'malvex doctor' to check tool availability."

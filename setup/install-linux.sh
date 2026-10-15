#!/usr/bin/env bash
set -euo pipefail

echo "╔══════════════════════════════════════╗"
echo "║  Malvex Tool Setup — Linux           ║"
echo "╚══════════════════════════════════════╝"
echo

if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

# Detect package manager
if command -v apt-get &>/dev/null; then
    PM="apt"
elif command -v dnf &>/dev/null; then
    PM="dnf"
elif command -v pacman &>/dev/null; then
    PM="pacman"
else
    echo "[!] No supported package manager found (apt/dnf/pacman)"
    PM="none"
fi

# ── System packages ──────────────────────────────────────────────────────────
echo "[1/6] Installing system packages ($PM)..."

if [ "$PM" = "apt" ]; then
    $SUDO apt-get update -qq
    APT_PKGS=(
        build-essential git curl wget unzip
        python3 python3-pip python3-venv
        radare2 yara binwalk foremost
        exiftool libimage-exiftool-perl
        ssdeep hashdeep
        gdb strace ltrace
        ngrep zeek suricata termshark
        apktool
        osslsigncode checksec patchelf
        bulk-extractor innoextract
        podman qemu-user-static
        tshark mitmproxy tcpdump
        upx-ucl firejail
        cabextract p7zip-full
        sqlite3 jq xxd
        libcapstone-dev libunicorn-dev
        npm
    )
    for pkg in "${APT_PKGS[@]}"; do
        if dpkg -l "$pkg" &>/dev/null; then
            echo "  ✓ $pkg"
        else
            echo "  ↓ $pkg"
            $SUDO apt-get install -y -qq "$pkg" 2>/dev/null || echo "  ✗ $pkg failed"
        fi
    done

elif [ "$PM" = "dnf" ]; then
    DNF_PKGS=(
        gcc gcc-c++ git curl wget unzip
        python3 python3-pip
        radare2 yara binwalk foremost
        perl-Image-ExifTool
        ssdeep hashdeep
        gdb strace ltrace
        ngrep zeek suricata
        checksec patchelf
        podman qemu-user-static
        wireshark-cli mitmproxy tcpdump
        upx firejail
        cabextract p7zip
        sqlite jq xxd
        capstone-devel unicorn-devel
        npm
    )
    for pkg in "${DNF_PKGS[@]}"; do
        echo "  ↓ $pkg"
        $SUDO dnf install -y -q "$pkg" 2>/dev/null || echo "  ✗ $pkg failed"
    done

elif [ "$PM" = "pacman" ]; then
    PACMAN_PKGS=(
        base-devel git curl wget unzip
        python python-pip
        radare2 yara binwalk foremost
        perl-image-exiftool
        ssdeep hashdeep
        gdb strace ltrace
        ngrep zeek suricata
        checksec patchelf
        podman qemu-user-static
        wireshark-cli mitmproxy tcpdump
        upx firejail
        cabextract p7zip
        sqlite jq xxd
        capstone unicorn
        npm
    )
    $SUDO pacman -Syu --noconfirm --needed "${PACMAN_PKGS[@]}" 2>/dev/null || true
fi

# ── Rust ─────────────────────────────────────────────────────────────────────
command -v cargo >/dev/null 2>&1 || {
    echo
    echo "[!] Rust not found. Installing..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
}

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
npm install -g js-beautify 2>/dev/null && echo "  ✓ js-beautify" || echo "  ✗ js-beautify"

# ── GitHub releases ──────────────────────────────────────────────────────────
echo
echo "[4/6] Installing from GitHub releases..."

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
        echo "  ✓ $name"
    else
        echo "  ✗ $name — no release found"
    fi
}

ARCH=$(uname -m)
case "$ARCH" in
    x86_64) ARCH_PAT="linux.*amd64\|linux.*x86_64\|linux64" ;;
    aarch64) ARCH_PAT="linux.*arm64\|linux.*aarch64" ;;
    *) ARCH_PAT="linux" ;;
esac

install_github_release "capa" "mandiant/capa" "linux.zip"
install_github_release "floss" "mandiant/flare-floss" "linux.zip"
install_github_release "retdec" "avast/retdec" "Linux"
install_github_release "dex2jar" "pxb1988/dex2jar" ".zip"
install_github_release "jadx" "skylot/jadx" "no-jre-portable"
install_github_release "apktool" "iBotPeaches/Apktool" "apktool_"

# ── Ghidra ───────────────────────────────────────────────────────────────────
echo
echo "[5/6] Installing Ghidra..."
if [ -d "${GHIDRA_HOME:-/opt/ghidra}" ] || command -v ghidra &>/dev/null; then
    echo "  ✓ Ghidra (already installed)"
else
    GHIDRA_VER="11.3.2"
    GHIDRA_DATE="20250415"
    GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VER}_build/ghidra_${GHIDRA_VER}_PUBLIC_${GHIDRA_DATE}.zip"
    echo "  ↓ Ghidra $GHIDRA_VER"
    curl -sL "$GHIDRA_URL" -o /tmp/ghidra.zip
    $SUDO unzip -qo /tmp/ghidra.zip -d /opt/ 2>/dev/null
    $SUDO ln -sf "/opt/ghidra_${GHIDRA_VER}_PUBLIC" /opt/ghidra
    rm -f /tmp/ghidra.zip
    echo "  ✓ Ghidra installed to /opt/ghidra"
    echo "    Set GHIDRA_HOME=/opt/ghidra in your shell"
fi

# ── Build Malvex ─────────────────────────────────────────────────────────────
echo
echo "[6/6] Building Malvex..."
cd "$(dirname "$0")/.."
cargo build --release 2>/dev/null && echo "  ✓ malvex built" || echo "  ✗ build failed"

# ── PATH setup ───────────────────────────────────────────────────────────────
echo
if [[ ":$PATH:" != *":$TOOLS_DIR/bin:"* ]]; then
    SHELL_RC="$HOME/.bashrc"
    [ -f "$HOME/.zshrc" ] && SHELL_RC="$HOME/.zshrc"
    echo "Add to $SHELL_RC:"
    echo "  export PATH=\"$TOOLS_DIR/bin:\$PATH\""
fi

# ── Verify ───────────────────────────────────────────────────────────────────
echo
echo "Running malvex doctor..."
./target/release/malvex doctor 2>/dev/null || echo "(doctor not available yet)"

echo
echo "Done! Run 'malvex doctor' to check tool availability."

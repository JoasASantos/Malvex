#!/usr/bin/env bash
# Malvex — macOS/Linux bootstrap.
# Idempotent, detect-before-install. Installs Rust + open-source RE tools,
# audits MCP-capable runtimes, builds `malvex`, and runs the doctor.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

log()  { printf '\033[1;36m[malvex]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[malvex]\033[0m %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

OS="$(uname -s)"
log "host: $OS"

# ── 1. package manager ──────────────────────────────────────────────────────
if [ "$OS" = "Darwin" ]; then
  if ! have brew; then
    warn "Homebrew missing. Install from https://brew.sh then re-run."; exit 1
  fi
  PKG="brew install"
else
  if have apt-get; then PKG="sudo apt-get install -y"; else PKG=""; fi
fi

# ── 2. Rust toolchain ───────────────────────────────────────────────────────
if ! have cargo; then
  log "installing Rust via rustup"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi
log "rust: $(cargo --version)"

# ── 3. open-source RE tools (only what's missing) ───────────────────────────
install_if_missing() { # $1=probe  $2..=install cmd
  local probe="$1"; shift
  if have "$probe"; then log "have $probe"; else log "install $probe"; "$@" || warn "install $probe failed (continuing)"; fi
}

if [ "$OS" = "Darwin" ]; then
  install_if_missing r2        brew install radare2
  install_if_missing ghidraRun brew install ghidra
  install_if_missing yara      brew install yara
  install_if_missing binwalk   brew install binwalk
  install_if_missing mitmdump  brew install mitmproxy
  install_if_missing typst     brew install typst
  # Windows-installer unpacking from macOS (MSI/CAB) — analyze Windows builds on a Mac
  install_if_missing msiextract brew install msitools
  install_if_missing 7zz         brew install sevenzip
  install_if_missing cabextract  brew install cabextract
elif [ -n "$PKG" ]; then
  install_if_missing radare2    sudo apt-get install -y radare2
  install_if_missing yara       sudo apt-get install -y yara
  install_if_missing binwalk    sudo apt-get install -y binwalk
  install_if_missing msiextract sudo apt-get install -y msitools
  install_if_missing 7z         sudo apt-get install -y p7zip-full
  install_if_missing cabextract sudo apt-get install -y cabextract
fi

# python analysis libs
PY="$(command -v python3 || true)"
if [ -n "$PY" ]; then
  for mod in lief capstone frida-tools yara-python; do
    log "pip: $mod"; "$PY" -m pip install --user --quiet "$mod" 2>/dev/null || warn "pip $mod skipped"
  done
fi

# ── 4. Claude Code CLI (install if missing) ─────────────────────────────────
if ! have claude; then
  log "Claude Code not found — installing"
  # Official install script (no npm needed); falls back to npm if present.
  if curl -fsSL https://claude.ai/install.sh | bash 2>/dev/null; then
    log "Claude Code installed via official script"
  elif have npm; then
    npm install -g @anthropic-ai/claude-code || warn "npm install of claude failed"
  else
    warn "could not install Claude Code (no curl/npm). Install manually: https://claude.ai/install.sh"
  fi
  # the installer drops the binary in ~/.local/bin — make sure it's on PATH for this run
  case ":$PATH:" in *":$HOME/.local/bin:"*) : ;; *) export PATH="$HOME/.local/bin:$PATH" ;; esac
fi

# ── 5. audit claude + MCP servers (reused, not reconfigured) ────────────────
if have claude; then
  log "claude: $(claude --version)"
  log "configured MCP servers:"
  claude mcp list 2>/dev/null | sed 's/^/    /' || warn "could not list MCPs — the harness auto-uses whatever is configured"
  warn "IDA Pro is reached via its MCP (idalib); commercial tools (IDA/WinDbg) are detected, never auto-installed."
  warn "Sign in once with 'claude' (interactive) before running real agents."
else
  warn "claude CLI still not on PATH — the harness needs it. Open a new shell or add \$HOME/.local/bin to PATH."
fi

# ── 5b. RE MCP servers for Claude Code (ida/ghidra/radare2/frida/x64dbg/...) ─
# uv/pipx help several of the python MCP servers install cleanly.
have uv || (have brew && brew install uv 2>/dev/null) || true
have pipx || (have brew && brew install pipx 2>/dev/null) || "$PY" -m pip install --user pipx 2>/dev/null || true

# ── 6. build + doctor ───────────────────────────────────────────────────────
log "building malvex (release)"
cargo build --release
BIN="$HERE/target/release/malvex"
log "running doctor"
"$BIN" doctor || true
echo
if have claude; then
log "installing RE MCP servers into Claude Code (open-source; use --commercial for IDA/BN)"
  "$BIN" mcp-setup --install || warn "some MCP servers failed to install (non-fatal)"
fi
echo
log "done. binary: $BIN"
log "next: $BIN run <path-to-binary>    (MCP: $BIN mcp-setup --install --commercial)"

#!/usr/bin/env bash
# Malvex — one-liner installer for malware analysis harness.
#
#   curl -fsSL https://raw.githubusercontent.com/user/MalvexAI/main/install.sh | bash
#
# Installs the malvex binary, sets up RE tools, MCP servers, and REA integration.
# Idempotent — safe to run multiple times.
set -euo pipefail

REPO="https://github.com/user/MalvexAI"
INSTALL_DIR="${MALVEX_INSTALL_DIR:-$HOME/.malvex}"
BIN_DIR="${MALVEX_BIN_DIR:-$HOME/.local/bin}"
VERSION="${MALVEX_VERSION:-latest}"

# ── helpers ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[1;36m'; NC='\033[0m'
log()  { printf "${CYAN}[malvex]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}[malvex]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[malvex]${NC} %s\n" "$*"; }
err()  { printf "${RED}[malvex]${NC} %s\n" "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
  Darwin) PLATFORM="apple-darwin" ;;
  Linux)  PLATFORM="unknown-linux-gnu" ;;
  *)      err "unsupported OS: $OS"; exit 1 ;;
esac
case "$ARCH" in
  x86_64|amd64) ARCH="x86_64" ;;
  arm64|aarch64) ARCH="aarch64" ;;
  *)             err "unsupported arch: $ARCH"; exit 1 ;;
esac

TARGET="${ARCH}-${PLATFORM}"
log "installing Malvex for ${TARGET}"

# ── 1. ensure dependencies ────────────────────────────────────────────────
if ! have git; then
  err "git is required. Install it first."
  exit 1
fi

# ── 2. clone or update repo ───────────────────────────────────────────────
if [ -d "$INSTALL_DIR" ]; then
  log "updating existing install at $INSTALL_DIR"
  git -C "$INSTALL_DIR" pull --ff-only 2>/dev/null || warn "git pull failed — using existing version"
else
  log "cloning MalvexAI to $INSTALL_DIR"
  git clone --depth 1 "$REPO.git" "$INSTALL_DIR" 2>/dev/null || {
    # fallback: download tarball if git clone fails (private repo, etc.)
    log "git clone failed — trying local build from current directory"
    if [ -f "Cargo.toml" ] && grep -q "malvex\|malvex" Cargo.toml 2>/dev/null; then
      INSTALL_DIR="$(pwd)"
      warn "using current directory as install source: $INSTALL_DIR"
    else
      err "could not clone repo and not in a MalvexAI directory"
      exit 1
    fi
  }
fi

# ── 3. install Rust if needed ─────────────────────────────────────────────
if ! have cargo; then
  log "installing Rust via rustup"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
fi
log "rust: $(cargo --version)"

# ── 4. build malvex ───────────────────────────────────────────────────────
log "building malvex (release) — this may take a few minutes on first run"
cd "$INSTALL_DIR"
cargo build --release 2>&1 | tail -3

# ── 5. install binaries ──────────────────────────────────────────────────
mkdir -p "$BIN_DIR"
for bin in malvex malvex-web; do
  src="$INSTALL_DIR/target/release/$bin"
  if [ -f "$src" ]; then
    cp "$src" "$BIN_DIR/$bin"
    chmod +x "$BIN_DIR/$bin"
    ok "installed $bin -> $BIN_DIR/$bin"
  fi
done

# also symlink from malvex names if they exist
for bin in malvex malvex-web; do
  src="$INSTALL_DIR/target/release/$bin"
  if [ -f "$src" ]; then
    target_bin=$(echo "$bin" | sed 's/malvex/malvex/')
    cp "$src" "$BIN_DIR/$target_bin"
    chmod +x "$BIN_DIR/$target_bin"
    ok "installed $target_bin -> $BIN_DIR/$target_bin"
  fi
done

# ── 6. ensure BIN_DIR is on PATH ─────────────────────────────────────────
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    export PATH="$BIN_DIR:$PATH"
    for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
      [ -f "$rc" ] || continue
      if ! grep -q "$BIN_DIR" "$rc" 2>/dev/null; then
        printf '\nexport PATH="%s:$PATH"\n' "$BIN_DIR" >> "$rc"
        log "added $BIN_DIR to PATH in $rc"
      fi
    done
    ;;
esac

# ── 7. install RE tools + MCP servers ─────────────────────────────────────
log "running malvex setup (tools + MCP servers)"
"$BIN_DIR/malvex" setup 2>&1 || warn "malvex setup had warnings (non-fatal)"

# ── 8. install REA (base RE layer) ────────────────────────────────────────
if have npm || have npx; then
  log "installing REA (Reverse Engineer Anything)"
  npm install -g rea-agents 2>/dev/null && ok "REA installed" || warn "REA install failed (optional)"
  if have npx; then
    npx rea-agents setup 2>/dev/null && ok "REA agents configured" || warn "REA agents setup failed (optional)"
  fi
else
  warn "npm not found — skipping REA install. Install Node.js for full RE capabilities."
fi

# ── 9. register Malvex as MCP server in all detected editors ──────────
log "registering Malvex MCP server in detected editors"

register_json_mcp() {
  local cfg="$1" editor="$2"
  local dir; dir="$(dirname "$cfg")"
  mkdir -p "$dir"
  if [ -f "$cfg" ] && [ -s "$cfg" ]; then
    python3 -c "
import json, os
cfg = json.load(open('$cfg'))
cfg.setdefault('mcpServers', {})['malvex'] = {'command': '$BIN_DIR/malvex', 'args': ['serve', '--mcp']}
json.dump(cfg, open('$cfg', 'w'), indent=2)
" 2>/dev/null && ok "Malvex MCP registered in $editor" || warn "$editor MCP registration skipped"
  else
    printf '{"mcpServers":{"malvex":{"command":"%s","args":["serve","--mcp"]}}}\n' "$BIN_DIR/malvex" > "$cfg"
    ok "Malvex MCP registered in $editor"
  fi
}

# Claude Code
if have claude; then
  claude mcp add malvex -- "$BIN_DIR/malvex" serve --mcp 2>/dev/null && ok "Malvex MCP registered in Claude Code" || warn "Claude Code MCP skipped"
else
  warn "Claude Code not found — install: curl -fsSL https://claude.ai/install.sh | bash"
fi

# Windsurf
if [ -d "$HOME/.codeium/windsurf" ] || have windsurf; then
  register_json_mcp "$HOME/.codeium/windsurf/mcp_config.json" "Windsurf"
fi

# Cursor
if [ -d "$HOME/.cursor" ] || have cursor; then
  register_json_mcp "$HOME/.cursor/mcp.json" "Cursor"
fi

# VS Code (Copilot MCP)
if have code; then
  register_json_mcp "$HOME/.vscode/mcp.json" "VS Code"
fi

# OpenCode
if have opencode; then
  register_json_mcp "$HOME/.opencode/mcp.json" "OpenCode"
fi

# ── 10. preflight check ──────────────────────────────────────────────────
log "running preflight check"
"$BIN_DIR/malvex" preflight --root "$INSTALL_DIR" 2>&1 || true

# ── done ──────────────────────────────────────────────────────────────────
echo
ok "════════════════════════════════════════════════════════════"
ok "  Malvex installed successfully!"
ok ""
ok "  Binary:    $BIN_DIR/malvex"
ok "  Repo:      $INSTALL_DIR"
ok "  Tools:     malvex doctor"
ok "  Version:   $(\"$BIN_DIR/malvex\" --version 2>/dev/null || echo 'unknown')"
ok ""
ok "  Quick start:"
ok "    malvex run <sample.exe>              # full analysis"
ok "    malvex run <sample.exe> --dry-run    # plan only"
ok "    malvex tool capa <sample.exe>        # single tool"
ok "    malvex serve --mcp                   # MCP server mode"
ok ""
ok "  In Claude Code / Windsurf / Cursor / VS Code / OpenCode:"
ok "    \"Use Malvex to analyze malware.exe\"  # uses 31 MCP tools"
ok "════════════════════════════════════════════════════════════"

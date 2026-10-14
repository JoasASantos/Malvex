# Malvex - Windows bootstrap (PowerShell).
# Idempotent, detect-before-install. Installs Rust + open-source RE/debug tools,
# audits MCP-capable runtimes, builds malvex.exe, runs the doctor.
# Run:  powershell -ExecutionPolicy Bypass -File setup.ps1
$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Here

function Log($m)  { Write-Host "[malvex] $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "[malvex] $m" -ForegroundColor Yellow }
function Have($c) { $null -ne (Get-Command $c -ErrorAction SilentlyContinue) }

Log "host: Windows"

# 1. package managers
$choco  = Have choco
$winget = Have winget
if (-not $choco -and -not $winget) {
  Warn "Neither choco nor winget found. Install Chocolatey (https://chocolatey.org/install) then re-run."
  exit 1
}
function Install-Pkg($probe, $chocoId, $wingetId) {
  if (Have $probe) { Log "have $probe"; return }
  Log "install $probe"
  try {
    if ($choco -and $chocoId)       { choco install -y $chocoId }
    elseif ($winget -and $wingetId) { winget install -e --id $wingetId --accept-source-agreements --accept-package-agreements }
    else { Warn "no installer for $probe" }
  } catch { Warn "install $probe failed (continuing): $_" }
}

# 2. Rust
if (-not (Have cargo)) {
  Log "installing Rust via rustup"
  $ru = "$env:TEMP\rustup-init.exe"
  Invoke-WebRequest -Uri https://win.rustup.rs/x86_64 -OutFile $ru
  & $ru -y
  $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
}
Log ("rust: " + (cargo --version))

# 3. open-source RE / debug tools
Install-Pkg r2        radare2      'radare.radare2'
Install-Pkg ghidraRun ghidra       $null
Install-Pkg yara      yara         $null
Install-Pkg x64dbg    x64dbg.portable $null
# WinDbg is Store/winget only, commercial-ish - detect, offer, never force
if (-not (Have windbg) -and -not (Have cdb)) {
  if ($winget) { Install-Pkg windbg $null 'Microsoft.WinDbg' } else { Warn "WinDbg: install from Microsoft Store / winget Microsoft.WinDbg" }
}

# python libs
$py = (Get-Command python -ErrorAction SilentlyContinue) ?? (Get-Command python3 -ErrorAction SilentlyContinue)
if ($py) {
  foreach ($m in @('lief','capstone','frida-tools','yara-python')) {
    Log "pip: $m"; try { & $py.Source -m pip install --quiet $m } catch { Warn "pip $m skipped" }
  }
} else { Warn "python not found - lief/capstone/frida skipped" }

# MSI/CAB tooling (msitools optional on Windows; 7zip covers MSI/CAB)
Install-Pkg 7z '7zip' '7zip.7zip'

# 4. Claude Code CLI (install if missing)
if (-not (Have claude)) {
  Log "Claude Code not found - installing"
  $installed = $false
  try {
    # official PowerShell installer
    irm https://claude.ai/install.ps1 | iex
    $installed = $true
  } catch {
    Warn "official installer failed: $_"
  }
  if (-not $installed -and (Have npm)) {
    try { npm install -g '@anthropic-ai/claude-code'; $installed = $true } catch { Warn "npm install of claude failed" }
  }
  # installer drops into %USERPROFILE%\.local\bin — add to PATH for this run
  $lb = Join-Path $env:USERPROFILE ".local\bin"
  if (Test-Path $lb) { $env:Path = "$lb;$env:Path" }
  if (-not $installed) { Warn "could not install Claude Code. Manual: https://claude.ai/install.ps1" }
}

# 5. audit claude + MCP servers
if (Have claude) {
  Log ("claude: " + (claude --version))
  Log "configured MCP servers:"
  try { claude mcp list | ForEach-Object { "    $_" } } catch { Warn "could not list MCPs - the harness auto-uses whatever is configured" }
  Warn "IDA Pro reached via its MCP (idalib); commercial tools (IDA/WinDbg) detected, never auto-installed."
  Warn "Sign in once with 'claude' (interactive) before running real agents."
} else {
  Warn "claude CLI still not on PATH - open a new shell or add %USERPROFILE%\.local\bin to PATH."
}

# 5b. helpers for python MCP servers
if (-not (Have uv))   { try { winget install -e --id astral-sh.uv --accept-source-agreements --accept-package-agreements } catch { } }
if (-not (Have pipx) -and $py) { try { & $py.Source -m pip install --user pipx } catch { } }

# 6. build + doctor
Log "building malvex.exe (release)"
cargo build --release
$bin = Join-Path $Here "target\release\malvex.exe"
Log "running doctor"
& $bin doctor
if (Have claude) {
  Log "installing RE MCP servers into Claude Code (open-source; --commercial for IDA/BN/x64dbg)"
  try { & $bin mcp-setup --install } catch { Warn "some MCP servers failed (non-fatal)" }
}
Log "done. binary: $bin"
Log "next: $bin run <path-to-binary>   (MCP: $bin mcp-setup --install --commercial)"

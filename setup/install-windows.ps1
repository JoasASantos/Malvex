# Malvex Tool Setup — Windows
# Run as Administrator: powershell -ExecutionPolicy Bypass -File setup\install-windows.ps1

Write-Host "╔══════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Malvex Tool Setup — Windows         ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = "Continue"
$TOOLS_DIR = if ($env:MALVEX_TOOLS_DIR) { $env:MALVEX_TOOLS_DIR } else { "$env:USERPROFILE\.malvex\tools" }
New-Item -ItemType Directory -Force -Path "$TOOLS_DIR\bin" | Out-Null

# ── Chocolatey ───────────────────────────────────────────────────────────────
Write-Host "[0/7] Checking Chocolatey..." -ForegroundColor Yellow
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "  Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

# ── Chocolatey packages ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "[1/7] Installing Chocolatey packages..." -ForegroundColor Yellow
$chocoPackages = @(
    "python3", "nodejs", "rust", "git",
    "7zip", "upx",
    "wireshark", "nmap",
    "sqlite", "jq",
    "ghidra", "x64dbg.portable",
    "exiftool",
    "yara"
)
foreach ($pkg in $chocoPackages) {
    $installed = choco list --local-only $pkg 2>$null | Select-String $pkg
    if ($installed) {
        Write-Host "  ✓ $pkg" -ForegroundColor Green
    } else {
        Write-Host "  ↓ $pkg"
        choco install $pkg -y --no-progress 2>$null
        if ($LASTEXITCODE -eq 0) { Write-Host "  ✓ $pkg" -ForegroundColor Green }
        else { Write-Host "  ✗ $pkg failed" -ForegroundColor Red }
    }
}

# ── pip packages ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[2/7] Installing pip packages..." -ForegroundColor Yellow
$pipPackages = @(
    "pefile", "lief", "capstone", "keystone-engine", "unicorn",
    "angr", "ropper",
    "yara-python",
    "oletools", "msoffcrypto-tool",
    "pdf-parser", "pdfid",
    "oledump", "zipdump",
    "XLMMacroDeobfuscator",
    "volatility3",
    "frida-tools",
    "androguard",
    "pyinstxtractor", "uncompyle6",
    "speakeasy-emulator",
    "sigma-cli", "pySigma",
    "pySigma-backend-splunk", "pySigma-backend-elasticsearch",
    "stix2-validator", "stix-shifter", "taxii2-client",
    "pymisp",
    "py-tlsh", "rich-header-hash",
    "vt-cli",
    "iocextract", "cymru-whois",
    "macholib", "hachoir", "balbuzard",
    "jsbeautifier"
)
pip install --upgrade pip 2>$null
foreach ($pkg in $pipPackages) {
    pip install $pkg 2>$null
    if ($LASTEXITCODE -eq 0) { Write-Host "  ✓ $pkg" -ForegroundColor Green }
    else { Write-Host "  ✗ $pkg" -ForegroundColor Red }
}

# ── npm packages ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[3/7] Installing npm packages..." -ForegroundColor Yellow
npm install -g js-beautify 2>$null
if ($LASTEXITCODE -eq 0) { Write-Host "  ✓ js-beautify" -ForegroundColor Green }

# ── GitHub releases ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[4/7] Installing from GitHub releases..." -ForegroundColor Yellow

function Install-GithubRelease {
    param([string]$Name, [string]$Repo, [string]$Pattern)
    if (Get-Command $Name -ErrorAction SilentlyContinue) {
        Write-Host "  ✓ $Name (already installed)" -ForegroundColor Green
        return
    }
    Write-Host "  ↓ $Name from $Repo"
    try {
        $releases = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
        $asset = $releases.assets | Where-Object { $_.name -match $Pattern } | Select-Object -First 1
        if ($asset) {
            $tmp = "$env:TEMP\malvex-$Name"
            Invoke-WebRequest $asset.browser_download_url -OutFile $tmp
            if ($asset.name -match '\.zip$') {
                Expand-Archive $tmp -DestinationPath "$TOOLS_DIR\bin\" -Force
            } else {
                Copy-Item $tmp "$TOOLS_DIR\bin\$Name.exe"
            }
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            Write-Host "  ✓ $Name" -ForegroundColor Green
        }
    } catch {
        Write-Host "  ✗ $Name failed" -ForegroundColor Red
    }
}

Install-GithubRelease "capa" "mandiant/capa" "windows\.zip"
Install-GithubRelease "floss" "mandiant/flare-floss" "windows\.zip"
Install-GithubRelease "retdec" "avast/retdec" "Windows"
Install-GithubRelease "dex2jar" "pxb1988/dex2jar" "\.zip"
Install-GithubRelease "jadx" "skylot/jadx" "no-jre-portable"
Install-GithubRelease "apktool" "iBotPeaches/Apktool" "apktool_"
Install-GithubRelease "pe-bear" "hasherezade/pe-bear" "x64_win"
Install-GithubRelease "hollows-hunter" "hasherezade/hollows_hunter" "x64"
Install-GithubRelease "pe-sieve" "hasherezade/pe-sieve" "x64"

# ── Windows-specific tools ───────────────────────────────────────────────────
Write-Host ""
Write-Host "[5/7] Installing Windows-specific tools..." -ForegroundColor Yellow

# Sysinternals
$sysinternals = @("procmon", "procexp", "autoruns", "Sysmon")
foreach ($tool in $sysinternals) {
    if (-not (Test-Path "$TOOLS_DIR\bin\$tool.exe")) {
        Write-Host "  ↓ $tool (Sysinternals)"
        try {
            Invoke-WebRequest "https://live.sysinternals.com/$tool.exe" -OutFile "$TOOLS_DIR\bin\$tool.exe"
            Write-Host "  ✓ $tool" -ForegroundColor Green
        } catch {
            Write-Host "  ✗ $tool" -ForegroundColor Red
        }
    } else {
        Write-Host "  ✓ $tool" -ForegroundColor Green
    }
}

# .NET tools
Write-Host ""
Write-Host "[6/7] Installing .NET analysis tools..." -ForegroundColor Yellow
$dotnetTools = @(
    @{Name="de4dot"; Repo="de4dot/de4dot"; Pattern="net.*\.zip"},
    @{Name="dnSpy"; Repo="dnSpyEx/dnSpy"; Pattern="win64"},
    @{Name="ILSpy"; Repo="icsharpcode/ILSpy"; Pattern="win-x64"}
)
foreach ($tool in $dotnetTools) {
    Install-GithubRelease $tool.Name $tool.Repo $tool.Pattern
}

# ── Build Malvex ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[7/7] Building Malvex..." -ForegroundColor Yellow
Push-Location (Split-Path $PSScriptRoot)
cargo build --release 2>$null
if ($LASTEXITCODE -eq 0) { Write-Host "  ✓ malvex built" -ForegroundColor Green }
else { Write-Host "  ✗ build failed" -ForegroundColor Red }
Pop-Location

# ── PATH ─────────────────────────────────────────────────────────────────────
Write-Host ""
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($currentPath -notlike "*$TOOLS_DIR\bin*") {
    Write-Host "Adding $TOOLS_DIR\bin to PATH..."
    [Environment]::SetEnvironmentVariable("PATH", "$TOOLS_DIR\bin;$currentPath", "User")
    Write-Host "  ✓ PATH updated (restart terminal to take effect)"
}

# ── Verify ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Running malvex doctor..." -ForegroundColor Yellow
& ".\target\release\malvex.exe" doctor 2>$null

Write-Host ""
Write-Host "Done! Run 'malvex doctor' to check tool availability." -ForegroundColor Green

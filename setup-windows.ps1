#Requires -Version 5.1
<#
.SYNOPSIS
    SentryQ Windows Setup & Build Script
.DESCRIPTION
    Installs all prerequisites (Git, Go, Node.js, GCC via MSYS2),
    builds the React frontend and Go binary, then launches SentryQ.
    Run this script ONCE — after that just run .\sentryq.exe directly.
.NOTES
    Must be run as Administrator (the script will self-elevate if needed).
#>

# ── Self-elevate if not running as Admin ──────────────────────────────────────
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Requesting administrator privileges (required for installations)..." -ForegroundColor Yellow
    $args = "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Start-Process powershell -Verb RunAs -ArgumentList $args
    exit
}

# ── Script root ───────────────────────────────────────────────────────────────
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# ── Colour helpers ────────────────────────────────────────────────────────────
function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗ ██████╗ " -ForegroundColor Cyan
    Write-Host "  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝██╔═══██╗" -ForegroundColor Cyan
    Write-Host "  ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ ██║   ██║" -ForegroundColor Cyan
    Write-Host "  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  ██║▄▄ ██║" -ForegroundColor Cyan
    Write-Host "  ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   ╚██████╔╝" -ForegroundColor Cyan
    Write-Host "  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝    ╚══▀▀═╝ " -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Windows Setup & Build Script" -ForegroundColor White
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
}

function Write-Step  { param($n, $msg) Write-Host "  [$n] $msg" -ForegroundColor Cyan }
function Write-OK    { param($msg) Write-Host "      OK  $msg" -ForegroundColor Green }
function Write-Skip  { param($msg) Write-Host "      --  $msg (already installed)" -ForegroundColor DarkGray }
function Write-Warn  { param($msg) Write-Host "      !!  $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "      XX  $msg" -ForegroundColor Red }
function Write-Info  { param($msg) Write-Host "          $msg" -ForegroundColor DarkGray }

function Pause-OnFail {
    param($msg)
    Write-Fail $msg
    Write-Host ""
    Write-Host "  Setup cannot continue. Press any key to exit." -ForegroundColor Red
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

# Refresh PATH from registry so newly installed tools are visible immediately
function Refresh-EnvPath {
    $machine = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    $user    = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$machine;$user"
}

function Is-Available { param($cmd) return [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

function Add-ToSystemPath {
    param($newPath)
    if (-not (Test-Path $newPath)) { return }
    $current = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($current -notlike "*$newPath*") {
        [System.Environment]::SetEnvironmentVariable("Path", "$newPath;$current", "Machine")
        Write-Info "Added to system PATH: $newPath"
    }
    if ($env:Path -notlike "*$newPath*") {
        $env:Path = "$newPath;$env:Path"
    }
}

# ── Start ─────────────────────────────────────────────────────────────────────
Write-Banner

# ── 1. Winget ─────────────────────────────────────────────────────────────────
Write-Step 1 "Checking winget (Windows Package Manager)..."
if (-not (Is-Available "winget")) {
    Pause-OnFail "winget not found. Update Windows or install 'App Installer' from the Microsoft Store, then re-run this script."
}
Write-OK "winget is available"

# ── 2. Git ────────────────────────────────────────────────────────────────────
Write-Step 2 "Git..."
if (Is-Available "git") {
    Write-Skip "git $(git --version 2>&1)"
} else {
    Write-Info "Installing Git..."
    winget install --id Git.Git -e --source winget `
        --accept-package-agreements --accept-source-agreements -h 2>&1 | Out-Null
    Refresh-EnvPath
    Add-ToSystemPath "C:\Program Files\Git\cmd"
    if (Is-Available "git") { Write-OK "Git installed" }
    else { Pause-OnFail "Git installation failed. Install manually from https://git-scm.com" }
}

# ── 3. Go ─────────────────────────────────────────────────────────────────────
Write-Step 3 "Go language runtime..."
if (Is-Available "go") {
    Write-Skip "$(go version)"
} else {
    Write-Info "Installing Go (latest stable)..."
    winget install --id GoLang.Go -e --source winget `
        --accept-package-agreements --accept-source-agreements -h 2>&1 | Out-Null
    Refresh-EnvPath
    Add-ToSystemPath "C:\Program Files\Go\bin"
    # GOPATH/bin
    $goBin = "$env:USERPROFILE\go\bin"
    Add-ToSystemPath $goBin
    if (Is-Available "go") { Write-OK "Go installed: $(go version)" }
    else { Pause-OnFail "Go installation failed. Install manually from https://golang.org/dl" }
}

# ── 4. Node.js ────────────────────────────────────────────────────────────────
Write-Step 4 "Node.js (for React frontend build)..."
if (Is-Available "node") {
    Write-Skip "Node.js $(node --version) / npm $(npm --version)"
} else {
    Write-Info "Installing Node.js LTS..."
    winget install --id OpenJS.NodeJS.LTS -e --source winget `
        --accept-package-agreements --accept-source-agreements -h 2>&1 | Out-Null
    Refresh-EnvPath
    Add-ToSystemPath "C:\Program Files\nodejs"
    if (Is-Available "node") { Write-OK "Node.js installed: $(node --version)" }
    else { Pause-OnFail "Node.js installation failed. Install manually from https://nodejs.org" }
}

# ── 5. MSYS2 + GCC (required for CGO: sqlite3 + tree-sitter) ─────────────────
Write-Step 5 "GCC / MinGW-w64 (required for CGO compilation)..."

$msys2Root = "C:\msys64"
$gccExe    = "$msys2Root\mingw64\bin\gcc.exe"

if (Test-Path $gccExe) {
    $gccVer = (& $gccExe --version 2>&1 | Select-Object -First 1)
    Write-Skip "GCC: $gccVer"
} else {
    # Check if MSYS2 is installed but GCC not yet
    if (-not (Test-Path "$msys2Root\usr\bin\bash.exe")) {
        Write-Info "Installing MSYS2 (this may take a few minutes)..."
        winget install --id MSYS2.MSYS2 -e --source winget `
            --accept-package-agreements --accept-source-agreements -h 2>&1 | Out-Null

        # Give MSYS2 installer time to finish unpacking
        Write-Info "Waiting for MSYS2 to finish setup..."
        $retries = 0
        while (-not (Test-Path "$msys2Root\usr\bin\bash.exe") -and $retries -lt 30) {
            Start-Sleep -Seconds 2
            $retries++
        }

        if (-not (Test-Path "$msys2Root\usr\bin\bash.exe")) {
            Pause-OnFail "MSYS2 installation failed. Install manually from https://www.msys2.org then run: pacman -S mingw-w64-x86_64-gcc"
        }
        Write-OK "MSYS2 installed"
    } else {
        Write-Info "MSYS2 found but GCC not installed — installing now..."
    }

    Write-Info "Installing MinGW-w64 GCC toolchain via pacman (this takes a minute)..."
    $pacmanCmd = "pacman -S --noconfirm --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-binutils 2>&1"
    & "$msys2Root\usr\bin\bash.exe" -lc $pacmanCmd | ForEach-Object { Write-Info $_ }

    if (Test-Path $gccExe) {
        Write-OK "GCC installed: $((& $gccExe --version 2>&1 | Select-Object -First 1))"
    } else {
        Pause-OnFail "GCC installation via pacman failed. Open MSYS2 manually and run: pacman -S mingw-w64-x86_64-gcc"
    }
}

# Make GCC visible in this session and permanently
Add-ToSystemPath "$msys2Root\mingw64\bin"

# ── 6. CGO environment variables ──────────────────────────────────────────────
Write-Step 6 "Configuring CGO environment variables..."
[System.Environment]::SetEnvironmentVariable("CGO_ENABLED", "1", "Machine")
[System.Environment]::SetEnvironmentVariable("CC", $gccExe, "Machine")
$env:CGO_ENABLED = "1"
$env:CC = $gccExe
Write-OK "CGO_ENABLED=1  |  CC=$gccExe"

# ── 7. Optional tools (non-blocking) ─────────────────────────────────────────
Write-Step 7 "Optional tools (Ollama, Semgrep, OSV-Scanner)..."

# Ollama
if (Is-Available "ollama") {
    Write-Skip "Ollama already installed"
} else {
    Write-Info "Installing Ollama (local AI engine)..."
    winget install --id Ollama.Ollama -e --source winget `
        --accept-package-agreements --accept-source-agreements -h 2>&1 | Out-Null
    Refresh-EnvPath
    if (Is-Available "ollama") { Write-OK "Ollama installed" }
    else { Write-Warn "Ollama not installed — AI scan features will be unavailable (install from https://ollama.com)" }
}

# Semgrep (via pip — needs Python)
if (Is-Available "semgrep") {
    Write-Skip "Semgrep already installed"
} else {
    if (Is-Available "pip") {
        Write-Info "Installing Semgrep via pip..."
        pip install semgrep --quiet 2>&1 | Out-Null
        Refresh-EnvPath
        if (Is-Available "semgrep") { Write-OK "Semgrep installed" }
        else { Write-Warn "Semgrep install failed — framework-aware scanning will be skipped" }
    } else {
        Write-Warn "Python/pip not found — Semgrep skipped (install Python then: pip install semgrep)"
    }
}

# OSV-Scanner
if ((Is-Available "osv-scanner") -or (Test-Path "C:\Program Files\osv-scanner\osv-scanner.exe")) {
    Write-Skip "OSV-Scanner already installed"
} else {
    Write-Info "Downloading OSV-Scanner..."
    $osvDest = "$env:ProgramFiles\osv-scanner"
    $osvExe  = "$osvDest\osv-scanner.exe"
    try {
        $osvRelease = Invoke-RestMethod "https://api.github.com/repos/google/osv-scanner/releases/latest" -ErrorAction Stop
        $osvAsset   = $osvRelease.assets | Where-Object { $_.name -like "*windows*amd64*" } | Select-Object -First 1
        if ($osvAsset) {
            New-Item -ItemType Directory -Path $osvDest -Force | Out-Null
            Invoke-WebRequest -Uri $osvAsset.browser_download_url -OutFile $osvExe -ErrorAction Stop
            Add-ToSystemPath $osvDest
            Write-OK "OSV-Scanner installed"
        } else {
            Write-Warn "OSV-Scanner Windows asset not found — dependency scanning will use API fallback"
        }
    } catch {
        Write-Warn "OSV-Scanner download failed — dependency scanning will use API fallback"
    }
}

# ── 8. Build React frontend ───────────────────────────────────────────────────
Write-Step 8 "Building React frontend..."
Set-Location "$ScriptDir\web"

if (-not (Test-Path "node_modules")) {
    Write-Info "Installing npm dependencies..."
    npm install 2>&1 | ForEach-Object { Write-Info $_ }
    if ($LASTEXITCODE -ne 0) { Pause-OnFail "npm install failed" }
}

Write-Info "Running Vite build..."
npm run build 2>&1 | ForEach-Object { Write-Info $_ }
if ($LASTEXITCODE -ne 0) { Pause-OnFail "Frontend build failed" }
Write-OK "React frontend built"

Set-Location $ScriptDir

# ── 9. Sync frontend assets ───────────────────────────────────────────────────
Write-Step 9 "Syncing frontend assets to internal\ui\dist..."

$destDir = "$ScriptDir\internal\ui\dist"
if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }

# Remove stale assets
Get-ChildItem -Path $destDir -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

# Copy fresh build
Copy-Item -Path "$ScriptDir\web\dist\*" -Destination $destDir -Recurse -Force

if (Test-Path "$destDir\index.html") {
    Write-OK "Assets synced to $destDir"
} else {
    Pause-OnFail "Asset sync failed — $destDir\index.html not found"
}

# ── 10. Build Go binary ────────────────────────────────────────────────────────
Write-Step 10 "Building SentryQ Go binary (sentryq.exe)..."

$env:CGO_ENABLED = "1"
$env:CC = $gccExe

Write-Info "Running: go build -o sentryq.exe .\cmd\scanner"
go build -o "$ScriptDir\sentryq.exe" ".\cmd\scanner" 2>&1 | ForEach-Object { Write-Info $_ }

if ($LASTEXITCODE -ne 0) { Pause-OnFail "Go build failed. Check errors above." }
Write-OK "sentryq.exe built successfully"

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "   SentryQ is ready to run!" -ForegroundColor Green
Write-Host "  ════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "  To start SentryQ:" -ForegroundColor White
Write-Host ""
Write-Host "    .\sentryq.exe" -ForegroundColor Yellow
Write-Host "    .\sentryq.exe --port 8080          (custom port)" -ForegroundColor DarkGray
Write-Host "    .\sentryq.exe --ollama-host HOST:PORT  (remote Ollama)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  The dashboard will open in your browser at http://localhost:5336" -ForegroundColor White
Write-Host ""

# ── Offer to launch immediately ───────────────────────────────────────────────
$launch = Read-Host "  Launch SentryQ now? (Y/N)"
if ($launch -match "^[Yy]") {
    Write-Host ""
    Write-Host "  Starting SentryQ..." -ForegroundColor Cyan
    Start-Process -FilePath "$ScriptDir\sentryq.exe" -WorkingDirectory $ScriptDir
    Start-Sleep -Seconds 2
    Start-Process "http://localhost:5336"
    Write-Host "  SentryQ is running. Dashboard opened in your browser." -ForegroundColor Green
} else {
    Write-Host "  Run .\sentryq.exe whenever you are ready." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  Note: You only need to run this setup script ONCE." -ForegroundColor DarkGray
Write-Host "        After this, just double-click sentryq.exe to start." -ForegroundColor DarkGray
Write-Host ""
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

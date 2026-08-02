# Build script for Online Patcher for Magisk.
#
# Compiles src/patcher.c into an ARM64 Android executable using the NDK,
# assembles the Magisk module under out/online_patcher/, and (unless
# -SkipZip) packs it into out/online_patcher.zip ready for installation via
# Magisk Manager.
#
# Usage:
#   .\build.ps1                    # build + package
#   .\build.ps1 -NdkPath <path>     # override auto-detected NDK location
#   .\build.ps1 -SkipZip            # only build the module folder, no zip

param(
    [string]$NdkPath = "",
    [switch]$SkipZip
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$srcDir = Join-Path $root "src"
$outDir = Join-Path $root "out"
$moduleOut = Join-Path $outDir "online_patcher"

Write-Host "==== Online Patcher for Magisk - Build ====" -ForegroundColor Cyan

# --- Locate the NDK ---
if (-not $NdkPath) {
    $candidates = @(
        "$env:LOCALAPPDATA\Android\Sdk\ndk\*",
        "$env:ANDROID_HOME\ndk\*",
        "C:\Android\Sdk\ndk\*"
    )
    $found = $candidates | ForEach-Object { Get-ChildItem $_ -Directory -ErrorAction SilentlyContinue } | Sort-Object Name -Descending | Select-Object -First 1
    if (-not $found) {
        Write-Host "✗ Android NDK not found. Pass -NdkPath <ndk-root> explicitly." -ForegroundColor Red
        exit 1
    }
    $NdkPath = $found.FullName
}

$toolchainBin = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin"
$clang = Join-Path $toolchainBin "aarch64-linux-android24-clang.cmd"
$strip = Join-Path $toolchainBin "llvm-strip.exe"

if (-not (Test-Path $clang)) {
    Write-Host "✗ Compiler not found at: $clang" -ForegroundColor Red
    Write-Host "  Check -NdkPath, or that this NDK version lays out toolchains the same way." -ForegroundColor Yellow
    exit 1
}
Write-Host "✓ NDK: $NdkPath" -ForegroundColor Green

# --- Compile ---
Write-Host "`nCompiling patcher.c..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path (Join-Path $moduleOut "bin") | Out-Null

$outBin = Join-Path $moduleOut "bin\patcher"
$patcherC = Join-Path $srcDir "patcher.c"
$puffC = Join-Path $srcDir "puff.c"

Push-Location $srcDir
& $clang -O2 -Wall -o $outBin $patcherC $puffC -ldl
$compileExit = $LASTEXITCODE
Pop-Location

if ($compileExit -ne 0) {
    Write-Host "✗ Compilation failed (exit $compileExit)" -ForegroundColor Red
    exit 1
}

if (Test-Path $strip) {
    & $strip $outBin
}

$size = (Get-Item $outBin).Length
Write-Host "✓ Built: $outBin ($([Math]::Round($size/1KB,1)) KB)" -ForegroundColor Green

# --- Assemble module ---
Write-Host "`nAssembling Magisk module..." -ForegroundColor Yellow
Copy-Item (Join-Path $root "module\module.prop") $moduleOut -Force
Copy-Item (Join-Path $root "module\post-fs-data.sh") $moduleOut -Force
Copy-Item (Join-Path $root "module\service.sh") $moduleOut -Force
Copy-Item (Join-Path $root "module\sepolicy.rule") $moduleOut -Force
Copy-Item (Join-Path $root "module\customize.sh") $moduleOut -Force

# Ship the config server URL: config_url.txt in the repo root becomes the
# module's "config_url" file (the exact name the binary reads next to itself).
# config_url.txt is gitignored (holds your real server); if it's absent (fresh
# clone) fall back to the committed placeholder in config_url.txt.example.
$configUrlSrc = Join-Path $root "config_url.txt"
if (-not (Test-Path $configUrlSrc)) {
    $configUrlSrc = Join-Path $root "config_url.txt.example"
    if (Test-Path $configUrlSrc) {
        Write-Host "! config_url.txt not found - using config_url.txt.example (placeholder URL)" -ForegroundColor Yellow
    }
}
if (Test-Path $configUrlSrc) {
    $url = (Get-Content $configUrlSrc -Raw).Trim()
    if ($url) {
        Set-Content -Path (Join-Path $moduleOut "config_url") -Value $url -NoNewline -Encoding ascii
        Write-Host "✓ config_url set to: $url" -ForegroundColor Green
    } else {
        Write-Host "! config_url.txt is empty - module will ship without a server URL" -ForegroundColor Yellow
    }
} else {
    Write-Host "! config_url.txt not found - module will ship without a server URL" -ForegroundColor Yellow
}

Write-Host "✓ Module assembled at $moduleOut" -ForegroundColor Green

# --- Package ZIP ---
if (-not $SkipZip) {
    Write-Host "`nPackaging ZIP..." -ForegroundColor Yellow
    $zipPath = Join-Path $outDir "online_patcher.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

    Compress-Archive -Path (Join-Path $moduleOut "*") -DestinationPath $zipPath -Force
    Write-Host "✓ Packaged: $zipPath" -ForegroundColor Green
}

Write-Host "`n==== Build complete ====" -ForegroundColor Cyan
Write-Host "Module folder : $moduleOut" -ForegroundColor Gray
if (-not $SkipZip) { Write-Host "Install ZIP   : $(Join-Path $outDir 'online_patcher.zip')" -ForegroundColor Gray }

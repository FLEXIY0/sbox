# sbox installer — Windows (обёртка).
# Скачивает sbox-windows-<arch>.exe (amd64 или arm64), кладёт в %LOCALAPPDATA%\sbox,
# добавляет папку в PATH пользователя и прописывает альяс `s` в профиль PowerShell.
#
# Использование (PowerShell):
#   irm https://raw.githubusercontent.com/flexiy0/sbox/main/install.ps1 | iex
$ErrorActionPreference = "Stop"

$repo = "flexiy0/sbox"
$dir  = Join-Path $env:LOCALAPPDATA "sbox"
New-Item -ItemType Directory -Force -Path $dir | Out-Null

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    default { throw "unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
}

$asset = "sbox-windows-$arch.exe"
$url   = "https://github.com/$repo/releases/latest/download/$asset"
$exe   = Join-Path $dir "sbox.exe"

Write-Host "-> downloading $asset ..."
Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing

# Добавить в PATH пользователя (если ещё нет)
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$dir*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$dir", "User")
    Write-Host "-> added $dir to user PATH"
}

# Альяс `s` в профиле PowerShell
if (-not (Test-Path $PROFILE)) {
    New-Item -ItemType File -Force -Path $PROFILE | Out-Null
}
$aliasLine = "Set-Alias -Name s -Value `"$exe`""
if (-not (Select-String -Path $PROFILE -Pattern "Set-Alias -Name s " -Quiet)) {
    Add-Content -Path $PROFILE -Value $aliasLine
    Write-Host "-> alias 's' added to $PROFILE"
}

Write-Host ""
Write-Host "Done. Open a new PowerShell window and press: s"
Write-Host "Autostart daemon (optional): sbox --install-service"

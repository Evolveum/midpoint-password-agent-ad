<#
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 #>
#Requires -RunAsAdministrator

param(
    [string] $DllPath    = (Join-Path $PSScriptRoot "..\listener\build\MidPointPasswordAgentListener.dll"),
    [string] $SenderExePath = (Join-Path $PSScriptRoot "..\sender\bin\Release\net10.0\win-x64\publish\sender.exe"),
    [switch] $NoReboot
)

$ErrorActionPreference = "Stop"

$DllName     = "MidPointPasswordAgentListener"
$ServiceName = "MidPointPasswordAgentSender"
$System32    = "$env:SystemRoot\System32"
$LsaKey      = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$EventLogKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$DllName"

# ── 1. Validate source DLL ────────────────────────────────────────────────────
Write-Host ""
Write-Host "[1/5] Checking source DLL..." -ForegroundColor Cyan

if (-not (Test-Path $DllPath)) {
    Write-Error "DLL not found at: $DllPath"
}

Write-Host "      Found: $DllPath" -ForegroundColor Green

# ── 2. Copy to System32 ───────────────────────────────────────────────────────
Write-Host "[2/5] Copying to System32..." -ForegroundColor Cyan

$destination = Join-Path $System32 "$DllName.dll"
Copy-Item -Path $DllPath -Destination $destination -Force
Write-Host "      Installed: $destination" -ForegroundColor Green

# ── 3. Register LSA Notification Package ─────────────────────────────────────
Write-Host "[3/5] Registering LSA Notification Package..." -ForegroundColor Cyan

$current = (Get-ItemProperty $LsaKey)."Notification Packages"

if ($current -contains $DllName) {
    Write-Host "      Already registered - skipping." -ForegroundColor Yellow
} else {
    Set-ItemProperty -Path $LsaKey -Name "Notification Packages" -Value ($current + $DllName)
    Write-Host "      Registered: $DllName" -ForegroundColor Green
}

# ── 4. Register Event Log source ─────────────────────────────────────────────
Write-Host "[4/5] Registering Event Log source..." -ForegroundColor Cyan

if (Test-Path $EventLogKey) {
    Write-Host "      Event Log source already exists - skipping." -ForegroundColor Yellow
} else {
    New-EventLog -LogName Application -Source $DllName
    Write-Host "      Registered Event Log source: $DllName" -ForegroundColor Green
}

# ── 5. Install sender Windows Service ────────────────────────────────────────
Write-Host "[5/5] Installing sender Windows Service..." -ForegroundColor Cyan

if (-not (Test-Path $SenderExePath)) {
    Write-Error "sender.exe not found at: $SenderExePath`nBuild it first: dotnet publish -c Release -r win-x64 --self-contained"
}

$InstallDir = "$env:ProgramFiles\Evolveum\MidPoint Password Agent for Active Directory"
$InstalledExe = Join-Path $InstallDir "sender.exe"

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item $SenderExePath $InstalledExe -Force
Write-Host "      Installed: $InstalledExe" -ForegroundColor Green

$existing = sc.exe query $ServiceName 2>$null
if ($existing -match "SERVICE_NAME") {
    Write-Host "      Service '$ServiceName' already exists - skipping create." -ForegroundColor Yellow
} else {
    sc.exe create $ServiceName `
        binPath= "`"$InstalledExe`"" `
        DisplayName= "MidPoint Password Agent for Active Directory Sender" `
        start= auto | Out-Null
    Write-Host "      Created service: $ServiceName" -ForegroundColor Green
}

sc.exe start $ServiceName 2>$null | Out-Null
$status = (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue).Status
Write-Host "      Service status: $status" -ForegroundColor Green

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Installation complete." -ForegroundColor Green
Write-Host "Notification Packages:"
(Get-ItemProperty $LsaKey)."Notification Packages" | ForEach-Object { Write-Host "  - $_" }
Write-Host ""
Write-Host "A reboot is required for LSA to load the new DLL." -ForegroundColor Yellow

# ── Reboot ────────────────────────────────────────────────────────────────────
if (-not $NoReboot) {
    Write-Host ""
    $answer = Read-Host "Reboot now? (y/n)"
    if ($answer -match "^[Yy]") {
        Restart-Computer -Force
    } else {
        Write-Host "Remember to reboot manually before testing." -ForegroundColor Yellow
    }
}

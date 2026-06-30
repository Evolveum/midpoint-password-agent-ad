<#
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 #>
#Requires -RunAsAdministrator

param(
    [switch] $NoReboot
)

$ErrorActionPreference = "Stop"

$DllName     = "MidPointPasswordAgentListener"
$ServiceName = "MidPointPasswordAgentSender"
$System32    = "$env:SystemRoot\System32"
$LsaKey      = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$EventLogKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$DllName"
$DllPath     = Join-Path $System32 "$DllName.dll"
$InstallDir  = "$env:ProgramFiles\Evolveum\MidPoint Password Agent for Active Directory"

# ── 1. Stop and remove sender Windows Service ─────────────────────────────────
Write-Host ""
Write-Host "[1/5] Stopping and removing sender Windows Service..." -ForegroundColor Cyan

$existing = sc.exe query $ServiceName 2>$null
if ($existing -match "SERVICE_NAME") {
    sc.exe stop $ServiceName 2>$null | Out-Null
    sc.exe delete $ServiceName | Out-Null
    Write-Host "      Removed service: $ServiceName" -ForegroundColor Green
} else {
    Write-Host "      Service '$ServiceName' not found - skipping." -ForegroundColor Yellow
}

# ── 2. Remove from LSA Notification Packages ──────────────────────────────────
Write-Host ""
Write-Host "[2/5] Removing from LSA Notification Packages..." -ForegroundColor Cyan

$current = (Get-ItemProperty $LsaKey)."Notification Packages"

if ($current -notcontains $DllName) {
    Write-Host "      Not registered - skipping." -ForegroundColor Yellow
} else {
    $updated = $current | Where-Object { $_ -ne $DllName }
    Set-ItemProperty -Path $LsaKey -Name "Notification Packages" -Value $updated
    Write-Host "      Removed: $DllName" -ForegroundColor Green
}

# ── 3. Remove Event Log source ────────────────────────────────────────────────
Write-Host "[3/5] Removing Event Log source..." -ForegroundColor Cyan

if (Test-Path $EventLogKey) {
    Remove-EventLog -Source $DllName
    Write-Host "      Removed Event Log source: $DllName" -ForegroundColor Green
} else {
    Write-Host "      Event Log source not found - skipping." -ForegroundColor Yellow
}

# ── 4. Remove sender.exe ──────────────────────────────────────────────────────
Write-Host "[4/4] Removing sender installation..." -ForegroundColor Cyan

if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force
    Write-Host "      Removed: $InstallDir" -ForegroundColor Green
} else {
    Write-Host "      Install directory not found - skipping." -ForegroundColor Yellow
}

# ── 5. Delete DLL from System32 ───────────────────────────────────────────────
Write-Host "[5/5] Removing DLL from System32..." -ForegroundColor Cyan

if (Test-Path $DllPath) {
    # The DLL is locked by lsass until reboot.
    # MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT (flag 4) and IntPtr.Zero
    # as the destination schedules the file for deletion on next boot.
    # - Resolve the full path so the Win32 API gets an unambiguous path.
    # - Use IntPtr for the destination parameter — passing $null as a string
    #   can cause the marshaller to send an empty string instead of a null pointer.
    $signature = @"
using System;
using System.Runtime.InteropServices;
public class FileUtil {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool MoveFileEx(string lpExistingFileName, IntPtr lpNewFileName, int dwFlags);
}
"@
    Add-Type -TypeDefinition $signature

    $resolvedPath = [System.IO.Path]::GetFullPath($DllPath)
    $scheduled = [FileUtil]::MoveFileEx($resolvedPath, [IntPtr]::Zero, 4)
    if ($scheduled) {
        Write-Host "      DLL scheduled for deletion on next reboot: $resolvedPath" -ForegroundColor Green
    } else {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Warning "      MoveFileEx failed (error $err). Delete manually after reboot: $resolvedPath"
    }
} else {
    Write-Host "      DLL not found in System32 - skipping." -ForegroundColor Yellow
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Uninstallation complete." -ForegroundColor Green
Write-Host "Remaining Notification Packages:"
(Get-ItemProperty $LsaKey)."Notification Packages" | ForEach-Object { Write-Host "  - $_" }
Write-Host ""
Write-Host "A reboot is required for LSA to fully unload the DLL." -ForegroundColor Yellow

# ── Reboot ────────────────────────────────────────────────────────────────────
if (-not $NoReboot) {
    Write-Host ""
    $answer = Read-Host "Reboot now? (y/n)"
    if ($answer -match "^[Yy]") {
        Restart-Computer -Force
    } else {
        Write-Host "Remember to reboot manually to complete uninstallation." -ForegroundColor Yellow
    }
}

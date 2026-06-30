<#
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 #>

$ErrorActionPreference = 'SilentlyContinue'

function Write-Check {
    param([string]$Label, [bool]$Present, [string]$Detail = "")
    $icon  = if ($Present) { "[OK]     " } else { "[MISSING]" }
    $color = if ($Present) { "Green"    } else { "Red"      }
    $msg   = "  $icon  $Label"
    if ($Detail) { $msg += "  ->  $Detail" }
    Write-Host $msg -ForegroundColor $color
}

Write-Host ""
Write-Host "MidPoint Password Agent - Installation Check" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Registry
Write-Host "Registry" -ForegroundColor Yellow

$regRoot  = 'HKLM:\SOFTWARE\Evolveum\MidPointPasswordAgent'
$rootPath = $null
if (Test-Path $regRoot) {
    $rootPath = (Get-ItemProperty $regRoot).RootPath
    $version  = (Get-ItemProperty $regRoot).Version
    Write-Check "RootPath" ($null -ne $rootPath -and $rootPath -ne '') $rootPath
    Write-Check "Version"  ($null -ne $version  -and $version  -ne '') $version
} else {
    Write-Check "RootPath" $false "key HKLM:\SOFTWARE\Evolveum\MidPointPasswordAgent missing"
    Write-Check "Version"  $false
}

$keysReg = 'HKLM:\SOFTWARE\Evolveum\MidPointPasswordAgent\Keys'
if (Test-Path $keysReg) {
    $latestKey = (Get-ItemProperty $keysReg).LatestKey
    Write-Check "AES LatestKey"   ($null -ne $latestKey -and $latestKey -ne '') $latestKey
    $keyCount = (Get-Item $keysReg).Property.Count
    Write-Check "AES key entries" ($keyCount -gt 1) "$($keyCount - 1) key(s) stored"
} else {
    Write-Check "AES Keys subkey" $false
}

# Files
Write-Host ""
Write-Host "Files" -ForegroundColor Yellow

$dll = Join-Path $env:SystemRoot "System32\MidPointPasswordAgentListener.dll"
$exe = Join-Path $env:ProgramFiles "Evolveum\MidPoint Password Agent for Active Directory\sender.exe"
Write-Check "MidPointPasswordAgentListener.dll" (Test-Path $dll) $dll
Write-Check "sender.exe"                         (Test-Path $exe) $exe

# Windows Service
Write-Host ""
Write-Host "Service" -ForegroundColor Yellow

$svc = Get-Service MidPointPasswordAgentSender -ErrorAction SilentlyContinue
if ($svc) {
    Write-Check "MidPointPasswordAgentSender" $true "Status: $($svc.Status)  StartType: $($svc.StartType)"
} else {
    Write-Check "MidPointPasswordAgentSender" $false
}

# Security group (AD on Domain Controllers, local SAM on standalone servers)
Write-Host ""
Write-Host "Security group" -ForegroundColor Yellow

$grpName = "MidPoint Password Agent Managers"
$adGrp   = Get-ADGroup -Filter { Name -eq $grpName } -ErrorAction SilentlyContinue
$locGrp  = Get-LocalGroup -Name $grpName -ErrorAction SilentlyContinue

if ($adGrp) {
    $members = (Get-ADGroupMember -Identity $grpName -ErrorAction SilentlyContinue).Count
    Write-Check $grpName $true "AD group, $members member(s)"
} elseif ($locGrp) {
    $members = (Get-LocalGroupMember -Group $grpName -ErrorAction SilentlyContinue).Count
    Write-Check $grpName $true "local group, $members member(s)"
} else {
    Write-Check $grpName $false
}

# LSA Notification Packages
Write-Host ""
Write-Host "LSA" -ForegroundColor Yellow

$lsaPackages = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa').'Notification Packages'
Write-Check "MidPointPasswordAgentListener registered" ($lsaPackages -contains 'MidPointPasswordAgentListener')

# Data directory
Write-Host ""
Write-Host "Data directory" -ForegroundColor Yellow

if ($rootPath) {
    $p = $rootPath.TrimEnd('\')
    Write-Check "APPROOTDIR"  (Test-Path $p)                           $p
    Write-Check "Logs"        (Test-Path (Join-Path $p "Logs"))
    Write-Check "Data"        (Test-Path (Join-Path $p "Data"))
    Write-Check "Config"      (Test-Path (Join-Path $p "Config"))
    Write-Check "config.json" (Test-Path (Join-Path $p "Config\config.json"))
} else {
    Write-Host "  (skipped - RootPath not found in registry)" -ForegroundColor DarkGray
}

# Event log sources
Write-Host ""
Write-Host "Event log sources" -ForegroundColor Yellow

Write-Check "MidPointPasswordAgentListener" ([System.Diagnostics.EventLog]::SourceExists('MidPointPasswordAgentListener'))
Write-Check "MidPointPasswordAgentSender"   ([System.Diagnostics.EventLog]::SourceExists('MidPointPasswordAgentSender'))

# MSI registration
Write-Host ""
Write-Host "MSI registration" -ForegroundColor Yellow

$msiEntries = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
              Where-Object { $_.DisplayName -like '*MidPoint Password Agent*' }
if ($msiEntries) {
    foreach ($m in $msiEntries) {
        Write-Check "$($m.DisplayName) $($m.DisplayVersion)" $true $m.PSChildName
    }
} else {
    Write-Check "MidPoint Password Agent" $false "not registered"
}

Write-Host ""

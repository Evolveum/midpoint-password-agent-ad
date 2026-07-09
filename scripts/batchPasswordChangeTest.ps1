#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Creates N test AD users, then changes all of their passwords as fast as possible,
    to load-test a service that reacts to AD password changes (e.g. a Password Filter DLL
    or a sync listener like ad-midpoint-password-sync).

.DESCRIPTION
    Two phases:
      1) Create-phase: creates -UserCount users under -OU (created if missing) with an
         initial password.
      2) Change-phase: sets a brand new password on every user, either sequentially or
         in parallel (-Parallel), and reports per-user timing + throughput.

    Set-ADAccountPassword talks to AD via ADWS (not a raw LDAP simple bind), so it is
    NOT directly affected by LdapEnforceChannelBinding/LDAPServerIntegrity the way your
    simple-bind LDAP client is. It does require an encrypted channel to the DC though
    (AD PowerShell enforces SSL for password ops unless the underlying connection is
    already encrypted via Kerberos sealing, which is the default for domain-joined
    Windows PowerShell sessions). If you see "unable to update the password" errors,
    try -Server pointing explicitly at a DC, or run this from a domain-joined Windows
    host rather than over a plain LDAP proxy.

.PARAMETER UserCount
    How many test users to create / cycle. Default 100.

.PARAMETER OU
    Distinguished name of the OU to create users in. Created automatically if missing.
    Default: OU=PwTestUsers,<domain default naming context>

.PARAMETER NamePrefix
    SamAccountName / name prefix for generated users. Default "pwtest".

.PARAMETER Server
    Optional explicit DC to target (FQDN or hostname). Recommended if you have
    multiple DCs or are debugging replication timing.

.PARAMETER Parallel
    If set, changes passwords concurrently using a runspace pool instead of sequentially.

.PARAMETER ThrottleLimit
    Max concurrent runspaces when -Parallel is used. Default 16.

.PARAMETER SkipCreate
    Skip user creation phase; assumes users already exist (matching NamePrefix+UserCount).

.PARAMETER Cleanup
    After the run, delete all the test users that were created/targeted.

.EXAMPLE
    .\Test-AdPasswordChangeLoad.ps1 -UserCount 200 -Parallel -ThrottleLimit 32

.EXAMPLE
    .\Test-AdPasswordChangeLoad.ps1 -UserCount 50 -Server dc1.lab.local -Cleanup
#>
[CmdletBinding()]
param(
    [int]$UserCount = 1000,

    [string]$OU,

    [string]$NamePrefix = "pwtest",

    [string]$Server,

    [switch]$Parallel,

    [int]$ThrottleLimit = 16,

    [switch]$SkipCreate,

    [switch]$Cleanup
)

Import-Module ActiveDirectory -ErrorAction Stop

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function New-RandomComplexPassword {
    # Guarantees at least one lower, upper, digit, symbol - satisfies default AD complexity.
    param([int]$Length = 16)

    $lower  = 'abcdefghijkmnopqrstuvwxyz'
    $upper  = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $digits = '23456789'
    $symbols = '!@#$%^&*-_=+'
    $all = $lower + $upper + $digits + $symbols

    $chars = @(
        $lower[(Get-Random -Maximum $lower.Length)]
        $upper[(Get-Random -Maximum $upper.Length)]
        $digits[(Get-Random -Maximum $digits.Length)]
        $symbols[(Get-Random -Maximum $symbols.Length)]
    )
    for ($i = $chars.Count; $i -lt $Length; $i++) {
        $chars += $all[(Get-Random -Maximum $all.Length)]
    }
    # shuffle
    $shuffled = $chars | Get-Random -Count $chars.Count
    -join $shuffled
}

function Get-DefaultOuDn {
    $rootDse = Get-ADRootDSE @adParams
    "OU=PwTestUsers,$($rootDse.defaultNamingContext)"
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

$adParams = @{}
if ($Server) { $adParams['Server'] = $Server }

if (-not $OU) {
    $OU = Get-DefaultOuDn
}

Write-Host "Target OU:      $OU" -ForegroundColor Cyan
Write-Host "User count:     $UserCount" -ForegroundColor Cyan
Write-Host "Name prefix:    $NamePrefix" -ForegroundColor Cyan
Write-Host "Mode:           $(if ($Parallel) { "Parallel (throttle=$ThrottleLimit)" } else { 'Sequential' })" -ForegroundColor Cyan
if ($Server) { Write-Host "Server:         $Server" -ForegroundColor Cyan }
Write-Host ""

# Ensure OU exists
try {
    Get-ADOrganizationalUnit -Identity $OU @adParams -ErrorAction Stop | Out-Null
    Write-Host "OU already exists." -ForegroundColor DarkGray
}
catch {
    $ouName = ($OU -split ',', 2)[0] -replace '^OU=', ''
    $parentDn = ($OU -split ',', 2)[1]
    Write-Host "Creating OU '$ouName' under '$parentDn'..." -ForegroundColor Yellow
    New-ADOrganizationalUnit -Name $ouName -Path $parentDn -ProtectedFromAccidentalDeletion $false @adParams
}

$samNames = 0..($UserCount - 1) | ForEach-Object { "{0}{1:D4}" -f $NamePrefix, $_ }

# ---------------------------------------------------------------------------
# Phase 1: create users
# ---------------------------------------------------------------------------

if (-not $SkipCreate) {
    Write-Host "`n== Phase 1: creating $UserCount users ==" -ForegroundColor Green
    $initialPwd = ConvertTo-SecureString -String (New-RandomComplexPassword) -AsPlainText -Force

    $created = 0
    foreach ($sam in $samNames) {
        $existing = Get-ADUser -Filter "SamAccountName -eq '$sam'" @adParams -ErrorAction SilentlyContinue
        if ($existing) { continue }

        New-ADUser -Name $sam `
            -SamAccountName $sam `
            -UserPrincipalName "$sam@$((Get-ADDomain @adParams).DNSRoot)" `
            -Path $OU `
            -AccountPassword $initialPwd `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -ChangePasswordAtLogon $false `
            @adParams
        $created++
    }
    Write-Host "Created $created new users ($($UserCount - $created) already existed)." -ForegroundColor Green
}
else {
    Write-Host "Skipping creation phase (-SkipCreate)." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Phase 2: change passwords as fast as possible
# ---------------------------------------------------------------------------

Write-Host "`n== Phase 2: changing $UserCount passwords ($(if ($Parallel) {'parallel'} else {'sequential'})) ==" -ForegroundColor Green

$results = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
$overallSw = [System.Diagnostics.Stopwatch]::StartNew()

if ($Parallel) {
    # Runspace pool works on Windows PowerShell 5.1 as well as PS7.
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit, $iss, $Host)
    $pool.Open()

    $scriptBlock = {
        param($Sam, $ServerParam)

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $newPwd = ConvertTo-SecureString -String ("Cx!" + [guid]::NewGuid().ToString("N").Substring(0,13) + "9a") -AsPlainText -Force
        $adParams = @{}
        if ($ServerParam) { $adParams['Server'] = $ServerParam }
        $err = $null
        try {
            Set-ADAccountPassword -Identity $Sam -NewPassword $newPwd -Reset @adParams -ErrorAction Stop
        }
        catch {
            $err = $_.Exception.Message
        }
        $sw.Stop()
        [PSCustomObject]@{
            SamAccountName = $Sam
            ElapsedMs      = $sw.Elapsed.TotalMilliseconds
            Success        = [string]::IsNullOrEmpty($err)
            Error          = $err
        }
    }

    $handles = foreach ($sam in $samNames) {
        $ps = [System.Management.Automation.PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($scriptBlock).AddArgument($sam).AddArgument($Server)
        [PSCustomObject]@{
            PowerShell = $ps
            Handle     = $ps.BeginInvoke()
        }
    }

    foreach ($h in $handles) {
        $out = $h.PowerShell.EndInvoke($h.Handle)
        foreach ($o in $out) { $results.Add($o) }
        $h.PowerShell.Dispose()
    }

    $pool.Close()
    $pool.Dispose()
}
else {
    foreach ($sam in $samNames) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $newPwd = ConvertTo-SecureString -String (New-RandomComplexPassword) -AsPlainText -Force
        $err = $null
        try {
            Set-ADAccountPassword -Identity $sam -NewPassword $newPwd -Reset @adParams -ErrorAction Stop
        }
        catch {
            $err = $_.Exception.Message
        }
        $sw.Stop()
        $results.Add([PSCustomObject]@{
            SamAccountName = $sam
            ElapsedMs      = $sw.Elapsed.TotalMilliseconds
            Success        = [string]::IsNullOrEmpty($err)
            Error          = $err
        })
    }
}

$overallSw.Stop()

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

$resultsArray = $results.ToArray() | Sort-Object SamAccountName
$success = $resultsArray | Where-Object Success
$failed  = $resultsArray | Where-Object { -not $_.Success }

Write-Host "`n== Results ==" -ForegroundColor Green
Write-Host ("Total wall time:      {0:N2} s" -f $overallSw.Elapsed.TotalSeconds)
Write-Host ("Succeeded / Failed:   {0} / {1}" -f $success.Count, $failed.Count)
if ($success.Count -gt 0) {
    $times = $success.ElapsedMs
    Write-Host ("Per-call avg/min/max: {0:N1} / {1:N1} / {2:N1} ms" -f ($times | Measure-Object -Average).Average, ($times | Measure-Object -Minimum).Minimum, ($times | Measure-Object -Maximum).Maximum)
    Write-Host ("Throughput:           {0:N1} password changes/sec" -f ($success.Count / $overallSw.Elapsed.TotalSeconds))
}

if ($failed.Count -gt 0) {
    Write-Host "`nFailures:" -ForegroundColor Red
    $failed | Select-Object SamAccountName, Error | Format-Table -AutoSize
}

$csvPath = Join-Path -Path (Get-Location) -ChildPath ("pwtest-results-{0:yyyyMMdd-HHmmss}.csv" -f (Get-Date))
$resultsArray | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "`nDetailed per-user timings written to: $csvPath" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Optional cleanup
# ---------------------------------------------------------------------------

if ($Cleanup) {
    Write-Host "`n== Cleanup: removing $UserCount test users ==" -ForegroundColor Yellow
    foreach ($sam in $samNames) {
        Get-ADUser -Filter "SamAccountName -eq '$sam'" @adParams -ErrorAction SilentlyContinue |
            Remove-ADUser -Confirm:$false @adParams -ErrorAction SilentlyContinue
    }
    Write-Host "Cleanup complete." -ForegroundColor Yellow
}
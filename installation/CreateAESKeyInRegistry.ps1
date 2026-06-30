
param(
    [string] $registryPath = "HKLM:\\SOFTWARE\\Evolveum\\MidPointPasswordAgent\\Keys",
    [string] $keyName = "v1",
    [string] $latestKeyName = "LatestKey"
)

Add-Type -AssemblyName System.Security

$aesKey = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($aesKey)

$protectedKey = [System.Security.Cryptography.ProtectedData]::Protect(
    $aesKey,
    $null,
    [System.Security.Cryptography.DataProtectionScope]::LocalMachine
)

if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

New-ItemProperty `
    -Path         $registryPath `
    -Name         $keyName `
    -Value        $protectedKey `
    -PropertyType Binary `
    -Force | Out-Null

New-ItemProperty `
    -Path         $registryPath `
    -Name         $latestKeyName `
    -Value        $keyName `
    -Force | Out-Null

Write-Host "Key '$keyName' written to $registryPath"

# Clear the plaintext key from memory (best effort)
[Array]::Clear($aesKey, 0, $aesKey.Length)

$Password = Read-Host -Prompt "Enter midpoint password" -AsSecureString

Add-Type -AssemblyName System.Security

$rootFolder = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Evolveum\MidPointPasswordAgent" -Name "RootPath").RootPath

Write-Host $rootFolder

$Path = Join-Path $rootFolder "Config\config.json"

$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
try {
    $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($plain)
} finally {
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}

$encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
    $bytes,
    $null,
    [System.Security.Cryptography.DataProtectionScope]::LocalMachine)

$encoded   = [Convert]::ToBase64String($encrypted)

[Array]::Clear($bytes, 0, $bytes.Length)

if (Test-Path -Path $Path) {
    $raw = Get-Content -Path $Path -Raw
}

if ([string]::IsNullOrWhiteSpace($raw)) {
    $json = [pscustomobject]@{
        MidPoint = [pscustomobject]@{
            Password = ""
        }
    }
} else {
    $json = $raw | ConvertFrom-Json
}

$json.MidPoint.Password = $encoded
$json | ConvertTo-Json -Depth 2 | Set-Content -Path $Path
$Password = Read-Host -Prompt "Enter midpoint password" -AsSecureString

Add-Type -AssemblyName System.Security

$rootFolder = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Evolveum\MidPointPasswordAgent" -Name "RootPath").RootPath

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

try {
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    $stream.Close()
} catch [System.UnauthorizedAccessException] {
    Write-Error "Access denied to config.json. Make sure you are a member of MidPoint Password Agent Managers."
    exit 1
} catch [System.IO.FileNotFoundException] {
    Write-Error "config.json not found at: $Path"
    exit 1
} catch {
    Write-Error "Cannot open config.json: $_"
    exit 1
}

$senderServiceName = 'MidPointPasswordAgentSender'
$senderRunning = (Get-Service -Name $senderServiceName -ErrorAction SilentlyContinue).Status -eq 'Running'
if ($senderRunning) {
    Write-Host "Stopping $senderServiceName..."
    Stop-Service -Name $senderServiceName -Force
}

try {
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
    $output = [System.Text.Encoding]::UTF8.GetBytes(($json | ConvertTo-Json -Depth 2))
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    try {
        $stream.Write($output, 0, $output.Length)
    } finally {
        $stream.Close()
    }
    Write-Host "MidPoint password updated successfully."
} finally {
    Write-Host "Starting $senderServiceName..."
    Start-Service -Name $senderServiceName
}

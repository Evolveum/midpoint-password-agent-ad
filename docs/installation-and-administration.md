# Installation and Administration Guide

This document describes how to install and administer MidPoint Password Agent for AD.

## Installation

As a prerequisite there must be a running midPoint node (currently supported version is 4.10.3 and later), with a service user that has the right to access `notifyChange` REST endpoint. Also, there must be appropriately configured Active Directory resource, with an inbound mapping for the `password` credentials.

The installation:

1. Download `installer.msi` from https://github.com/Evolveum/midpoint-password-agent-ad/releases.
2. Check the SHA256 hash.
3. Run the installer.
4. Provide the midPoint server URL, username, password, and the Active Directory resource OID.
5. At the end of the installation, reboot the server.

## Silent (Non-Interactive) Installation

```
$msiArgs = @( "/i", "Z:\Installer.msi", "/qn", "/norestart", "/l*v", "Z:\install.log", "MIDPOINT_URL=http://192.168.64.1:8080", "MIDPOINT_USERNAME=ad-pwd-sync", "MIDPOINT_RESOURCE_OID=baaad572-97d0-491e-9b4a-024633533778", "MIDPOINT_PASSWORD=...", "APPROOTDIR=C:\ProgramData\MidPoint Password Agent for Active Directory\")
Start-Process msiexec.exe -ArgumentList $msiArgs -Wait
```

if we dont want to put password as plaintext to arguments list, installer also support password from ENV variable:

```
[Environment]::SetEnvironmentVariable("MIDPOINT_PASSWORD", "...", "User")

$msiArgs = @(
    "/i", "C:\evolveum\Installer.msi",
    "/qn",
    "/norestart",
    "/l*v", "C:\evolveum\install.log",
    "MIDPOINT_URL=http://192.168.64.1:8080",
    "MIDPOINT_USERNAME=testUsername"
    "MIDPOINT_RESOURCE_OID=testResourceID"
)
Start-Process msiexec.exe -ArgumentList $msiArgs -Wait

[Environment]::SetEnvironmentVariable("MIDPOINT_PASSWORD", $null, "User")
```

It is advised to set logfile parameter, because in case of error isntaller crashes without printing error.

## Updating

Application can be updated with running updated `.msi` installer on Windows Server where this application is already installed.

Update does not touch:
- encryption keys
- root path folder of application
- config.json

Only Listener DLL and Sender EXE binaries are updated.

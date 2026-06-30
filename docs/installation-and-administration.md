# Installation and Administration Guide

This document describes how to install and administer MidPoint Password Agent for AD.

## Installation

As a prerequisite there must be a running midPoint node (currently supported version is 4.10.3 and later), with a service user that has the right to access `notifyChange` REST endpoint. Also, there must be appropriately configured Active Directory resource, with an inbound mapping for the `password` credentials.

### Standard (Interactive) Installation

1. Download `installer.msi` from https://github.com/Evolveum/midpoint-password-agent-ad/releases.
2. Check the SHA256 hash.
3. Run the installer.
4. Provide the midPoint server URL, username, password, and the Active Directory resource OID.
5. At the end of the installation, reboot the server.

### Silent (Non-Interactive) Installation

Let us assume that `ad-pwd-sync` is the name of the service account in midPoint.

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
    "MIDPOINT_USERNAME=ad-pwd-sync"
    "MIDPOINT_RESOURCE_OID=testResourceID"
)
Start-Process msiexec.exe -ArgumentList $msiArgs -Wait

[Environment]::SetEnvironmentVariable("MIDPOINT_PASSWORD", $null, "User")
```

It is advised to set logfile parameter, because in case of error isntaller crashes without printing error.

### Updating

Application can be updated with running updated `.msi` installer on Windows Server where this application is already installed.

Update does not touch:
- encryption keys
- root path folder of application
- config.json

Only Listener DLL and Sender EXE binaries are updated.

### Post-Installation Tasks

In order to provide adequate security, the only users with full access to the data files managed by the agent are those in `MidPoint Password Agent Managers` group. (Even `Administrators` are limited to reading the log files, nothing more.) So, please add designated user(s) to that group in order to be able to manage the agent.

## Administration

The application is installed in `C:\Program Files\Evolveum\MidPoint Password Agent for Active Directory` with the data files being stored, by default, in `C:\ProgramData\MidPoint Password Agent for Active Directory\`.

In the `ProgramData` directory, there are three subdirectories.

### Config directory

Here the configuration is stored in a file like this:

```json
{
  "MidPoint": {
    "BaseUrl": "https://192.168.64.1:8080/",
    "Username": "ad-pwd-sync",
    "Password": "AQAAANCMnd8BFdERjHoAwE/Cl\u002BsBAAAAPlDffp\u002B75UqFk6k1ZiLKswQAAAACAAAAAAAQZgAAAAEAACAAAAB7Ii70c/\u002BI4EWjzcuMMkECTC9SGPZ7FqSiv2AvaHxPpwAAAAAOgAAAAAIAACAAAADq0zCOHzMOfyOQ/K4FdJCODlXtkBlHLQl2sD0jqzkTGRAAAAAzIyJ6G4gF0E5AM54u3BzrQAAAAC2oIPaB2hkzdzlYfDLQdg0n39Q\u002BzOxhGWHqDI54uT8susLznmaeevDpjvUcXktmL5t6JKt/No0hzEIH3y3\u002B9u8=",
    "ResourceOid": "baaad572-97d0-491e-9b4a-024633533778"
  }
}
```

You can edit the file as you like. The password can be changed by invoking `updateMidpointPassword.ps1` in the `C:\Program Files\Evolveum\MidPoint Password Agent for Active Directory` directory.

### Logs directory

Here are `listener.json` and `sender.json` logs - for two main components of the agent.
Listener captures passwords from Local Security Authority subsystem and Sender sends the events to midPoint.

### Data directory

It contains the persistent storage for storing password data in transit.
Please just read the files here; do not touch them.

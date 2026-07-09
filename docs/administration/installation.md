## Installation of Midpoint Password Agent for Active Directory

Installation/updating is done using msi file, that can be downloaded from https://github.com/Evolveum/midpoint-password-agent-ad/releases..

During installation, user can configure midpoint endpoint (URL, username, password, Active Directory resource OID). During installation all values are stored to config.json file, with password encrypted using Windows DPAPI. For more details about configuration (see [configuration](configuration.md)).

After installation is done, restart of server is required before Midpoint Password Agent for Active Directory is able to listen to password changes.

There is also possibility of silent installation (without user interaction). Example of powershell script that installs application in silent mode:

```
$msiArgs = @(
    "/i", "C:\evolveum\Installer.msi",
    "/qn",
    "/norestart",
    "/l*v", "C:\evolveum\install.log",
    "MIDPOINT_URL=http://example.com",
    "MIDPOINT_USERNAME=testUsername"
    "MIDPOINT_RESOURCE_OID=testResourceID",
    "MIDPOINT_PASSWORD=secretpassword"
)
Start-Process msiexec.exe -ArgumentList $msiArgs -Wait
```

If we dont want to put password as plaintext to arguments list (to avoid revealing it in process explorer for example), installer also support password from ENV variable:

```
[Environment]::SetEnvironmentVariable("MIDPOINT_PASSWORD", "secretpassword", "User")

$msiArgs = @(
    "/i", "C:\evolveum\Installer.msi",
    "/qn",
    "/norestart",
    "/l*v", "C:\evolveum\install.log",
    "MIDPOINT_URL=http://example.com",
    "MIDPOINT_USERNAME=testUsername"
    "MIDPOINT_RESOURCE_OID=testResourceID"
)
Start-Process msiexec.exe -ArgumentList $msiArgs -Wait

[Environment]::SetEnvironmentVariable("MIDPOINT_PASSWORD", $null, "User")
```

It is also possible to omit MIDPOINT_PASSWORD argument and configure password separately (see [configuration](configuration.md))

It is advised to set logfile parameter (```/l*v```), because in case of error, installer crashes without printing error.

### Updating

Application can be updated with running updated `.msi` installer on Windows Server where this application is already installed.

Update does not touch:
- encryption keys
- root path folder of application
- config.json

Only Listener DLL and Sender EXE binaries are updated.
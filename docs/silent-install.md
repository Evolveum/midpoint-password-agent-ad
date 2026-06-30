MSI installer supports silent (non-interactive) mode.



```
$msiArgs = @( "/i", "Z:\Installer_1.0.0.msi", "/qn", "/norestart", "/l*v", "Z:\install.log", "MIDPOINT_URL=http://192.168.64.1:8080", "MIDPOINT_USERNAME=administrator", "MIDPOINT_RESOURCE_OID=baaad572-97d0-491e-9b4a-024633533778", "MIDPOINT_PASSWORD=SUPER5ecr3t", "APPROOTDIR=C:\ProgramData\MidPoint Password Agent for Active Directory\")
Start-Process msiexec.exe -ArgumentList $msiArgs -Wait
```

if we dont want to put password as plaintext to arguments list, installer also support password from ENV variable:

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

It is advised to set logfile parameter, because in case of error isntaller crashes without printing error.

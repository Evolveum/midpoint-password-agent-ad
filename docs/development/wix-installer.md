# Wixtoolset

Wixtoolset is used for building `.msi` installation file that consists instalation steps for listener & sender module. We published our own wix NuGet packages into Github Packages so we are able to use them in pipelines or locally.

Multiple packages were build and all of them were pushed to Github Packages with

```bash
dotnet nuget push "artifacts/**/*.nupkg" --source github --api-key <api_key> --skip-duplicate
```

Make sure that `api_key` has package read/write permissions.

Packages are not part of this repository.

To be able to install packages locally you need to define following environment variables that are defined inside `nuget.config`

```xml
<add key="Username" value="%NUGET_GITHUB_USER%" />
<add key="ClearTextPassword" value="%NUGET_GITHUB_TOKEN%" />
```

```bash
export NUGET_GITHUB_USER=<github_username>
export NUGET_GITHUB_TOKEN=<api_key>
```

After that use `just build-installer` recipe to build `Installer.msi` file.

### Silent installation

Wix by default supports also silent installation of `.msi` file (installation inside terminal without UI). Installation can be started with command

```powershell
msiexec /i Installer.msi /quiet MIDPOINT_URL=http://192.168.64.1:8080/midpoint MIDPOINT_USERNAME=administrator MIDPOINT_RESOURCE_OID=baaad572-97d0-491e-9b4a-024633533778 MIDPOINT_PASSWORD=SUPER5ecr3t APPROOTDIR=C:\ProgramData\MidPoint Password Agent for Active Directory\ /l*v install.log
```

This command only sets value for `APPROOTDIR` attribute

And stores installation logs inside `install.log` file

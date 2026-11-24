# WiX Toolset

WiX Toolset is used for building `.msi` installation file that contains installation steps for Listener & Sender components. 
We created our fork of WiX at https://github.com/Evolveum/wix and build the binaries from it.
(They are published into Evolveum's GitHub Packages so we are able to use them in our pipelines.
They are not available publicly, for now.)

When you are using WiX Toolset for building this agent, you can either use official WiX distribution, or you can build WiX Toolset yourself (using the original repository or our fork).
Using official distribution is the easiest way, but you might be obliged to pay Open Source Maintenance Fee. 

Note that if you use either the official distribution or the original sources, please adapt the WiX dependency versions in the `Installer.wixproj` file accordingly - by changing current Evolveum-specific version (e.g., `7.0.1-e1`) to official one (e.g., `7.0.1`), or your own.

## How to Build The Thing From Sources

An easy way how to build both WiX and MidPoint Password Agent for AD completely from sources is:

1. Build WiX
    1. Fork `Evolveum/wix`. 
    2. Create a tag in `wix` fork matching the appropriate Evolveum tag (e.g., `v7.0.1-e1`).
        - This is important, as it will be the version built by GitHub action in the next step.
    4. The build GitHub action should run automatically; if it's not, run it manually. 
    5. Check that WiX packages were created in your GitHub account, with the correct version.
2. Build MidPoint Password Agent for AD
    1. Fork `Evolveum/midpoint-password-agent-ad`
    2. Add read access to your own `WixToolset.Sdk`, `WixToolset.Util.wixext`, `WixToolset.UI.wixext` packages by your fork of `midpoint-password-agent-ad` repository.
    3. Build your fork of `midpoint-password-agent-ad`.

## How to Access Custom Builds from the Outside

To be able to install packages **locally** you need to define following environment variables that are used inside `nuget.config`.

Here is the `nuget.config` fragment:

```xml
<add key="Username" value="%NUGET_GITHUB_USER%" />
<add key="ClearTextPassword" value="%NUGET_GITHUB_TOKEN%" />
```

and it uses the following env variables:

```bash
export NUGET_GITHUB_USER=<github_username>
export NUGET_GITHUB_TOKEN=<api_key>
```

GitHub username and API key point to a NuGet repository to which you have "read" access. 
Typically, it's your own repository created above (in "Build WiX" step), but it can be any other that provides you with a "read" access.

After that use `just build-installer` recipe to build `Installer.msi` file. Or, build `Installer.msi` using GitHub action.

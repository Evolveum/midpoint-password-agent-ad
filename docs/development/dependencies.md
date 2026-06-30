## Listener Dependencies
[Listener dependencies](../listener/dependencies.txt)

Generated using bash script taken from ./licence folder of each installed package

`./vcpkg-licenses.sh vcpkg ./vcpkg_installed/x64-linux/share ~/Projects/vcpkg /vcpkg  | tee licenses.txt`

## Sender Dependencies
[Sender dependencies with licences](../sender/dependencies.txt)  
[Sender dependencies tree](../sender/dependencies-tree.txt)

### Licences Generation
Generated using https://www.nuget.org/packages/nuget-license

all (including transitive)
`nuget-license -i ./sender.csproj -fo ./dependencies.txt -t`

only top
`nuget-license -i ./sender.csproj -fo ./dependencies.txt`

### Dependencies Tree Generation
Generated from obj/project.assets.json.

First need to call `dotnet restore`. Check if `obj\project.assets.json` was generated.
Then execute `./nuget-tree.sh` 

# Installation of dependencies on Mac OS

### Install CMake
```bash
brew install cmake
```

Make sure cmake version >= 4.3.0

### Install mingw

Is cross-compilation tool. This is necessary for building `.dll` of listener module

```bash
brew install mingw-w64
```

### Install vcpkg

Small package manager for C++. At first we need to clone repo localy.

```bash
git clone https://github.com/microsoft/vcpkg
```

Now define `VCPKG_ROOT` environment variable. If you have `zsh` shell, add following line into your `~/.zshrc`
```bash
# vcpkg (c++ package manager)
export VCPKG_ROOT="$HOME/Documents/Dev/vcpkg"
```

### Install dotnet

.NET SDK 10

```bash
brew install dotnet
```

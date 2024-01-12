# GW2 Network Proxy

Clone: `git clone --recurse-submodules https://github.com/0xZ0F/gw2.git`

> If needed, resolve submodules: `git submodule update --init --recursive`

# Building
GW2FishingBot:
* Deprecated
* Python3

CryptIntercept:
* Built with Visual Studio
* Depends on:
  * Microsoft Detours

Proxy:
* Built with Visual Studio or QT (QT will probably fail).
* Depends on:
  * [QT](https://www.qt.io/)

## Building Detours:
> Reference: https://github.com/microsoft/Detours/wiki/FAQ#where-can-i-find-detourslib-and-detoursh

* `cd Detours/src`
* `git pull`
* `nmake`

Output is in "Detours/lib.<ARCH>".

* Add the directory the .lib is in to the additional libraries directory in 'Project Properties > Linker > General'
* Add the .lib to additional dependencies in 'Project Properties > Linker > Input'

# Usage:
Launch the proxy. Once the game loads, inject the DLL. Release builds are recommended for use.

# GW2 Hack

clone: `git clone --recurse-submodules https://github.com/0xZ0F/gw2.git`

> If needed, resolve submodules: `git submodule update --init --recurse`

## Building Detours:
> Reference: https://github.com/microsoft/Detours/wiki/FAQ#where-can-i-find-detourslib-and-detoursh

* `cd Detours/src`
* `git pull`
* `nmake`

Output is in "Detours/lib.<ARCH>".

* Add the directory the .lib is in to the additional libraries directory in 'Project Properties > Linker > General'
* Add the .lib to additional dependencies in 'Project Properties > Linker > Input'

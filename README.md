# GW2 Network Proxy

# Project Not Maintained
This project is no longer in development and was originally a private project. It's been made public for educational purposes, no support will be provided.

Clone: `git clone --recurse https://github.com/0xZ0F/gw2.git`

> If needed, resolve submodules: `git submodule update --init --recursive`

# Building
GW2FishingBot:
* Deprecated
* Python3

CryptIntercept:
* Build with Visual Studio
* Depends on:
  * Microsoft Detours (NuGet package)

Proxy:
* Depends on:
  * [QT](https://www.qt.io/)
* Requires Visual Studio QT extension.
* DO NOT open QT `.pro` file as it will overwrite the solution.
* Open the solution file.

## References:

> MS Detours: https://github.com/microsoft/Detours/wiki/FAQ#where-can-i-find-detourslib-and-detoursh

# Usage:

> Release builds are recommended for use.

Launch the proxy. Once the game loads, inject the DLL.

## Execution Flow

The following is a very brief summary as to how the cheat works.

1. The GUI will start a named pipe server (`\\.\pipe\Z0F_Pipe`).
	* [Common/PipeManager.hpp](Common/PipeManager.hpp).
	* The pipe server is used to transport data, currently only unencrypted network packets, from the hook created by the DLL to the GUI.
2. Proxy will inject DLL.
	* [Proxy/ManualMap.hpp](Proxy/ManualMap.hpp).
3. DLL will connect to the pipe server.
	* [CryptIntercept/CryptIntercept/GW2Hack.cpp](CryptIntercept/CryptIntercept/GW2Hack.cpp)
4. DLL will create an RPC server. This server is local-only using ALPC with NTLM authentication and encryption.
	* See `GW2Hack::StartRPCServer` in [CryptIntercept/CryptIntercept/GW2Hack.cpp](CryptIntercept/CryptIntercept/GW2Hack.cpp).
	* RPC is the mechanism used to communicate changes to the DLL, such as enabling or disabling a cheat or changing values for cheats.
	* In theory, with RPC almost any degree of control and customization is possible.
5. The DLL will resolve various offsets, function pointers, etc.
	* [CryptIntercept/CryptIntercept/GW2Functions.hpp](CryptIntercept/CryptIntercept/GW2Functions.hpp)
6. The DLL will hook any initial functions it needs to, such as the packet encryption routine.
	* [CryptIntercept/CryptIntercept/FishingHook.cpp](CryptIntercept/CryptIntercept/FishingHook.cpp)
	* [CryptIntercept/CryptIntercept/CryptWrapperHook.cpp](CryptIntercept/CryptIntercept/CryptWrapperHook.cpp)
7. At this point the DLL is in it's normal operating state.
	* It will be mirroring unencrypted network traffic to the proxy, with the proxy having the option to intercept and modify packets.
	* RPC calls can now be made to the DLL such as to enable a specific cheat.
#include <iostream>
#include <string>
#include <thread>

#include "GW2Hack.hpp"

auto gw2hack = std::make_unique<GW2Hack>();

BOOL Main() {
	if (!gw2hack->Start()) {
		return FALSE;
	}
	return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  dwReason, LPVOID lpReserved)
{
	UNREFERENCED_PARAMETER(dwReason);
	UNREFERENCED_PARAMETER(lpReserved);

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		return Main();
		break;
	
	case DLL_PROCESS_DETACH:
		gw2hack.reset();
		break;
	}

	return TRUE;
}


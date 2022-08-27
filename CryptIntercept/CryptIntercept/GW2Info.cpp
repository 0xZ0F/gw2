#include "pch.h"
#include "Pattern.h"
#include "GW2Info.h"

GW2Functions::GW2Functions() {
	GW2Functions::CryptWrapper = nullptr; // Offset 0x14B2410
	FindCryptWrapper();
}

void* GW2Functions::FindCryptWrapper() {
	HMODULE modBase = NULL;

	modBase = ::GetModuleHandle(L"gw2-64.exe");
	if (modBase == NULL) {
		GW2Functions::CryptWrapper = nullptr;
		return nullptr;
	}

	GW2Functions::CryptWrapper = (GW2Functions::CryptWrapper_t)PatternScan((void*)modBase, "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 83 79 48 00 41 8B F8 48 8B F2 48 8B D9 74 06 83 79 4C 00 74 19 41 B8 60 00 00 00 48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ?");

	return GW2Functions::CryptWrapper;
}
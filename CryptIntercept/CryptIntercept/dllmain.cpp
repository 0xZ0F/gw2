#include "ZLog.hpp"
#include "Pattern.hpp"
#include "GW2Functions.hpp"
#include "Comms.hpp"
#include "detours.h"

static ZLog zlog;
static GW2Functions funcs;
static Comms comms;

void* __fastcall CryptWrapper_Hook(void* unk1, char* pkt, int pktLen) {
	int toSend = pktLen;
	int origLen = 0;
	int newLen = 0;
	std::string str(pkt, pkt + pktLen);

	PipePacket packet;
	packet.m_size = pktLen;
	packet.m_data.assign(pkt, pkt + pktLen);
	
	if (zlog.AnyFilesFailed()) {
		zlog.DbgBox(L"CryptWrapper_Hook() AnyFilesFailed()");
		return funcs.GetCryptWrapper()(unk1, pkt, pktLen);
	}

	// GUI log
	zlog.GUIFile << "--------------" << "Len: " << pktLen
		<< "--------------\n" << str << std::endl << "----------------------------\n";

	// Trade log
	if (str.find("Game.gw2.Trade") != std::string::npos) {
		zlog.tradeFile << "--------------" << "Len: " << pktLen
			<< "--------------\n" << str << std::endl << "----------------------------\n";
	}

	if (pktLen <= 4096) {
		if (!comms.SendPacket(packet)) {
			return funcs.GetCryptWrapper()(unk1, pkt, pktLen);
		}

		if (!comms.RecvPacket(packet)) {
			return funcs.GetCryptWrapper()(unk1, pkt, pktLen);
		}

		// Send edited packet
		return funcs.GetCryptWrapper()(unk1, packet.m_data.data(), packet.m_size);
	}

	// Send unedited packet
	return funcs.GetCryptWrapper()(unk1, pkt, pktLen);
}

void* __fastcall Fishing_Hook(void* base, INT64 speedMult, void* unk3, void* unk4)
{
#pragma pack(push, 1)
	struct FishingInfo {
		/*
		000001A0DF6BCF40           UNK---FUNC---ADDR           UNK---rdata---PTR
		000001A0DF6BCF50      progress     green loc      hole loc     hole size
		000001A0DF6BCF60             0   -0.00046757   1.6171e-042             0
		000001A0DF6BCF70             0             0             1           0.5
		000001A0DF6BCF80   grn spd inc  grn base spd          5000          3000
		000001A0DF6BCF90           0.5    fail speed success speed      0.000405
		*/
		PVOID pUnk1;
		PVOID pUnk2;
		float flProgress;
		float flGreenLoc;
		float flHoleLoc;
		float flHoleSize;
		DWORD dwUnk3;
		DWORD dwUnk4;
		DWORD dwUnk5;
		DWORD dwUnk6;
		DWORD dwUnk7;
		DWORD dwUnk8;
		DWORD dwUnk9;
		DWORD dwUnk10;
		float flGreenSpeadInc;
		float flGreenBaseSpeed;
		DWORD dwUnk11;
		DWORD dwUnk12;
		DWORD dwUnk13;
		float flFailSpeed;
		float flSuccessSpeed;
		DWORD dwUnk14;
	};
#pragma pack(pop)

	FishingInfo* info = static_cast<FishingInfo*>(base);

	info->flProgress = std::max(info->flProgress, 0.95f);
	info->flGreenLoc = 0.5f;
	info->flHoleLoc = 0.5f;
	info->flHoleSize = 2.5f;

	return funcs.GetFishingPatch()(base, speedMult, unk3, unk4);
}

void* __fastcall PlayerLoad_Hook(void* unk1, void* unk2, void* unk3, void* unk4)
{
	PVOID playerStruct = funcs.GetPlayerFunc()(unk1, unk2, unk3, unk4);
	return playerStruct;
}

BOOL Main() {
	HMODULE modBase = 0;

	if (zlog.AnyFilesFailed()) {
		zlog.DbgBox(L"Main() AnyFilesFailed()");
		return FALSE;
	}

	if (!comms.OpenPipe()) {
		zlog.dbgFile << "OpenPipe()\n";
		return FALSE;
	}

	// Resolve Functions
	//zlog.dbgFile << "PlayerFunc: " << funcs.GetPlayerFunc() << std::endl;
	zlog.dbgFile << "CryptWrapper: " << funcs.GetCryptWrapper() << std::endl;
	zlog.dbgFile << "FishingPatch: " << funcs.GetFishingPatch() << std::endl;

	// Instantly complete fishing
	//*(float*)0x7FF7286555E4 = 5.0f;

	// Detour Functions
	DetourTransactionBegin();
	DetourUpdateThread(::GetCurrentThread());
	
	DetourAttach((PVOID*)&funcs.m_fpCryptWrapper, (PVOID)CryptWrapper_Hook);
	DetourAttach((PVOID*)&funcs.m_fpFishingPatch, (PVOID)Fishing_Hook);
	//DetourAttach((PVOID*)&funcs.m_fpPlayerFunc, (PVOID)PlayerLoad_Hook);

	LONG error = DetourTransactionCommit();
	if (error != NO_ERROR) {
		zlog.dbgFile << "Failed to detour (" << error << ")\n";
		return FALSE;
	}

	return TRUE;
}

BOOL Detach() {
	if (NO_ERROR != DetourTransactionBegin()) {
		zlog.dbgFile << "Detach() DetourTransactionBegin()\n";
		return FALSE;
	}

	if (NO_ERROR != DetourUpdateThread(GetCurrentThread())) {
		zlog.dbgFile << "Detach() DetourUpdateThread()\n";
		return FALSE;
	}

	LONG error = 0;
	/*error = DetourDetach((PVOID*)&funcs.m_fpPlayerFunc, (PVOID)PlayerLoad_Hook);
	if (NO_ERROR != error) {
		zlog.dbgFile << "Detach() DetourDetach(m_fpPlayerFunc) (" << error << ")\n";
		return FALSE;
	}*/

	error = DetourDetach((PVOID*)&funcs.m_fpCryptWrapper, (PVOID)CryptWrapper_Hook);
	if (NO_ERROR != error) {
		zlog.dbgFile << "Detach() DetourDetach(m_fpCryptWrapper) (" << error << ")\n";
		return FALSE;
	}

	error = DetourDetach((PVOID*)&funcs.m_fpFishingPatch, (PVOID)Fishing_Hook);
	if (NO_ERROR != error) {
		zlog.dbgFile << "Detach() DetourDetach(m_fpFishingPatch) (" << error << ")\n";
		return FALSE;
	}

	error = DetourTransactionCommit();
	if (NO_ERROR != error) {
		zlog.dbgFile << "Detach() DetourTransactionCommit() (" << error << ")\n";
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
		Main();
		break;
	case DLL_PROCESS_DETACH:
		if (Detach()) {
			zlog.DbgBox(L"DLL Unloaded Successfully.");
		}
		else {
			zlog.DbgBox(L"DLL unloaded failed. May have artifacts.");
		}
		break;
	}
	return TRUE;
}


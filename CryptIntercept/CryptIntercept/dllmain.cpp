#include "pch.h"

#include "ZLog.hpp"
#include "Pattern.hpp"
#include "GW2Functions.hpp"
#include "PipeManager.hpp"

static HANDLE hPipe;
static ZLog zlog;
static GW2Functions funcs;
static PipeManager manager;

void* __fastcall CryptWrapper_Hook(void* unk1, char* pkt, int pktLen) {
	int toSend = pktLen;
	int origLen = 0;
	int newLen = 0;
	std::string str(pkt, pktLen);

	if (zlog.AnyFilesFailed()) {
		zlog.DbgBox(L"CryptWrapper_Hook() AnyFilesFailed()");
		return funcs.GetCryptWrapper()(unk1, pkt, pktLen);
	}

	if (hPipe == INVALID_HANDLE_VALUE) {
		zlog.DbgBox(L"Pipe handle invalid.");
		return funcs.GetCryptWrapper()(unk1, pkt, pktLen);
	}

	// Send to proxy
	manager.ZeroPacket();
	if (pktLen < manager.GetBufSize()) {
		size_t startPos = 0;
		size_t endPos = 0;

		startPos = str.find("l:");
		endPos = str.find("\r", startPos);
		if (startPos != std::string::npos && endPos != std::string::npos) {
			//zlog.dbgFile << "----------------------------------\n";
			try {
				origLen = std::stoi(str.substr(startPos + 2, endPos - startPos));
				//zlog.dbgFile << "origLen: " << origLen << "\n";
			}
			catch (std::invalid_argument const& e) {
				zlog.dbgFile << e.what();
			}
			catch (std::out_of_range const& e) {
				zlog.dbgFile << e.what();
			}
			catch (...) {
				return funcs.GetCryptWrapper()(unk1, pkt, pktLen);
			}
		}

		manager.SetPacketSize(pktLen);
		snprintf(manager.GetBuf(), manager.GetPacketSize(), str.c_str());
		if (!manager.SendPacket(hPipe)) {
			return funcs.GetCryptWrapper()(unk1, pkt, pktLen);
		}

		// Get back from proxy
		if (!manager.RecvPacket(hPipe)) {
			return funcs.GetCryptWrapper()(unk1, pkt, pktLen);
		}

		startPos = 0;
		endPos = 0;
		str = std::string(manager.GetBuf(), manager.GetPacketSize());
		startPos = str.find("l:");
		endPos = str.find("\r", startPos);
		if (startPos != std::string::npos && endPos != std::string::npos) {
			try {
				newLen = std::stoi(str.substr(startPos + 2, endPos - startPos));
				pktLen = pktLen + origLen - newLen;
				//zlog.dbgFile << "New: " << pktLen << "\n";
				toSend = pktLen;
			}
			catch (std::invalid_argument const& e) {
				zlog.dbgFile << e.what();
				toSend = pktLen;
			}
			catch (std::out_of_range const& e) {
				zlog.dbgFile << e.what();
				toSend = pktLen;
			}
			catch (...) {
				return funcs.GetCryptWrapper()(unk1, pkt, pktLen);
			}
		}
		//zlog.dbgFile << "----------------------------------\n";
	}


	// GUI log
	zlog.GUIFile << "--------------" << "Len: " << pktLen
		<< "--------------\n" << str << std::endl << "----------------------------\n";

	// Trade log
	if (str.find("Game.gw2.Trade") != std::string::npos) {
		zlog.tradeFile << "--------------" << "Len: " << pktLen
			<< "--------------\n" << str << std::endl << "----------------------------\n";
	}

	/*
	-------------------------------------
		STILL SENDING UNEDITIED PACKET
	-------------------------------------
	*/
	return funcs.GetCryptWrapper()(unk1, pkt, pktLen);
}

void* __fastcall Fishing_Hook(void* base, INT64 speedMult, void* unk3, void* unk4)
{
	// Dynamic max for evasion (hopefully)
	static INT64 fishingSpeedMultMax = 1;

	// Set the green dot to the middle.
	*((float*)((UINT_PTR)base + 0x14)) = 0.5f;

	if (speedMult > fishingSpeedMultMax) {
		fishingSpeedMultMax = speedMult;
	}

	return funcs.GetFishingPatch()(base, fishingSpeedMultMax, unk3, unk4);
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

	hPipe = CreateFile(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (INVALID_HANDLE_VALUE == hPipe) {
		zlog.dbgFile << "OpenPipe() CreateFile() err: " << GetLastError() << std::endl;
		return FALSE;
	}

	DWORD lpMode = PIPE_READMODE_MESSAGE;
	if (FALSE == SetNamedPipeHandleState(hPipe, &lpMode, NULL, NULL)) {
		zlog.dbgFile << "SetNamedPipeHandleState() err: " << GetLastError() << std::endl;
		return FALSE;
	}

	if (hPipe == INVALID_HANDLE_VALUE) {
		zlog.DbgBox(L"main() OpenPipe() err");
		return FALSE;
	}

	// Resolve Functions
	//zlog.dbgFile << "PlayerFunc: " << funcs.GetPlayerFunc() << std::endl;
	zlog.dbgFile << "CryptWrapper: " << funcs.GetCryptWrapper() << std::endl;
	zlog.dbgFile << "FishingPatch: " << funcs.GetFishingPatch() << std::endl;

	// Instant complete fishing - buggy
	/*float* pFishingStats = (float*)0x7FF6877755E4;
	*pFishingStats = 2.0f;*/

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

	CloseHandle(hPipe);

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


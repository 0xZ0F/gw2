#include "pch.h"

#include "ZLog.hpp"
#include "Pattern.hpp"
#include "GW2Functions.hpp"
#include "Packet.hpp"

ZLog zlog;
GW2Functions funcs;
HANDLE hPipe;
PACKET packet;

static void ReadString(char* output, HANDLE file) {
	ULONG read = 0;
	int index = 0;
	do {
		if (!ReadFile(file, output + index++, 1, &read, NULL)) {
			std::cerr << "ReadString() ReadFile() err\n";
			return;
		}
	} while (read > 0 && *(output + index - 1) != 0);
}

void* __fastcall CryptWrapper_Hook(void* unk1, char* pkt, int pktLen) {
	int toSend = pktLen;
	int origLen = 0;
	int newLen = 0;
	std::string str(pkt, pktLen);

	if (zlog.AnyFilesFailed()) {
		zlog.DbgBox(L"CryptWrapper_Hook() AnyFilesFailed()");
		return NULL;
	}

	if (hPipe == INVALID_HANDLE_VALUE) {
		zlog.DbgBox(L"Invalid handle value");
		return NULL;
	}

	// Send to proxy
	memset(&packet, 0, sizeof(packet));
	/*
	if (pktLen < sizeof(packet.buf)) {
		size_t startPos = 0;
		size_t endPos = 0;

		startPos = str.find("l:");
		endPos = str.find("\r", startPos);
		if (startPos != std::string::npos && endPos != std::string::npos) {
			zlog.dbgFile << "----------------------------------\n";
			try {
				origLen = std::stoi(str.substr(startPos + 2, endPos - startPos));
				zlog.dbgFile << "origLen: " << origLen << "\n";
			}
			catch (std::invalid_argument const& e) {
				zlog.dbgFile << e.what();
			}
			catch (std::out_of_range const& e) {
				zlog.dbgFile << e.what();
			}
			catch (...) {
				zlog.dbgFile << "!!!!!!!!!!!!! UNKOWN EXCEPTION\n";
			}
		}

		packet.size = pktLen;
		snprintf(packet.buf, sizeof(packet.buf), str.c_str());
		if (SendPacket(hPipe, &packet) == FALSE) {
			zlog.DbgBox(L"CryptWrapper_Hook() SendPacket()");
		}

		// Get back from proxy
		if (RecvPacket(hPipe, &packet) == FALSE) {
			zlog.DbgBox(L"CryptWrapper_Hook() SendPacket()");
		}

		startPos = 0;
		endPos = 0;
		str = std::string(packet.buf, sizeof(packet.buf));
		startPos = str.find("l:");
		endPos = str.find("\r", startPos);
		if (startPos != std::string::npos && endPos != std::string::npos) {
			try {
				newLen = std::stoi(str.substr(startPos + 2, endPos - startPos));
				pktLen = pktLen + origLen - newLen;
				zlog.dbgFile << "New: " << pktLen << "\n";
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
				zlog.dbgFile << "WTF\n";
			}
		}
		zlog.dbgFile << "----------------------------------\n";
	}
	*/

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
	return funcs.m_fpCryptWrapper(unk1, pkt, pktLen);
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

	return ((FishingFunc_t)funcs.m_pFishingPatch)(base, fishingSpeedMultMax, unk3, unk4);
}

BOOL Main() {
	LONG error = 0;
	HMODULE modBase = 0;

	if (zlog.AnyFilesFailed()) {
		zlog.DbgBox(L"Main() AnyFilesFailed()");
		return FALSE;
	}

	memset(&packet, 0, sizeof(packet));
	hPipe = OpenPipe(L"\\\\.\\pipe\\Z0F_Pipe", GENERIC_READ | GENERIC_WRITE);
	if (hPipe == INVALID_HANDLE_VALUE) {
		zlog.DbgBox(L"main() OpenPipe() err");
		return FALSE;
	}

	// Resolve Functions
	zlog.dbgFile << "CryptWrapper: " << funcs.GetCryptWrapper() << std::endl;
	zlog.dbgFile << "FishingPatch: " << funcs.GetFishingPatch() << std::endl;

	// Detour Functions
	DetourTransactionBegin();
	DetourUpdateThread(::GetCurrentThread());

	DetourAttach((PVOID*)&funcs.m_fpCryptWrapper, (PVOID)CryptWrapper_Hook);
	DetourAttach((PVOID*)&funcs.m_pFishingPatch, (PVOID)Fishing_Hook);

	error = DetourTransactionCommit();
	if (error != NO_ERROR) {
		zlog.dbgFile << "Failed to detour.\n";
		return FALSE;
	}

	return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		zlog.DbgBox(L"GW2 Hack Loaded");
		Main();
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}


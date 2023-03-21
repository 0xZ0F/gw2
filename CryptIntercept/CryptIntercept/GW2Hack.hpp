#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <functional>
#include <string>

#include "ZLog.hpp"
#include "Pattern.hpp"
#include "GW2Functions.hpp"
#include "Comms.hpp"
#include "detours.h"
#include "RPC_Common.hpp"

class GW2Hack
{
protected:
	inline static GW2Hack* m_this = NULL;
	bool m_fFishingState = false;
	
public:
	ZLog zlog;

protected:
	GW2Functions funcs;
	Comms comms;

private:
	static void* __fastcall CryptWrapper_Hook(void* unk1, char* pkt, int pktLen);
	static void* __fastcall Fishing_Hook(void* base, INT64 speedMult, void* unk3, void* unk4);
	static void* __fastcall PlayerLoad_Hook(void* unk1, void* unk2, void* unk3, void* unk4);

public:
	GW2Hack();
	~GW2Hack();

	bool Start();
	bool Detach();

	RPC_STATUS StartRPCServer();
	static bool SetFishingHook(bool fState);
};
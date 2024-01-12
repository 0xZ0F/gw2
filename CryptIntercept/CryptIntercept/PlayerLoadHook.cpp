#include "GW2Hack.hpp"

void* __fastcall GW2Hack::PlayerLoad_Hook(void* unk1, void* unk2, void* unk3, void* unk4)
{
	PVOID playerStruct = m_this->funcs.GetPlayerFunc()(unk1, unk2, unk3, unk4);
	return playerStruct;
}
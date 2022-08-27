#pragma once

class GW2Functions {
private:
	typedef void* (__fastcall* CryptWrapper_t)(void* unk1, char* pkt, int unk2);
public:
	GW2Functions();
	CryptWrapper_t CryptWrapper; // Offset 0x14B2410
	void* FindCryptWrapper();
};
#include "Pattern.hpp"
#include "GW2Functions.hpp"

GW2Functions::GW2Functions() : m_fpCryptWrapper(NULL), m_hModBase(NULL)
{
	if (!ResolveModBase()) {
		return;
	}

	ResolveCryptWrapper();
	ResolveFishingPatch();
}

GW2Functions::~GW2Functions()
{
	CloseHandle(m_hModBase);
}

BOOL GW2Functions::ResolveModBase(const PCWSTR pMod, BOOL fForce)
{
	if (fForce || m_hModBase == NULL) {
		m_hModBase = GetModuleHandle(pMod);
		if (m_hModBase == NULL) {
			return FALSE;
		}
	}
	
	return TRUE;
}

HMODULE GW2Functions::GetModBase()
{
	ResolveModBase();
	return m_hModBase;
}

BOOL GW2Functions::ResolvePlayerFunc(BOOL fForce)
{
	if (!ResolveModBase()) {
		return FALSE;
	}

	if (fForce || m_fpPlayerFunc == NULL) {
		m_fpPlayerFunc = (PlayerFunc_t)PatternScan(m_hModBase, "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55 41 56 41 57 48 83 EC 20 48 8B D9 F3 0F 10 05 ? ? ? ? F3 0F 10 0D ? ? ? ? 48 8D 05 D2 43 E4 00");

		if (m_fpPlayerFunc == NULL) {
			return FALSE;
		}
	}

	return TRUE;
}

BOOL GW2Functions::ResolveCryptWrapper(BOOL fForce) {
	if (!ResolveModBase()) {
		return FALSE;
	}

	if (fForce || m_fpCryptWrapper == NULL) {
		m_fpCryptWrapper = (CryptWrapper_t)PatternScan((void*)m_hModBase, "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 83 79 48 00 41 8B F8 48 8B F2 48 8B D9 74 06 83 79 4C 00 74 19 41 B8 60 00 00 00 48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ?");
		
		if (m_fpCryptWrapper == NULL) {
			return FALSE;
		}
	}

	return TRUE;
}

BOOL GW2Functions::ResolveFishingPatch(BOOL fForce)
{
	if (!ResolveModBase()) {
		return FALSE;
	}

	if (fForce || m_fpFishingPatch == NULL) {
		m_fpFishingPatch = (FishingFunc_t)PatternScan(m_hModBase, "48 8B C4 48 89 58 20 41 56 48 83 EC 60 F3 0F 10 51 24 48 8B D9 F3 0F 10 1D ? ? ? ? 0F 28 C2 48 89 78 18 0F 29 70 E8 0F 57 F6 0F 29 78 D8 F3 0F 10 3D ? ? ? ?");

		if (m_fpFishingPatch == NULL) {
			return FALSE;
		}
	}

	return TRUE;
}

BOOL GW2Functions::ResolveAlertStruct(BOOL fForce)
{
	if (!ResolveModBase()) {
		return FALSE;
	}

	if (fForce || m_pAlertStruct == NULL) {
		m_pAlertStruct = PatternScan(m_hModBase, "F3 0F 10 05 ? ? ? ? 48 8B 51 08 F3 0F 11 41 34 F3 0F 11 41 38 F3 0F 10 05 ? ? ? ? F3 0F 11 41 3C F3 0F 10 05 ? ? ? ? 0F 29 74 24 60 45 0F 29 4B B8 F3 44 0F 10 0D ? ? ? ? F3 41 0F 5E C9 F3 41 0F 59 C1 F3 0F 11 49 40 F3 0F 59 0D ? ? ? ?");

		if (m_pAlertStruct == NULL) {
			return FALSE;
		}
	}

	return TRUE;
}

GW2Functions::PlayerFunc_t GW2Functions::GetPlayerFunc()
{
	ResolvePlayerFunc();
	return m_fpPlayerFunc;
}

GW2Functions::CryptWrapper_t GW2Functions::GetCryptWrapper()
{
	ResolveCryptWrapper();
	return m_fpCryptWrapper;
}

GW2Functions::FishingFunc_t GW2Functions::GetFishingPatch()
{
	ResolveFishingPatch();
	return m_fpFishingPatch;
}
#include "pch.h"

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

BOOL GW2Functions::ResolveModBase(PCWSTR pMod, BOOL fForce)
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

BOOL GW2Functions::ResolveCryptWrapper(BOOL fForce) {
	if (!ResolveModBase()) {
		return FALSE;
	}

	if (m_fpCryptWrapper == NULL) {
		m_fpCryptWrapper = (CryptWrapper_t)PatternScan((void*)m_hModBase, "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 83 79 48 00 41 8B F8 48 8B F2 48 8B D9 74 06 83 79 4C 00 74 19 41 B8 60 00 00 00 48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ?");
		
		if (m_fpCryptWrapper == NULL) {
			return FALSE;
		}
	}

	return TRUE;
}

CryptWrapper_t GW2Functions::GetCryptWrapper()
{
	ResolveCryptWrapper();
	return m_fpCryptWrapper;
}

BOOL GW2Functions::ResolveFishingPatch(BOOL fForce)
{
	if (!ResolveModBase()) {
		return FALSE;
	}

	if (m_pFishingPatch == NULL) {
		m_pFishingPatch = PatternScan(m_hModBase, "48 8B C4 48 89 58 20 41 56 48 83 EC 60 F3 0F 10 51 24 48 8B D9 F3 0F 10 1D ? ? ? ? 0F 28 C2 48 89 78 18 0F 29 70 E8 0F 57 F6 0F 29 78 D8 F3 0F 10 3D ? ? ? ?");

		if (m_pFishingPatch == NULL) {
			return FALSE;
		}
	}

	return TRUE;
}

PVOID GW2Functions::GetFishingPatch()
{
	ResolveFishingPatch();
	return m_pFishingPatch;
}
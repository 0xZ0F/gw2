#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <minwindef.h>

/// <summary>
/// Handles the resolution of various GW2 functions based on their signatures.
/// </summary>
class GW2Functions {
public:
	using CryptWrapper_t = void* (__fastcall*)(void* unk1, char* pkt, int unk2);
	using FishingFunc_t = void* (__fastcall*)(void* base, INT64 speedMult, void* unk3, void* unk4);
	using PlayerFunc_t = void* (__fastcall*)(void* unk1, void* unk2, void* unk3, void* unk4);

protected:
	HMODULE m_hModBase;

public:
	GW2Functions();
	~GW2Functions();

	PlayerFunc_t m_fpPlayerFunc;
	CryptWrapper_t m_fpCryptWrapper;
	FishingFunc_t m_fpFishingPatch;
	PVOID m_pAlertStruct;

	/// <summary>
	/// Set the module base (m_hModBase) of GW2.
	/// </summary>
	/// <param name="pMod">(Optional) Name of a module.</param>
	/// <param name="fForce">(Optional) Force get the module, even if it's already resolved.</param>
	/// <returns>TRUE on success, FALSE on failure.</returns>
	BOOL ResolveModBase(const PCWSTR pMod = L"gw2-64.exe", BOOL fForce = FALSE);

	/// <summary>
	/// Resolve the pointer to the player constructor.
	/// </summary>
	/// <param name="fForce">(Optional) Force get the pointer even if it's already resolved.</param>
	/// <returns></returns>
	BOOL ResolvePlayerFunc(BOOL fForce = FALSE);

	/// <summary>
	/// Resolve the pointer to the packet encryption function.
	/// </summary>
	/// <param name="fForce">(Optional) Force get the pointer even if it's already resolved.</param>
	/// <returns></returns>
	BOOL ResolveCryptWrapper(BOOL fForce = FALSE);

	/// <summary>
	/// Get the location of the fishing patch.
	/// </summary>
	/// <param name="fForce">(Optional) Force get the pointer even if it's already resolved.</param>
	/// <returns>Returns TRUE on success, FALSE on failure.</returns>
	BOOL ResolveFishingPatch(BOOL fForce = FALSE);

	/// <summary>
	/// Resolve the pointer to the alert structure.
	/// </summary>
	/// <param name="fForce">(Optional) Force get the pointer even if it's already resolved.</param>
	/// <returns>Returns TRUE on success, FALSE on failure.</returns>
	BOOL ResolveAlertStruct(BOOL fForce);
	
	/// <summary>
	/// Get the handle to the module base.
	/// </summary>
	/// <returns>Returns the handle to the module base.</returns>
	HMODULE GetModBase();

	/// <summary>
	/// Get the pointer to the 
	/// </summary>
	/// <returns></returns>
	PlayerFunc_t GetPlayerFunc();

	/// <summary>
	/// Get the pointer to the encryption function wrapper.
	/// </summary>
	/// <returns>Returns a pointer to the function.</returns>
	CryptWrapper_t GetCryptWrapper();

	/// <summary>
	/// Get a pointer to the fishing patch location.
	/// </summary>
	/// <returns>Returns a pointer to the fishing patch location.</returns>
	FishingFunc_t GetFishingPatch();
};
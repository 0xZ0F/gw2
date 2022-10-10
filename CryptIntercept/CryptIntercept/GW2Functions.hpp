#pragma once

using CryptWrapper_t = void* (__fastcall*)(void* unk1, char* pkt, int unk2);

using FishingFunc_t = void* (__fastcall*)(void* base, INT64 speedMult, void* unk3, void* unk4);

using PlayerFunc_t = void* (__fastcall*)(void* unk1, void* unk2, void* unk3, void* unk4);

class GW2Functions {
protected:
	HMODULE m_hModBase;

public:
	GW2Functions();
	~GW2Functions();
	
	// Pointer to the encryption wrapper function. Made public for efficiency.
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
	BOOL ResolveModBase(PCWSTR pMod = L"gw2-64.exe", BOOL fForce = FALSE);

	/// <summary>
	/// Get the handle to the module base.
	/// </summary>
	/// <returns>Returns the handle to the module base.</returns>
	HMODULE GetModBase();

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

	BOOL ResolveAlertStruct(BOOL fForce);
	
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
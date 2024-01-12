#include "GW2Hack.hpp"
#include "RPC_Common.hpp"

void* __fastcall GW2Hack::Fishing_Hook(void* base, INT64 speedMult, void* unk3, void* unk4)
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

	//info->flProgress = std::max(info->flProgress, 0.8f);
	info->flGreenLoc = 0.5f;
	info->flHoleLoc = 0.5f;
	info->flHoleSize = 2.5f;

	return m_this->funcs.GetFishingPatch()(base, speedMult, unk3, unk4);
}

bool GW2Hack::SetFishingHook(bool fState) {
	LONG error = 0;
	if (fState && !m_this->m_fFishingState) {
		// Enable Fishing
		if (!m_this->funcs.m_fpFishingPatch) {
			m_this->funcs.GetFishingPatch();
			if (!m_this->funcs.m_fpFishingPatch) {
				return false;
			}
		}

		error = DetourTransactionBegin();
		if (NO_ERROR != error) {
			m_this->zlog.dbgFile << "SetFishingHook() DetourTransactionBegin()" << error << "\n";
			return false;
		}

		error = DetourUpdateThread(GetCurrentThread());
		if (NO_ERROR != error) {
			m_this->zlog.dbgFile << "SetFishingHook() DetourUpdateThread()" << error << "\n";
			return false;
		}

		error = DetourAttach((PVOID*)&m_this->funcs.m_fpFishingPatch, (PVOID)Fishing_Hook);
		if (NO_ERROR != error) {
			m_this->zlog.dbgFile << "SetFishingHook() DetourAttach()" << error << "\n";
			return false;
		}

		LONG error = DetourTransactionCommit();
		if (error != NO_ERROR) {
			m_this->zlog.dbgFile << "Failed to detour (" << error << ")\n";
			return false;
		}
	}
	else if (!fState && m_this->m_fFishingState) {
		// Disable Fishing
		error = DetourTransactionBegin();
		if (NO_ERROR != error) {
			m_this->zlog.dbgFile << "SetFishingHook() DetourTransactionBegin()" << error << "\n";
			return false;
		}

		error = DetourUpdateThread(GetCurrentThread());
		if (NO_ERROR != error) {
			m_this->zlog.dbgFile << "SetFishingHook() DetourUpdateThread()" << error << "\n";
			return false;
		}

		error = DetourDetach((PVOID*)&m_this->funcs.m_fpFishingPatch, (PVOID)Fishing_Hook);
		if (NO_ERROR != error) {
			m_this->zlog.dbgFile << "SetFishingHook() DetourDetach(m_fpFishingPatch) (" << error << ")\n";
			return false;
		}

		error = DetourTransactionCommit();
		if (NO_ERROR != error) {
			m_this->zlog.dbgFile << "SetFishingHook() DetourTransactionCommit() (" << error << ")\n";
			return false;
		}
	}

	return true;
}

boolean SetFishingHook(boolean fState) {
	return GW2Hack::SetFishingHook(fState);
}
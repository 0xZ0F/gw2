#include "GW2Hack.hpp"

GW2Hack::GW2Hack() : m_fFishingState(false) {
	m_this = this;
}

GW2Hack::~GW2Hack() {
	if (Detach()) {
		zlog.DbgBox(L"DLL Unloaded Successfully.");
	}
	else {
		zlog.DbgBox(L"DLL unloaded failed. May have artifacts.");
	}
}

bool GW2Hack::Start() {
	if (zlog.AnyFilesFailed()) {
		zlog.DbgBox(L"Main() AnyFilesFailed()");
		return false;
	}

	if (!comms.OpenPipe()) {
		zlog.dbgFile << "OpenPipe()\n";
		return false;
	}

	RPC_STATUS status = StartRPCServer();
	if (status) {
		zlog.dbgFile << "StartRPCServer() " + std::to_string(status) + "\n";
		return false;
	}

	// Resolve Functions
	//zlog.dbgFile << "PlayerFunc: " << funcs.GetPlayerFunc() << std::endl;
	zlog.dbgFile << "CryptWrapper: " << funcs.GetCryptWrapper() << std::endl;
	zlog.dbgFile << "FishingPatch: " << funcs.GetFishingPatch() << std::endl;

	// Instantly complete fishing
	//*(float*)0x7FF7286555E4 = 5.0f;

	// Detour Functions
	//DetourTransactionBegin();
	//DetourUpdateThread(::GetCurrentThread());

	//DetourAttach((PVOID*)&funcs.m_fpCryptWrapper, CryptWrapper_Hook);
	//DetourAttach((PVOID*)&funcs.m_fpFishingPatch, (PVOID)Fishing_Hook);
	////DetourAttach((PVOID*)&funcs.m_fpPlayerFunc, (PVOID)PlayerLoad_Hook);

	//LONG error = DetourTransactionCommit();
	//if (error != NO_ERROR) {
	//	zlog.dbgFile << "Failed to detour (" << error << ")\n";
	//	return FALSE;
	//}

	return true;
}

bool GW2Hack::Detach() {
	if (NO_ERROR != DetourTransactionBegin()) {
		zlog.dbgFile << "Detach() DetourTransactionBegin()\n";
		return false;
	}

	if (NO_ERROR != DetourUpdateThread(GetCurrentThread())) {
		zlog.dbgFile << "Detach() DetourUpdateThread()\n";
		return false;
	}

	LONG error = 0;
	/*error = DetourDetach((PVOID*)&funcs.m_fpPlayerFunc, (PVOID)PlayerLoad_Hook);
	if (NO_ERROR != error) {
		zlog.dbgFile << "Detach() DetourDetach(m_fpPlayerFunc) (" << error << ")\n";
		return false;
	}*/

	error = DetourDetach((PVOID*)&funcs.m_fpCryptWrapper, (PVOID)CryptWrapper_Hook);
	if (NO_ERROR != error) {
		zlog.dbgFile << "Detach() DetourDetach(m_fpCryptWrapper) (" << error << ")\n";
		return false;
	}

	error = DetourDetach((PVOID*)&funcs.m_fpFishingPatch, (PVOID)Fishing_Hook);
	if (NO_ERROR != error) {
		zlog.dbgFile << "Detach() DetourDetach(m_fpFishingPatch) (" << error << ")\n";
		return false;
	}

	error = DetourTransactionCommit();
	if (NO_ERROR != error) {
		zlog.dbgFile << "Detach() DetourTransactionCommit() (" << error << ")\n";
		return false;
	}

	return true;
}

RPC_STATUS GW2Hack::StartRPCServer() {
	RPC_STATUS status;
	// Uses the protocol combined with the endpoint for receiving
	// remote procedure calls.
	status = RpcServerUseProtseqEpA((RPC_CSTR)"ncalrpc", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_CSTR)"\\RPC Control\\Z0F", NULL);
	if (status) {
		return status;
	}

	status = RpcServerRegisterAuthInfoA((RPC_CSTR)"Host/local", RPC_C_AUTHN_WINNT, NULL, NULL);
	if (status) {
		return status;
	}

	// Registers the Example1 interface.
	status = RpcServerRegisterIf2(GW2Hack_v1_0_s_ifspec, NULL, NULL, RPC_IF_ALLOW_LOCAL_ONLY, RPC_C_LISTEN_MAX_CALLS_DEFAULT, (unsigned)-1, NULL);
	if (status) {
		return status;
	}

	/*
	Start to listen for remote procedure calls for all registered interfaces.
	This call will not return until RpcMgmtStopServerListening is called.

	Set DontWait to TRUE to return immediately. This thread can continue
	and clients can still connect and communicate.
	*/
	status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
	if (status) {
		return status;
	}

	return RPC_S_OK;
}

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t len)
{
	return(malloc(len));
}

void __RPC_USER midl_user_free(void __RPC_FAR* ptr)
{
	free(ptr);
}
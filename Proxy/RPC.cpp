#include <iostream>

#include "RPC.hpp"

RPC_STATUS RPC::Start() {
	RPC_STATUS status = 0;
	unsigned char* szStringBinding = NULL;

	// Creates a string binding handle.
	// This function is nothing more than a printf.
	// Connection is not done here.
	status = RpcStringBindingComposeA(
		NULL,
		(RPC_CSTR)"ncalrpc",
		NULL,
		(RPC_CSTR)"\\RPC Control\\Z0F",
		NULL,
		&szStringBinding);
	if (status) {
		return status;
	}

	// Validates the format of the string binding handle and
	// converts it to a binding handle.
	// Connection is not done here either.
	status = RpcBindingFromStringBindingA(
		szStringBinding,        // The string binding to validate.
		&hExample1Binding);     // Put result in the implicit binding handle defined in IDL file.
	if (status) {
		return status;
	}

	status = RpcBindingSetAuthInfoA(
		hExample1Binding,
		(RPC_CSTR)"Host/local",
		RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
		RPC_C_AUTHN_WINNT,
		NULL,
		RPC_C_AUTHZ_DEFAULT);
	if (status) {
		return status;
	}
		
	// Free the memory allocated by a string.
	status = RpcStringFreeA(&szStringBinding);
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
#pragma once

#include "../CryptIntercept/CryptIntercept/GW2Hack_h.h"

class RPC {
public:
	~RPC() {
		// Frees the implicit binding handle defined in the IDL file and disconnects from the server.
		RPC_STATUS status = RpcBindingFree(&hExample1Binding);
	}

	RPC_STATUS Start();
};
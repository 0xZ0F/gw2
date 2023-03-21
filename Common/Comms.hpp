#pragma once

#define NOMINMAX
#pragma comment(lib, "Ws2_32.lib")
#include <WS2tcpip.h> // htons

#include "PipeManager.hpp"

struct PipePacket {
	DWORD m_size;
	std::vector<CHAR> m_data;

	PipePacket() { ZeroPacket(); }

	VOID ZeroPacket() {
		m_size = 0;
		m_data.clear();
	}
};

class Comms : public PipeManager
{
public:
	BOOL RecvPacket(PipePacket& packet);

	BOOL SendPacket(const PipePacket& packet);
};


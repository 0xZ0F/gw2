#include "Comms.hpp"

BOOL Comms::SendPacket(const PipePacket& packet) {
	DWORD size = htonl(packet.m_size);
	std::vector<CHAR> out;
	out.assign((CHAR*)&size, (CHAR*)&size + sizeof(size));

	out.insert(out.end(), packet.m_data.begin(), packet.m_data.end());

	if (!WriteFile(m_hPipe.get(), out.data(), (DWORD)out.size(), NULL, NULL)) {
		return FALSE;
	}

	if (!FlushFileBuffers(m_hPipe.get())) {
		return FALSE;
	}

	return TRUE;
}

BOOL Comms::RecvPacket(PipePacket& packet) {
	packet.m_data.clear();

	// Header
	if (!ReadFile(m_hPipe.get(), &packet.m_size, sizeof(packet.m_size), NULL, NULL)) {
		if (ERROR_MORE_DATA != GetLastError()) {
			return FALSE;
		}
	}

	packet.m_size = ntohl(packet.m_size);
	packet.m_data.resize(packet.m_size);

	if (packet.m_size) {
		// Body
		if (!ReadFile(m_hPipe.get(), packet.m_data.data(), packet.m_size, NULL, NULL)) {
			if (ERROR_MORE_DATA != GetLastError()) {
				return FALSE;
			}
		}
	}

	return TRUE;
}
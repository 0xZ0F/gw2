#include "GW2Hack.hpp"

void* __fastcall GW2Hack::CryptWrapper_Hook(void* unk1, char* pkt, int pktLen) {
	int toSend = pktLen;
	int origLen = 0;
	int newLen = 0;
	std::string str(pkt, pkt + pktLen);

	PipePacket packet;
	packet.m_size = pktLen;
	packet.m_data.assign(pkt, pkt + pktLen);

	if (m_this->zlog.AnyFilesFailed()) {
		m_this->zlog.DbgBox(L"CryptWrapper_Hook() AnyFilesFailed()");
		return m_this->funcs.GetCryptWrapper()(unk1, pkt, pktLen);
	}

	// GUI log
	m_this->zlog.GUIFile << "--------------" << "Len: " << pktLen
		<< "--------------\n" << str << std::endl << "----------------------------\n";

	// Trade log
	if (str.find("Game.gw2.Trade") != std::string::npos) {
		m_this->zlog.tradeFile << "--------------" << "Len: " << pktLen
			<< "--------------\n" << str << std::endl << "----------------------------\n";
	}

	if (pktLen <= 4096) {
		if (!m_this->comms.SendPacket(packet)) {
			return m_this->funcs.GetCryptWrapper()(unk1, pkt, pktLen);
		}

		if (!m_this->comms.RecvPacket(packet)) {
			return m_this->funcs.GetCryptWrapper()(unk1, pkt, pktLen);
		}

		// Send edited packet
		return m_this->funcs.GetCryptWrapper()(unk1, packet.m_data.data(), packet.m_size);
	}

	// Send unedited packet
	return m_this->funcs.GetCryptWrapper()(unk1, pkt, pktLen);
}
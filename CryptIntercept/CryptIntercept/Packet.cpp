#include "pch.h"

#include "Packet.h"

/// <summary>
/// Send a packet over a pipe.
/// </summary>
/// <param name="hPipe">Handle to the pipe to send the packet over.</param>
/// <param name="packet">Pointer to the packet to be sent.</param>
/// <returns>TRUE on success, FALSE on failure.</returns>
BOOL SendPacket(HANDLE hPipe, PACKET* packet) {
	if (packet == nullptr) {
		std::cerr << "SendPacket() NULL pointer\n";
		return FALSE;
	}

	if (WriteFile(hPipe, packet, sizeof(*packet), NULL, NULL) == FALSE) {
		std::cerr << "SendPacket() WriteFile() err: " << GetLastError() << std::endl;
		return FALSE;
	}

	if (FlushFileBuffers(hPipe) == FALSE) {
		std::cerr << "SendPacket() FlushFileBuffers() err: " << GetLastError() << std::endl;
		return FALSE;
	}

	return TRUE;
}

/// <summary>
/// Recieve a packet from a pipe. The results are stored in the provided packet.
/// </summary>
/// <param name="hPipe">Handle to the pipe to get the packet from.</param>
/// <param name="packet">Pointer to the packet structure to fill with the recieved packet.</param>
/// <returns>TRUE on success, FALSE on failure.</returns>
BOOL RecvPacket(HANDLE hPipe, PACKET* packet) {
	if (packet == nullptr) {
		std::cerr << "RecvPacket() NULL pointer\n";
		return FALSE;
	}

	if (ReadFile(hPipe, packet, sizeof(*packet), NULL, NULL) == FALSE) {
		std::cerr << "RecvPacket() ReadFile() err: " << GetLastError() << std::endl;
		return FALSE;
	}

	return TRUE;
}

/// <summary>
/// Setup a named pipe.
/// </summary>
/// <param name="pipeName">Name of the pipe.</param>
/// <param name="openMode">Open mode, such as PIPE_ACCESS_DUPLEX.</param>
/// <param name="pipeMode">Pipe mode such as PIPE_TYPE_MESSAGE.</param>
/// <returns>Handle to the created pipe on success, INVALID_HANDLE_VALUE on failure.</returns>
HANDLE SetupPipe(LPCWSTR pipeName, DWORD openMode, DWORD pipeMode) {
	HANDLE hPipe;

	if (pipeName == nullptr) {
		std::cerr << "SetupPipe() NULL pointer\n";
		return INVALID_HANDLE_VALUE;
	}

	hPipe = CreateNamedPipe(pipeName, openMode, pipeMode, PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, NULL);

	if (hPipe == INVALID_HANDLE_VALUE) {
		std::cerr << "SetupPipe() err: " << GetLastError() << std::endl;
		return INVALID_HANDLE_VALUE;
	}

	if (ConnectNamedPipe(hPipe, NULL) == FALSE) {
		std::cerr << "SetupPipe() ConnectNamedPipe() err: " << GetLastError() << std::endl;
		return INVALID_HANDLE_VALUE;
	}

	return hPipe;
}

/// <summary>
/// Get a handle to a pipe.
/// </summary>
/// <param name="pipeName">Name of the pipe to open.</param>
/// <param name="desiredAccess">Desired access for the pipe.</param>
/// <returns>HANDLE to the pipe on success, INVALID_HANDLE_VALUE on failure.</returns>
HANDLE OpenPipe(LPCWSTR pipeName, DWORD desiredAccess) {
	HANDLE hPipe = INVALID_HANDLE_VALUE;

	if (pipeName == nullptr) {
		std::cerr << "OpenPipe() NULL pointer\n";
		return INVALID_HANDLE_VALUE;
	}

	hPipe = CreateFile(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hPipe == INVALID_HANDLE_VALUE) {
		std::cerr << "OpenPipe() CreateFile() err: " << GetLastError() << std::endl;
		return INVALID_HANDLE_VALUE;
	}
	return hPipe;
}


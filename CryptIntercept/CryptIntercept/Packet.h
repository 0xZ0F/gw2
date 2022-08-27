#pragma once
struct PACKET {
	int size;
	char buf[4096];
};

/// <summary>
/// Send a packet over a pipe.
/// </summary>
/// <param name="hPipe">Handle to the pipe to send the packet over.</param>
/// <param name="packet">Pointer to the packet to be sent.</param>
/// <returns>TRUE on success, FALSE on failure.</returns>
BOOL SendPacket(HANDLE hPipe, PACKET* packet);

/// <summary>
/// Recieve a packet from a pipe. The results are stored in the provided packet.
/// </summary>
/// <param name="hPipe">Handle to the pipe to get the packet from.</param>
/// <param name="packet">Pointer to the packet structure to fill with the recieved packet.</param>
/// <returns>TRUE on success, FALSE on failure.</returns>
BOOL RecvPacket(HANDLE hPipe, PACKET* packet);

/// <summary>
/// Setup a named pipe.
/// </summary>
/// <param name="pipeName">Name of the pipe.</param>
/// <param name="openMode">Open mode, such as PIPE_ACCESS_DUPLEX.</param>
/// <param name="pipeMode">Pipe mode such as PIPE_TYPE_MESSAGE.</param>
/// <returns>Handle to the created pipe on success, INVALID_HANDLE_VALUE on failure.</returns>
HANDLE SetupPipe(LPCWSTR pipeName, DWORD openMode, DWORD pipeMode);

/// <summary>
/// Get a handle to a pipe.
/// </summary>
/// <param name="pipeName">Name of the pipe to open.</param>
/// <param name="desiredAccess">Desired access for the pipe.</param>
/// <returns>HANDLE to the pipe on success, INVALID_HANDLE_VALUE on failure.</returns>
HANDLE OpenPipe(LPCWSTR pipeName, DWORD desiredAccess);


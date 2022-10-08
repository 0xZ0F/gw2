#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define PIPE_NAME L"\\\\.\\pipe\\Z0F_Pipe"

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
/// <returns>Handle to the created pipe on success, INVALID_HANDLE_VALUE on failure.</returns>
HANDLE SetupPipe();

/// <summary>
/// Get a handle to a pipe.
/// </summary>
/// <param name="pipeName">Name of the pipe to open.</param>
/// <param name="desiredAccess">Desired access for the pipe.</param>
/// <returns>HANDLE to the pipe on success, INVALID_HANDLE_VALUE on failure.</returns>
HANDLE OpenPipe(LPCWSTR pipeName, DWORD desiredAccess);


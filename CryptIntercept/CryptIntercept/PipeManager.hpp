#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <memory>

#define PIPE_NAME L"\\\\.\\pipe\\Z0F_Pipe"

typedef struct PipePacket {
	DWORD size;
	CHAR buf[4096];
}*PPipePacket;

typedef class PipeManager {
protected:
	PipePacket m_packet;
	DWORD m_pPipeNameLen;
	std::unique_ptr<WCHAR[]> m_pPipeName;

public:
	PipeManager();

	/// <summary>
	/// Initialize with a different pipe name than default.
	/// </summary>
	/// <param name="name">Name of the pipe.</param>
	/// <param name="len">Length of the pipe name.</param>
	PipeManager(PCWSTR name, DWORD len);

	/// <summary>
	/// Get the length of the pipe name.
	/// </summary>
	/// <returns>Returns the length of the pipe name.</returns>
	DWORD GetPipeNameLen() { return m_pPipeNameLen; }

	/// <summary>
	/// Set the name of the pipe. Don't do this if the pipe has already started.
	/// </summary>
	/// <param name="name">Name of the pipe.</param>
	/// <param name="len">Length of the pipe name.</param>
	VOID SetPipeName(PCWSTR name, DWORD len);

	/// <summary>
	/// Get the size field of the packet.
	/// </summary>
	/// <returns>Returns the size field of the packet.</returns>
	DWORD GetPacketSize() { return m_packet.size; }

	/// <summary>
	/// Set the packet size.
	/// </summary>
	/// <param name="size"></param>
	VOID SetPacketSize(DWORD size) { m_packet.size = size; }

	/// <summary>
	/// Zero out the packet.
	/// </summary>
	VOID ZeroPacket() { ZeroMemory(&m_packet, sizeof(m_packet)); }

	/// <summary>
	/// Get a pointer to the packet buffer.
	/// </summary>
	/// <returns>Returns a pointer to the packet buffer.</returns>
	CHAR* GetBuf() { return m_packet.buf; }

	/// <summary>
	/// Get the max size of the packet buffer.
	/// </summary>
	/// <returns></returns>
	DWORD GetBufSize() { return sizeof(m_packet.buf); }

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
	HANDLE OpenPipe(LPCWSTR pipeName);

	/// <summary>
	/// Send a packet over a pipe.
	/// </summary>
	/// <param name="hPipe">Handle to the pipe to send the packet over.</param>
	/// <param name="packet">Pointer to the packet to be sent.</param>
	/// <returns>TRUE on success, FALSE on failure.</returns>
	BOOL SendPacket(HANDLE hPipe);

	/// <summary>
	/// Recieve a packet from a pipe. The results are stored in the provided packet.
	/// </summary>
	/// <param name="hPipe">Handle to the pipe to get the packet from.</param>
	/// <param name="packet">Pointer to the packet structure to fill with the recieved packet.</param>
	/// <returns>TRUE on success, FALSE on failure.</returns>
	BOOL RecvPacket(HANDLE hPipe);
}*PPipeManager;

#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <memory>
#include <iostream>
#include <vector>

class PipeManager {
public:
	using unique_handle = std::unique_ptr<void, decltype(&::CloseHandle)>;

protected:
	unique_handle m_hPipe{ nullptr, &::CloseHandle };

	DWORD m_pPipeNameLen;
	std::unique_ptr<WCHAR[]> m_pPipeName;

public:
	PipeManager();

	/// <summary>
	/// Initialize with a different pipe name than default.
	/// </summary>
	/// <param name="name">Name of the pipe.</param>
	/// <param name="len">Length of the pipe name.</param>
	PipeManager(const PCWSTR name, DWORD len);

	~PipeManager(){
		DisconnectNamedPipe(m_hPipe.get());
	}

	/// <summary>
	/// Set the name of the pipe. Don't do this if the pipe has already started.
	/// </summary>
	/// <param name="name">Name of the pipe.</param>
	/// <param name="len">Length of the pipe name.</param>
	virtual VOID SetPipeName(const PCWSTR name, DWORD len);

	/// <summary>
	/// Setup a named pipe.
	/// </summary>
	/// <returns>Handle to the created pipe on success, INVALID_HANDLE_VALUE on failure.</returns>
	virtual BOOL CreatePipe();

	/// <summary>
	/// Get a handle to a pipe.
	/// </summary>
	/// <param name="pipeName">Name of the pipe to open.</param>
	/// <param name="desiredAccess">Desired access for the pipe.</param>
	/// <returns>HANDLE to the pipe on success, INVALID_HANDLE_VALUE on failure.</returns>
	virtual BOOL OpenPipe(const LPCWSTR pipeName);
	virtual BOOL OpenPipe() { return OpenPipe(m_pPipeName.get()); }

	/// <summary>
	/// Send a packet over a pipe.
	/// </summary>
	/// <returns>TRUE on success, FALSE on failure.</returns>
	virtual BOOL SendPacket(const std::vector<CHAR>& packet);

	/// <summary>
	/// Recieve a packet from a pipe. The results are stored in the provided packet.
	/// </summary>
	/// <returns>TRUE on success, FALSE on failure.</returns>
	virtual BOOL RecvPacket(std::vector<CHAR>& packet);

	BOOL ConnectPipe();
};

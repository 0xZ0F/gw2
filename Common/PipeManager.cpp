#include "PipeManager.hpp"

PipeManager::PipeManager() {
	WCHAR pName[] = L"\\\\.\\pipe\\Z0F_Pipe";
	SetPipeName(pName, sizeof(pName));
}

PipeManager::PipeManager(const PCWSTR name, DWORD len) {
	SetPipeName(name, len);
}

VOID PipeManager::SetPipeName(const PCWSTR name, DWORD len) {
	m_pPipeNameLen = len;
	m_pPipeName = std::make_unique<WCHAR[]>(m_pPipeNameLen);
	CopyMemory(m_pPipeName.get(), name, m_pPipeNameLen);
}

BOOL PipeManager::SendPacket(const std::vector<CHAR>& packet) {
	if (!WriteFile(m_hPipe.get(), packet.data(), packet.size(), NULL, NULL)) {
		return FALSE;
	}

	if (!FlushFileBuffers(m_hPipe.get())) {
		return FALSE;
	}

	return TRUE;
}

BOOL PipeManager::RecvPacket(std::vector<CHAR>& packet) {
	packet.clear();

	DWORD dwBytesAvail = 0;
	if (!PeekNamedPipe(m_hPipe.get(), NULL, 0, NULL, &dwBytesAvail, NULL)) {
		return FALSE;
	}

	packet.resize(dwBytesAvail);
	if (!ReadFile(m_hPipe.get(), packet.data(), packet.size(), NULL, NULL)) {
		return FALSE;
	}

	return TRUE;
}

BOOL PipeManager::CreatePipe() {
	m_hPipe = unique_handle(CreateNamedPipe(m_pPipeName.get(),
		PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, 0, 0, 0, NULL),
		&::CloseHandle);
	
	if (m_hPipe.get() == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	if (!FlushFileBuffers(m_hPipe.get())) {
		return FALSE;
	}

	return TRUE;
}

BOOL PipeManager::OpenPipe(const LPCWSTR pipeName) {
	if (NULL == pipeName) {
		return FALSE;
	}

	m_hPipe = unique_handle(CreateFile(pipeName,
		GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL),
		&::CloseHandle);

	if (INVALID_HANDLE_VALUE == m_hPipe.get()) {
		return FALSE;
	}

	DWORD lpMode = PIPE_READMODE_MESSAGE;
	if (FALSE == SetNamedPipeHandleState(m_hPipe.get(), &lpMode, NULL, NULL)) {
		return FALSE;
	}

	return TRUE;
}

BOOL PipeManager::ConnectPipe() {
	if (!ConnectNamedPipe(m_hPipe.get(), NULL)) {
		return FALSE;
	}

	return TRUE;
}
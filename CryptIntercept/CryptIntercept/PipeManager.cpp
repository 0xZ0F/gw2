#include "pch.h"

#include "PipeManager.hpp"

#include <iostream>

PipeManager::PipeManager() {
    ZeroMemory(&m_packet, sizeof(m_packet));

    WCHAR pName[] = L"\\\\.\\pipe\\Z0F_Pipe";
    SetPipeName(pName, sizeof(pName));
}

PipeManager::PipeManager(const PCWSTR name, DWORD len) {
    ZeroMemory(&m_packet, sizeof(m_packet));
    SetPipeName(name, len);
}

VOID PipeManager::SetPipeName(const PCWSTR name, DWORD len) {
    m_pPipeNameLen = len;
    m_pPipeName = std::make_unique<WCHAR[]>(m_pPipeNameLen);
    CopyMemory(m_pPipeName.get(), name, m_pPipeNameLen);
}

BOOL PipeManager::SendPacket(HANDLE hPipe) {
    if (WriteFile(hPipe, &m_packet, sizeof(m_packet), NULL, NULL) == FALSE) {
        std::cerr << "SendPacket() WriteFile() err: " << GetLastError() << std::endl;
        return FALSE;
    }

    if (FlushFileBuffers(hPipe) == FALSE) {
        std::cerr << "SendPacket() FlushFileBuffers() err: " << GetLastError() << std::endl;
        return FALSE;
    }

    return TRUE;
}

BOOL PipeManager::RecvPacket(HANDLE hPipe) {
    ZeroMemory(&m_packet, sizeof(m_packet));

    if (ReadFile(hPipe, &m_packet, sizeof(m_packet), NULL, NULL) == FALSE) {
        std::cerr << "RecvPacket() ReadFile() err: " << GetLastError() << std::endl;
        return FALSE;
    }

    m_packet.buf[sizeof(m_packet.buf) - 1] = '\0';

    return TRUE;
}

HANDLE PipeManager::SetupPipe() {
    HANDLE hPipe;

    hPipe = CreateNamedPipe(PIPE_NAME, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, 0, 0, 0, NULL);
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

HANDLE PipeManager::OpenPipe(const LPCWSTR pipeName) {
    HANDLE hPipe = INVALID_HANDLE_VALUE;

    if (NULL == pipeName) {
        std::cerr << "OpenPipe() NULL pointer\n";
        return INVALID_HANDLE_VALUE;
    }

    hPipe = CreateFile(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (INVALID_HANDLE_VALUE == hPipe) {
        std::cerr << "OpenPipe() CreateFile() err: " << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }

    DWORD lpMode = PIPE_READMODE_MESSAGE;
    if (FALSE == SetNamedPipeHandleState(hPipe, &lpMode, NULL, NULL)) {
        std::cerr << "SetNamedPipeHandleState() err: " << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }

    return hPipe;
}


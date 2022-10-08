#include "Packet.hpp"

#include <iostream>

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

HANDLE SetupPipe() {
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

HANDLE OpenPipe(LPCWSTR pipeName, DWORD desiredAccess) {
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


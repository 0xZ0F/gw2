#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

using DllMain_t = BOOL(WINAPI*)(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_opt_ LPVOID lpReserved);
using GetProcAddress_t = UINT_PTR(WINAPI*)(_In_ HMODULE hModule, _In_ LPCSTR  lpProcName);
using LoadLibraryA_t = HMODULE(WINAPI*)(_In_ LPCSTR lpLibFileName);
using VirtualProtect_t = BOOL(WINAPI*)(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD  flNewProtect, _Out_ PDWORD lpflOldProtect);

typedef struct {
    WORD offset : 12;
    WORD type : 4;
}IMAGE_RELOC, * PIMAGE_RELOC;

typedef struct {
    GetProcAddress_t _GetProcAddress;
    LoadLibraryA_t _LoadLibraryA;
    VirtualProtect_t _VirtualProtect;
    PBYTE pInMemory;
}SHELLCODE_DATA, * PSHELLCODE_DATA;

typedef class ManualMap {
protected:
    BOOL MapToMemory(HANDLE proc, PBYTE pData);
public:
    PVOID m_pShellcode;
    PVOID m_pDllInMemory;
    HANDLE m_hThread;
    
    SIZE_T m_stShellcodeSize;
    SIZE_T m_stDllSize;

    DWORD m_PID;

    ManualMap() : m_pShellcode(NULL), m_pDllInMemory(NULL), m_hThread(INVALID_HANDLE_VALUE), m_stShellcodeSize(0), m_stDllSize(0) {}
    ~ManualMap() { CloseHandle(m_hThread); }

    /// <summary>
    /// Checks if the current process architecture matches the target's.
    /// </summary>
    /// <param name="hProc">Handle to the target process to check.</param>
    /// <returns>TRUE if the current process's and the target process's architectures match, FALSE otherwise.</returns>
    BOOL IsCorrectTargetArchitecture(HANDLE hProc);
    BOOL ReadAllBytes(LPCWSTR pwszFileName, PBYTE* ppData, PDWORD pdwDataLen);

    BOOL FreeDLL();

    /// <summary>
    /// Map a DLL into a target process.
    /// </summary>
    /// <param name="proc">Handle to the process to map into.</param>
    /// <param name="dll">Path of the DLL to map.</param>
    /// <returns>Returns a pointer to the manual map data on success, NULL on failure. Caller must delete the ManualMap pointer.</returns>
    BOOL CustomMap(HANDLE proc, LPCWSTR dll);
}*PManualMap;
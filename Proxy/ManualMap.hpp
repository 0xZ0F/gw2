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

/// <summary>
/// Map a DLL into a target process.
/// </summary>
/// <param name="proc">Handle to the process to map into.</param>
/// <param name="dll">Path of the DLL to map.</param>
/// <returns>TRUE on success, FALSE on failure.</returns>
BOOL CustomMap(HANDLE proc, LPCWSTR dll);

/// <summary>
/// Checks if the current process architecture matches the target's.
/// </summary>
/// <param name="hProc">Handle to the target process to check.</param>
/// <returns>TRUE if the current process's and the target process's architectures match, FALSE otherwise.</returns>
BOOL IsCorrectTargetArchitecture(HANDLE hProc);

/// <summary>
/// Shellcode function to be allocated in the target process.
/// </summary>
/// <param name="pShellcodeData"></param>
/// <returns></returns>
void __stdcall Shellcode(PSHELLCODE_DATA pShellcodeData);
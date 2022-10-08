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

BOOL CustomMap(HANDLE proc, LPCWSTR dll);
BOOL IsCorrectTargetArchitecture(HANDLE hProc);
void __stdcall Shellcode(PSHELLCODE_DATA pShellcodeData);
DWORD __stdcall __shellcode_end_stub();
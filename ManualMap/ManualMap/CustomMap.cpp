#include <Windows.h>
#include <strsafe.h>

#include "Injection.h"

typedef BOOL(WINAPI* DllMain)(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_opt_ LPVOID lpReserved);
typedef UINT_PTR(WINAPI* GetProcAddress_t)(_In_ HMODULE hModule, _In_ LPCSTR  lpProcName);
typedef HMODULE(WINAPI* LoadLibraryA_t)(_In_ LPCSTR lpLibFileName);
typedef BOOL(WINAPI* VirtualProtect_t)(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD  flNewProtect, _Out_ PDWORD lpflOldProtect);

typedef struct {
	WORD offset : 12;
	WORD type : 4;
}IMAGE_RELOC, *PIMAGE_RELOC;

typedef struct {
	GetProcAddress_t _GetProcAddress;
	LoadLibraryA_t _LoadLibraryA;
	VirtualProtect_t _VirtualProtect;
	PBYTE pInMemory;
}SHELLCODE_DATA, *PSHELLCODE_DATA;

VOID PrintDebugMessage(PCSTR pszMessage)
{
	PSTR pszSystem = NULL;
	PSTR pszFormatted = NULL;
	PCSTR pszFormat = "%1!s!: %2!s!\r\n";
	DWORD dwSystemLen = 0;
	DWORD dwFormattedLen = 0;
	DWORD dwBytesWritten = 0;
	DWORD_PTR adwpArgs[3] = { 0 };

	dwSystemLen = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		GetLastError(),
		0,
		(LPSTR)&pszSystem,
		0,
		NULL);
	if (0 == dwSystemLen)
	{
		return;
	}

	adwpArgs[0] = (DWORD_PTR)pszMessage;
	adwpArgs[1] = (DWORD_PTR)pszSystem;
	dwFormattedLen = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY,
		pszFormat,
		0,
		0,
		(LPSTR)&pszFormatted,
		0,
		(va_list*)adwpArgs);
	if (0 == dwFormattedLen)
	{
		LocalFree(pszSystem);
		return;
	}

	WriteFile(GetStdHandle(STD_ERROR_HANDLE),
		pszFormatted,
		dwFormattedLen,
		&dwBytesWritten,
		NULL);

	LocalFree(pszFormatted);
	LocalFree(pszSystem);
}

VOID PrintMessage(PCSTR pszFormat, ...)
{
	PSTR pszFormatted = NULL;
	DWORD dwFormattedLen = 0;
	DWORD dwBytesWritten = 0;
	va_list vaArgs = NULL;

	va_start(vaArgs, pszFormat);

	dwFormattedLen = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_STRING,
		pszFormat,
		0,
		0,
		(LPSTR)&pszFormatted,
		0,
		&vaArgs);

	if (dwFormattedLen > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),
			pszFormatted,
			dwFormattedLen,
			&dwBytesWritten,
			NULL);

		LocalFree(pszFormatted);
	}

	va_end(vaArgs);
}

BOOL ReadAllBytes(LPCWSTR pwszFileName, PBYTE* ppData, PDWORD pdwDataLen)
{
	if (!(ppData && pdwDataLen))
	{
		return FALSE;
	}

	HANDLE hFile = INVALID_HANDLE_VALUE;
	PBYTE pData = NULL;
	DWORD dwBytesRead = 0;
	DWORD dwTotalBytes = 0;
	LARGE_INTEGER liFileSize = { 0 };

	hFile = CreateFileW(pwszFileName,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		PrintDebugMessage("CreateFile");
		goto fail;
	}

	if (FALSE == GetFileSizeEx(hFile, &liFileSize) ||
		liFileSize.HighPart > 0)	// Don't want to bother with file sizes > 4GB
	{
		PrintDebugMessage("GetFileSizeEx");
		goto fail;
	}

	pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, liFileSize.LowPart);
	if (NULL == pData)
	{
		PrintDebugMessage("HeapAlloc");
		goto fail;
	}

	do
	{
		dwBytesRead = 0;

		if (FALSE == ReadFile(hFile,
			pData + dwTotalBytes,
			liFileSize.LowPart - dwTotalBytes,
			&dwBytesRead,
			NULL))
		{
			goto fail;
		}

		dwTotalBytes += dwBytesRead;
	} while (dwTotalBytes != liFileSize.LowPart);

	*ppData = pData;
	*pdwDataLen = liFileSize.LowPart;

	return TRUE;

fail:
	if (NULL != pData)					HeapFree(GetProcessHeap(), 0, pData);
	if (INVALID_HANDLE_VALUE != hFile)	CloseHandle(hFile);
	return FALSE;
}

void __stdcall Shellcode(PSHELLCODE_DATA pShellcodeData) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(pShellcodeData->pInMemory);
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)(pShellcodeData->pInMemory + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(&pNTHeader->FileHeader);
	PIMAGE_OPTIONAL_HEADER pOptHeader = (PIMAGE_OPTIONAL_HEADER)(&pNTHeader->OptionalHeader);
	PIMAGE_DATA_DIRECTORY pDataDir = (PIMAGE_DATA_DIRECTORY)(pOptHeader->DataDirectory);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNTHeader);

	if (NULL == pShellcodeData || NULL == pShellcodeData->pInMemory || NULL == pShellcodeData->_GetProcAddress
		|| NULL == pShellcodeData->_LoadLibraryA || NULL == pShellcodeData->_VirtualProtect) {
		return;
	}

	// Perform relocations if needed
	BYTE* imageDelta = pShellcodeData->pInMemory - pOptHeader->ImageBase;
	if (imageDelta) {
		// Get reloc dir
		PIMAGE_BASE_RELOCATION baseReloc = (PIMAGE_BASE_RELOCATION)(pShellcodeData->pInMemory + pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		while (baseReloc->VirtualAddress) {
			UINT numOfRelocs = (baseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			PIMAGE_RELOC pReloc = (PIMAGE_RELOC)(baseReloc + 1);

			for (UINT x = 0; x < numOfRelocs; ++x, ++pReloc) {
				if (pReloc->type == IMAGE_REL_BASED_HIGHLOW) {
					*(DWORD*)(pShellcodeData->pInMemory + baseReloc->VirtualAddress + pReloc->offset) += (DWORD)imageDelta;
				}
				if(pReloc->type == IMAGE_REL_BASED_DIR64){
					*(ULONG_PTR*)(pShellcodeData->pInMemory + baseReloc->VirtualAddress + pReloc->offset) += (ULONG_PTR)imageDelta;
				}
			}

			baseReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)baseReloc + baseReloc->SizeOfBlock);
		}
	}

	// Resolve imports
	PIMAGE_DATA_DIRECTORY pImportDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)&pShellcodeData->pInMemory[pImportDir->VirtualAddress];
	PSTR pszImportName = (PSTR)(pShellcodeData->pInMemory + pImportDesc->Name);

	while (pImportDesc->Name) {
		pszImportName = (PSTR)(pShellcodeData->pInMemory + pImportDesc->Name);

		// A version since names are ASCII
		HMODULE hLib = pShellcodeData->_LoadLibraryA(pszImportName);
		if (hLib == NULL) {
			return;
		}

		// OFT & FT are copies, OFT remains unchanged, FT get's overwritten when it's loaded
		PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)(pShellcodeData->pInMemory + pImportDesc->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(pShellcodeData->pInMemory + pImportDesc->FirstThunk);

		while (pOrigThunk && pOrigThunk->u1.Ordinal) {
			// Handle if imported by ord vs name - ord is indicated by high bit
			if (IMAGE_SNAP_BY_ORDINAL(pFirstThunk->u1.Ordinal)) {
				// IMAGE_ORDINAL removes high bit when getting addr
				pFirstThunk->u1.Function = pShellcodeData->_GetProcAddress(hLib, (PSTR)IMAGE_ORDINAL(pOrigThunk->u1.Ordinal));
			}
			else {
				// By name
				PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)(pShellcodeData->pInMemory + pOrigThunk->u1.AddressOfData);
				pFirstThunk->u1.Function = pShellcodeData->_GetProcAddress(hLib, pImportName->Name);
			}

			++pFirstThunk;
			++pOrigThunk;
		}
		++pImportDesc;
	}

	// Fix section perms
	/*pSection = IMAGE_FIRST_SECTION(pNTHeader);
	for (INT x = 0; x < pFileHeader->NumberOfSections; ++x, ++pSection) {
		DWORD dwNewProtect = 0;
		DWORD dwOldProtect = 0;

		DWORD ProtectionFlags[2][2][2] = {
			{
				{PAGE_NOACCESS, PAGE_WRITECOPY},
				{PAGE_READONLY, PAGE_READWRITE},
			},
			{
				{PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
				{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
			},
		};

		WORD executable = (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
		WORD readable = (pSection->Characteristics & IMAGE_SCN_MEM_READ) != 0;
		WORD writeable = (pSection->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
		dwNewProtect = ProtectionFlags[executable][readable][writeable];
		pShellcodeData->_VirtualProtect((pShellcodeData->pInMemory + pSection->VirtualAddress), pSection->SizeOfRawData, dwNewProtect, &dwOldProtect);
	}*/

	// Call main
	DllMain entry = (DllMain)(pShellcodeData->pInMemory + pOptHeader->AddressOfEntryPoint);
	(entry)((HINSTANCE)pShellcodeData->pInMemory, DLL_PROCESS_ATTACH, NULL);
}

PBYTE MapToMemory(HANDLE proc, PBYTE pData) {
	if (NULL == pData) {
		return NULL;
	}

	PBYTE pInMemory = NULL;
	SHELLCODE_DATA shellcodeData = { 0 };
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(pData);
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)(pData + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(&pNTHeader->FileHeader);
	PIMAGE_OPTIONAL_HEADER pOptHeader = (PIMAGE_OPTIONAL_HEADER)(&pNTHeader->OptionalHeader);
	PIMAGE_DATA_DIRECTORY pDataDir = (PIMAGE_DATA_DIRECTORY)(pOptHeader->DataDirectory);

	// Alloc space for the DLL, try first @ ImageBase
	pInMemory = (PBYTE)VirtualAllocEx(proc, (LPVOID)(pOptHeader->ImageBase), pOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NULL == pInMemory) {
		pInMemory = (PBYTE)VirtualAllocEx(proc, NULL, pOptHeader->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NULL == pInMemory) {
			PrintDebugMessage("VirtualAllocEx()\n");
			return NULL;
		}
	}

	shellcodeData.pInMemory = pInMemory;
	shellcodeData._GetProcAddress = reinterpret_cast<GetProcAddress_t>(GetProcAddress);
	shellcodeData._LoadLibraryA = LoadLibraryA;
	shellcodeData._VirtualProtect = VirtualProtect;

	printf("Loaded DLL @ %p\n", pInMemory);

	// If VirtualSize > SizeOfRawData, the section is 0 padded
	// We handle this by zeroing the entire memory region of the image
	// Otherwise, we'd have to right zeroes to VirtualSize - SizeOfRawData
	/*ZeroMemory(pInMemory, pOptHeader->SizeOfImage);
	WriteProcessMemory(proc, pInMemory, 0, pOptHeader->SizeOfImage, NULL);*/

	// Copy headers
	printf("Copying Headers\n");
	if (!WriteProcessMemory(proc, pInMemory, pData, pOptHeader->SizeOfHeaders, NULL)) {
		PrintDebugMessage("WriteProcessMemory()\n");
		return NULL;
	}

	// Copy sections
	printf("Copying Sections\n");
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNTHeader);
	for (INT x = 0; x < pFileHeader->NumberOfSections; ++x) {
		if (pSection->SizeOfRawData) {
			if (!WriteProcessMemory(proc, pInMemory + pSection->VirtualAddress, pData + pSection->PointerToRawData, pSection->SizeOfRawData, NULL)) {
				PrintDebugMessage("WriteProcessMemory()\n");
				return NULL;
			}
		}
		++pSection;
	}

	// Alloc and copy shellcode data
	printf("Creating and allocating shellcode\n");	
	LPVOID pShellcodeData = VirtualAllocEx(proc, NULL, sizeof(shellcodeData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (NULL == pShellcodeData) {
		PrintDebugMessage("VirtualAllocEx()\n");
		return NULL;
	}
	if (!WriteProcessMemory(proc, pShellcodeData, &shellcodeData, sizeof(shellcodeData), NULL)) {
		PrintDebugMessage("WriteProcessMemory()\n");
		return NULL;
	}

	// Alloc and copy shellcode
	LPVOID pShellcode = VirtualAllocEx(proc, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NULL == pShellcode) {
		PrintDebugMessage("VirtualAllocEx()\n");
		return NULL;
	}
	if (!WriteProcessMemory(proc, pShellcode, Shellcode, 0x1000, NULL)) {
		PrintDebugMessage("WriteProcessMemory()\n");
		return NULL;
	}

	// Exec Shellcode
	HANDLE hThread = CreateRemoteThread(proc, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pShellcodeData, 0, NULL);
	if (NULL == hThread) {
		PrintDebugMessage("CreateRemoteThread()\n");
		return NULL;
	}

	// Cleanup

	return pInMemory;
}

INT CustomMap(HANDLE proc, LPCWSTR dll)
{
	PBYTE pData = NULL;
	DWORD dwDataLen = 0;

	// 1. Read in the contents of the test (or your own) dll/exe
	// You can use the helper functions
	if (FALSE == ReadAllBytes(dll, &pData, &dwDataLen)) {
		PrintDebugMessage("ReadAllBytes()\n");
		return 1;
	}

	// 3. Map disk image to a virtual image
	PBYTE pInMemory = MapToMemory(proc, pData);

	if (NULL == pInMemory) {
		PrintDebugMessage("MapToMemory()\n");
		return 1;
	}

	VirtualFree(pInMemory, 0, MEM_RELEASE);

	// 4. (Optional) Implement a custom GetProcAddress to resolve exports from your loaded Dll
	// If done correctly, you should be able to use your GetProcAddress to get an address to DisplayMessage
	// Call DisplayMessage like you would MessageBoxW, and a message box should appear

	// 5. Resolve imports
	// Done in MapToMemory(pData, dwDataLen);

	// 6. Handle relocations
	// Done in MapToMemory(pData, dwDataLen);

	// 7. (Optional) Handle TLS callbacks

	// 8. Finalize Sections

	// 9. Call entry point

	return EXIT_SUCCESS;
}
#include "ManualMap.hpp"

void __stdcall _ManualMapShellcode(PSHELLCODE_DATA pShellcodeData);
void __stdcall _DetachDLLShellcode(PSHELLCODE_DATA pShellcodeData);

BOOL ManualMap::IsCorrectTargetArchitecture(HANDLE hProc)
{
	BOOL isTarget32 = FALSE;
	if (!IsWow64Process(hProc, &isTarget32))
	{
		return FALSE;
	}

	BOOL isInjector32 = FALSE;
	IsWow64Process(GetCurrentProcess(), &isInjector32);

	return (isTarget32 == isInjector32);
}

BOOL ManualMap::ReadAllBytes(LPCWSTR pwszFileName, PBYTE* ppData, PDWORD pdwDataLen)
{
	if (!(pwszFileName && ppData && pdwDataLen)) {
		return FALSE;
	}
	
	HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile = CreateFileW(pwszFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (INVALID_HANDLE_VALUE == hFile) {
		return FALSE;
	}

	// No files > 4GB
	LARGE_INTEGER liFileSize = { 0 };
	if (FALSE == GetFileSizeEx(hFile, &liFileSize) || liFileSize.HighPart > 0) {
		CloseHandle(hFile);
		return FALSE;
	}

	PBYTE pData = new BYTE[liFileSize.LowPart];
	if (NULL == pData) {
		CloseHandle(hFile);
		return FALSE;
	}
	ZeroMemory(pData, liFileSize.LowPart);

	DWORD dwBytesRead = 0;
	DWORD dwTotalBytes = 0;
	do {
		dwBytesRead = 0;

		if (FALSE == ReadFile(hFile, pData + dwTotalBytes, liFileSize.LowPart - dwTotalBytes, &dwBytesRead, NULL)) {
			delete[] pData;
			CloseHandle(hFile);
			return FALSE;
		}

		dwTotalBytes += dwBytesRead;
	} while (dwTotalBytes != liFileSize.LowPart);

	*ppData = pData;
	*pdwDataLen = liFileSize.LowPart;

	return TRUE;
}

BOOL ManualMap::MapToMemory(HANDLE hProc, PBYTE pData) {
	if (!pData) {
		return FALSE;
	}

	PBYTE pInMemory = NULL;
	SHELLCODE_DATA shellcodeData = { 0 };
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(pData);
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)(pData + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(&pNTHeader->FileHeader);
	PIMAGE_OPTIONAL_HEADER pOptHeader = (PIMAGE_OPTIONAL_HEADER)(&pNTHeader->OptionalHeader);

	// Alloc space for the DLL, try first @ ImageBase
	pInMemory = (PBYTE)VirtualAllocEx(hProc, (LPVOID)(pOptHeader->ImageBase), pOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NULL == pInMemory) {
		pInMemory = (PBYTE)VirtualAllocEx(hProc, NULL, pOptHeader->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NULL == pInMemory) {
			return FALSE;
		}
	}

	shellcodeData.pInMemory = pInMemory;
	shellcodeData._GetProcAddress = reinterpret_cast<GetProcAddress_t>(GetProcAddress);
	shellcodeData._LoadLibraryA = LoadLibraryA;
	shellcodeData._VirtualProtect = VirtualProtect;

	// Copy headers
	if (!WriteProcessMemory(hProc, pInMemory, pData, pOptHeader->SizeOfHeaders, NULL)) {
		VirtualFreeEx(hProc, pInMemory, 0, MEM_RELEASE);
		return FALSE;
	}

	// Copy sections
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNTHeader);
	for (INT x = 0; x < pFileHeader->NumberOfSections; ++x) {
		if (pSection->SizeOfRawData) {
			if (!WriteProcessMemory(hProc, pInMemory + pSection->VirtualAddress, pData + pSection->PointerToRawData, pSection->SizeOfRawData, NULL)) {
				VirtualFreeEx(hProc, pInMemory, 0, MEM_RELEASE);
				return FALSE;
			}
		}
		++pSection;
	}

	// Alloc and copy shellcode data
	LPVOID pShellcodeData = VirtualAllocEx(hProc, NULL, sizeof(shellcodeData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (NULL == pShellcodeData) {
		VirtualFreeEx(hProc, pInMemory, 0, MEM_RELEASE);
		return FALSE;
	}
	if (!WriteProcessMemory(hProc, pShellcodeData, &shellcodeData, sizeof(shellcodeData), NULL)) {
		VirtualFreeEx(hProc, pInMemory, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcodeData, 0, MEM_RELEASE);
		return FALSE;
	}

	// Alloc for shellcode
	LPVOID pShellcode = VirtualAllocEx(hProc, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NULL == pShellcode) {
		VirtualFreeEx(hProc, pInMemory, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcodeData, 0, MEM_RELEASE);
		return FALSE;
	}

	PUINT_PTR pShellcodeFunc = (PUINT_PTR)_ManualMapShellcode;

#ifdef _DEBUG
	// If built w/ debug, resolve shellcode address from jump table
	// Only works for short jumps (opcode E9)
	pShellcodeFunc = (PUINT_PTR)((BYTE*)pShellcodeFunc + (*(UINT32*)((BYTE*)pShellcodeFunc + 1)) + 5);
#endif

	// Copy shellcode into target. 4096 is arbitrary, it just needs to be big enough for Shellcode().
	if (!WriteProcessMemory(hProc, pShellcode, (LPCVOID)pShellcodeFunc, 4096, NULL)) {
		VirtualFreeEx(hProc, pInMemory, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcodeData, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return FALSE;
	}

	// Exec Shellcode
	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pShellcodeData, 0, NULL);
	if (NULL == hThread) {
		VirtualFreeEx(hProc, pInMemory, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcodeData, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return FALSE;
	}

	// Wait for DLLMain() to return
	if (WAIT_OBJECT_0 != WaitForSingleObject(hThread, INFINITE)) {
		return FALSE;
	}

	// Cleanup
	CloseHandle(hThread);
	if (!VirtualFreeEx(hProc, pShellcodeData, 0, MEM_RELEASE)) {
		return FALSE;
	}
	if (!VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE)) {
		return FALSE;
	}

	m_hThread = INVALID_HANDLE_VALUE;
	m_pDllInMemory = pInMemory;
	m_pShellcode = NULL;
	m_stShellcodeSize = 4096;
	m_stDllSize = pOptHeader->SizeOfImage;

	return TRUE;
}

BOOL ManualMap::CustomMap(HANDLE proc, LPCWSTR dll)
{
	if (!dll) {
		return FALSE;
	}

	PBYTE pData = NULL;
	DWORD dwDataLen = 0;

	if (!ReadAllBytes(dll, &pData, &dwDataLen)) {
		return FALSE;
	}

	if (!MapToMemory(proc, pData)) {
		return FALSE;
	}

	delete[] pData;

	return TRUE;
}

BOOL ManualMap::FreeDLL() {
	if (!(m_pDllInMemory && m_stDllSize)) {
		return FALSE;
	}

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_PID);
	if (NULL == hProc) {
		return FALSE;
	}

	SHELLCODE_DATA shellcodeData = { 0 };
	shellcodeData.pInMemory = (PBYTE)m_pDllInMemory;

	// Alloc and copy shellcode data
	LPVOID pShellcodeData = VirtualAllocEx(hProc, NULL, sizeof(shellcodeData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (NULL == pShellcodeData) {
		return FALSE;
	}
	if (!WriteProcessMemory(hProc, pShellcodeData, &shellcodeData, sizeof(shellcodeData), NULL)) {
		return FALSE;
	}

	// Alloc for shellcode
	LPVOID pShellcode = VirtualAllocEx(hProc, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NULL == pShellcode) {
		return FALSE;
	}

	PUINT_PTR pShellcodeFunc = (PUINT_PTR)_DetachDLLShellcode;

#ifdef _DEBUG
	// If built w/ debug, resolve shellcode address from jump table
	// Only works for short jumps (opcode E9)
	pShellcodeFunc = (PUINT_PTR)((BYTE*)pShellcodeFunc + (*(UINT32*)((BYTE*)pShellcodeFunc + 1)) + 5);
#endif

	// Copy shellcode into target. 4096 is arbitrary, it just needs to be big enough for Shellcode().
	if (!WriteProcessMemory(hProc, pShellcode, (LPCVOID)pShellcodeFunc, 4096, NULL)) {
		return FALSE;
	}

	// Exec Shellcode
	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pShellcodeData, 0, NULL);
	if (NULL == hThread) {
		return FALSE;
	}

	if (WAIT_OBJECT_0 != WaitForSingleObject(hThread, 10000)) {
		return FALSE;
	}

	// Free DLL
	if (!VirtualFreeEx(hProc, m_pDllInMemory, 0, MEM_RELEASE)) {
		return FALSE;
	}
	// Free Shellcode
	if (!VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE)) {
		return FALSE;
	}
	// Free Shellcode Data
	if (!VirtualFreeEx(hProc, pShellcodeData, 0, MEM_RELEASE)) {
		return FALSE;
	}

	CloseHandle(hProc);
	CloseHandle(hThread);

	m_pDllInMemory = NULL;
	m_stDllSize = 0;

	return TRUE;
}

void __stdcall _ManualMapShellcode(PSHELLCODE_DATA pShellcodeData) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(pShellcodeData->pInMemory);
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)(pShellcodeData->pInMemory + pDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptHeader = (PIMAGE_OPTIONAL_HEADER)(&pNTHeader->OptionalHeader);
	PIMAGE_DATA_DIRECTORY pDataDir = (PIMAGE_DATA_DIRECTORY)(pOptHeader->DataDirectory);

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
					*(DWORD*)(pShellcodeData->pInMemory + baseReloc->VirtualAddress + pReloc->offset) += (ULONG_PTR)imageDelta;
				}
				if (pReloc->type == IMAGE_REL_BASED_DIR64) {
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

		// "A" version since names are ASCII
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

	// Ideally section permission should be fixed here.

	// Call main
	DllMain_t entry = (DllMain_t)(pShellcodeData->pInMemory + pOptHeader->AddressOfEntryPoint);
	(entry)((HINSTANCE)pShellcodeData->pInMemory, DLL_PROCESS_ATTACH, NULL);
}

void __stdcall _DetachDLLShellcode(PSHELLCODE_DATA pShellcodeData) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(pShellcodeData->pInMemory);
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)(pShellcodeData->pInMemory + pDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptHeader = (PIMAGE_OPTIONAL_HEADER)(&pNTHeader->OptionalHeader);

	// Call main
	DllMain_t entry = (DllMain_t)(pShellcodeData->pInMemory + pOptHeader->AddressOfEntryPoint);
	(entry)((HINSTANCE)pShellcodeData->pInMemory, DLL_PROCESS_DETACH, NULL);
}
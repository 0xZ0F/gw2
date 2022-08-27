#include "Injection.h"

//declaration of the function which is writen below the ManualMap function. 
//__stdcall is here for x86 applications for compatibility reasons. See explanations in header file
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);

bool ManualMap(HANDLE hProc, const char* szDllFile)
{
	BYTE* dllData = nullptr;
	BYTE* pTargetBase = nullptr;
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;

	// Make sure DLL exists:
	if (::GetFileAttributesA(szDllFile) == INVALID_FILE_ATTRIBUTES)
	{
		fprintf(stderr, "File does not exist\n");
		return false;
	}

	//std::ios::binary | std::ios::ate - means binary mode AND initial position at the end (ate) of the file
	std::ifstream File(szDllFile, std::ios::binary | std::ios::ate);

	if (File.fail())
	{
		//returns current internal error state flag http://www.cplusplus.com/reference/ios/ios/rdstate/
		fprintf(stderr, "Failed to open file: %X\n", (DWORD)File.rdstate());
		File.close();
		return false;
	}

	auto fileSize = File.tellg();
	// Lazy way to check if DLL is valid (4096 for PE header)
	if (fileSize < 0x1000)
	{
		printf("fileSize is invalid.\n");
		File.close();
		return false;
	}

	// Alloc space to read DLL into
	dllData = new BYTE[static_cast<UINT_PTR>(fileSize)];
	if (!dllData)
	{
		fprintf(stderr, "Memory alloc failed\n");
		File.close();
		return false;
	}

	// Read DLL
	File.seekg(0, std::ios::beg);
	File.read(reinterpret_cast<char*>(dllData), fileSize);
	File.close();

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(dllData)->e_magic != 0x5A4D)
	{
		fprintf(stderr, "Invalid DLL\n");
		delete[] dllData;
		return false;
	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(dllData + reinterpret_cast<IMAGE_DOS_HEADER*>(dllData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

	#ifdef _WIN64
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		fprintf(stderr, "Invalid platform\n");
		delete[] dllData;
		return false;
	}
	#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
	{
		fprintf(stderr, "Invalid platform\n");
		delete[] dllData;
		return false;
	}
	#endif

	// Now we are going to allocate memory into target process
	// lpAddress is not strictly followed, it's a suggestion, in this case the usual requested base addr of a DLL is used as a starting point
	pTargetBase = reinterpret_cast<BYTE*>(::VirtualAllocEx(hProc, reinterpret_cast<void*>(pOldOptHeader->ImageBase), pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	if (!pTargetBase)
	{
		//another try without preferred address
		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

		if (!pTargetBase)
		{
			fprintf(stderr, "Memory allocation failed (ex) 0x%X\n", ::GetLastError());
			delete[] dllData;
			return false;
		}
	}

	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = ::LoadLibraryA;
	data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(::GetProcAddress); //reinterpret_cast is used here because f_GetProcAddress defined different (return UINT_PTR)
	auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);

	/*
	Why do we need to map sections?
	The PE file on disk is "compressed". Some sections don't even exist in the raw file.
	The section header contains the required information for the "runtime version" of the file.
	*/
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) //++pSectionHeader - next pointer to next section
	{
		if (pSectionHeader->SizeOfRawData)
		{
			// Write Section
			if (!::WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, dllData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
			{
				fprintf(stderr, "Can't map sections: 0x%x\n", ::GetLastError());
				delete[] dllData;
				::VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}


	/*
	Data overrides dllData here. The data structure is only 12 / 24 bytes big and the first 12 / 24 bytes of the DOS header are irrelevant at this point.
	(We will be manually calling DllMain() so it doesn't matter if some of the DOS Header is corrupt)

	This is done to avoid additional memory allocations by instead using already allocated memory to the store the required data.
	To make this staff correct we should allocate memory for data structure and rewrite some things in shellcode function.
	*/
	#pragma warning(suppress: 6386) // Compiler doesn't know sizeof(data) < sizeof(dllData)
	memcpy(dllData, &data, sizeof(data));

	// Write PE Headers (first 0x1000 bytes are reserved for the headers) of data into the target process
	#pragma warning(suppress: 6385) // See previous #pragma
	::WriteProcessMemory(hProc, pTargetBase, dllData, 0x1000, nullptr);
	
	delete[] dllData; // No longer needed

	//0x1000 hardcode 4 kB for shellcode which should be more than enough
	void* pShellcode = ::VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode)
	{
		fprintf(stderr, "Memory allocation failed (1) (ex) 0x%X\n", ::GetLastError());
		::VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	// The 0x1000 is just an "estimate" to make sure the whole function gets copied. 0x1000 is more than enough for this function.
	::WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr); //Write shellcode to the process

	/*
		Run shellcode in the proc

		LPTHREAD_START_ROUTINE lpStartAddress
			A pointer to the application-defined function of type LPTHREAD_START_ROUTINE to be executed by the thread
			and represents the starting address of the thread in the remote process. The function must exist in the remote process.
		LPVOID lpParameter
			A pointer to a variable to be passed to the thread function.
	*/
	HANDLE hThread = ::CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, nullptr);
	if (!hThread)
	{
		fprintf(stderr, "Thread creation failed 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}
	::CloseHandle(hThread);

	// Wait for shellcode to finish
	HINSTANCE hCheck = NULL;
	while (!hCheck)
	{
		MANUAL_MAPPING_DATA data_checked{ 0 };
		::ReadProcessMemory(hProc, pTargetBase, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod;
		::Sleep(10);
	}

	// Deallocate the DLL.
	/*VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);*/

	// Deallocate the shellcode.
	::VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);

	return true;
}

/*
Macro for relocations in shellcode

shift RelInfo right on 12. RelInfo has WORD type (see below). For example if RelInfo is '1010 1111 0000 1111' after operation >> 0x0C it becomes '1010'
These bits '1010' are represent type in the relocation table: https://stackoverflow.com/questions/17436668/how-are-pe-base-relocations-build-up
This number is compared with 0011 in x86 architecture or with 1010 in x64
IMAGE_REL_BASED_HIGHLOW - The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
IMAGE_REL_BASED_DIR64   - The base relocation applies the difference to the 64-bit field at offset.
https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only
You can also look how this relocation table looks like with CFF Explorer in Relocation Directory of your DLL
*/
#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

/// <summary>
/// This function is allocated inside target process and executed to load DLL.
/// It applies relocations required, imports anything required by the DLL to be imported, and execute TLS.
/// </summary>
/// <param name="pData"></param>
/// <returns></returns>
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData)
{
	// Do as little as possible in here.

	// We use pData for two things here: 1) for pointer to the base address of the data structure and 2) for pointer to relocations Dll data (headers)
	if (!pData)
		return;

	BYTE* pBase = reinterpret_cast<BYTE*>(pData);
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;

	// AddressOfEntryPoint is offset to dll entry point after allocating section .text in memory
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	// ImageBase is preferred address for the DLL, pBase is actual address
	BYTE* locationDelta = pBase - pOpt->ImageBase;
	if (locationDelta)
	{
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return;

		/*
		All memory addresses in the code/data sections of a library are stored relative to the address defined by ImageBase in the OptionalHeader.
		If the library can't be imported to this memory address, the references must get adjusted => relocated.
		The file format helps by storing information about all these references in the base relocation table,
		which can be found at the directory entry index 5 in the OptionalHeader.

		This table consists of a series of this structure:
		typedef struct _IMAGE_DATA_DIRECTORY {
			DWORD   VirtualAddress;
			DWORD   Size;
		} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
		It contains (SizeOfBlock * IMAGE_SIZEOF_BASE_RELOCATION) / 2 entries of 16 bits each.
		The upper 4 bits define the type of relocation, the lower 12 bits define the offset relative to the VirtualAddress.
		https://www.joachim-bauch.de/tutorials/loading-a-dll-from-memory/
		DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size is Relocation Directory Size. Same as .reloc Virtual Size in Section Headers

		The .reloc section is a list of places in the image where the difference between the linker assumed load address and the actual load address needs to be factored in.
		https://www.codeproject.com/Articles/12532/Inject-your-code-to-a-Portable-Executable-file#ImplementRelocationTable7_2
		By relocation, some values inside the virtual memory are corrected according to the current image base by the ".reloc" section packages.
		delta_ImageBase = current_ImageBase - image_nt_headers->OptionalHeader.ImageBase
		mem[ current_ImageBase + 0x1000 ] = mem[ current_ImageBase + 0x1000 ] + delta_ImageBase ;
		*/

		// get pointer to .reloc
		auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		// Apply relocs
		while (pRelocData->VirtualAddress)
		{
			// (SizeOfBlock - Structure in the beginning) / (65535 or 0xFFFF or 16 bits)
			UINT numOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			// Data after struct IMAGE_BASE_RELOCATION
			WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

			// pRelativeInfo increment 1 WORD here
			for (UINT i = 0; i != numOfEntries; ++i, ++pRelativeInfo)
			{
				// If *pRelativeInfo has type 3 or 10 (x86 or x64 respectively)
				if (RELOC_FLAG(*pRelativeInfo))
				{
					//*pRelativeInfo & 0xFFF get rid of type
					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));

					/*
					Add to *pRelativeInfo (without type) a LocationDelta offset here

					pPatch is a pointer to a cell in the relocation table. It is little bit difficult to figure out how relocation table looks like to understand what is going on here.
					The better way to understand this is watch a relocation table with CFF Explorer as was mentioned above. pPatch is a pointer to a cell which contain an address (RVA)
					LocationDelta is added to the value in the cell (is added ro RVA)
					*/
					*pPatch += reinterpret_cast<UINT_PTR>(locationDelta);
				}
			}
			// next block
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	// Import all the imports required for the injected DLL
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		/*
		Pointer to Import Directory

		IAT - Import Address Table https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
		typedef struct _IMAGE_IMPORT_DESCRIPTOR {
			union {									//OFTs
				DWORD   Characteristics;            // 0 for terminating null import descriptor
				DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
			} DUMMYUNIONNAME;
			DWORD   TimeDateStamp;                  // 0 if not bound,
													// -1 if bound, and real date\time stamp
													//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
													// O.W. date/time stamp of DLL bound to (Old BIND)

			DWORD   ForwarderChain;                 // -1 if no forwarders. The index of the first forwarder reference.
			DWORD   Name;							// Name RVA. The address of an ASCII string that contains the name of the DLL. This address is relative to the image base.
			DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses). The RVA of the import address table.
													   The contents of this table are identical to the contents of the import lookup table until the image is bound.
													   In Other words OriginalFirstThunk = FirstThunk until the image is bound.
		} IMAGE_IMPORT_DESCRIPTOR;
		About bound import:
		For bound imports, the linker saves the timestamp and checksum of the DLL to which the import is bound.
		At run-time Windows checks to see if the same version of library is being used, and if so, Windows bypasses processing the imports.
		Otherwise, if the library is different from the one which was bound to, Windows processes the imports in a normal way.
		For example, all the standard Windows applications are bound to the system DLLs of their respective Windows release.
		*/
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		// If DLL import is found
		while (pImportDescr->Name)
		{
			// Name of DLL to Import
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			// Get Handle to that Dll
			// It is Important to use defined functions in the beggining (auto _LoadLibraryA = pData->pLoadLibraryA;). Otherwise shellcode won't determine the functions.
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			// There is a chance that OriginalFirstThunk is not define. In this case we don't want to get an error.
			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				/*
				Function import can be execed using either function name or ordinal number:
				Something like GetProcAddress(lib, "ReadProcessMemory") or GetProcAddress(lib, (char*)42)
				*/

				/*
				If *pThunkRef has high bit (0x80000000) then *pThunkRef low bits (0xFFFF) contain ordinal number and *pThunkRef has structure:
				typedef struct _IMAGE_THUNK_DATA32 {
					union {
						DWORD ForwarderString;      // PBYTE
						DWORD Function;             // PDWORD
						DWORD Ordinal;
						DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
					} u1;
				} IMAGE_THUNK_DATA32;
				(This structure can not be seen in CFF Explorer, in this case another editor is needed, but same structure can be seen in Export Directory for some Dll)
				*/
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					// Add ProcAddress of the function in dll to FirstThunk (FTs or IAT) by number
					*pFuncRef = _GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}

				/*
				If *pThunkRef doesn't have high bit then *pThunkRef low bits (0xFFFF) contain name and *pThunkRef has structure:
				typedef struct _IMAGE_IMPORT_BY_NAME {
					WORD    Hint;   - number of the function
					BYTE    Name[1];
				} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
				This structure can be seen in CFF Explorer
				*/
				else
				{
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					//add ProcAddress of the function in dll to FirstThunk (FTs or IAT) by name
					*pFuncRef = _GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	// We need to execute TLSs
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) //it is usually 0 for simple hacks which don't contain opened threads
	{
		/*
		About TLS:
		The TLS array is an array of addresses that the system maintains for each thread.
		Each address in this array gives the location of TLS data for a given module (EXE or DLL) within the program.
		The TLS index indicates which member of the array to use. The index is a number (meaningful only to the system) that identifies the module.
		https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
		The best explanation is here:
		https://docs.microsoft.com/en-us/windows/win32/procthread/thread-local-storage

		Therefore: If you didn't create a thread in Dll with CreateThread() function then TLS Size and VirtualAddress are set to 0
		*/

		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr); // Exec DllMain();

	pData->hMod = reinterpret_cast<HINSTANCE>(pBase); // Signal ManualMap the shellcode has completed.
}
#include "Injection.h"
#include "CustomMap.h"

/// <summary>
/// Check if both the injector and the target process are the same architecture.
/// </summary>
/// <param name="hProc">Handle to the proc to check</param>
/// <returns>True if both the injector and the target are the same arch.</returns>
bool IsCorrectTargetArchitecture(HANDLE hProc)
{
	BOOL isTarget32 = FALSE;
	if (!IsWow64Process(hProc, &isTarget32))
	{
		printf("Can't confirm target process architecture: 0x%X\n", ::GetLastError());
		return false;
	}

	BOOL isInjector32 = FALSE;
	IsWow64Process(GetCurrentProcess(), &isInjector32);

	return (isTarget32 == isInjector32);
}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
	if (argc != 3) {
		fprintf(stderr, "Usage: %ls <Process Name> <DLL Path>\n", argv[0]);
		return 1;
	}

	fprintf(stderr, "Target: %ls\n", argv[1]);
	fprintf(stderr, "Injecting: %ls\n", argv[2]);

	PROCESSENTRY32W PE32{ 0 };

	// Req for Process32First()
	PE32.dwSize = sizeof(PE32);

	// Find the target PID
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		DWORD Err = GetLastError();
		printf("CreateToolhelp32Snapshot failed: 0x%X\n", Err);
		system("PAUSE");
		return 0;
	}

	DWORD PID = 0;
	BOOL bRet = Process32FirstW(hSnap, &PE32);
	while (bRet)
	{
		if (wcsncmp(PE32.szExeFile, argv[1], sizeof(PE32.szExeFile)) == 0)
		{
			PID = PE32.th32ProcessID;
			break;
		}
		bRet = Process32NextW(hSnap, &PE32);
	}

	CloseHandle(hSnap);

	HANDLE hProc = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProc)
	{
		DWORD Err = ::GetLastError();
		printf("OpenProcess failed: 0x%X\n", Err);
		system("PAUSE");
		return 0;
	}

	if (!IsCorrectTargetArchitecture(hProc))
	{
		printf("Invalid target process.\n");
		CloseHandle(hProc);
		system("PAUSE");
		return 0;
	}

	CustomMap(hProc, argv[2]);

	// Map DLL
	/*BOOL res = ManualMap(hProc, pszDLL_NAME);
	if (!res)
	{
		::CloseHandle(hProc);
		printf("Something went wrong in ManualMap function. Exit.\n");
		system("PAUSE");
		return 0;
	}*/

	CloseHandle(hProc);
	return 0;
}
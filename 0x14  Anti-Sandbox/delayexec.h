#pragma once
#include <Windows.h>
#include <stdio.h>
#include "UserDefineApi.h"

typedef NTSTATUS(NTAPI* fnNtDelayExecution)(
	BOOLEAN              Alertable,
	PLARGE_INTEGER       DelayInterval
	);
BOOL DelayExecutionVia_NtDE(FLOAT ftMinutes) {

	// converting minutes to milliseconds
	DWORD				dwMilliSeconds = ftMinutes * 60000;
	LARGE_INTEGER		DelayInterval = { 0 };
	LONGLONG			Delay = NULL;
	NTSTATUS			STATUS = NULL;
	fnNtDelayExecution	pNtDelayExecution = (fnNtDelayExecution)MyGetProcAddress(MyGetModuleHandle(L"NTDLL.DLL"), "NtDelayExecution");
	DWORD				_T0 = NULL,
		_T1 = NULL;

	printf("[i] Delaying Execution Using \"NtDelayExecution\" For %0.3d Seconds", (dwMilliSeconds / 1000));

	// converting from milliseconds to the 100-nanosecond - negative time interval
	Delay = dwMilliSeconds * 10000;
	DelayInterval.QuadPart = -Delay;

	_T0 = GetTickCount64();

	// sleeping for 'dwMilliSeconds' ms 
	if ((STATUS = pNtDelayExecution(FALSE, &DelayInterval)) != 0x00 && STATUS != STATUS_TIMEOUT) {
		printf("[!] NtDelayExecution Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	_T1 = GetTickCount64();

	// slept for at least 'dwMilliSeconds' ms, then 'DelayExecutionVia_NtDE' succeeded, otherwize it failed
	if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
		return FALSE;

	printf("\n\t>> _T1 - _T0 = %d \n", (DWORD)(_T1 - _T0));

	printf("[+] DONE \n");

	return TRUE;
}


typedef NTSTATUS(NTAPI* fnNtWaitForSingleObject)(
	HANDLE         Handle,
	BOOLEAN        Alertable,
	PLARGE_INTEGER Timeout
	);

BOOL DelayExecutionVia_NtWFSO(FLOAT ftMinutes) {

	// converting minutes to milliseconds
	DWORD					dwMilliSeconds = ftMinutes * 60000;
	HANDLE					hEvent = CreateEvent(NULL, NULL, NULL, NULL);
	LONGLONG				Delay = NULL;
	NTSTATUS				STATUS = NULL;
	LARGE_INTEGER			DelayInterval = { 0 };
	fnNtWaitForSingleObject	pNtWaitForSingleObject = (fnNtWaitForSingleObject)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtWaitForSingleObject");
	DWORD					_T0 = NULL,
		_T1 = NULL;


	printf("[i] Delaying Execution Using \"NtWaitForSingleObject\" For %0.3d Seconds", (dwMilliSeconds / 1000));

	// converting from milliseconds to the 100-nanosecond - negative time interval
	Delay = dwMilliSeconds * 10000;
	DelayInterval.QuadPart = -Delay;

	_T0 = GetTickCount64();

	// sleeping for 'dwMilliSeconds' ms 
	if ((STATUS = pNtWaitForSingleObject(hEvent, FALSE, &DelayInterval)) != 0x00 && STATUS != STATUS_TIMEOUT) {
		printf("[!] NtWaitForSingleObject Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	_T1 = GetTickCount64();

	// slept for at least 'dwMilliSeconds' ms, then 'DelayExecutionVia_NtWFSO' succeeded, otherwize it failed
	if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
		return FALSE;

	printf("\n\t>> _T1 - _T0 = %d \n", (DWORD)(_T1 - _T0));

	printf("[+] DONE \n");

	CloseHandle(hEvent);

	return TRUE;
}

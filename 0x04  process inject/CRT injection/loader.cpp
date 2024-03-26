#include <iostream>
#include <tchar.h>
#include <windows.h>
#include <TlHelp32.h>

DWORD GetProcessPID(LPCTSTR lpProcessName)
{
    DWORD Ret = 0;
    PROCESSENTRY32 p32;
    HANDLE lpSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (lpSnapshot == INVALID_HANDLE_VALUE)
    {
        printf("获取进程快照失败,请重试,error:%d", ::GetLastError());
        return Ret;
    }
    p32.dwSize = sizeof(PROCESSENTRY32);
    ::Process32First(lpSnapshot, &p32);
    do {
    	if (!lstrcmp(p32.szExeFile, lpProcessName))	
            {
            Ret = p32.th32ProcessID;
            break;
            }
    } while (::Process32Next(lpSnapshot, &p32));
        ::CloseHandle(lpSnapshot);
    return Ret;
}

DWORD RemoteThreadInject(DWORD Pid, LPCWSTR DllName)
{
    DWORD size = 0;
    DWORD DllAddr = 0;
    
    // 1.打开进程
    HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
    if (hprocess == NULL)
    {
        printf("OpenProcess error!\n");
        return FALSE;
    }
    size = (wcslen(DllName) + 1) * sizeof(TCHAR);
    
    // 2.申请空间
    LPVOID pAllocMemory = VirtualAllocEx(hprocess, NULL, size, MEM_COMMIT,PAGE_READWRITE);
    if (pAllocMemory == NULL)
    {
        printf("VirtualAllocEx error!\n");
        return FALSE;
    }
    
    // 3.写入内存
    BOOL Write = WriteProcessMemory(hprocess, pAllocMemory, DllName, size,NULL);
    if (pAllocMemory == 0)
    {
        printf("WriteProcessMemory error!\n");
        return FALSE;
    

    // 4.获取LoadLibrary - kenrel32.dll
    FARPROC pThread = GetProcAddress(GetModuleHandle(L"kernel32.dll"),"LoadLibraryW");
    LPTHREAD_START_ROUTINE addr = (LPTHREAD_START_ROUTINE)pThread;
    
    // 5.创建线程
    HANDLE hThread = CreateRemoteThread(hprocess, NULL, 0, addr, pAllocMemory,0, NULL);
    if (hThread == NULL)
    {
    printf("CreateRemoteThread error!\n");
    return FALSE;
    }
    
    // 6.等待线程函数结束
    WaitForSingleObject(hThread, -1);
    // 7.释放DLL空间
    VirtualFreeEx(hprocess, pAllocMemory, size, MEM_DECOMMIT);
    // 8.关闭句柄
    CloseHandle(hprocess);
    return TRUE;
}

int main()
{
    DWORD PID = GetProcessPID(L"notepad.exe");
    RemoteThreadInject(PID, L"C:\\Users\\test\\Desktop\\x64.dll");
}
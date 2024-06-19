#pragma once

#include <Windows.h>
#include <stdio.h>
#include <Shlwapi.h>
#include <psapi.h>

#pragma comment(lib, "Shlwapi.lib")

class VenvChecker {
public:
    static BOOL IsVenvByHardwareCheck();

private:
    VenvChecker() = default;
};

BOOL VenvChecker::IsVenvByHardwareCheck() {
    SYSTEM_INFO SysInfo = { 0 };
    MEMORYSTATUSEX MemStatus = { sizeof(MEMORYSTATUSEX) };
    HKEY hKey = NULL;
    DWORD dwUsbNumber = NULL;
    DWORD dwRegErr = NULL;

    // CPU 检查
    GetSystemInfo(&SysInfo);

    // 处理器少于2个
    if (SysInfo.dwNumberOfProcessors < 2) {
        return TRUE;
    }

    // 内存检查
    if (!GlobalMemoryStatusEx(&MemStatus)) {
        printf("\n\t[!] GlobalMemoryStatusEx 失败，错误码: %d \n", GetLastError());
        return FALSE;
    }

    // 内存少于2GB
    if ((DWORD)MemStatus.ullTotalPhys < (DWORD)(2 * 1073741824)) {
        return TRUE;
    }

    // 检查曾经连接过的USB数量
    if ((dwRegErr = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Enum\\USBSTOR", NULL, KEY_READ, &hKey)) != ERROR_SUCCESS) {
        printf("\n\t[!] RegOpenKeyExA 失败，错误码: %d | 0x%0.8X \n", dwRegErr, dwRegErr);
        return FALSE;
    }

    if ((dwRegErr = RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &dwUsbNumber, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) != ERROR_SUCCESS) {
        printf("\n\t[!] RegQueryInfoKeyA 失败，错误码: %d | 0x%0.8X \n", dwRegErr, dwRegErr);
        return FALSE;
    }

    // 曾经连接过的USB少于2个
    if (dwUsbNumber < 2) {
        return TRUE;
    }

    RegCloseKey(hKey);

    return FALSE;
}

